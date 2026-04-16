// taint-report.js — human-friendly taint-flow presentation and
// PoC reproducer synthesis.
//
// Reads `trace.taintFlows`, then per flow:
//
//   * Looks up the attempts library at `typeDB.exploits[sink.exploit]`.
//     Every payload shape lives in the TypeDB as pure data — the
//     consumer holds zero hardcoded exploit strings.
//
//   * Builds an SMT predicate from each attempt's `trigger`
//     ('contains' / 'equals' / 'prefixof') applied to the flow's
//     `valueFormula`, conjoins it with the flow's pathFormula,
//     and asks Z3 for a model. First SAT wins.
//
//   * Emits a runnable JavaScript program — a PoC — that
//     orchestrates every source binding through its declared
//     delivery mechanism (URL construction + navigation for
//     location-*, postMessage after load for message handlers,
//     localStorage setItem before navigation, etc.). The PoC is
//     a string the consumer can paste into a browser console to
//     demonstrate the flow.
//
// The consumer does NO hardcoded mapping of sink-kind → payload
// or source-label → delivery. Every choice lives in the TypeDB:
// swap `options.typeDB` and PoCs come out different.
//
// Options:
//
//   contextUrl       — base URL the PoC navigates the victim to.
//                      Default 'https://example.com/'.
//   smtTimeoutMs     — per Z3 call.
//   deliveryEmitters — overrides for per-delivery-code JS
//                      emitters; consumer-supplied JS that takes
//                      (value, context) and returns a snippet.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const SMT = require('../src/smt.js');
const Z3 = require('../src/z3.js');

// Trigger predicates: map TypeDB trigger-name → SMT helper.
// The ONLY hardcoded knowledge in this consumer. These are
// mathematical primitives of the string theory Z3 implements
// — no user-facing choices encoded here.
const TRIGGERS = {
  contains: (val, payload) => SMT.mkContains(val, SMT.mkConst(payload)),
  equals:   (val, payload) => SMT.mkCmp('===', val, SMT.mkConst(payload)),
  prefixof: (val, payload) => SMT.mkPrefixOf(SMT.mkConst(payload), val),
  suffixof: (val, payload) => SMT.mkSuffixOf(SMT.mkConst(payload), val),
};

// Default per-delivery JS emitters. Each takes (value, ctx) —
// `value` is the string the attacker must supply at this
// source, `ctx` is the accumulated PoC-build context
// ({ contextUrl, target, seen, parts, ... }). Emitters may
// return either:
//   * a string (inline snippet), or
//   * { setup, navigate, postload } for staged delivery
//     (setup runs synchronously, navigate opens the victim,
//     postload runs after `load` fires on the opened window).
//
// Consumers can override by passing `options.deliveryEmitters`;
// unknown delivery codes fall through to a generic placeholder.
const DEFAULT_DELIVERY_EMITTERS = {
  'location-fragment': (value) => ({
    urlHash: value,
  }),
  'location-search': (value) => ({
    urlSearch: value,
  }),
  'location-pathname': (value) => ({
    urlPath: value,
  }),
  'location-href': (value) => ({
    urlFull: value,
  }),
  'postMessage:data': (value) => ({
    // `value` may be a string OR an object (when the flow's
    // path references multiple fields of `ev.data`). postMessage
    // natively accepts any structured-clone-able value, so we
    // pass it verbatim via JSON.stringify — no field-by-field
    // serialisation needed.
    postload: [
      '  w.postMessage(' + jsRepr(value) + ', "*");',
    ],
  }),
  'postMessage:origin': () => ({
    // The attacker can't choose origin — it's determined by
    // where the postMessage call is made from. Emit a note
    // rather than an inert snippet.
    note: '// NOTE: the flow requires a specific `event.origin`. ' +
          'Host the PoC on that origin (or use an iframe/popup ' +
          'from it) so `window.postMessage(..., "*")` delivers ' +
          'the expected origin.',
  }),
  'localStorage': (value, ctx) => ({
    setup: [
      'localStorage.setItem(' + jsRepr(ctx.storageKey || 'key') + ', ' + jsRepr(value) + ');',
    ],
  }),
  'cookie': (value, ctx) => ({
    setup: [
      'document.cookie = ' + jsRepr((ctx.cookieKey || 'key') + '=' + value) + ';',
    ],
  }),
  'window-name': (value) => ({
    // `window.name` survives navigation; set on opener before
    // calling window.open.
    preopen: [
      'w.name = ' + jsRepr(value) + ';',
    ],
  }),
  'referrer': () => ({
    note: '// NOTE: the flow reads `document.referrer`. Host the ' +
          'PoC page on the origin you want reported as referrer ' +
          'and link (<a href>, Location header, etc.) to the ' +
          'target URL below.',
  }),
  'network-response': (value, ctx) => ({
    note: '// NOTE: the flow requires a specific network response ' +
          'body. Stand up a service worker or mock server ' +
          'returning ' + jsRepr(value) + ' for the relevant fetch.',
  }),
  'file-drop': (value) => ({
    // UI-interaction: self-XSS. The victim cooperates by
    // dropping a file. Build a lure page that instructs + auto-
    // fills on click (still requires user cooperation, which
    // is what `ui-interaction` means in the assumption model).
    selfXssLure: {
      kind: 'file-drop',
      value: typeof value === 'string' ? value : JSON.stringify(value),
      instruction: 'Drop a file whose content is the value shown.',
    },
  }),
  'clipboard-paste': (value) => ({
    selfXssLure: {
      kind: 'clipboard-paste',
      value: typeof value === 'string' ? value : JSON.stringify(value),
      instruction: 'Paste the following text into the target field.',
    },
  }),
  'ui-form-input': (value) => ({
    selfXssLure: {
      kind: 'form-input',
      value: typeof value === 'string' ? value : JSON.stringify(value),
      instruction: 'Type the value shown into the target field.',
    },
  }),
  'history-state': (value) => ({
    setup: [
      'history.pushState(' + jsRepr(value) + ', "");',
    ],
  }),
};

function jsRepr(v) {
  return JSON.stringify(v);
}

// Map a Z3 witness symbol name back to its source descriptor.
// Sym names are constructed by `allocSourceSym` as
// `discriminator + '_' + counter`, where discriminator is
// typically `typeName + '.' + propName` (e.g. `Location.hash_1`)
// or the source label itself for ephemeral-fallback syms.
//
// To map back, we strip the numeric suffix and try to match
// against the flow's declared sources. When ambiguous, we fall
// through to generic naming.
function resolveSymbolToSource(symName, flow) {
  if (!symName) return null;
  const m = symName.match(/^(.*)_\d+$/);
  const stem = m ? m[1] : symName;
  const sources = (flow && flow.source) || [];
  // Exact discriminator match (e.g. `Location.hash` vs source at
  // Location.hash). Try (typeName.propName) style first.
  for (const s of sources) {
    if (stem === s.discriminator) return s;
  }
  // Match by label (symName stem === label, e.g. ephemeral-
  // fallback syms whose stem IS the label).
  for (const s of sources) {
    if (stem === s.label) return s;
  }
  return null;
}

async function synthesisePocForFlow(flow, db, options, sourceSchema) {
  const timeoutMs = options.smtTimeoutMs != null ? options.smtTimeoutMs : 5000;
  const val = flow.valueFormula;

  // Concrete-literal flow: no solving needed.
  if (val && val.value && typeof val.value.val === 'string') {
    return {
      verdict: 'trivial',
      payload: val.value.val,
      bindings: buildDirectBindings(flow, val.value.val),
      attempt: 'concrete',
      witness: { __const__: val.value.val },
      note: null,
    };
  }

  // Look up exploit attempts from the TypeDB.
  const exploitName = flow.sink && flow.sink.exploit;
  const exploitDesc = exploitName && db && db.exploits && db.exploits[exploitName];
  const attempts = (exploitDesc && exploitDesc.attempts) || null;

  if (!attempts || attempts.length === 0) {
    return {
      verdict: 'unsolvable',
      payload: null,
      bindings: {},
      attempt: null,
      witness: null,
      note: exploitName
        ? 'no exploit attempts declared for `' + exploitName + '` in typeDB.exploits'
        : 'sink has no `exploit` tag — TypeDB needs an exploit name to drive PoC synthesis',
    };
  }

  // Direct attacker-controlled flow (no path / no symbolic
  // value). The attacker supplies the source bytes directly,
  // so the first attempt's payload IS the sink-arriving value.
  if (!flow.pathFormula && !val) {
    const primary = attempts[0];
    return {
      verdict: 'synthesised',
      payload: primary.payload,
      bindings: buildDirectBindings(flow, primary.payload),
      attempt: primary.name,
      witness: null,
      note: 'direct attacker-controlled flow; attacker-supplied ' +
        'source value equals the sink-arriving payload',
    };
  }

  // Constrained flow: try each attempt. Conjoin
  // pathFormula ∧ trigger(valueFormula, payload). First SAT
  // wins; the attempt's payload is the value arriving at the
  // sink, Z3's witness is per-source-symbol attacker input.
  const basePath = flow.pathFormula || null;
  const notes = [];
  for (const attempt of attempts) {
    const trig = TRIGGERS[attempt.trigger];
    if (!trig) {
      notes.push(attempt.name + ': unknown trigger `' + attempt.trigger + '`');
      continue;
    }
    let formula = basePath;
    let exploited = false;
    if (val) {
      const c = trig(val, attempt.payload);
      if (c) {
        formula = formula ? SMT.mkAnd(formula, c) : c;
        exploited = true;
      }
    }
    if (!formula) {
      return {
        verdict: 'synthesised',
        payload: attempt.payload,
        bindings: buildDirectBindings(flow, attempt.payload),
        attempt: attempt.name,
        witness: null,
        note: 'path and value are unconstrained; direct delivery',
      };
    }
    const witness = await Z3.getModel(formula, timeoutMs);
    if (witness === null) {
      notes.push(attempt.name + ': UNSAT');
      continue;
    }
    return {
      verdict: 'synthesised',
      payload: attempt.payload,           // value at the sink
      bindings: witnessToBindings(witness, flow, sourceSchema),
      attempt: attempt.name,
      witness,
      note: null,
    };
  }

  return {
    verdict: 'infeasible',
    payload: null,
    bindings: {},
    attempt: null,
    witness: null,
    note: 'all ' + attempts.length + ' exploit attempts UNSAT: ' + notes.join('; '),
  };
}

function buildDirectBindings(flow, payload) {
  const out = {};
  const sources = flow.source || [];
  if (sources.length === 0) {
    out['attacker-input'] = payload;
    return out;
  }
  for (const s of sources) {
    const k = s.label || 'attacker-input';
    out[k] = payload;
  }
  return out;
}

// Group a Z3 witness by its source-schema parents. Given a
// witness like { 'ev.data_1.action_2': 'run',
// 'ev.data_1.payload_3': 'alert(1)' } and a sourceSchema
// mapping 'ev.data_1' → [{name: '*.action_2', prop: 'action'},
// {name: '*.payload_3', prop: 'payload'}], produce an
// assembled object { action: 'run', payload: 'alert(1)' } per
// parent. Returns:
//
//   { [parentSymName]: { object: {...}, label: '...' } }
//
// Parents that have no children in the schema (ordinary flat
// symbols like location.hash) map to { scalar: value }.
function groupWitnessByParent(witness, flow, schema) {
  if (!witness) return {};
  schema = schema || {};
  const groups = {};
  // Reverse-index: childSymName → parentSymName.
  const childToParent = Object.create(null);
  for (const parent in schema) {
    for (const c of schema[parent]) {
      childToParent[c.name] = { parent, prop: c.prop };
    }
  }
  for (const sym of Object.keys(witness)) {
    const pc = childToParent[sym];
    if (pc) {
      if (!groups[pc.parent]) groups[pc.parent] = { object: {} };
      groups[pc.parent].object[pc.prop] = witness[sym];
    } else {
      // Top-level sym — flat scalar (e.g. location.hash_1).
      groups[sym] = { scalar: witness[sym] };
    }
  }
  // Attach per-group source label by looking up flow.source —
  // heuristic: map by label whose parent-sym stem matches the
  // typeName.propName discriminator ('MessageEvent.data_1'
  // matches label 'postMessage' via the flow.source list).
  const sources = (flow && flow.source) || [];
  for (const parent in groups) {
    const g = groups[parent];
    // Strip trailing `_N` counter from the sym name to get the
    // discriminator.
    const m = parent.match(/^(.*)_\d+$/);
    const stem = m ? m[1] : parent;
    let found = null;
    for (const s of sources) {
      if (s.discriminator === stem || s.label === stem) { found = s; break; }
    }
    g.label    = found ? found.label    : (sources.length === 1 ? sources[0].label    : null);
    g.delivery = found ? found.delivery : (sources.length === 1 ? sources[0].delivery : null);
  }
  return groups;
}

function witnessToBindings(witness, flow, schema) {
  const groups = groupWitnessByParent(witness, flow, schema);
  const bindings = {};
  for (const parent in groups) {
    const g = groups[parent];
    const key = g.label || parent;
    if (g.object) {
      // Multi-child group — the attacker must supply this
      // whole object at the source.
      bindings[key] = g.object;
    } else {
      bindings[key] = g.scalar;
    }
  }
  return bindings;
}

// --- Reproducer emission ---------------------------------------------------

function resolveDelivery(label, flow) {
  const sources = (flow && flow.source) || [];
  for (const s of sources) {
    if (s.label === label && s.delivery) return s.delivery;
  }
  return null;
}

function buildReproducer(flow, pocRecord, db, options) {
  if (!pocRecord || pocRecord.payload == null) return null;
  const emitters = Object.assign({}, DEFAULT_DELIVERY_EMITTERS,
    options.deliveryEmitters || {});
  const contextUrl = options.contextUrl || 'https://example.com/';

  const setup    = [];
  const preopen  = [];
  const postload = [];
  const notes    = [];
  const lures    = [];
  let urlHash     = null;
  let urlSearch   = null;
  let urlPath     = null;
  let urlFull     = null;

  for (const label in pocRecord.bindings) {
    const value = pocRecord.bindings[label];
    const deliveryCode = resolveDelivery(label, flow);
    if (!deliveryCode) {
      notes.push('// delivery unknown for source `' + label +
        '`: attacker must supply ' + jsRepr(value));
      continue;
    }
    const emit = emitters[deliveryCode];
    if (!emit) {
      notes.push('// no emitter for delivery `' + deliveryCode +
        '` (source `' + label + '`); value = ' + jsRepr(value));
      continue;
    }
    const result = emit(value, { contextUrl });
    if (typeof result === 'string') {
      setup.push(result);
      continue;
    }
    if (!result) continue;
    if (result.urlHash   != null) urlHash   = result.urlHash;
    if (result.urlSearch != null) urlSearch = result.urlSearch;
    if (result.urlPath   != null) urlPath   = result.urlPath;
    if (result.urlFull   != null) urlFull   = result.urlFull;
    if (result.setup)    for (const s of result.setup)    setup.push(s);
    if (result.preopen)  for (const s of result.preopen)  preopen.push(s);
    if (result.postload) for (const s of result.postload) postload.push(s);
    if (result.note) notes.push(result.note);
    if (result.selfXssLure) lures.push(Object.assign({ label }, result.selfXssLure));
  }

  // Self-XSS lure block. When one or more sources require user
  // cooperation (file drop, paste, form typing), emit a
  // self-contained lure that opens the victim page, builds a
  // floating instruction panel on the attacker window, and
  // tells the victim exactly what to type/paste/drop. The PoC
  // is still end-to-end runnable — the human cooperator IS the
  // `ui-interaction` assumption.
  if (lures.length > 0) {
    setup.push('// === Self-XSS lure (requires user cooperation) ===');
    setup.push('var __lure = document.createElement("div");');
    setup.push('__lure.style.cssText = "position:fixed;top:12px;right:12px;z-index:2147483647;background:#1d2024;color:#eee;padding:12px 14px;border:1px solid #e74c3c;border-radius:4px;font:13px/1.4 system-ui;max-width:360px;box-shadow:0 4px 12px rgba(0,0,0,.5)";');
    setup.push('__lure.innerHTML = ' + jsRepr(renderLureHtml(lures)) + ';');
    setup.push('document.body.appendChild(__lure);');
  }

  // Build the victim URL.
  let url;
  if (urlFull != null) {
    url = urlFull;
  } else {
    url = contextUrl;
    if (urlPath) {
      // Path override: replace the context URL's path.
      url = url.replace(/\/[^?#]*(?=($|[?#]))/, '/' + urlPath.replace(/^\//, ''));
    }
    if (urlSearch) {
      url += (url.indexOf('?') >= 0 ? '&' : '?') + urlSearch.replace(/^\?/, '');
    }
    if (urlHash) {
      url += '#' + urlHash.replace(/^#/, '');
    }
  }

  const body = [];
  body.push('(function () {');
  body.push('  // Auto-generated PoC from jsanalyze.');
  body.push('  // Flow: ' + describeFlow(flow));
  body.push('  // Attempt: ' + (pocRecord.attempt || 'direct'));
  if (notes.length) {
    for (const n of notes) body.push('  ' + n.split('\n').join('\n  '));
  }
  if (setup.length) {
    body.push('  // Synchronous setup (storage / cookies / state):');
    for (const s of setup) body.push('  ' + s);
  }
  const needsOpener = preopen.length > 0 || postload.length > 0;
  if (needsOpener) {
    body.push('  var w = window.open(' + jsRepr(url) + ');');
    if (preopen.length) {
      for (const s of preopen) body.push(s);
    }
    if (postload.length) {
      body.push('  // Wait for the victim page to load before');
      body.push('  // delivering post-load inputs (postMessage etc.).');
      body.push('  w.addEventListener("load", function () {');
      for (const s of postload) body.push(s);
      body.push('  });');
    }
  } else {
    body.push('  // Navigate the victim to the exploit URL:');
    body.push('  window.open(' + jsRepr(url) + ');');
  }
  body.push('})();');
  return body.join('\n');
}

// Render the self-XSS instruction panel HTML as a static
// string (escaped for safe innerHTML; this is our own UI, the
// payload is in a <pre> so it renders as text). Each lure
// carries `instruction` + `value` + `kind` (file-drop /
// clipboard-paste / form-input).
function renderLureHtml(lures) {
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
  const rows = lures.map(function (l) {
    return '<div style="margin-top:8px"><b>' + esc(l.instruction) +
      '</b><br><pre style="background:#15181b;padding:6px 8px;margin:4px 0 0;border-radius:3px;font:11px/1.3 ui-monospace;white-space:pre-wrap;word-break:break-all">' +
      esc(l.value) +
      '</pre><small style="color:#888">source: ' + esc(l.label) +
      '  kind: ' + esc(l.kind) + '</small></div>';
  }).join('');
  return '<b>jsanalyze self-XSS PoC</b>' +
    '<div style="color:#aaa;margin-top:4px">This flow needs user cooperation to fire (the <code>ui-interaction</code> assumption). Follow the steps below on the victim page.</div>' +
    rows;
}

function describeFlow(flow) {
  const srcs = (flow.source || []).map(s => s.label).join(', ');
  const sinkLabel = flow.sink.prop +
    (flow.sink.elementTag ? ' on <' + flow.sink.elementTag + '>' : '');
  return srcs + ' -> ' + sinkLabel +
    (flow.sink.location && flow.sink.location.file
      ? ' (' + flow.sink.location.file +
        (flow.sink.location.line ? ':' + flow.sink.location.line : '') + ')'
      : '');
}

// --- Public API -----------------------------------------------------------

async function synthesisePocs(trace, options) {
  options = options || {};
  const db = options.typeDB || TDB;
  if (!trace || !trace.taintFlows || trace.taintFlows.length === 0) {
    return trace;
  }
  const schema = trace.sourceSchema || {};
  for (const flow of trace.taintFlows) {
    try {
      const rec = await synthesisePocForFlow(flow, db, options, schema);
      rec.reproducer = buildReproducer(flow, rec, db, options);
      flow.poc = rec;
    } catch (err) {
      flow.poc = {
        verdict: 'unsolvable',
        payload: null,
        bindings: {},
        attempt: null,
        witness: null,
        reproducer: null,
        note: 'synthesis threw: ' +
          (err && err.message ? err.message : String(err)),
      };
    }
  }
  return trace;
}

async function analyzeReport(input, options) {
  options = options || {};
  const trace = await analyze(input, {
    typeDB: options.typeDB || TDB,
    accept: options.accept,
    watchers: options.watchers,
    smtTimeoutMs: options.smtTimeoutMs,
  });

  await synthesisePocs(trace, options);

  const flows = trace.taintFlows || [];
  const refuted = trace.refutedFlows || [];

  const bySource = Object.create(null);
  const bySink = Object.create(null);
  const bySeverity = Object.create(null);
  const byFile = Object.create(null);

  for (const f of flows) {
    for (const srcEntry of f.source || []) {
      const k = srcEntry.label || '<unknown>';
      if (!bySource[k]) bySource[k] = [];
      bySource[k].push(f);
    }
    const sinkKey = (f.sink && f.sink.prop) || '<unknown>';
    if (!bySink[sinkKey]) bySink[sinkKey] = [];
    bySink[sinkKey].push(f);
    const sev = f.severity || 'medium';
    if (!bySeverity[sev]) bySeverity[sev] = [];
    bySeverity[sev].push(f);
    const file = (f.sink && f.sink.location && f.sink.location.file) || '<anonymous>';
    if (!byFile[file]) byFile[file] = [];
    byFile[file].push(f);
  }

  const counts = {
    total:   flows.length,
    high:    (bySeverity.high || []).length,
    medium:  (bySeverity.medium || []).length,
    low:     (bySeverity.low || []).length,
    refuted: refuted.length,
  };

  return {
    schemaVersion: '2',
    flows,
    refuted,
    grouped: { bySource, bySink, bySeverity, byFile },
    counts,
    partial:  trace.partial,
    warnings: trace.warnings,
    trace: options.includeTrace ? trace : undefined,
  };
}

function render(report, opts) {
  opts = opts || {};
  const lines = [];
  const c = report.counts;
  lines.push('taint report: ' + c.total + ' flow(s) total' +
    (c.high   ? '  ' + c.high   + ' high'   : '') +
    (c.medium ? '  ' + c.medium + ' medium' : '') +
    (c.low    ? '  ' + c.low    + ' low'    : '') +
    (c.refuted ? '  (' + c.refuted + ' refuted by SMT)' : ''));
  if (report.partial) lines.push('  partial trace — analysis incomplete');
  if (report.warnings && report.warnings.length) {
    for (const w of report.warnings) {
      lines.push('  ! ' + (w.severity || 'warning') + ': ' + w.message);
    }
  }
  const groupBy = opts.groupBy || 'source';
  if (groupBy === 'source') {
    for (const src of Object.keys(report.grouped.bySource).sort()) {
      lines.push('');
      lines.push('  source: ' + src + ' (' + report.grouped.bySource[src].length + ')');
      for (const f of report.grouped.bySource[src]) {
        const loc = f.sink && f.sink.location;
        const poc = f.poc && f.poc.payload != null ? '  payload: ' + f.poc.payload : '';
        lines.push('    ' + (loc ? loc.file + ':' + loc.line : '?') +
          '  ->  ' + ((f.sink && f.sink.prop) || '?') + poc);
      }
    }
  }
  return lines.join('\n');
}

module.exports = {
  analyze: analyzeReport,
  render,
  synthesisePocs,
  buildReproducer,
};
