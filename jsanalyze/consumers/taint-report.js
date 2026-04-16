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
    note: '// NOTE: the flow reads file/dataTransfer content. ' +
          'Attacker must lure the victim to drop a file whose ' +
          'content is:\n//   ' + value.replace(/\n/g, '\n//   '),
  }),
  'clipboard-paste': (value) => ({
    note: '// NOTE: the flow reads clipboard data. Attacker must ' +
          'lure the victim to paste the following text:\n//   ' +
          value.replace(/\n/g, '\n//   '),
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

async function synthesisePocForFlow(flow, db, options) {
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
      bindings: witnessToBindings(witness, flow),
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

function witnessToBindings(witness, flow) {
  const bindings = {};
  if (!witness) return bindings;
  const sources = flow && flow.source ? flow.source : [];
  const syms = Object.keys(witness);
  if (syms.length === 0) return bindings;
  // If there's one sym and one source, map directly.
  if (sources.length === 1 && syms.length === 1) {
    bindings[sources[0].label || 'attacker-input'] = witness[syms[0]];
    return bindings;
  }
  // Otherwise attempt to match sym stem → source label/discriminator.
  for (const sym of syms) {
    const matched = resolveSymbolToSource(sym, flow);
    if (matched) {
      bindings[matched.label || sym] = witness[sym];
    } else {
      bindings[sym] = witness[sym];
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
  for (const flow of trace.taintFlows) {
    try {
      const rec = await synthesisePocForFlow(flow, db, options);
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
