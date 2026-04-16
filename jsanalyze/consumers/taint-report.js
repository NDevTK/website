// taint-report.js — human-friendly taint-flow presentation +
// PoC witness synthesis.
//
// Reads trace.taintFlows and attaches:
//
//   * `poc` — a concrete attacker-input witness for every
//     surviving flow. Runs the sink-kind exploit constraint
//     against the flow's pathFormula ∧ valueFormula and calls
//     Z3.getModel to extract a payload. For flows whose source
//     value is opaque (the common `location.hash → sink` case
//     where no symbolic variable exists for the attacker byte),
//     synthesises a canonical demo payload keyed off the sink
//     kind — no solver round-trip needed, since the flow is
//     unconstrained.
//
//   * grouping / counts — buckets by source label, sink prop,
//     severity, and originating file.
//
// PoC synthesis lives here (not in the engine) because exploit
// shapes are third-party knowledge about XSS / prototype /
// navigation payloads — exactly the "emit output" work D11.1
// assigns to consumers. The engine's job stopped when it
// produced pathFormula + valueFormula.
//
// Public API:
//
//   const tr = require('jsanalyze/consumers/taint-report');
//   const report = await tr.analyze(input, options?);
//     // { schemaVersion, flows, grouped, counts, partial, warnings }
//   const text = tr.render(report, { groupBy: 'source' });
//   await tr.synthesisePocs(trace, { smtTimeoutMs });
//     // mutates each flow with `flow.poc = { verdict, payload,
//     //                                      witness, note }`

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const SMT = require('../src/smt.js');
const Z3 = require('../src/z3.js');

// Per-sink exploit attempts. Each sink kind has an ordered list
// of candidate payloads; when the flow is constrained, the
// synthesiser tries each attempt against Z3 and keeps the first
// that comes back SAT. For unconstrained direct flows, the
// primary (first) attempt is returned verbatim.
//
// Multiple attempts matter because a single-shape exploit misses
// injection contexts that require different breakouts:
//
//   html       — primary: a full <script> element. Alternates
//                cover attribute context (' onerror=…'), style
//                break-out ('</style>…'), and comment break-out
//                ('-->…') — in case Z3 needs a specific shape to
//                satisfy path constraints.
//   navigation — javascript: URL, then a data:text/html URL as
//                a fallback for frames that disallow the former.
//   url        — same as navigation, suitable for iframe src.
//   code       — an alert(1) canary; no real alternates needed
//                (the body is free-form JS).
const EXPLOIT_ATTEMPTS = {
  html: [
    { name: 'script-tag',    payload: '<script>alert(1)</script>' },
    { name: 'img-onerror',   payload: '<img src=x onerror=alert(1)>' },
    { name: 'svg-onload',    payload: '<svg onload=alert(1)>' },
    { name: 'attr-breakout', payload: '" onerror="alert(1)' },
    { name: 'style-breakout', payload: '</style><script>alert(1)</script>' },
  ],
  navigation: [
    { name: 'javascript-url', payload: 'javascript:alert(1)' },
    { name: 'data-html',      payload: 'data:text/html,<script>alert(1)</script>' },
  ],
  url: [
    { name: 'javascript-url', payload: 'javascript:alert(1)' },
    { name: 'data-html',      payload: 'data:text/html,<script>alert(1)</script>' },
  ],
  code: [
    { name: 'alert-canary',   payload: 'alert(1)' },
  ],
};

function buildExploitConstraint(val, payload) {
  return SMT.mkContains(val, SMT.mkConst(payload));
}

// Extract the primary payload and per-symbol bindings from a Z3
// witness map. A witness has one binding per declared symbol in
// the formula; for PoC purposes we care about the string-sorted
// ones (those are the attacker-visible source values). The
// primary payload is picked by the selector, which falls back to
// the first string binding.
function extractWitness(witness, primarySelector) {
  if (!witness) return { payload: null, bindings: {} };
  const keys = Object.keys(witness);
  const bindings = {};
  for (const k of keys) bindings[k] = witness[k];
  let payload = null;
  if (primarySelector) payload = primarySelector(bindings);
  if (payload == null) {
    for (const k of keys) {
      if (typeof witness[k] === 'string') { payload = witness[k]; break; }
    }
  }
  if (payload == null && keys.length > 0) payload = JSON.stringify(bindings);
  return { payload, bindings };
}

async function synthesisePocForFlow(flow, timeoutMs) {
  const val = flow.valueFormula;

  // Trivial: the value is a concrete source literal. Report
  // the literal as the payload without touching Z3.
  if (val && val.value && typeof val.value.val === 'string') {
    return {
      verdict: 'trivial',
      payload: val.value.val,
      bindings: { __const__: val.value.val },
      witness: { __const__: val.value.val },
      attempt: 'concrete',
      note: null,
    };
  }

  const sinkKind = flow.sink && flow.sink.kind;
  const attempts = EXPLOIT_ATTEMPTS[sinkKind];

  if (!attempts || attempts.length === 0) {
    return {
      verdict: 'unsolvable',
      payload: null,
      bindings: {},
      witness: null,
      note: 'no exploit shape registered for sink kind "' + sinkKind + '"',
    };
  }

  // Direct attacker-controlled flow with no intermediate
  // constraints: pathFormula is null AND valueFormula is null.
  // The attacker picks the source bytes directly, so the
  // primary attempt's payload IS the witness.
  if (!flow.pathFormula && !val) {
    const primary = attempts[0];
    return {
      verdict: 'synthesised',
      payload: primary.payload,
      bindings: buildDirectBindings(flow, primary.payload),
      witness: null,
      attempt: primary.name,
      note: 'direct attacker-controlled flow; set ' +
        describeSource(flow) + ' to the payload above',
    };
  }

  // Constrained flow: try each exploit attempt in order.
  // First one SAT wins. If all UNSAT, report infeasible.
  const basePath = flow.pathFormula || null;
  let lastVerdict = 'infeasible';
  let lastNote = 'path condition + exploit constraint is UNSAT';
  for (const attempt of attempts) {
    let formula = basePath;
    let exploited = false;
    if (val) {
      const c = buildExploitConstraint(val, attempt.payload);
      if (c) {
        formula = formula ? SMT.mkAnd(formula, c) : c;
        exploited = true;
      }
    }
    if (!formula) {
      // No constraint at all — same as direct flow.
      return {
        verdict: 'synthesised',
        payload: attempt.payload,
        bindings: buildDirectBindings(flow, attempt.payload),
        witness: null,
        attempt: attempt.name,
        note: 'unconstrained path; set ' + describeSource(flow) +
          ' to the payload above',
      };
    }
    const witness = await Z3.getModel(formula, timeoutMs);
    if (witness === null) {
      lastVerdict = exploited ? 'infeasible' : 'unsolvable';
      lastNote = exploited
        ? 'path condition + exploit constraint (' + attempt.name + ') is UNSAT'
        : 'Z3 returned unknown (timeout or unhandled theory)';
      continue;
    }
    const { payload, bindings } = extractWitness(witness);
    return {
      verdict: exploited ? 'synthesised' : 'no-constraint',
      payload: payload || attempt.payload,
      bindings,
      witness,
      attempt: attempt.name,
      note: null,
    };
  }
  return {
    verdict: lastVerdict,
    payload: null,
    bindings: {},
    witness: null,
    note: lastNote + ' (tried ' + attempts.length + ' exploit shape' +
      (attempts.length === 1 ? '' : 's') + ')',
  };
}

// Produce a "bindings" map for direct attacker-controlled flows,
// keyed by source label. Makes downstream delivery (see UI's
// "Copy exploit" button) a 1:1 mapping from source label to the
// string the attacker should supply.
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

function describeSource(flow) {
  const sources = flow.source || [];
  if (sources.length === 0) return 'the attacker-controlled input';
  const labels = sources.map((s) => s.label).filter(Boolean);
  if (labels.length === 0) return 'the attacker-controlled input';
  return '`' + labels.join(' / ') + '`';
}

async function synthesisePocs(trace, options) {
  options = options || {};
  const timeoutMs = options.smtTimeoutMs != null ? options.smtTimeoutMs : 5000;
  if (!trace || !trace.taintFlows || trace.taintFlows.length === 0) {
    return trace;
  }
  for (const flow of trace.taintFlows) {
    // Per-flow isolation: a Z3 parse error or theory mismatch on
    // one flow (e.g. the vendored solver not supporting a string
    // op we emitted) shouldn't take down witness generation for
    // the other flows. Record the failure as `unsolvable` with
    // the error note so the UI can surface it.
    try {
      flow.poc = await synthesisePocForFlow(flow, timeoutMs);
    } catch (err) {
      flow.poc = {
        verdict: 'unsolvable',
        payload: null,
        witness: null,
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
          '  →  ' + ((f.sink && f.sink.prop) || '?') + poc);
      }
    }
  } else if (groupBy === 'sink') {
    for (const sink of Object.keys(report.grouped.bySink).sort()) {
      lines.push('');
      lines.push('  sink: ' + sink + ' (' + report.grouped.bySink[sink].length + ')');
      for (const f of report.grouped.bySink[sink]) {
        const loc = f.sink && f.sink.location;
        const srcs = (f.source || []).map(s => s.label).join('+');
        lines.push('    ' + (loc ? loc.file + ':' + loc.line : '?') +
          '  from ' + srcs);
      }
    }
  }
  return lines.join('\n');
}

module.exports = {
  analyze: analyzeReport,
  render,
  synthesisePocs,
};
