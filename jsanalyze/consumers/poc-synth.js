// poc-synth.js — PoC synthesis consumer.
//
// Takes a Trace produced by the jsanalyze engine, iterates
// `trace.taintFlows`, and for each flow asks Z3 to produce a
// concrete attacker input that would make the flow actually
// trigger the sink. The witness is a `{ [sourceSymName]:
// concrete-value }` map that drops into an HTTP request,
// a URL fragment, a postMessage payload, etc., depending on
// which source supplied the sym.
//
// Contract (DESIGN-DECISIONS.md §Scope, item 2):
//
//     PoC synthesis — take a taint flow, invoke Z3 with the
//     accumulated path condition + a sink-specific
//     exploitability constraint, produce a concrete attacker
//     input that triggers the sink.
//
// This file is the second primary consumer listed in D11
// alongside `dom-convert.js`.
//
// Input shape: a Trace. PoC synth does not re-run analysis.
// Output shape: an array of PocResult records, one per taint
// flow that the engine believed was reachable and for which
// Z3 produced a witness:
//
//     type PocResult = {
//       flowId:   number;
//       source:   TaintFlow.source;
//       sink:     TaintFlow.sink;
//       verdict:  'synthesised' | 'infeasible' | 'no-constraint'
//               | 'unsolvable' | 'trivial';
//       witness:  { [symName: string]: string | number | boolean } | null;
//       payload:  string | null;   // pretty-printed exploit string
//       note?:    string;
//     };
//
// Verdict meaning:
//
//   synthesised   — Z3 returned a model. `witness` is the
//                   raw sym→value map; `payload` is the
//                   single most-interesting value, formatted
//                   for human consumption.
//   infeasible    — path ∧ exploit constraint is UNSAT. The
//                   sink is reachable but the attacker
//                   cannot craft an input that triggers it
//                   (e.g. a sanitizer made the contains-check
//                   impossible).
//   unsolvable    — Z3 returned unknown (timeout, unhandled
//                   theory fragment).
//   no-constraint — no exploit constraint is known for this
//                   sink kind. The witness is only the
//                   pathFormula's SAT assignment — useful
//                   for auditing but not a payload.
//   trivial       — the flow's valueFormula is a plain
//                   concrete string. Z3 isn't needed; we
//                   use the concrete string as the witness.
//
// Usage:
//
//     const { synthesiseTrace } = require('./poc-synth.js');
//     const results = await synthesiseTrace(trace, { timeoutMs: 5000 });
//     for (const r of results) {
//       if (r.verdict === 'synthesised') {
//         console.log(`[${r.sink.kind}] payload:`, r.payload);
//       }
//     }

'use strict';

const Z3 = require('../src/z3.js');
const SMT = require('../src/smt.js');

// --- Sink exploitability constraints -----------------------------------
//
// For each sink kind the engine classifies, we build an SMT
// constraint that expresses "a value satisfying this
// constraint would actually trigger the sink's vulnerability
// class". The constraint is a formula over the sink's
// valueFormula — which is the SMT expression representing the
// value flowing into the sink.
//
// These constraints are intentionally MINIMAL. They ask for a
// payload that a penetration tester would consider a valid
// proof of concept — not the full space of exploits. A
// sophisticated PoC generator could iterate multiple
// constraints per sink (e.g. `<script>` vs `<img onerror=>`
// for html) and pick the shortest witness; this first
// version ships one canonical payload shape per sink.
//
// The constraint is a function (valueFormula → smtFormula)
// so it can build a fresh sub-expression that references the
// value sym directly. Returning null means "no known
// exploitability class for this sink" — the consumer emits
// a 'no-constraint' verdict.
const EXPLOIT_CONSTRAINTS = {
  // HTML sink: the value ends up in innerHTML / outerHTML /
  // document.write / insertAdjacentHTML. A payload that
  // contains a `<script>` open tag is parsed as an element
  // whose content is executed inline by the HTML parser.
  // This is the canonical DOM XSS payload.
  html: (val) => SMT.mkContains(val, SMT.mkConst('<script>')),

  // Navigation sink: the value assigns to location.href,
  // location.assign, window.open, etc. A payload that starts
  // with `javascript:` is executed as a URL-scheme handler by
  // the browser, running arbitrary code.
  navigation: (val) => SMT.mkPrefixOf(SMT.mkConst('javascript:'), val),

  // URL sink: iframe.src / frame.src / img.src assignment.
  // Same payload as navigation — `javascript:` URLs execute
  // in an iframe / frame context.
  url: (val) => SMT.mkPrefixOf(SMT.mkConst('javascript:'), val),

  // Code sink: eval / Function / setTimeout(string) /
  // setInterval(string). Any non-empty string is executable;
  // we ask for a length > 0 constraint.
  code: (val) => SMT.mkCmp('>', SMT.mkLength(val), SMT.mkConst(0)),
};

// --- synthesiseTrace -------------------------------------------------------
//
// Main entry point. Iterates every flow on the trace, tries
// to build a witness for each, and returns the result list.
// The solver budget is shared across the whole trace — each
// flow gets up to `timeoutMs` milliseconds before Z3 bails
// with 'unknown'. Default is 5000ms per flow.
async function synthesiseTrace(trace, options) {
  const opts = options || {};
  const timeoutMs = typeof opts.timeoutMs === 'number' ? opts.timeoutMs : 5000;
  const results = [];
  if (!trace || !trace.taintFlows) return results;
  for (const flow of trace.taintFlows) {
    const result = await synthesiseFlow(flow, timeoutMs);
    results.push(result);
  }
  return results;
}

// --- synthesiseFlow --------------------------------------------------------
//
// Build a witness for a single TaintFlow. Returns one
// PocResult. The exploit constraint is chosen from
// EXPLOIT_CONSTRAINTS by the sink's kind; if the kind isn't
// known the verdict is 'no-constraint'.
async function synthesiseFlow(flow, timeoutMs) {
  const base = {
    flowId: flow.id,
    source: flow.source,
    sink: flow.sink,
  };

  // Trivial case: valueFormula is a concrete const. No solver
  // round-trip is needed; return the concrete value as the
  // witness, tagged 'trivial'. The attacker doesn't need to
  // supply anything — the literal is already present in the
  // source.
  const val = flow.valueFormula;
  if (val && val.value && typeof val.value.val === 'string') {
    return Object.assign({}, base, {
      verdict: 'trivial',
      witness: { __const__: val.value.val },
      payload: val.value.val,
    });
  }

  const sinkKind = flow.sink && flow.sink.kind;
  const builder = EXPLOIT_CONSTRAINTS[sinkKind];

  // Compose: pathFormula ∧ exploitConstraint(valueFormula).
  // When pathFormula is null the block is trivially
  // reachable (no branch constraints); when builder is null
  // we fall back to pathFormula alone (producing a
  // 'no-constraint' verdict even on SAT).
  let formula = flow.pathFormula || null;
  let exploited = false;
  if (builder && val) {
    const exploitC = builder(val);
    if (exploitC) {
      formula = formula ? SMT.mkAnd(formula, exploitC) : exploitC;
      exploited = true;
    }
  }

  if (!formula) {
    return Object.assign({}, base, {
      verdict: 'no-constraint',
      witness: null,
      payload: null,
      note: 'no pathFormula and no valueFormula to constrain',
    });
  }

  const witness = await Z3.getModel(formula, timeoutMs);
  if (witness === null) {
    return Object.assign({}, base, {
      verdict: exploited ? 'infeasible' : 'unsolvable',
      witness: null,
      payload: null,
      note: exploited
        ? 'path condition + exploit constraint is UNSAT'
        : 'Z3 returned unknown (timeout or unhandled theory)',
    });
  }

  // Pick the "payload" — the single value most likely to
  // interest a human reading the result. Priority order:
  //
  //   1. The first source sym in the flow's `source` list.
  //      The flow tells us which source the taint came from;
  //      its sym name is what an attacker would supply.
  //   2. The first String-sorted sym in the witness.
  //   3. The entire witness as JSON.
  const payload = extractPayload(witness, flow);
  return Object.assign({}, base, {
    verdict: exploited ? 'synthesised' : 'no-constraint',
    witness,
    payload,
  });
}

// extractPayload — single-string summary of a witness. We
// surface the value bound to the first source sym (the
// attacker-controlled input), falling back to the first
// String-sorted sym, and finally to a JSON summary of all
// bindings when neither heuristic fires.
function extractPayload(witness, flow) {
  if (!witness) return null;
  const keys = Object.keys(witness);
  if (keys.length === 0) return '';
  // Prefer a String-sorted binding — those are actual
  // payload strings. Int bindings (from loop counters or
  // array lengths) aren't what an attacker sends.
  for (const k of keys) {
    if (typeof witness[k] === 'string') return witness[k];
  }
  return JSON.stringify(witness);
}

module.exports = {
  synthesiseTrace,
  synthesiseFlow,
  EXPLOIT_CONSTRAINTS,
};
