// z3.js — Wave 11 / Phase D: Z3-backed SMT refutation.
//
// The engine's real SMT solver. Wraps the `z3-solver` npm
// package (the emscripten build of Microsoft Research's Z3)
// and exposes two async entry points:
//
//   getContext()                 → Promise<Z3Context>
//   refuteTrace(trace, ctxCache) → Promise<trace>
//
// Z3 is a REQUIRED dependency of the engine, not optional.
// There is no fallback path: if z3-solver cannot be loaded or
// initialised, the analyser fails loudly — a precision ceiling
// isn't something to paper over, and the "proper interprocedural,
// path-sensitive, state-correlated" contract depends on a real
// decision procedure.
//
// This module contains NO try/catch. Z3 is deterministic on
// well-formed SMT-LIB2 input, and the formulas the engine emits
// are well-formed by construction: `smt.js` flags any operand
// mismatch with `incompatible: true`, and `shouldCheckFlow`
// filters those out before submission. A Z3 parse or check
// error therefore indicates a bug in formula construction, not
// a runtime condition — crashing is the right outcome because
// it surfaces the bug immediately instead of silently keeping
// unrefuted flows.
//
// Interprocedural + path-sensitive + state-correlated refutation
// -------------------------------------------------------------
//
// The refutation pass ingests the post-walk trace and examines
// every taint flow. Each flow carries:
//
//   * `pathFormula`  — the FULL path condition from the function
//                      entry (in the OUTERMOST caller) to the
//                      sink, with interprocedural conjunctions
//                      woven in by `transfer.applyCall` when it
//                      walks user functions. A call site's own
//                      pathCond is ANDed into the callee's
//                      initial pathCond so any sink fired inside
//                      inherits the caller context.
//
//   * `valueFormula` — the SMT expression for the value at the
//                      sink, typically a `str.++` / `str.substr`
//                      chain over the source symbols. For an
//                      Opaque source this is just the source's
//                      symbolic name; for a constructed value
//                      it's the full composite.
//
// The solver asserts:
//
//   (assert <pathFormula-as-bool>)
//
// and optionally, when the valueFormula constrains the sink
// input to a specific literal or a str.contains pattern, adds
// additional assertions. If the combined assertion is `unsat`,
// the path is statically infeasible and the flow is removed.

'use strict';

const z3 = require('z3-solver');
const SMT = require('./smt.js');

// Lazy, memoised context loader. Z3's WASM boots once per
// process; we cache the initialised Context and every
// subsequent refutation reuses it. No catches — z3.init() is
// expected to succeed; a failure is a dependency-install bug
// and should crash the analyser.
let _contextPromise = null;
function getContext() {
  if (_contextPromise) return _contextPromise;
  _contextPromise = z3.init().then(api => api.Context('jsanalyze'));
  return _contextPromise;
}

// Build the SMT-LIB v2 script the solver should check. The
// script declares every free symbol the formula references and
// asserts the formula itself.
//
// Bool formulas assert directly; non-Bool formulas are wrapped
// in smt.js's `toBool` predicate (the same JavaScript-truthiness
// encoding used for branch conditions). Returns null if the
// formula is unusable (null, incompatible, or trivially
// concrete); callers filter those upstream via `shouldCheckFlow`.
function buildScript(formula) {
  if (!formula || !formula.expr) return null;
  if (formula.incompatible) return null;
  if (!SMT.hasSym(formula)) return null;
  const decls = SMT.emitDeclarations(formula);
  const asserted = formula.isBool
    ? formula.expr
    : SMT._internals.toBool(formula);
  return (decls ? decls + '\n' : '') + '(assert ' + asserted + ')';
}

// True iff `flow` carries a checkable pathFormula. Used by the
// refutation pass to skip flows whose formulas can't be
// submitted (missing / concrete / incompatible) so we don't pay
// a solver round-trip for trivial cases.
function shouldCheckFlow(flow) {
  if (!flow) return false;
  const f = flow.pathFormula;
  if (!f) return false;
  if (f.incompatible) return false;
  if (!SMT.hasSym(f)) return false;
  return true;
}

// refuteTrace — post-pass over a completed trace's taint flows.
// For each flow with a non-trivial pathFormula, submits it to
// Z3 and records the verdict. Flows with a `unsat` verdict are
// moved from `trace.taintFlows` to `trace.refutedFlows`; all
// other flows (sat, unknown, not-checkable) remain in place.
//
// Soundness: only `unsat` refutes. `sat` and `unknown` both
// leave the flow alone. We never drop a flow we can't prove
// infeasible.
//
// The function is idempotent: running it twice on the same
// trace leaves it in the same state (the second pass sees an
// already-filtered `taintFlows` array and refutes no more).
async function refuteTrace(trace) {
  if (!trace || !trace.taintFlows || trace.taintFlows.length === 0) {
    return trace;
  }
  let anyCheckable = false;
  for (const f of trace.taintFlows) {
    if (shouldCheckFlow(f)) { anyCheckable = true; break; }
  }
  if (!anyCheckable) return trace;

  const ctx = await getContext();

  const kept = [];
  const refuted = trace.refutedFlows || [];
  for (const flow of trace.taintFlows) {
    if (!shouldCheckFlow(flow)) {
      kept.push(flow);
      continue;
    }
    const script = buildScript(flow.pathFormula);
    if (!script) {
      kept.push(flow);
      continue;
    }
    const solver = new ctx.Solver();
    solver.fromString(script);
    const verdict = await solver.check();
    if (verdict === 'unsat') {
      refuted.push(flow);
    } else {
      kept.push(flow);
    }
  }
  trace.taintFlows = kept;
  if (refuted.length > 0) {
    trace.refutedFlows = refuted;
  }
  return trace;
}

module.exports = {
  getContext,
  refuteTrace,
  buildScript,
  shouldCheckFlow,
};
