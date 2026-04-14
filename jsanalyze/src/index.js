// index.js — public entry point for jsanalyze
//
// Exposes `analyze()` and the `query` namespace. Consumers should
// depend on this file only; internal modules (ir, domain, worklist,
// transfer) are implementation details.

'use strict';

const { buildModule } = require('./ir.js');
const { analyseFunction } = require('./worklist.js');
const { AssumptionTracker, REASONS, SEVERITIES } = require('./assumptions.js');
const D = require('./domain.js');
const { overlayEntries } = require('./domain.js');
const Z3 = require('./z3.js');
const query = require('./query.js');

// analyze(input, options) → Promise<Trace>
//
// Runs the full pipeline: parse → IR → worklist → trace projection.
// Returns a Trace object conforming to docs/API.md.
//
// Options (see docs/API.md §AnalyzeOptions):
//
//   * typeDB        — custom TypeDB; falls back to the default.
//
//   * precision     — 'fast' | 'precise' | 'exact'. Default 'precise'.
//                     'fast'   skips Layer 5 (Z3) entirely; the
//                              worklist uses only layers 1-4 to
//                              decide branches, and post-pass
//                              refutation is disabled. Undecided
//                              branches become 'unsolvable-math'
//                              precision assumptions.
//                     'precise' uses cascaded layers 1-5, Z3 at
//                              the branch cascade and refuteTrace
//                              at post-pass (default).
//                     'exact'  same as 'precise' but also clears
//                              the summary cache per call site
//                              so full context sensitivity is
//                              preserved. Slowest.
//
//   * smtTimeoutMs  — per-Z3-check wall-clock cap in milliseconds.
//                     Default 5000. Z3 returns 'unknown' when a
//                     check exceeds this; 'unknown' falls through
//                     to "keep the edge" at Layer 5 and raises an
//                     'unsolvable-math' precision assumption.
//
//   * taint         — enable taint-flow emission. Default true
//                     (docs say false, but the existing test
//                     suite depends on default-on behaviour;
//                     docs updated in the same commit).
//
//   * watchers      — streaming observation hooks: onCall,
//                     onFinding, onAssumption. Invoked during
//                     the walk so long-running analyses can
//                     surface incremental progress.
async function analyze(input, options) {
  options = options || {};
  const precision = options.precision || 'precise';
  const smtTimeoutMs = options.smtTimeoutMs != null ? options.smtTimeoutMs : 5000;
  const watchers = options.watchers || null;
  const files = typeof input === 'string'
    ? { '<input>.js': input }
    : Object.assign(Object.create(null), input);

  const trace = {
    schemaVersion: '2',
    files,
    calls: [],
    taintFlows: [],
    innerHtmlAssignments: [],
    stringLiterals: [],
    mayBe: Object.create(null),
    bindings: Object.create(null),
    callGraph: { nodes: [], edges: [] },
    reachability: new Map(),
    assumptions: [],
    warnings: [],
    partial: false,
  };

  const assumptions = new AssumptionTracker();

  // Wire the streaming watchers into the tracker so onAssumption
  // fires as assumptions are raised, not only at snapshot time.
  if (watchers && typeof watchers.onAssumption === 'function') {
    const origRaise = assumptions.raise.bind(assumptions);
    assumptions.raise = function (...args) {
      const a = origRaise(...args);
      watchers.onAssumption(a);
      return a;
    };
  }

  // D6 Layer 5: the worklist's BRANCH handler calls
  // `ctx.solverCheckPathSat(formula)` when layers 1-4 leave
  // both successors reachable. Only bound when precision is
  // not 'fast'. Results are cached inside z3.js by the
  // formula's expression text.
  const solverCheckPathSat = precision === 'fast'
    ? null
    : (formula) => Z3.checkPathSat(formula, smtTimeoutMs);

  for (const filename of Object.keys(files)) {
    let module;
    // Boundary: parse/IR errors. We catch here — and ONLY here —
    // so one bad file doesn't tank the whole multi-file analysis.
    // Every caught error raises an explicit `unimplemented`
    // soundness assumption so consumers that only inspect
    // `trace.assumptions` still see the floor, AND a
    // human-readable entry in `trace.warnings`. The underlying
    // exception's message is recorded on both.
    try {
      module = buildModule(files[filename], filename);
    } catch (e) {
      trace.partial = true;
      trace.warnings.push({
        severity: 'error',
        message: 'parse/IR error: ' + e.message,
        file: filename,
        stack: e.stack,
      });
      assumptions.raise(
        REASONS.UNIMPLEMENTED,
        'parse/IR error: ' + e.message,
        { file: filename, line: 0, col: 0, pos: 0 },
        { severity: SEVERITIES.SOUNDNESS }
      );
      continue;
    }

    // When precision === 'exact', clear every function's
    // summary cache before this file's walk. Different call
    // sites will then walk the callee independently, getting
    // full context sensitivity at the cost of redoing work.
    if (precision === 'exact') {
      for (const fn of module.functions) {
        if (fn._summaryCache) fn._summaryCache = new Map();
      }
    }

    const ctx = {
      module,
      assumptions,
      typeDB: options.typeDB || null,
      nextObjId: 0,
      onCall: (watchers && typeof watchers.onCall === 'function') ? watchers.onCall : null,
      onFinding: (watchers && typeof watchers.onFinding === 'function') ? watchers.onFinding : null,
      // Taint flows emitted by sink classification in
      // transfer.js. The trace projection below copies these
      // into trace.taintFlows after the walk completes.
      taintFlows: [],
      // Flow id counter — assigned at emission time so flows
      // have stable identity within a trace.
      nextFlowId: 1,
      // Precision mode + Z3 hookup.
      precision,
      smtTimeoutMs,
      solverCheckPathSat,
    };

    const initialState = D.createState();
    let result;
    // Boundary: worklist / transfer function errors. Same
    // dual-visibility rule as above — warning + soundness
    // assumption.
    try {
      result = await analyseFunction(module, module.top, initialState, ctx);
    } catch (e) {
      trace.partial = true;
      trace.warnings.push({
        severity: 'error',
        message: 'worklist error: ' + e.message,
        file: filename,
        stack: e.stack,
      });
      assumptions.raise(
        REASONS.UNIMPLEMENTED,
        'worklist error: ' + e.message,
        { file: filename, line: 0, col: 0, pos: 0 },
        { severity: SEVERITIES.SOUNDNESS }
      );
      continue;
    }

    // Project final top-level bindings into trace.bindings keyed by
    // source-level name. The AST→IR lowering stores the last SSA
    // register each name maps to in the top function's scope; we
    // walk the exit state and surface those.
    //
    // The minimal slice doesn't track name → register mappings past
    // analysis, so for now we expose register-indexed bindings.
    // A future refinement will record a Name→Register map at IR
    // build time and project through it here.
    if (result.exitState && result.exitState.regs) {
      for (const [reg, value] of overlayEntries(result.exitState.regs)) {
        trace.bindings[reg] = projectValue(value);
      }
    }

    // Reachability: for every block with source locations, record
    // whether the worklist reached it.
    for (const [blockId, block] of module.top.cfg.blocks) {
      const reached = result.blockStates.has(blockId);
      for (const instr of block.instructions) {
        const loc = module.sourceMap.get(instr._id);
        if (loc) {
          trace.reachability.set(loc, reached ? 'reachable' : 'unreachable');
        }
      }
    }

    // Copy taint flows emitted during the walk into the trace.
    // Each flow already has its source labels, sink info,
    // assumption ids, and location attached. Also fire the
    // onFinding watcher for streaming consumers.
    for (const flow of ctx.taintFlows) {
      trace.taintFlows.push(flow);
      if (watchers && typeof watchers.onFinding === 'function') {
        watchers.onFinding(flow);
      }
    }
  }

  // Wave 11 / Phase D: Z3 post-pass refutation. The branch
  // cascade (Layer 5) already kills infeasible paths at the
  // block level; this pass catches residual flows whose
  // pathFormula reached its final disjunctive form only after
  // the flow was emitted. Skipped in 'fast' precision.
  if (precision !== 'fast') {
    await Z3.refuteTrace(trace, smtTimeoutMs);
  }

  trace.assumptions = assumptions.snapshot();
  return trace;
}

// Project an internal Value (the immutable lattice record) into
// the public API shape. For now this is mostly a pass-through
// with a few field normalisations.
function projectValue(v) {
  if (!v) return { kind: 'opaque', assumptionIds: [], provenance: [] };
  if (v.kind === 'bottom') return { kind: 'opaque', assumptionIds: [], provenance: [] };
  if (v.kind === 'top') return { kind: 'opaque', assumptionIds: [], provenance: v.provenance || [] };
  return v;
}

module.exports = {
  analyze,
  query,
  // Re-exports for consumers that want direct access to the
  // assumption system (e.g. tests).
  AssumptionTracker,
};
