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
const query = require('./query.js');

// analyze(input, options) → Promise<Trace>
//
// Runs the full pipeline: parse → IR → worklist → trace projection.
// Returns a Trace object conforming to docs/API.md.
async function analyze(input, options) {
  options = options || {};
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

    const ctx = {
      module,
      assumptions,
      typeDB: options.typeDB || null,
      nextObjId: 0,
      onCall: null,
      // Taint flows emitted by sink classification in
      // transfer.js. The trace projection below copies these
      // into trace.taintFlows after the walk completes.
      taintFlows: [],
      // Flow id counter — assigned at emission time so flows
      // have stable identity within a trace.
      nextFlowId: 1,
    };

    const initialState = D.createState();
    let result;
    // Boundary: worklist / transfer function errors. Same
    // dual-visibility rule as above — warning + soundness
    // assumption.
    try {
      result = analyseFunction(module, module.top, initialState, ctx);
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
    // assumption ids, and location attached.
    for (const flow of ctx.taintFlows) {
      trace.taintFlows.push(flow);
    }
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
