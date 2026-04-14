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
const HTML = require('./html.js');
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
//
//   * smtTimeoutMs  — per-Z3-check wall-clock cap in milliseconds.
//                     Default 5000.
//
//   * accept        — Array<AssumptionReason>. The set of
//                     assumption reason codes the consumer is
//                     willing to tolerate. Any assumption raised
//                     with a reason NOT in this set is copied into
//                     `trace.rejectedAssumptions` and marks
//                     `trace.partial = true` — the consumer knows
//                     its result is untrustworthy for paths that
//                     depend on the rejected assumptions, and can
//                     rerun with stricter `precision` / a larger
//                     `smtTimeoutMs` / a richer TypeDB to suppress
//                     them. Performance shortcuts (loop-widening,
//                     summary-reused) are assumption reasons like
//                     any other, so consumers that reject them
//                     force the engine into higher-precision
//                     modes.
//                     Default: every defined reason code is
//                     accepted (no rejection).
//
//   * taint         — enable taint-flow emission. Default true.
//
//   * watchers      — streaming observation hooks: onCall,
//                     onFinding, onAssumption.
async function analyze(input, options) {
  options = options || {};
  const precision = options.precision || 'precise';
  const smtTimeoutMs = options.smtTimeoutMs != null ? options.smtTimeoutMs : 5000;
  const watchers = options.watchers || null;
  // `accept` is a Set<string> — the assumption reason codes
  // the consumer tolerates. If omitted, every reason is
  // implicitly accepted. The set is PRESCRIPTIVE: rejecting a
  // reason forces the engine to NOT take that shortcut,
  // instead of merely reporting it. For performance-shortcut
  // reasons (loop-widening, summary-reused) this means the
  // engine walks exhaustively at the consumer's request; for
  // theoretical-floor reasons (network, attacker-input, etc.)
  // rejection is advisory — the engine can't conjure bytes it
  // doesn't have, so the rejection lands in
  // `trace.rejectedAssumptions` with `partial = true` as a
  // signal to the consumer that the analysis isn't trustworthy
  // for those paths.
  const acceptAll = options.accept == null;
  const accept = acceptAll
    ? null
    : new Set(Array.isArray(options.accept) ? options.accept : []);
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
    domMutations: [],
    mayBe: Object.create(null),
    bindings: Object.create(null),
    callGraph: { nodes: [], edges: [] },
    reachability: new Map(),
    assumptions: [],
    // Assumptions the consumer explicitly rejected via
    // options.accept. Empty unless the consumer opted in to
    // strict-mode rejection. Presence sets partial = true.
    rejectedAssumptions: [],
    warnings: [],
    partial: false,
  };

  // Extract inline <script> content from HTML files so the
  // walker sees the JS. For each .html key in `files` we
  // parse the HTML via src/html.js, walk the token stream,
  // pull every inline <script>'s text into a synthetic
  // `<page>.inline.N.js` file, and replace the HTML entry
  // with the extracted JS sources. Non-HTML files pass through
  // unchanged.
  //
  // Consumers (dom-convert, taint-report, csp-derive,
  // fetch-trace) that take raw project files expect HTML
  // inputs to be analyzed as if the <script> blocks were
  // standalone JS — this is the same auto-extraction the
  // legacy engine did inline inside its walker, lifted here
  // to the public entry so every consumer benefits.
  const extracted = Object.create(null);
  for (const filename of Object.keys(files)) {
    if (!/\.html?$/i.test(filename)) {
      extracted[filename] = files[filename];
      continue;
    }
    const toks = HTML.tokenize(files[filename]);
    let idx = 0;
    const base = filename.replace(/\.html?$/i, '');
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (t.type !== 'start' || t.tagName !== 'script') continue;
      const hasSrc = t.attrs && t.attrs.some(a => a.name === 'src');
      if (hasSrc) continue;
      // Scan for the matching </script> and collect inner TEXT.
      let body = '';
      let j = i + 1;
      for (; j < toks.length; j++) {
        if (toks[j].type === 'end' && toks[j].tagName === 'script') break;
        if (toks[j].type === 'text') body += toks[j].value;
      }
      body = body.trim();
      if (body) {
        const synth = base + '.inline.' + idx + '.js';
        idx++;
        extracted[synth] = body;
      }
      i = j;
    }
  }

  // Replace the working set with the extracted map so the
  // walker loop sees only JS entries (HTML files have been
  // replaced by their inline JS; HTML files with no inline
  // scripts simply disappear from the set).
  for (const k of Object.keys(files)) {
    if (/\.html?$/i.test(k)) delete extracted[k];
  }
  const workingFiles = extracted;

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

  for (const filename of Object.keys(workingFiles)) {
    let module;
    // Boundary: parse/IR errors. We catch here — and ONLY here —
    // so one bad file doesn't tank the whole multi-file analysis.
    // Every caught error raises an explicit `unimplemented`
    // soundness assumption so consumers that only inspect
    // `trace.assumptions` still see the floor, AND a
    // human-readable entry in `trace.warnings`. The underlying
    // exception's message is recorded on both.
    try {
      module = buildModule(workingFiles[filename], filename);
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
      // Wave 12: innerHTML / outerHTML / insertAdjacentHTML
      // assignments recorded during the walk. The DOM-
      // conversion consumer (consumers/dom-convert.js) iterates
      // these to rewrite unsafe sinks into createElement trees.
      innerHtmlAssignments: [],
      // Wave 12b: generic call-site recording. Populated by
      // applyCall for every CALL instruction. fetch-trace and
      // csp-derive are the primary consumers; dom-convert reads
      // it for addEventListener / appendChild / setAttribute
      // call resolution.
      calls: [],
      // Wave 12b: concrete string-literal arguments passed to
      // any call, plus concrete string property writes. csp-
      // derive reads this to find script-src / img-src / etc.
      // allow-list origins; fetch-trace reads it to find
      // hardcoded endpoint URLs.
      stringLiterals: [],
      // Wave 12b: DOM mutations (method calls + property writes)
      // on DOM-typed receivers. dom-convert's primary input
      // alongside innerHtmlAssignments; csp-derive checks it
      // for createElement('script') patterns; any consumer
      // that rewrites DOM code reads from here.
      domMutations: [],
      // Flow id counter — assigned at emission time so flows
      // have stable identity within a trace.
      nextFlowId: 1,
      // Precision mode + Z3 hookup.
      precision,
      smtTimeoutMs,
      solverCheckPathSat,
      // Accept set (null = all accepted). The worklist and
      // transfer functions consult this to decide whether to
      // take performance shortcuts like loop widening and
      // summary-cache reuse. Rejected shortcuts force the
      // engine into the exhaustive equivalent.
      accept,
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

    // Wave 12 / Phase E: copy innerHTML-family assignments
    // recorded during the walk into the trace. These records
    // drive the DOM-conversion consumer (and any consumer that
    // wants to inventory unsafe HTML sink sites).
    //
    // When the assigned value is a concrete string we
    // EAGERLY parse it via the vendored HTML parser and
    // attach the resulting fragment + flat token stream so
    // consumers can operate on a structured view without
    // re-parsing. `parsedHtml` is the tree (nodes with tag,
    // attrs, children, loc); `htmlTokens` is the flat token
    // stream that dom-convert mutates in place for source-
    // preserving rewrites. Non-concrete values (loop-built
    // strings, tainted opaque) have `parsedHtml = null` and
    // the consumer has to reconstruct the HTML from the
    // trace's calls/bindings context.
    for (const ih of ctx.innerHtmlAssignments) {
      const v = ih.value;
      if (v && v.kind === D.V.CONCRETE && typeof v.value === 'string') {
        ih.parsedHtml = HTML.parse(v.value);
        ih.htmlTokens = HTML.tokenize(v.value);
        ih.concrete = v.value;
      } else {
        ih.parsedHtml = null;
        ih.htmlTokens = null;
        ih.concrete = null;
      }
      trace.innerHtmlAssignments.push(ih);
    }
    for (const c of ctx.calls) trace.calls.push(c);
    for (const s of ctx.stringLiterals) trace.stringLiterals.push(s);
    for (const d of ctx.domMutations) trace.domMutations.push(d);

    // Projection: trace.callGraph is derived from ctx.calls.
    // Nodes are unique callee identities (by calleeName +
    // typeName), edges connect caller-file to callee-target.
    // The call graph is intentionally coarse — consumers that
    // need finer-grained edges read trace.calls directly.
    for (const c of ctx.calls) {
      const calleeId = (c.callee.typeName ? c.callee.typeName + '.' : '') +
        (c.callee.methodName || c.callee.calleeName || '<anonymous>');
      if (!trace.callGraph.nodes.some(n => n.id === calleeId)) {
        trace.callGraph.nodes.push({ id: calleeId, kind: 'callee' });
      }
      const callerId = filename;
      if (!trace.callGraph.nodes.some(n => n.id === callerId)) {
        trace.callGraph.nodes.push({ id: callerId, kind: 'file' });
      }
      trace.callGraph.edges.push({
        from: callerId,
        to: calleeId,
        site: c.site,
      });
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

  // Assumption rejection pass. If the consumer passed an
  // explicit `accept` set, any assumption with a reason not in
  // the set is rejected — copied into `rejectedAssumptions`
  // and setting `partial = true`. Consumers that did NOT pass
  // `accept` get every assumption as-tolerated (the default
  // permissive mode).
  if (!acceptAll) {
    for (const a of trace.assumptions) {
      if (!accept.has(a.reason)) {
        trace.rejectedAssumptions.push(a);
      }
    }
    if (trace.rejectedAssumptions.length > 0) {
      trace.partial = true;
    }
  }

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

// resetCache() — hard-reset the per-process Z3 solver cache.
// Hosts that reuse a single jsanalyze import across many
// analyses (browser UI, analysis server, long-running worker)
// call this when they want to guarantee no stale SAT results
// from a previous analyse() leak into the next. The shared
// Solver is released so its declaration table is rebuilt from
// scratch on the next use. Safe to call at any time.
//
// Not needed for normal CLI / single-analysis workflows — the
// cache is LRU-bounded, so it will stabilise at a constant
// memory footprint without manual intervention.
function resetCache() {
  Z3.resetCache();
}

module.exports = {
  analyze,
  query,
  resetCache,
  // Re-exports for consumers that want direct access to the
  // assumption system (e.g. tests).
  AssumptionTracker,
};
