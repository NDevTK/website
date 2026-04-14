// index.js — public entry point for jsanalyze
//
// Exposes `analyze()` and the `query` namespace. Consumers should
// depend on this file only; internal modules (ir, domain, worklist,
// transfer) are implementation details.

'use strict';

const { buildModule, buildProjectModule } = require('./ir.js');
const { analyseFunction } = require('./worklist.js');
const { AssumptionTracker, REASONS, SEVERITIES, DEFAULT_ACCEPT } = require('./assumptions.js');
const D = require('./domain.js');
const { overlayEntries } = require('./domain.js');
const Z3 = require('./z3.js');
const HTML = require('./html.js');
const HtmlTemplates = require('./html-templates.js');
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
//   * smtTimeoutMs  — per-Z3-check wall-clock cap in
//                     milliseconds. Default 5000. Plumbed
//                     through to z3.checkPathSat on every
//                     Layer 5 invocation and to the post-pass
//                     refutation. A soft cap; Z3 returns
//                     `unknown` on timeout, which raises an
//                     `unsolvable-math` assumption and leaves
//                     the branch / flow in place.
//
//   * accept        — PRESCRIPTIVE Set<AssumptionReason>.
//                     The single axis for all precision /
//                     performance / soundness trade-offs.
//                     When omitted, defaults to
//                     assumptions.DEFAULT_ACCEPT which
//                     accepts every reason EXCEPT the opt-in
//                     performance shortcut 'smt-skipped'.
//
//                     Rejecting a reason is prescriptive: the
//                     engine does NOT take the shortcut that
//                     would raise that reason. For example:
//                       * reject 'loop-widening'  → engine
//                         walks loops per-iteration (may not
//                         terminate on big loops).
//                       * reject 'summary-reused' → every
//                         call walks the callee body fresh
//                         (full context sensitivity).
//                       * reject 'smt-skipped'    → engine
//                         runs Z3 at every branch and in the
//                         post-pass refutation. This is the
//                         DEFAULT.
//                       * accept 'smt-skipped'    → engine
//                         skips Z3 entirely (fast mode).
//
//                     Rejections of theoretical-floor
//                     reasons (network, attacker-input, etc.)
//                     are advisory — the engine can't conjure
//                     bytes it doesn't have; the rejection
//                     lands in `trace.rejectedAssumptions`
//                     with `partial = true` so the consumer
//                     knows its result is untrustworthy.
//
//   * taint         — enable taint-flow emission. Default true.
//
//   * watchers      — streaming observation hooks: onCall,
//                     onFinding, onAssumption.
async function analyze(input, options) {
  options = options || {};
  const smtTimeoutMs = options.smtTimeoutMs != null ? options.smtTimeoutMs : 5000;
  const watchers = options.watchers || null;
  // Single axis for precision / performance / soundness
  // trade-offs: `accept`. When the consumer doesn't pass
  // one, we use the default set which accepts every reason
  // except 'smt-skipped' (Z3 runs by default).
  const accept = options.accept != null
    ? new Set(Array.isArray(options.accept) ? options.accept : [])
    : DEFAULT_ACCEPT;
  // Derived shortcut gates — read directly from `accept` so
  // the same Set controls every engine decision uniformly.
  const smtSkipped = accept.has(REASONS.SMT_SKIPPED);
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
  // both successors reachable. Bound only when the consumer
  // has NOT accepted 'smt-skipped' (i.e. the default
  // precise-mode path). Results are cached inside z3.js by
  // the formula's expression text.
  const solverCheckPathSat = smtSkipped
    ? null
    : (formula) => Z3.checkPathSat(formula, smtTimeoutMs);

  // Project-mode walk: when `options.project` is set, we
  // build a SINGLE module whose top function body is the
  // concatenation of the listed files' top-level statements
  // in the given order. Declarations in earlier files are
  // visible to later files (shared module-level scope),
  // matching the way a browser evaluates multiple
  // `<script src>` tags into the same global scope. This
  // replaces the per-file-isolated walk below with one
  // project-wide walk.
  //
  // The file iteration (for loop below) is skipped when
  // project mode is active; instead we synthesize a single
  // iteration over the virtual "project module" whose name
  // is the first file's name (for display / trace
  // attribution). Per-instruction source locations already
  // carry their originating file via the sourceMap — see
  // buildProjectModule — so trace projection attributes
  // each observation to the right file.
  const projectOrder = Array.isArray(options.project) ? options.project : null;
  const iterFiles = projectOrder ? [projectOrder[0]] : Object.keys(workingFiles);

  for (const filename of iterFiles) {
    let module;
    // Boundary: parse/IR errors. We catch here — and ONLY here —
    // so one bad file doesn't tank the whole multi-file analysis.
    // Every caught error raises an explicit `unimplemented`
    // soundness assumption so consumers that only inspect
    // `trace.assumptions` still see the floor, AND a
    // human-readable entry in `trace.warnings`. The underlying
    // exception's message is recorded on both.
    try {
      if (projectOrder) {
        // Build the shared-scope module from the ordered file list.
        const projectFiles = Object.create(null);
        for (const p of projectOrder) {
          if (workingFiles[p] != null) projectFiles[p] = workingFiles[p];
        }
        module = buildProjectModule(projectFiles, projectOrder, filename);
      } else {
        module = buildModule(workingFiles[filename], filename);
      }
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

    // When the consumer has rejected 'summary-reused' (no
    // longer the permissive default), clear every function's
    // summary cache before this file's walk. Different call
    // sites will then walk the callee independently, getting
    // full context sensitivity at the cost of redoing work.
    // The per-call gate inside transfer.applyCall also
    // checks ctx.accept.has('summary-reused'); clearing here
    // is a belt-and-suspenders step so stale cache entries
    // from a prior permissive analyse() don't accidentally
    // get reused.
    if (!accept.has(REASONS.SUMMARY_REUSED)) {
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
      // Z3 hookup. When the consumer has accepted
      // 'smt-skipped', solverCheckPathSat is null and the
      // worklist's branch cascade stops at Layer 4.
      smtTimeoutMs,
      solverCheckPathSat,
      // Accept set. The worklist and transfer functions
      // consult this to decide whether to take performance
      // shortcuts (loop widening, summary-cache reuse) and
      // whether to call Z3 at all. Every engine decision
      // reads from the same set so there's no parallel
      // precision axis.
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
    // drive the DOM-conversion consumer (and any consumer
    // that wants to inventory unsafe HTML sink sites).
    //
    // Per D11.1 the engine attaches EVERY piece of structured
    // knowledge consumers might need to each record:
    //
    //   * concrete / parsedHtml / htmlTokens — when the
    //     assigned Value is a compile-time string, the
    //     engine parses it via src/html.js (tree + flat
    //     token stream) so consumers can operate on a
    //     structured view without re-parsing.
    //
    //   * template — a structured HtmlTemplate (from
    //     src/html-templates.js) that covers patterns the
    //     value lattice can't fold to a concrete string.
    //     Right now:
    //       - { kind: 'concrete', html, nodes } — same as
    //         the concrete case above, also surfaced here
    //         for uniform consumer reads
    //       - { kind: 'loop', ... } — accumulator loops
    //         (`var H='<tag>'; for (...){H+=...} ...`)
    //       - { kind: 'opaque', reason } — recognised site,
    //         engine couldn't match a pattern
    //     Consumers read `ih.template` first and fall back
    //     to `ih.parsedHtml` only when template is null
    //     (engine couldn't find the site).
    //
    // The template extractor caches its parsed AST per
    // source file so multiple assignments in the same file
    // share a single parse.
    const astCache = Object.create(null);
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
      // Attach the structured template. Ordering:
      //
      //   1. Run the AST-level template extractor FIRST. It
      //      recognises dynamic shapes (accumulator loops,
      //      branches, etc.) that preserve runtime iteration
      //      semantics — consumers that rewrite the source
      //      need these to generate code that still works
      //      when a runtime caller mutates the underlying
      //      data (e.g. items.push from a later event).
      //      If the value-lattice analysis has folded the
      //      accumulator to a specific compile-time value,
      //      we'd be tempted to call it concrete — but that
      //      answer IGNORES the runtime mutability and would
      //      produce an unsound rewrite.
      //
      //   2. Fall back to the value-lattice concrete view
      //      only when the extractor returns null or an
      //      `opaque` verdict. This covers the common
      //      `elem.innerHTML = "<p>" + x + "</p>"` shape
      //      where x is a plain concat hole and the lattice
      //      has resolved the final value but the AST
      //      extractor doesn't currently match concat
      //      chains without a surrounding loop.
      //
      //   3. If neither step produced a template, ih.template
      //      is null so consumers know the site exists but
      //      isn't rewritable.
      const srcFile = ih.location && ih.location.file;
      let astTemplate = null;
      if (srcFile && workingFiles[srcFile] != null) {
        if (!astCache[srcFile]) astCache[srcFile] = Object.create(null);
        astTemplate = HtmlTemplates.extractTemplate(
          workingFiles[srcFile],
          ih.location.pos,
          srcFile,
          astCache[srcFile]);
      }
      if (astTemplate && astTemplate.kind !== 'opaque') {
        ih.template = astTemplate;
      } else if (ih.concrete != null && ih.parsedHtml) {
        ih.template = {
          kind: 'concrete',
          html: ih.concrete,
          nodes: ih.parsedHtml,
        };
      } else {
        ih.template = astTemplate;  // opaque with reason, or null
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
  // the flow was emitted. Skipped when the consumer has
  // accepted 'smt-skipped'. Every SMT skip raises a
  // SMT_SKIPPED assumption so the consumer can audit where
  // the engine would have refuted if precision mattered.
  if (!smtSkipped) {
    await Z3.refuteTrace(trace, smtTimeoutMs);
  } else {
    assumptions.raise(
      REASONS.SMT_SKIPPED,
      'Z3 post-pass refutation skipped because consumer accepted smt-skipped',
      { file: '<solver>', line: 0, col: 0, pos: 0 }
    );
  }

  trace.assumptions = assumptions.snapshot();

  // Assumption rejection pass. The accept set is
  // prescriptive — every assumption with a reason NOT in the
  // set is flagged as rejected and sets `partial = true` on
  // the trace. Because the default accept set (when the
  // consumer doesn't pass one) already covers every reason
  // code, default analyse() calls never produce rejections.
  // Consumers that pass a narrower explicit set get
  // fine-grained strict-mode reporting.
  {
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
