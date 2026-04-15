// jsanalyze-bridge.js — thin adapter between the new jsanalyze
// engine (loaded via browser-bundle.js as `globalThis.Jsanalyze`)
// and the UI in `monaco-init.js`.
//
// The bridge exposes one async function per consumer output the
// UI panels need, and runs a SINGLE `analyze()` call per
// convert cycle whose trace is shared across every consumer
// that's pure-over-trace. This keeps the hot path O(files)
// instead of O(files × consumers).
//
// Exposed globals:
//
//   globalThis.HtmldomConvert = {
//     convertProject(files, options?) → { filename: content }
//     convertHtmlMarkup(html, pagePath, reserved)
//     convertJsFile(jsContent, filename?)
//   }
//
//   globalThis.__runAllConsumers(files, options?) → {
//     convertedFiles: { path: content },   // dom-convert output
//     taint:   { findings, summary },       // taint-report reshaped
//     csp:     { 'script-src': [...], ... },// csp-derive policy
//     fetches: FetchCallSite[],             // fetch-trace
//     pocs:    PocResult[],                 // poc-synth
//     accept:  string[],                    // echo of the accept set used
//     allAssumptions: Assumption[],         // every assumption raised
//     rejectedAssumptions: Assumption[],    // ones outside the accept set
//   }
//
// `options.accept`, when passed, is forwarded to every engine
// call (analyze + each consumer) so the UI's assumption-
// choice control is the single knob that steers precision /
// soundness / performance for the whole run.
//
// Finding records are enriched with their `assumptions` —
// the Assumption objects reached via `flow.assumptionIds` —
// so the UI can render "what assumptions this finding
// depends on" next to each sink. The bridge does the id →
// record lookup so the UI never has to cross-reference
// trace.assumptions itself.
//
// Load order (set by monaco-init.js):
//   1. jsanalyze/vendor/acorn.js            (sets globalThis.acorn)
//   2. analyzer/jsanalyze-z3-browser.js     (registers __htmldomZ3Init)
//   3. jsanalyze/browser-bundle.js          (sets globalThis.Jsanalyze)
//   4. analyzer/jsanalyze-bridge.js         (this file)

(function () {
  'use strict';

  if (typeof globalThis === 'undefined' || !globalThis.Jsanalyze) {
    throw new Error('jsanalyze-bridge: globalThis.Jsanalyze not available — ' +
      'load jsanalyze/browser-bundle.js before this file.');
  }

  var J = globalThis.Jsanalyze;

  // --- HtmldomConvert facade ----------------------------------------
  //
  // Thin pass-through to the dom-convert consumer. The UI's
  // convertAll() path stays unchanged so the existing
  // download / copy / file-list plumbing keeps working.
  globalThis.HtmldomConvert = {
    convertProject: function (files, options) {
      return J.consumers.domConvert.convertProject(files, options);
    },
    convertHtmlMarkup: function (html, pagePath, reserved) {
      return J.consumers.domConvert.convertHtmlMarkup(html, pagePath, reserved);
    },
    convertJsFile: async function (jsContent, filename) {
      var name = filename || '<input>.js';
      var trace = await J.analyze({ [name]: jsContent });
      return J.consumers.domConvert.convertJsFile(jsContent, trace, name);
    },
  };

  // --- HTML inline-script helper ------------------------------------
  //
  // The new engine auto-extracts <script> blocks from HTML
  // inputs into synthetic `<base>.inline.N.js` files. The UI
  // wants to map those back to the originating HTML file so
  // click-to-navigate goes to what the user sees in the
  // sidebar.
  function resolveOriginatingFile(f, files) {
    if (!f) return null;
    var m = f.match(/^(.+)\.inline\.\d+\.js$/);
    if (!m) return f;
    var base = m[1];
    if (files && files[base + '.html'] != null) return base + '.html';
    if (files && files[base + '.htm']  != null) return base + '.htm';
    return f;
  }

  // --- Analysis options ----------------------------------------------
  //
  // `__runAllConsumers` takes an optional second argument:
  //
  //   { accept: string[] | null }
  //
  // When `accept` is an array, it's forwarded as-is to every
  // engine entry point. When null / undefined, the engine
  // uses its own DEFAULT_ACCEPT (every reason except the
  // opt-in 'smt-skipped', i.e. Z3 runs).
  //
  // The UI surfaces four presets:
  //
  //   * 'precise' (default) → null       — engine default: Z3 on,
  //                                        every soundness-floor
  //                                        reason accepted.
  //   * 'fast'              → DEFAULT_ACCEPT ∪ ['smt-skipped']
  //                                      — Z3 off at branches
  //                                        and post-pass.
  //   * 'exact'             → DEFAULT_ACCEPT − ['summary-reused',
  //                                        'loop-widening']
  //                                      — every call site walks
  //                                        the callee body
  //                                        fresh; loops iterate
  //                                        per-iteration.
  //   * 'strict'            → empty set  — rejects everything.
  //                                        Every assumption raised
  //                                        during the walk is
  //                                        flagged on the trace
  //                                        and surfaces in the UI.
  //
  // The bridge just forwards whichever array the UI built;
  // the preset names are a UI concern.
  function buildAnalyseOptions(options) {
    var opts = {};
    if (options && options.accept != null) {
      opts.accept = options.accept;
    }
    return opts;
  }

  // --- Shared project trace ------------------------------------------
  //
  // For every consumer that's pure-over-trace we run a single
  // `analyze()` on the whole input map and share its result.
  // dom-convert is the exception: it's project-aware (per-HTML
  // page script grouping) and runs its own analyze calls via
  // convertProject.
  //
  // When the input has multiple HTML pages with different
  // script-src sets, this shared trace is an over-approximation
  // (union of all JS files). That's fine for CSP derivation,
  // fetch discovery, and PoC synthesis — each consumer's output
  // is a set that already accommodates the union. Taint
  // findings get their per-file attribution via
  // flow.sink.location.file.
  async function analyseAll(files, options) {
    var input = Object.create(null);
    for (var p in files) input[p] = files[p];
    return await J.analyze(input, buildAnalyseOptions(options));
  }

  // --- Assumption helpers --------------------------------------------
  //
  // Build an index from `trace.assumptions` that lets findings
  // resolve `assumptionIds: number[]` → Assumption[] in O(k)
  // instead of O(k × n).
  function buildAssumptionIndex(trace) {
    var byId = Object.create(null);
    var all = (trace && trace.assumptions) || [];
    for (var i = 0; i < all.length; i++) {
      byId[all[i].id] = all[i];
    }
    return byId;
  }

  function assumptionsFor(ids, byId) {
    if (!ids || !ids.length) return [];
    var out = [];
    var seen = Object.create(null);
    for (var i = 0; i < ids.length; i++) {
      var a = byId[ids[i]];
      if (!a || seen[a.id]) continue;
      seen[a.id] = true;
      out.push(a);
    }
    return out;
  }

  // --- Taint findings (shape for the sidebar) ------------------------
  //
  // Reshapes trace.taintFlows into the UI's { findings, summary }
  // schema. Each finding carries its own `assumptions: Assumption[]`
  // so the UI can render "what the engine had to assume" next to
  // each sink.
  function taintFindingsFromTrace(trace, files) {
    var findings = [];
    var byId = buildAssumptionIndex(trace);
    var flows = (trace && trace.taintFlows) || [];
    for (var i = 0; i < flows.length; i++) {
      var f = flows[i];
      var sources = [];
      for (var j = 0; j < (f.source || []).length; j++) {
        sources.push(f.source[j].label);
      }
      var sinkLoc = (f.sink && f.sink.location) || null;
      var conditions = [];
      if (f.pathFormula && f.pathFormula.expr) {
        conditions.push(f.pathFormula.expr);
      }
      // The engine now remaps inline-script filenames back
      // to their originating HTML at trace projection time,
      // so sinkLoc.file is already 'example.html' rather
      // than 'example.inline.0.js'. We still route through
      // resolveOriginatingFile for belt-and-suspenders
      // compatibility with callers that hand us a trace
      // built by an older engine build.
      var originatingFile = resolveOriginatingFile(
        sinkLoc ? sinkLoc.file : null, files);
      findings.push({
        id: f.id,
        sources: sources,
        sink: {
          prop: (f.sink && f.sink.prop) || null,
          kind: (f.sink && f.sink.kind) || null,
          targetType:  (f.sink && f.sink.targetType)  || null,
          elementTag:  (f.sink && f.sink.elementTag)  || null,
        },
        severity: f.severity || 'medium',
        file: originatingFile,
        location: sinkLoc ? { line: sinkLoc.line || 0, col: sinkLoc.col || 0 } : null,
        conditions: conditions,
        assumptions: assumptionsFor(f.assumptionIds, byId),
      });
    }
    var counts = { high: 0, medium: 0, low: 0, total: findings.length };
    for (var k = 0; k < findings.length; k++) {
      var s = findings[k].severity;
      if (counts[s] != null) counts[s]++;
    }
    return { findings: findings, summary: counts };
  }

  // Enrich PoC results with the assumptions that applied to
  // the flow. The poc-synth consumer returns records keyed by
  // `flowId`, so we look up the original flow and copy its
  // resolved assumptions. When Z3 is skipped (accept includes
  // 'smt-skipped'), the witness itself is gated on that
  // assumption — we annotate that case explicitly so the UI
  // can say "no real solver proof was run for this payload".
  function enrichPocResults(pocs, trace) {
    var byId = buildAssumptionIndex(trace);
    var flowsById = Object.create(null);
    for (var i = 0; i < (trace.taintFlows || []).length; i++) {
      var f = trace.taintFlows[i];
      flowsById[f.id] = f;
    }
    var out = [];
    for (var j = 0; j < pocs.length; j++) {
      var r = pocs[j];
      var flow = flowsById[r.flowId];
      var a = flow ? assumptionsFor(flow.assumptionIds, byId) : [];
      var enriched = {};
      for (var k in r) enriched[k] = r[k];
      enriched.assumptions = a;
      out.push(enriched);
    }
    return out;
  }

  // Kept for backwards compat — monaco-init.js historically
  // called __traceTaint(files) as its own entry point. We
  // leave it pointing at the shared trace path.
  globalThis.__traceTaint = async function (files, options) {
    var trace = await analyseAll(files, options);
    return taintFindingsFromTrace(trace, files);
  };

  // --- Unified runner --------------------------------------------------
  //
  // Runs one shared analyse() call and dispatches its trace to
  // every trace-over consumer. dom-convert runs its own pass
  // via convertProject because it's project-aware (per-HTML
  // page). Returns an aggregate object the UI renders from.
  //
  // `options.accept` is passed through to analyze() AND to
  // every consumer's own analyze-capable entry point so the
  // whole run obeys the same precision setting. The aggregate
  // result echoes the accept set back so the UI can keep its
  // control in sync with what was actually used.
  globalThis.__runAllConsumers = async function (files, options) {
    options = options || {};
    var engineOpts = buildAnalyseOptions(options);
    console.log('[bridge] __runAllConsumers entry',
      'fileNames=', Object.keys(files || {}),
      'accept=', options.accept,
      'engineOpts=', engineOpts);

    var convertedFiles = {};
    console.log('[bridge] step convertProject START');
    try {
      convertedFiles = (await J.consumers.domConvert.convertProject(
        files, engineOpts)) || {};
    } catch (e) {
      console.error('[bridge] step convertProject THREW', e && (e.stack || e.message), e);
    }
    console.log('[bridge] step convertProject END',
      'outputFileCount=', Object.keys(convertedFiles).length,
      'outputFileNames=', Object.keys(convertedFiles));

    var trace;
    console.log('[bridge] step analyseAll START');
    try {
      trace = await analyseAll(files, options);
    } catch (e) {
      console.error('[bridge] step analyseAll THREW', e && (e.stack || e.message), e);
      return {
        convertedFiles: convertedFiles,
        taint:   { findings: [], summary: { total: 0, high: 0, medium: 0, low: 0 } },
        csp:     null,
        fetches: [],
        pocs:    [],
        accept:  options.accept || null,
        allAssumptions: [],
        rejectedAssumptions: [],
        error:   e && e.message,
      };
    }
    console.log('[bridge] step analyseAll END',
      'taintFlows=', (trace.taintFlows || []).length,
      'innerHtmlAssignments=', (trace.innerHtmlAssignments || []).length,
      'calls=', (trace.calls || []).length,
      'assumptions=', (trace.assumptions || []).length,
      'partial=', !!trace.partial,
      'warnings=', (trace.warnings || []).length);

    var taint  = taintFindingsFromTrace(trace, files);
    var csp    = null;
    var fetches = [];
    var pocs   = [];
    // Each consumer is independent — a failure in one shouldn't
    // take down the others. The UI panel just shows empty for
    // a failing consumer.
    console.log('[bridge] step cspDerive START');
    try {
      csp = await J.consumers.cspDerive.derive(files, engineOpts);
    } catch (e) {
      console.error('[bridge] step cspDerive THREW', e && (e.stack || e.message), e);
    }
    console.log('[bridge] step cspDerive END', csp && Object.keys(csp));
    console.log('[bridge] step fetchTrace START');
    try {
      fetches = await J.consumers.fetchTrace.trace(files, engineOpts);
    } catch (e) {
      console.error('[bridge] step fetchTrace THREW', e && (e.stack || e.message), e);
    }
    console.log('[bridge] step fetchTrace END', 'count=', (fetches || []).length);
    console.log('[bridge] step pocSynth START');
    try {
      pocs = await J.consumers.pocSynth.synthesiseTrace(trace);
    } catch (e) {
      console.error('[bridge] step pocSynth THREW', e && (e.stack || e.message), e);
    }
    console.log('[bridge] step pocSynth END', 'count=', (pocs || []).length);
    pocs = enrichPocResults(pocs || [], trace);

    var result = {
      convertedFiles: convertedFiles,
      taint:   taint,
      csp:     csp,
      fetches: fetches,
      pocs:    pocs,
      accept:  options.accept || null,
      allAssumptions:      trace.assumptions || [],
      rejectedAssumptions: trace.rejectedAssumptions || [],
    };
    console.log('[bridge] __runAllConsumers exit',
      'taint.findings=', result.taint.findings.length,
      'convertedFiles=', Object.keys(result.convertedFiles).length,
      'csp=', result.csp && Object.keys(result.csp),
      'fetches=', result.fetches.length,
      'pocs=', result.pocs.length,
      'allAssumptions=', result.allAssumptions.length);
    return result;
  };

  // --- Preset accept-set builders ------------------------------------
  //
  // Exposed so monaco-init.js can build the four mode presets
  // from the engine's own REASONS table instead of hardcoding
  // strings. Returns an Array<string> suitable for passing as
  // `options.accept` to __runAllConsumers.
  globalThis.__buildAcceptSet = function (mode) {
    var all = Object.values(J.REASONS || {});
    var def = Array.from(J.DEFAULT_ACCEPT || []);
    if (mode === 'fast') {
      // DEFAULT_ACCEPT plus smt-skipped.
      return def.concat(['smt-skipped']);
    }
    if (mode === 'exact') {
      // Remove performance shortcuts from DEFAULT_ACCEPT so
      // the engine walks every call context fresh and iterates
      // loops per-iteration.
      return def.filter(function (r) {
        return r !== 'summary-reused' && r !== 'loop-widening';
      });
    }
    if (mode === 'strict') {
      // Reject everything. The engine still raises assumptions
      // for unknowable bytes; they end up in
      // rejectedAssumptions and the UI flags them.
      return [];
    }
    // 'precise' and anything else → null (engine default).
    return null;
  };

  // --- Expose the reason catalogue to the UI ------------------------
  //
  // monaco-init.js renders a "Custom accept set" checkbox list
  // when the user wants fine-grained control. Each checkbox's
  // label comes from this ordered list. The categories match
  // docs/ASSUMPTIONS.md so the grouping in the UI mirrors the
  // design doc.
  globalThis.__assumptionCatalog = [
    { group: 'Theoretical floor',
      note:  'Bytes the engine cannot know at analysis time. Rejecting these is advisory — the engine still cannot read them.',
      reasons: [
        'network', 'attacker-input', 'persistent-state', 'dom-state',
        'ui-interaction', 'environmental', 'runtime-time', 'pseudorandom',
        'cryptographic-random', 'unsolvable-math',
      ] },
    { group: 'Environmental',
      note:  'Can be narrowed with more input to the analyser (e.g. a consumer-supplied TypeDB).',
      reasons: ['opaque-call', 'external-module', 'code-from-data'] },
    { group: 'Engineering gaps',
      note:  'Could be eliminated by implementing the missing transfer function.',
      reasons: ['unimplemented', 'heap-escape'] },
    { group: 'Performance shortcuts',
      note:  'Rejecting these is PRESCRIPTIVE — the engine actually stops taking the shortcut. Costs more time; gains precision.',
      reasons: ['loop-widening', 'summary-reused', 'smt-skipped'] },
  ];

})();
