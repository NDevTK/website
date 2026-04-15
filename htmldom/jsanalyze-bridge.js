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
//   globalThis.__runAllConsumers(files) → {
//     convertedFiles: { path: content },   // dom-convert output
//     taint:   { findings, summary },       // taint-report reshaped
//     csp:     { 'script-src': [...], ... },// csp-derive policy
//     fetches: FetchCallSite[],             // fetch-trace
//     pocs:    PocResult[],                 // poc-synth
//   }
//
// The UI calls `__runAllConsumers` once per convert cycle and
// renders each panel from the shared result. Consumers that
// need their own analyze() pass (dom-convert is project-aware)
// still get one, but anything over trace.taintFlows /
// trace.calls / trace.stringLiterals flows through a single
// engine walk per file.
//
// Load order (set by monaco-init.js):
//   1. jsanalyze/vendor/acorn.js            (sets globalThis.acorn)
//   2. htmldom/jsanalyze-z3-browser.js      (registers __htmldomZ3Init)
//   3. jsanalyze/browser-bundle.js          (sets globalThis.Jsanalyze)
//   4. htmldom/jsanalyze-bridge.js          (this file)

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
  async function analyseAll(files) {
    // `analyze()` only takes a file map directly — build one
    // containing every .js file plus the HTML files themselves
    // (the engine auto-extracts inline <script> blocks).
    var input = Object.create(null);
    for (var p in files) input[p] = files[p];
    return await J.analyze(input);
  }

  // --- Taint findings (legacy shape for the sidebar) -----------------
  //
  // Reshapes trace.taintFlows + refutedFlows into the UI's
  // { findings, summary } schema.
  function taintFindingsFromTrace(trace, files) {
    var findings = [];
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
      var originatingFile = resolveOriginatingFile(
        sinkLoc ? sinkLoc.file : null, files);
      findings.push({
        id: f.id,
        sources: sources,
        sink: {
          prop: (f.sink && f.sink.prop) || null,
          kind: (f.sink && f.sink.kind) || null,
          elementTag: null,
        },
        severity: f.severity || 'medium',
        file: originatingFile,
        location: sinkLoc ? { line: sinkLoc.line || 0, col: sinkLoc.col || 0 } : null,
        conditions: conditions,
      });
    }
    var counts = { high: 0, medium: 0, low: 0, total: findings.length };
    for (var k = 0; k < findings.length; k++) {
      var s = findings[k].severity;
      if (counts[s] != null) counts[s]++;
    }
    return { findings: findings, summary: counts };
  }

  // Kept for backwards compat — monaco-init.js historically
  // called __traceTaint(files) as its own entry point. We
  // leave it pointing at the shared trace path.
  globalThis.__traceTaint = async function (files) {
    var trace = await analyseAll(files);
    return taintFindingsFromTrace(trace, files);
  };

  // --- CSP derivation -------------------------------------------------
  //
  // Returns the csp-derive consumer's full policy object.
  // Rendered in the UI as a grouped directive → source-list
  // view. See consumers/csp-derive.js for the shape.
  async function runCspDerive(files) {
    return await J.consumers.cspDerive.derive(files);
  }

  // --- Fetch trace ---------------------------------------------------
  //
  // Returns an array of FetchCallSite records, one per
  // discovered fetch / XHR / WebSocket / Beacon / EventSource
  // call. Rendered as a list of `METHOD URL @ file:line`.
  async function runFetchTrace(files) {
    return await J.consumers.fetchTrace.trace(files);
  }

  // --- PoC synthesis --------------------------------------------------
  //
  // Runs poc-synth on the shared trace. Returns an array of
  // PocResult records. The UI renders successful
  // 'synthesised' results with their payload inline and the
  // other verdicts (infeasible / unsolvable / trivial /
  // no-constraint) as a muted secondary list.
  async function runPocSynth(trace) {
    if (!J.consumers.pocSynth) return [];
    return await J.consumers.pocSynth.synthesiseTrace(trace);
  }

  // --- Unified runner --------------------------------------------------
  //
  // Runs one shared analyse() call and dispatches its trace to
  // every trace-over consumer. dom-convert runs its own pass
  // via convertProject because it's project-aware (per-HTML
  // page). Returns an aggregate object the UI renders from.
  globalThis.__runAllConsumers = async function (files) {
    var convertedFiles = {};
    try {
      convertedFiles = (await J.consumers.domConvert.convertProject(files)) || {};
    } catch (e) { /* convertProject failures are non-fatal */ }

    var trace;
    try {
      trace = await analyseAll(files);
    } catch (e) {
      return {
        convertedFiles: convertedFiles,
        taint:   { findings: [], summary: { total: 0, high: 0, medium: 0, low: 0 } },
        csp:     null,
        fetches: [],
        pocs:    [],
        error:   e && e.message,
      };
    }

    var taint  = taintFindingsFromTrace(trace, files);
    var csp    = null;
    var fetches = [];
    var pocs   = [];
    // Each consumer is independent — a failure in one shouldn't
    // take down the others. The UI panel just shows empty for
    // a failing consumer.
    try { csp     = await J.consumers.cspDerive.derive(files); } catch (e) {}
    try { fetches = await J.consumers.fetchTrace.trace(files); } catch (e) {}
    try { pocs    = await runPocSynth(trace); } catch (e) {}

    return {
      convertedFiles: convertedFiles,
      taint:   taint,
      csp:     csp,
      fetches: fetches,
      pocs:    pocs,
    };
  };

})();
