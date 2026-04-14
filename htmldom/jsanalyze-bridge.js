// jsanalyze-bridge.js — adapter layer between the new
// jsanalyze engine (loaded via browser-bundle.js as
// `globalThis.Jsanalyze`) and the existing UI in
// `monaco-init.js` that was written against the legacy
// engine's globals.
//
// This file is intentionally small: it delegates every real
// operation to the new engine's consumer namespace and only
// reshapes return values where the legacy UI expects a
// different JSON shape.
//
// Legacy globals exposed by this bridge:
//
//   * globalThis.HtmldomConvert = { convertProject }
//       — backed by Jsanalyze.consumers.domConvert
//
//   * globalThis.__traceTaint(files)
//       — backed by Jsanalyze.consumers.taintReport, reshaped
//         from the TaintFlow[] + refutedFlows[] trace shape
//         into the { findings, summary } shape monaco-init
//         reads.
//
// Load order:
//   1. jsanalyze/vendor/acorn.js            (sets globalThis.acorn)
//   2. htmldom/jsanalyze-z3-browser.js      (registers __htmldomZ3Init)
//   3. jsanalyze/browser-bundle.js          (sets globalThis.Jsanalyze)
//   4. htmldom/jsanalyze-bridge.js          (this file)
//
// monaco-init.js loads all four in sequence before calling
// convertAll().

(function () {
  'use strict';

  // Wait for the bundle to be loaded. We expect it to be
  // set synchronously by the script tag before this file runs.
  if (typeof globalThis === 'undefined' || !globalThis.Jsanalyze) {
    throw new Error('jsanalyze-bridge: globalThis.Jsanalyze not available — ' +
      'load jsanalyze/browser-bundle.js before this file.');
  }

  var J = globalThis.Jsanalyze;

  // --- HtmldomConvert facade ----------------------------------------
  //
  // The new engine's DOM-convert consumer already matches the
  // legacy `convertProject(files) → { filename: content }`
  // shape exactly, so this is a thin pass-through.
  globalThis.HtmldomConvert = {
    convertProject: function (files, options) {
      return J.consumers.domConvert.convertProject(files, options);
    },
    // Legacy single-file entry points are delegated to the
    // consumer's own helpers where they exist, otherwise they
    // wrap a single-file convertProject call.
    convertHtmlMarkup: function (html, pagePath, reserved) {
      return J.consumers.domConvert.convertHtmlMarkup(html, pagePath, reserved);
    },
    convertJsFile: async function (jsContent, precedingCode, knownDomFunctions) {  // eslint-disable-line no-unused-vars
      // The new engine's convertJsFile takes a trace (from
      // analyze()) plus the source. Run analyze() on the JS
      // fragment and pass its trace in.
      var filename = '<input>.js';
      var trace = await J.analyze({ [filename]: jsContent }, {
        precision: 'precise',
      });
      return J.consumers.domConvert.convertJsFile(jsContent, trace, filename);
    },
  };

  // --- __traceTaint adapter -----------------------------------------
  //
  // Legacy shape expected by monaco-init.js:
  //
  //   {
  //     findings: [
  //       {
  //         sources: string[],          // source labels
  //         sink:    { prop, elementTag },
  //         severity: 'high' | 'medium' | 'low',
  //         file:    string,
  //         location: { line, col },
  //         conditions: string[],
  //       },
  //       ...
  //     ],
  //     summary: {
  //       total:  number,
  //       high:   number,
  //       medium: number,
  //       low:    number,
  //     },
  //   }
  //
  // The new trace's taintFlows have:
  //
  //   {
  //     id, source: [{label, location}], sink: {kind, prop, location},
  //     severity, pathFormula, valueFormula, assumptionIds,
  //   }
  //
  // We reshape fields 1:1 and map the severity enum
  // (the new engine uses string severities that already
  // match). Flow "conditions" are rendered from the
  // pathFormula's expr so the UI's "when:" line has
  // something to show.
  // Map synthetic *.inline.N.js filenames produced by the
  // engine's HTML inline-script auto-extraction back to the
  // originating HTML file, so clicks on taint findings in
  // the UI navigate to the actual source file the user sees
  // in the sidebar.
  function resolveOriginatingFile(f, files) {
    if (!f) return null;
    // Pattern: `<base>.inline.<idx>.js` → `<base>.html`.
    var m = f.match(/^(.+)\.inline\.\d+\.js$/);
    if (!m) return f;
    var base = m[1];
    // Prefer .html if the input map has it, then .htm.
    if (files && (files[base + '.html'] != null)) return base + '.html';
    if (files && (files[base + '.htm']  != null)) return base + '.htm';
    return f;
  }

  globalThis.__traceTaint = async function (files) {
    var report = await J.consumers.taintReport.analyze(files);
    var findings = [];
    for (var i = 0; i < report.flows.length; i++) {
      var f = report.flows[i];
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
        sources: sources,
        sink: {
          prop: (f.sink && f.sink.prop) || null,
          elementTag: null,   // not carried on the new Trace
        },
        severity: f.severity || 'medium',
        file: originatingFile,
        location: sinkLoc ? { line: sinkLoc.line || 0, col: sinkLoc.col || 0 } : null,
        conditions: conditions,
      });
    }
    return {
      findings: findings,
      summary: {
        total:  report.counts.total,
        high:   report.counts.high,
        medium: report.counts.medium,
        low:    report.counts.low,
      },
    };
  };

  // --- Signal to the UI that the bridge is ready -------------------
  //
  // monaco-init.js polls `globalThis.HtmldomConvert &&
  // globalThis.__traceTaint` to decide when the engine is
  // usable. Both are now defined synchronously at this point,
  // so the poller exits on its next tick.
})();
