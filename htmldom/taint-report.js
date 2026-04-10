// taint-report.js
//
// Produces a human-friendly taint-flow report from a JavaScript
// bundle. A thin jsanalyze consumer that wraps `query.taintFlows`
// with presentation logic — grouping, filtering, severity
// mapping, and text rendering suitable for a terminal, a PR
// comment, or a security scanner's output.
//
// Core entry point:
//
//   const report = await taintReport.analyze(bundle, options);
//
// Returns:
//
//   {
//     schemaVersion: '1',
//     flows: TaintFlow[],      — straight pass-through of query.taintFlows
//     grouped: {                — convenient groupings for display
//       bySource: { 'url': [...], 'cookie': [...], ... },
//       bySink:   { 'innerHTML': [...], 'eval': [...], ... },
//       bySeverity: { 'high': [...], 'medium': [...], ... },
//       byFile:   { 'a.js': [...], ... }
//     },
//     counts: { total, high, medium, low, refuted },
//     partial: bool,
//     warnings: [...]
//   }
//
// Design note: this file is explicitly a *presentation* layer.
// All analysis work is done in the walker + query.taintFlows.
// If you need a flow not currently reported, the fix is in the
// walker, not here.

(function () {
  'use strict';

  function loadQuery() {
    if (typeof globalThis !== 'undefined' && globalThis.JsAnalyzeQuery) return globalThis.JsAnalyzeQuery;
    if (typeof require !== 'undefined') {
      try { return require('./jsanalyze-query.js'); } catch (_) {}
    }
    throw new Error('taint-report: jsanalyze-query not available');
  }

  async function analyze(input, options) {
    options = options || {};
    const { analyze: runAnalyze, query } = loadQuery();

    const trace = await runAnalyze(input, {
      taint: options.taint || { enabled: true },
      watchers: options.watchers,
    });

    const filter = options.filter || {};
    const flows = query.taintFlows(trace, filter);

    // Group flows by various dimensions. Mutating grouped
    // entries is safe because each array is built fresh here.
    const bySource = Object.create(null);
    const bySink = Object.create(null);
    const bySeverity = Object.create(null);
    const byFile = Object.create(null);

    for (const f of flows) {
      for (const src of f.sources) {
        if (!bySource[src]) bySource[src] = [];
        bySource[src].push(f);
      }
      const sinkKey = f.sink.prop || '<unknown>';
      if (!bySink[sinkKey]) bySink[sinkKey] = [];
      bySink[sinkKey].push(f);

      const sev = f.severity || 'medium';
      if (!bySeverity[sev]) bySeverity[sev] = [];
      bySeverity[sev].push(f);

      const file = f.site.file || '<anonymous>';
      if (!byFile[file]) byFile[file] = [];
      byFile[file].push(f);
    }

    const counts = {
      total: flows.length,
      high: (bySeverity.high || []).length,
      medium: (bySeverity.medium || []).length,
      low: (bySeverity.low || []).length,
      refuted: flows.filter(f => f.refutedByZ3).length,
    };

    return {
      schemaVersion: '1',
      flows: flows,
      grouped: { bySource, bySink, bySeverity, byFile },
      counts,
      partial: trace.partial,
      warnings: trace.warnings,
      trace: options.includeTrace ? trace : undefined,
    };
  }

  // Render a report as human-readable text. Useful for CI output
  // or PR comments. Consumers can plug in their own renderer.
  function render(report, opts) {
    opts = opts || {};
    const lines = [];
    const c = report.counts;
    lines.push('taint report: ' + c.total + ' flow(s) total' +
      (c.high ? '  ' + c.high + ' high' : '') +
      (c.medium ? '  ' + c.medium + ' medium' : '') +
      (c.low ? '  ' + c.low + ' low' : '') +
      (c.refuted ? '  (' + c.refuted + ' refuted by SMT)' : ''));

    if (report.partial) lines.push('  partial trace — analysis incomplete');
    if (report.warnings && report.warnings.length) {
      for (const w of report.warnings) lines.push('  ! ' + (w.severity || 'warning') + ': ' + w.message);
    }

    if (opts.groupBy === 'source' || !opts.groupBy) {
      for (const src of Object.keys(report.grouped.bySource).sort()) {
        lines.push('');
        lines.push('  source: ' + src + ' (' + report.grouped.bySource[src].length + ')');
        for (const f of report.grouped.bySource[src]) {
          lines.push('    ' + f.site.file + ':' + f.site.line + '  →  ' + (f.sink.prop || '?') +
            (f.sink.elementTag ? ' on <' + f.sink.elementTag + '>' : ''));
          if (f.conditions && f.conditions.length) {
            lines.push('        under: ' + f.conditions.map(c => c.text).join(' && '));
          }
        }
      }
    } else if (opts.groupBy === 'sink') {
      for (const sink of Object.keys(report.grouped.bySink).sort()) {
        lines.push('');
        lines.push('  sink: ' + sink + ' (' + report.grouped.bySink[sink].length + ')');
        for (const f of report.grouped.bySink[sink]) {
          lines.push('    ' + f.site.file + ':' + f.site.line + '  from ' + f.sources.join('+'));
        }
      }
    }

    return lines.join('\n');
  }

  const api = Object.freeze({ analyze, render });

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof globalThis !== 'undefined') globalThis.TaintReport = api;
})();
