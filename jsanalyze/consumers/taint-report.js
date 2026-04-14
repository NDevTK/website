// taint-report.js — human-friendly taint-flow presentation
// consumer (Wave 12 / Phase E, D11).
//
// Wraps trace.taintFlows with grouping / counting / rendering
// logic suitable for a terminal, a PR comment, or a security
// scanner's output. Port of the legacy htmldom/taint-report.js.
//
// Public API:
//
//   const tr = require('jsanalyze/consumers/taint-report');
//   const report = await tr.analyze(input, options?);
//     // returns {
//     //   schemaVersion: '1',
//     //   flows: TaintFlow[],
//     //   grouped: { bySource, bySink, bySeverity, byFile },
//     //   counts: { total, high, medium, low, refuted },
//     //   partial, warnings, trace? (when options.includeTrace),
//     // }
//
//   const text = tr.render(report, { groupBy: 'source' });

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');

async function analyzeReport(input, options) {
  options = options || {};
  const trace = await analyze(input, {
    typeDB: options.typeDB || TDB,
    
    accept: options.accept,
    watchers: options.watchers,
  });

  const flows = trace.taintFlows || [];
  const refuted = trace.refutedFlows || [];

  const bySource = Object.create(null);
  const bySink = Object.create(null);
  const bySeverity = Object.create(null);
  const byFile = Object.create(null);

  for (const f of flows) {
    // Each flow has a `source` array of {label, location}.
    for (const srcEntry of f.source || []) {
      const k = srcEntry.label || '<unknown>';
      if (!bySource[k]) bySource[k] = [];
      bySource[k].push(f);
    }
    const sinkKey = (f.sink && f.sink.prop) || '<unknown>';
    if (!bySink[sinkKey]) bySink[sinkKey] = [];
    bySink[sinkKey].push(f);
    const sev = f.severity || 'medium';
    if (!bySeverity[sev]) bySeverity[sev] = [];
    bySeverity[sev].push(f);
    const file = (f.sink && f.sink.location && f.sink.location.file) || '<anonymous>';
    if (!byFile[file]) byFile[file] = [];
    byFile[file].push(f);
  }

  const counts = {
    total:   flows.length,
    high:    (bySeverity.high || []).length,
    medium:  (bySeverity.medium || []).length,
    low:     (bySeverity.low || []).length,
    refuted: refuted.length,
  };

  return {
    schemaVersion: '1',
    flows,
    refuted,
    grouped: { bySource, bySink, bySeverity, byFile },
    counts,
    partial:  trace.partial,
    warnings: trace.warnings,
    trace: options.includeTrace ? trace : undefined,
  };
}

function render(report, opts) {
  opts = opts || {};
  const lines = [];
  const c = report.counts;
  lines.push('taint report: ' + c.total + ' flow(s) total' +
    (c.high   ? '  ' + c.high   + ' high'   : '') +
    (c.medium ? '  ' + c.medium + ' medium' : '') +
    (c.low    ? '  ' + c.low    + ' low'    : '') +
    (c.refuted ? '  (' + c.refuted + ' refuted by SMT)' : ''));
  if (report.partial) lines.push('  partial trace — analysis incomplete');
  if (report.warnings && report.warnings.length) {
    for (const w of report.warnings) {
      lines.push('  ! ' + (w.severity || 'warning') + ': ' + w.message);
    }
  }
  const groupBy = opts.groupBy || 'source';
  if (groupBy === 'source') {
    for (const src of Object.keys(report.grouped.bySource).sort()) {
      lines.push('');
      lines.push('  source: ' + src + ' (' + report.grouped.bySource[src].length + ')');
      for (const f of report.grouped.bySource[src]) {
        const loc = f.sink && f.sink.location;
        lines.push('    ' + (loc ? loc.file + ':' + loc.line : '?') +
          '  →  ' + ((f.sink && f.sink.prop) || '?'));
      }
    }
  } else if (groupBy === 'sink') {
    for (const sink of Object.keys(report.grouped.bySink).sort()) {
      lines.push('');
      lines.push('  sink: ' + sink + ' (' + report.grouped.bySink[sink].length + ')');
      for (const f of report.grouped.bySink[sink]) {
        const loc = f.sink && f.sink.location;
        const srcs = (f.source || []).map(s => s.label).join('+');
        lines.push('    ' + (loc ? loc.file + ':' + loc.line : '?') +
          '  from ' + srcs);
      }
    }
  }
  return lines.join('\n');
}

module.exports = {
  analyze: analyzeReport,
  render,
};
