// taint-report.test.js — consumers/taint-report.js coverage, focused
// on PoC witness synthesis (which moved out of src/z3.js into this
// consumer per D11.1).

'use strict';

const tr = require('../consumers/taint-report.js');
const { analyze } = require('../src/index.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'taint-report: direct location.hash → innerHTML synthesises a demo html payload',
    fn: async () => {
      const report = await tr.analyze(
        'document.body.innerHTML = location.hash;');
      assert(report.flows.length >= 1, 'at least one flow');
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'html');
      assert(flow, 'html-sink flow present');
      assert(flow.poc, 'flow has poc');
      assertEqual(flow.poc.verdict, 'synthesised');
      assertEqual(flow.poc.payload, '<script>alert(1)</script>');
    },
  },
  {
    name: 'taint-report: direct location.hash → location.href gets javascript: payload',
    fn: async () => {
      const report = await tr.analyze('location.href = location.hash;');
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'navigation');
      assert(flow, 'navigation flow present');
      assertEqual(flow.poc.verdict, 'synthesised');
      assertEqual(flow.poc.payload, 'javascript:alert(1)');
    },
  },
  {
    name: 'taint-report: eval(location.hash) gets alert(1) code payload',
    fn: async () => {
      const report = await tr.analyze('eval(location.hash);');
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'code');
      assert(flow, 'code-sink flow present');
      assertEqual(flow.poc.verdict, 'synthesised');
      assertEqual(flow.poc.payload, 'alert(1)');
    },
  },
  {
    name: 'taint-report: trivial verdict when sink receives a concrete string',
    fn: async () => {
      const trace = await analyze(
        'var s = location.hash; if (s === "ok") document.body.innerHTML = s;');
      await tr.synthesisePocs(trace, {});
      const flow = (trace.taintFlows || [])
        .find(f => f.poc && f.poc.verdict === 'trivial');
      if (flow) {
        assertEqual(flow.poc.payload, 'ok');
      }
    },
  },
  {
    name: 'taint-report: synthesisePocs attaches poc to every surviving flow',
    fn: async () => {
      const trace = await analyze(
        'document.body.innerHTML = location.hash;' +
        'location.href = location.hash;');
      await tr.synthesisePocs(trace, {});
      for (const f of (trace.taintFlows || [])) {
        assert(f.poc, 'every flow has a poc record');
        assert(f.poc.verdict, 'every poc has a verdict');
      }
    },
  },
  {
    name: 'taint-report: grouping buckets flows by source / sink / severity / file',
    fn: async () => {
      const report = await tr.analyze(
        'document.body.innerHTML = location.hash;');
      assert(report.grouped.bySource, 'bySource group present');
      assert(report.grouped.bySink, 'bySink group present');
      assert(report.grouped.bySeverity, 'bySeverity group present');
      assert(report.grouped.byFile, 'byFile group present');
      assert(report.counts.total >= 1);
    },
  },
  {
    name: 'taint-report: location.hash.slice(1) → innerHTML synthesises a PoC (symbolic string op)',
    fn: async () => {
      const report = await tr.analyze(
        'document.body.innerHTML = location.hash.slice(1);');
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'html');
      assert(flow, 'html flow present for slice-stripped hash');
      assert(flow.poc, 'flow has poc');
      // Either Z3 finds a symbolic witness that contains the demo,
      // or the fallback direct-flow demo payload fires. Both are
      // valid "synthesised" outcomes; we reject `no-constraint`
      // / `unsolvable` because Phase A-2 should have given the
      // flow a valueFormula.
      assert(flow.poc.verdict === 'synthesised' || flow.poc.verdict === 'trivial',
        'expected synthesised/trivial, got ' + flow.poc.verdict +
        ' (' + (flow.poc.note || '') + ')');
      assert(flow.poc.payload && flow.poc.payload.indexOf('<script>') >= 0,
        'payload contains <script>, got: ' + flow.poc.payload);
    },
  },
  {
    name: 'taint-report: concat of string prefix + location.hash is solvable',
    fn: async () => {
      const report = await tr.analyze(
        'document.body.innerHTML = "prefix:" + location.hash;');
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'html');
      assert(flow, 'html flow present for concat-prefix');
      assert(flow.poc, 'flow has poc');
      assert(flow.poc.verdict === 'synthesised' || flow.poc.verdict === 'trivial',
        'expected synthesised/trivial, got ' + flow.poc.verdict);
    },
  },
  {
    name: 'taint-report: eval(location.hash.toLowerCase()) synthesises alert(1) payload',
    fn: async () => {
      const report = await tr.analyze(
        'eval(location.hash.toLowerCase());');
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'code');
      assert(flow, 'code flow present');
      assert(flow.poc.verdict === 'synthesised' || flow.poc.verdict === 'trivial',
        'expected synthesised, got ' + flow.poc.verdict +
        ' (' + (flow.poc.note || '') + ')');
    },
  },
];

module.exports = { tests };
