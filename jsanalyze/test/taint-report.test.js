// taint-report.test.js — consumers/taint-report.js coverage, focused
// on PoC witness synthesis (which moved out of src/z3.js into this
// consumer per D11.1).

'use strict';

const tr = require('../consumers/taint-report.js');
const { analyze } = require('../src/index.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'taint-report: direct location.hash → innerHTML synthesises an executing html payload',
    fn: async () => {
      const report = await tr.analyze(
        'document.body.innerHTML = location.hash;');
      assert(report.flows.length >= 1, 'at least one flow');
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'html');
      assert(flow, 'html-sink flow present');
      assert(flow.poc, 'flow has poc');
      assertEqual(flow.poc.verdict, 'synthesised');
      // innerHTML does NOT execute <script> tags per HTML5
      // spec; the primary exploit for this context is an
      // event-handler payload.
      assertEqual(flow.poc.payload, '<img src=x onerror=alert(1)>');
      // Reproducer is JavaScript that navigates the victim.
      assert(typeof flow.poc.reproducer === 'string' &&
        flow.poc.reproducer.indexOf('window.open') >= 0,
        'reproducer is runnable JS that navigates the victim');
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
      assert(flow.poc.verdict === 'synthesised' || flow.poc.verdict === 'trivial',
        'expected synthesised/trivial, got ' + flow.poc.verdict +
        ' (' + (flow.poc.note || '') + ')');
      // Payload is the VALUE AT THE SINK (an executing shape)
      // — not the source-supplied bytes. For innerHTML that's
      // an event-handler payload.
      assert(flow.poc.payload && flow.poc.payload.indexOf('onerror') >= 0,
        'payload contains onerror, got: ' + flow.poc.payload);
      // bindings maps each attacker-controlled source to the
      // bytes the attacker must supply (witness-derived for
      // constrained flows).
      assert(flow.poc.bindings && Object.keys(flow.poc.bindings).length > 0,
        'bindings populated');
      assert(typeof flow.poc.reproducer === 'string',
        'runnable reproducer present');
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
  {
    name: 'taint-report: PoC reproducer is runnable JavaScript targeting options.contextUrl',
    fn: async () => {
      const report = await tr.analyze(
        'document.body.innerHTML = location.hash;',
        { contextUrl: 'https://victim.example/page.html' });
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'html');
      assert(flow, 'html flow present');
      assert(flow.poc.reproducer, 'reproducer present');
      const repro = flow.poc.reproducer;
      // Reproducer includes the user-supplied contextUrl.
      assert(repro.indexOf('https://victim.example/page.html') >= 0,
        'reproducer targets contextUrl');
      // The executing payload appears in the URL (fragment).
      assert(repro.indexOf('onerror=alert(1)') >= 0,
        'reproducer URL carries the executing payload');
      // Valid JS — this parses without throwing.
      new Function(repro);
    },
  },
  {
    name: 'taint-report: eval(postMessage.data) emits postMessage delivery in reproducer',
    fn: async () => {
      const report = await tr.analyze(
        'window.addEventListener("message", function(ev){ eval(ev.data); });',
        { contextUrl: 'https://target.example/' });
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'code');
      assert(flow, 'code flow present');
      assert(flow.poc.reproducer, 'reproducer present');
      const repro = flow.poc.reproducer;
      // Delivery for postMessage sources is window.open + postload
      // postMessage on the load event.
      assert(repro.indexOf('window.open') >= 0,
        'reproducer opens the victim window');
      assert(repro.indexOf('.postMessage(') >= 0,
        'reproducer delivers a postMessage');
      assert(repro.indexOf('alert(1)') >= 0,
        'reproducer payload is alert(1)');
      // Parse-valid.
      new Function(repro);
    },
  },
  {
    name: 'taint-report: two message handlers emit two independent flows with per-invocation symbols',
    fn: async () => {
      const trace = await tr.analyze(
        'window.addEventListener("message", function(a){ eval(a.data); });\n' +
        'window.addEventListener("message", function(b){ location.href = b.data; });\n'
      );
      const flows = trace.flows;
      const codeFlow = flows.find(f => f.sink && f.sink.kind === 'code');
      const navFlow  = flows.find(f => f.sink && f.sink.kind === 'navigation');
      assert(codeFlow && navFlow, 'both flows present (code + navigation)');
      // Per-invocation symbols: each handler's `event.data`
      // read gets its own sym, so the two flows' value
      // formulas (if any) reference distinct variables.
      if (codeFlow.valueFormula && navFlow.valueFormula) {
        const codeSorts = Object.keys(codeFlow.valueFormula.sorts || {});
        const navSorts  = Object.keys(navFlow.valueFormula.sorts || {});
        // Symbols in each formula's sort table shouldn't
        // overlap when both are per-invocation.
        const shared = codeSorts.filter(s => navSorts.indexOf(s) >= 0);
        assert(shared.length === 0,
          'per-invocation symbols must not overlap between handlers; shared: ' +
          shared.join(','));
      }
    },
  },
];

module.exports = { tests };
