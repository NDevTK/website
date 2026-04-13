// sink-classification.test.js — end-to-end tests that
// tainted values reaching sinks produce TaintFlow records
// with the expected source / sink / severity / labels.

'use strict';

const { analyze } = require('../src/index.js');
const db = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

async function flowsFor(code) {
  const trace = await analyze(code, { typeDB: db, taint: true });
  return trace.taintFlows;
}

function sinkKindOf(flow) { return flow.sink.kind; }
function sinkPropOf(flow) { return flow.sink.prop; }
function sourceLabelsOf(flow) { return flow.source.map(s => s.label).sort(); }

const tests = [
  // --- HTML sinks ---
  {
    name: 'SetProp: element.innerHTML = location.hash',
    fn: async () => {
      const flows = await flowsFor('document.body.innerHTML = location.hash;');
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'html');
      assertEqual(sinkPropOf(flows[0]), 'innerHTML');
      assertEqual(flows[0].severity, 'high');
      assert(sourceLabelsOf(flows[0]).includes('url'));
    },
  },
  {
    name: 'SetProp: flow through intermediate variable',
    fn: async () => {
      const flows = await flowsFor(
        'var x = location.hash; document.body.innerHTML = x;'
      );
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'html');
    },
  },
  {
    name: 'Call: document.write(tainted) is html sink',
    fn: async () => {
      const flows = await flowsFor(
        'var x = location.hash; document.write(x);'
      );
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'html');
      assertEqual(sinkPropOf(flows[0]), 'write.arg0');
    },
  },

  // --- Code sinks ---
  {
    name: 'Call: eval(tainted) is code sink',
    fn: async () => {
      const flows = await flowsFor('eval(location.hash);');
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'code');
      assertEqual(flows[0].severity, 'high');
    },
  },
  {
    name: 'Call: eval(cookie) carries cookie label',
    fn: async () => {
      const flows = await flowsFor(
        'var c = document.cookie; eval(c);'
      );
      assertEqual(flows.length, 1);
      assert(sourceLabelsOf(flows[0]).includes('cookie'));
    },
  },

  // --- Navigation sinks ---
  {
    name: 'SetProp: location.href = tainted is navigation',
    fn: async () => {
      const flows = await flowsFor('location.href = location.hash;');
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'navigation');
      assertEqual(sinkPropOf(flows[0]), 'href');
    },
  },

  // --- Negative cases ---
  {
    name: 'No flow: untainted string assignment',
    fn: async () => {
      const flows = await flowsFor(
        'var safe = "hello"; document.body.innerHTML = safe;'
      );
      assertEqual(flows.length, 0);
    },
  },
  {
    name: 'No flow: plain var assignment',
    fn: async () => {
      const flows = await flowsFor('var x = 1;');
      assertEqual(flows.length, 0);
    },
  },
  {
    name: 'No flow: Math.PI read',
    fn: async () => {
      const flows = await flowsFor('var pi = Math.PI;');
      assertEqual(flows.length, 0);
    },
  },

  // --- Label propagation ---
  {
    name: 'Label: referrer label propagates',
    fn: async () => {
      const flows = await flowsFor(
        'var r = document.referrer; document.write(r);'
      );
      assertEqual(flows.length, 1);
      assert(sourceLabelsOf(flows[0]).includes('referrer'));
    },
  },
  {
    name: 'Label: window.location.hash carries url',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = window.location.hash;'
      );
      assertEqual(flows.length, 1);
      assert(sourceLabelsOf(flows[0]).includes('url'));
    },
  },
  // --- BinOp label propagation (G2) ---
  {
    name: 'BinOp: concat with tainted right operand',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = "<a>" + location.hash + "</a>";'
      );
      assertEqual(flows.length, 1);
      assert(sourceLabelsOf(flows[0]).includes('url'));
    },
  },
  {
    name: 'BinOp: concat with tainted left operand',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = location.hash + "_suffix";'
      );
      assertEqual(flows.length, 1);
      assert(sourceLabelsOf(flows[0]).includes('url'));
    },
  },
  {
    name: 'BinOp: concat through intermediate variable',
    fn: async () => {
      const flows = await flowsFor(
        'var a = location.hash; var b = a + "x"; document.body.innerHTML = b;'
      );
      assertEqual(flows.length, 1);
      assert(sourceLabelsOf(flows[0]).includes('url'));
    },
  },
  {
    name: 'BinOp: empty-string concat does not lose taint',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = location.hash + "";'
      );
      assertEqual(flows.length, 1);
    },
  },
  {
    name: 'BinOp: nested concat in eval',
    fn: async () => {
      const flows = await flowsFor(
        'eval("alert(" + document.cookie + ")");'
      );
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'code');
      assert(sourceLabelsOf(flows[0]).includes('cookie'));
    },
  },
  {
    name: 'BinOp: untainted concat produces no flow',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = "<a>" + "hi" + "</a>";'
      );
      assertEqual(flows.length, 0);
    },
  },

  // --- TaintFlow shape ---
  {
    name: 'TaintFlow records have stable ids',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = location.hash;' +
        'document.body.outerHTML = document.cookie;'
      );
      assertEqual(flows.length, 2);
      const ids = new Set(flows.map(f => f.id));
      assertEqual(ids.size, 2, 'ids should be unique');
    },
  },
  {
    name: 'TaintFlow records have assumption ids',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = location.hash;'
      );
      assertEqual(flows.length, 1);
      assert(Array.isArray(flows[0].assumptionIds));
      assert(flows[0].assumptionIds.length >= 1,
        'should have at least one upstream assumption');
    },
  },
  {
    name: 'TaintFlow records have source locations',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = location.hash;'
      );
      assertEqual(flows.length, 1);
      assert(flows[0].sink.location);
      assert(flows[0].sink.location.file);
      assert(flows[0].source.every(s => s.location && s.location.file));
    },
  },
];

module.exports = { tests };
