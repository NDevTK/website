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

  // --- TypeDB return-type resolution (G3) ---
  //
  // createElement and getElementById return typed values via
  // the TypeDB's `returnType` field. Subsequent property access
  // resolves through the returned type's prop descriptors.
  {
    name: 'G3: createElement("iframe") → iframe.src is url sink',
    fn: async () => {
      const flows = await flowsFor(
        'var f = document.createElement("iframe"); f.src = location.hash;'
      );
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'url');
      assertEqual(sinkPropOf(flows[0]), 'src');
    },
  },
  {
    name: 'G3: createElement("script") → script.src is url sink',
    fn: async () => {
      const flows = await flowsFor(
        'var s = document.createElement("script"); s.src = location.hash;'
      );
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'url');
    },
  },
  {
    name: 'G3: createElement("a") → anchor.href is url sink',
    fn: async () => {
      const flows = await flowsFor(
        'var a = document.createElement("a"); a.href = location.hash;'
      );
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'url');
      assertEqual(sinkPropOf(flows[0]), 'href');
    },
  },
  {
    name: 'G3: createElement("div") → div.innerHTML is html sink',
    fn: async () => {
      const flows = await flowsFor(
        'var d = document.createElement("div"); d.innerHTML = location.hash;'
      );
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'html');
    },
  },
  {
    name: 'G3: getElementById return is typed HTMLElement',
    fn: async () => {
      const flows = await flowsFor(
        'var el = document.getElementById("x"); el.innerHTML = location.hash;'
      );
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'html');
    },
  },
  {
    name: 'G3: querySelector return is typed Element',
    fn: async () => {
      const flows = await flowsFor(
        'document.querySelector(".x").innerHTML = location.hash;'
      );
      assertEqual(flows.length, 1);
      assertEqual(sinkKindOf(flows[0]), 'html');
    },
  },
  {
    name: 'G3: createElement non-sink prop is safe',
    fn: async () => {
      const flows = await flowsFor(
        'var d = document.createElement("div"); d.id = location.hash;'
      );
      // HTMLElement.id has no `sink` field in the TypeDB so
      // assigning to it is not classified as a sink. (Sound:
      // setting an id from a tainted value is not by itself a
      // security hole.)
      assertEqual(flows.length, 0);
    },
  },

  // --- Sanitizer / call-fallback behavior (G5) ---
  //
  // Sanitizers are declared in the TypeDB via `sanitizer: true`
  // (or by simply not having `preservesLabels*` flags — the
  // default behavior is to clear). User functions and unknown
  // callees fall through to the conservative path which
  // propagates ALL argument labels (sound over-approximation).
  {
    name: 'G5: encodeURIComponent clears labels',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = encodeURIComponent(location.hash);'
      );
      assertEqual(flows.length, 0);
    },
  },
  {
    name: 'G5: parseInt clears labels',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = parseInt(location.hash);'
      );
      assertEqual(flows.length, 0);
    },
  },
  {
    name: 'G5: DOMPurify.sanitize clears labels',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = DOMPurify.sanitize(location.hash);'
      );
      assertEqual(flows.length, 0);
    },
  },
  {
    name: 'G5: decodeURIComponent does NOT clear (not a sanitizer)',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = decodeURIComponent(location.hash);'
      );
      assertEqual(flows.length, 1);
    },
  },
  {
    name: 'G5: String.slice preserves taint via receiver flag',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = location.hash.slice(1);'
      );
      assertEqual(flows.length, 1);
    },
  },
  {
    name: 'G5: String.toLowerCase preserves taint',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = location.hash.toLowerCase();'
      );
      assertEqual(flows.length, 1);
    },
  },
  {
    name: 'G5: String.replace preserves taint',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = location.hash.replace("a", "b");'
      );
      assertEqual(flows.length, 1);
    },
  },
  {
    name: 'G5: user wrapper conservatively propagates labels',
    fn: async () => {
      // function id(s) { return s; } is a user-defined wrapper.
      // The engine doesn't yet walk callee bodies (Phase C), so
      // applyCall falls through to the conservative path which
      // assumes ANY argument label could flow to the return.
      // Soundness wins: report the flow.
      const flows = await flowsFor(
        'function id(s) { return s; } document.body.innerHTML = id(location.hash);'
      );
      assertEqual(flows.length, 1);
    },
  },
  {
    name: 'G5: concat with sanitized still produces no flow',
    fn: async () => {
      const flows = await flowsFor(
        'document.body.innerHTML = "safe-" + encodeURIComponent(location.hash);'
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
