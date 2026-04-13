// source-classification.test.js — end-to-end tests that the
// TypeDB is wired into the GetGlobal / GetProp transfer
// functions and produces the right labels + assumption reason
// codes.

'use strict';

const { analyze, query } = require('../src/index.js');
const db = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

async function analyzeWithDB(code) {
  return analyze(code, { typeDB: db, taint: true });
}

// Find the first binding whose value has a non-empty label set.
function firstTaintedBinding(trace) {
  for (const name in trace.bindings) {
    const v = trace.bindings[name];
    if (v.labels && v.labels.size && v.labels.size > 0) {
      return { name, value: v };
    }
  }
  return null;
}

// Return the sorted list of reason codes the trace raised.
function reasons(trace) {
  return trace.assumptions.map(a => a.reason).sort();
}

const tests = [
  {
    name: 'location.hash raises attacker-input and tags with url label',
    fn: async () => {
      const trace = await analyzeWithDB('var x = location.hash;');
      const reasonsSet = new Set(reasons(trace));
      assert(reasonsSet.has('attacker-input'),
        'expected attacker-input, got: ' + JSON.stringify([...reasonsSet]));
      const tainted = firstTaintedBinding(trace);
      assert(tainted, 'expected at least one tainted binding');
      const labels = Array.from(tainted.value.labels || []);
      assert(labels.includes('url'),
        'expected url label, got: ' + JSON.stringify(labels));
    },
  },
  {
    name: 'location.search raises attacker-input',
    fn: async () => {
      const trace = await analyzeWithDB('var q = location.search;');
      assert(reasons(trace).includes('attacker-input'));
    },
  },
  {
    name: 'document.cookie raises persistent-state',
    fn: async () => {
      const trace = await analyzeWithDB('var c = document.cookie;');
      const r = reasons(trace);
      assert(r.includes('persistent-state'),
        'expected persistent-state, got: ' + JSON.stringify(r));
    },
  },
  {
    name: 'document.referrer raises attacker-input',
    fn: async () => {
      const trace = await analyzeWithDB('var r = document.referrer;');
      assert(reasons(trace).includes('attacker-input'));
    },
  },
  {
    name: 'localStorage raises persistent-state (selfSource)',
    fn: async () => {
      // Bare localStorage read. The Storage type carries
      // `selfSource: 'storage'` so reading the bare binding is
      // already labeled.
      const trace = await analyzeWithDB('var s = localStorage;');
      const r = reasons(trace);
      assert(r.includes('persistent-state'),
        'expected persistent-state, got: ' + JSON.stringify(r));
    },
  },
  {
    name: 'document.body does NOT raise a source assumption',
    fn: async () => {
      const trace = await analyzeWithDB('var el = document.body;');
      // document.body is a typed navigation (returns HTMLElement)
      // but carries no source label. The only assumption allowed
      // here is the implicit unimplemented for unmodeled
      // constructs, which shouldn't fire for plain var decls.
      const sourceKinds = new Set([
        'attacker-input',
        'persistent-state',
        'network',
        'ui-interaction',
        'dom-state',
        'environmental',
      ]);
      for (const a of trace.assumptions) {
        assert(!sourceKinds.has(a.reason),
          'document.body should not raise a source assumption, got: ' + a.reason);
      }
    },
  },
  {
    name: 'Math.PI does NOT raise a source assumption',
    fn: async () => {
      const trace = await analyzeWithDB('var pi = Math.PI;');
      const sourceKinds = new Set([
        'attacker-input', 'persistent-state', 'network', 'ui-interaction',
      ]);
      for (const a of trace.assumptions) {
        assert(!sourceKinds.has(a.reason),
          'Math.PI should not raise a source assumption, got: ' + a.reason);
      }
    },
  },
  {
    name: 'unknown global raises opaque-call',
    fn: async () => {
      const trace = await analyzeWithDB('var x = someGlobalThing;');
      assert(reasons(trace).includes('opaque-call'));
    },
  },
  {
    name: 'window.location.hash chains through two type resolutions',
    fn: async () => {
      // window → Window type; .location → Location type; .hash
      // → String with source label.
      const trace = await analyzeWithDB('var h = window.location.hash;');
      const r = reasons(trace);
      assert(r.includes('attacker-input'),
        'expected attacker-input, got: ' + JSON.stringify(r));
      const tainted = firstTaintedBinding(trace);
      assert(tainted);
      const labels = Array.from(tainted.value.labels || []);
      assert(labels.includes('url'));
    },
  },
  {
    name: 'assumption chain: chained source read records upstream id',
    fn: async () => {
      const trace = await analyzeWithDB('var x = location.hash;');
      // The hash read's assumption should list the location
      // read's assumption in its chain field.
      const chainedAssumptions = trace.assumptions.filter(a => a.chain.length > 0);
      assert(chainedAssumptions.length > 0,
        'expected at least one chained assumption, got: ' +
        JSON.stringify(trace.assumptions.map(a => ({ id: a.id, chain: a.chain }))));
    },
  },
  {
    name: 'assumptions have location information',
    fn: async () => {
      const trace = await analyzeWithDB('var x = location.hash;');
      for (const a of trace.assumptions) {
        assert(a.location, 'every assumption should have a location');
        assert(a.location.file, 'every assumption should have a file');
      }
    },
  },
];

module.exports = { tests };
