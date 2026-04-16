// writes.test.js — TypeDB `writes` schema coverage. A method
// descriptor's `writes` array describes heap mutations the
// opaque method performs; applying them lets the analyzer see
// taint flow through opaque-method side effects without a
// full points-to analysis.

'use strict';

const { analyze } = require('../src/index.js');
const DEFAULT = require('../src/default-typedb.js');
const { assert } = require('./run.js');

function makeTypeDB() {
  // Start from the default browser TypeDB so sources (location.hash)
  // and sinks (innerHTML) resolve. Extend with a synthetic `wrap`
  // global that writes arg 1's taint into arg 0's `.data` field.
  const db = {
    types: Object.create(null),
    roots: Object.create(null),
    tagMap: DEFAULT.tagMap,
    eventMap: DEFAULT.eventMap,
  };
  for (const k in DEFAULT.types) db.types[k] = DEFAULT.types[k];
  for (const k in DEFAULT.roots) db.roots[k] = DEFAULT.roots[k];
  db.roots.wrap = 'WrapGlobal';
  db.types.WrapGlobal = {
    call: {
      returnType: 'undefined',
      writes: [
        { target: 'arg:0', field: 'data', taintFromArg: 1 },
      ],
    },
  };
  return db;
}

const tests = [
  {
    name: 'writes: opaque wrapper propagates taint into object field',
    fn: async () => {
      const db = makeTypeDB();
      const trace = await analyze(
        'var c = { data: null };\n' +
        'wrap(c, location.hash);\n' +
        'document.body.innerHTML = c.data;\n',
        { typeDB: db }
      );
      const flows = trace.taintFlows || [];
      const flow = flows.find(f => f.sink && f.sink.prop === 'innerHTML');
      assert(flow, 'innerHTML flow present after wrap(c, location.hash)');
      const hasAttacker = (flow.source || []).some(s => s.label === 'url');
      assert(hasAttacker,
        'flow carries the attacker-input (url) source label, meaning ' +
        'the wrap write-effect propagated the label into c.data');
    },
  },
  {
    name: 'writes: without a writes descriptor, opaque wrapper loses taint (baseline)',
    fn: async () => {
      const db = makeTypeDB();
      // Same wrap but no writes entry — baseline.
      db.types.WrapGlobal = { call: { returnType: 'undefined' } };
      const trace = await analyze(
        'var c = { data: null };\n' +
        'wrap(c, location.hash);\n' +
        'document.body.innerHTML = c.data;\n',
        { typeDB: db }
      );
      const flows = trace.taintFlows || [];
      const flow = flows.find(f => f.sink && f.sink.prop === 'innerHTML');
      // Without writes the analyzer can't see the mutation, so
      // no flow is reported. (This baseline is the counterfactual
      // that justifies the writes schema.)
      assert(!flow,
        'no flow expected when writes are not declared; got ' +
        (flow ? JSON.stringify(flow.sink) : 'none'));
    },
  },
];

module.exports = { tests };
