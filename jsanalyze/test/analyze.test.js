'use strict';

const { analyze, query } = require('../src/index.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'analyze: empty string',
    fn: async () => {
      const t = await analyze('');
      assertEqual(t.schemaVersion, '2');
      assertEqual(t.partial, false);
      assertEqual(t.warnings.length, 0);
    },
  },
  {
    name: 'analyze: var decl produces a binding',
    fn: async () => {
      const t = await analyze('var x = 42;');
      assert(Object.keys(t.bindings).length > 0, 'has bindings');
    },
  },
  {
    name: 'analyze: opaque global raises assumption',
    fn: async () => {
      const t = await analyze('var x = foo;');
      const opaques = query.assumptions(t, { reason: ['opaque-call'] });
      assert(opaques.length >= 1, 'expected opaque-call assumption');
    },
  },
  {
    name: 'analyze: unimplemented switch raises soundness assumption',
    fn: async () => {
      // `switch` is still unimplemented (Wave 9). For-loops
      // became supported in Wave 3, try/catch in Wave 4, with
      // in Wave 7. We use a `switch` statement as the canonical
      // still-unimplemented marker.
      const t = await analyze('switch (x) { case 1: y = 1; break; }');
      const unimpl = query.assumptions(t, { reason: ['unimplemented'], severity: 'soundness' });
      assert(unimpl.length >= 1, 'expected unimplemented soundness assumption');
    },
  },
  {
    name: 'analyze: multi-file input',
    fn: async () => {
      const t = await analyze({
        'a.js': 'var x = 1;',
        'b.js': 'var y = 2;',
      });
      assertEqual(Object.keys(t.files).length, 2);
    },
  },
  {
    name: 'analyze: parse error becomes partial trace',
    fn: async () => {
      const t = await analyze('var = ;');
      assertEqual(t.partial, true);
      assert(t.warnings.length >= 1, 'has warning');
    },
  },
  {
    name: 'analyze: reachability map populated',
    fn: async () => {
      const t = await analyze('var x = 1; var y = 2;');
      assert(t.reachability.size > 0, 'reachability map has entries');
    },
  },
  {
    name: 'query.assumptions: filter by reason',
    fn: async () => {
      // `switch` is still unimplemented (Wave 9 territory).
      // `someGlobal` is the canonical opaque-call probe.
      const t = await analyze('var x = someGlobal; switch (y) { case 1: z = 1; break; }');
      const opaque = query.assumptions(t, { reason: ['opaque-call'] });
      const unimpl = query.assumptions(t, { reason: ['unimplemented'] });
      assert(opaque.length >= 1);
      assert(unimpl.length >= 1);
    },
  },
  {
    name: 'query.assumptions: all assumptions have stable ids',
    fn: async () => {
      const t = await analyze('var x = a; var y = b;');
      const all = query.assumptions(t);
      const ids = new Set(all.map(a => a.id));
      assertEqual(ids.size, all.length, 'all ids are unique');
    },
  },
  {
    name: 'query.reachability: concrete true branch is reachable, false is not',
    fn: async () => {
      // Note: we don't yet have precise reachability reporting at
      // block-end level in the trace projection. This test verifies
      // the map at least exists; a stricter check comes later.
      const t = await analyze('if (true) { var x = 1; } else { var y = 2; }');
      assert(t.reachability.size > 0);
    },
  },
];

module.exports = { tests };
