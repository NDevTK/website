// modern-js.test.js — Wave 5.4 + 5.5 regression coverage.
//
// Wave 5.4: template literals (`` `hi ${x}` ``) lower to a
// left-folded chain of BinOp('+') string concatenations. The
// existing BinOp transfer handles taint propagation + SMT
// formula construction (str.++) precisely for us, including
// const-folding when all parts are concrete.
//
// Wave 5.5: optional chaining (`a?.b`, `a?.[k]`, `a?.()`)
// desugars to the corresponding regular member / index / call
// with an `optional: true` flag. The lattice already handles
// undefined / null values gracefully so the
// short-circuit-to-undefined is captured via the normal
// transfer-function merge.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- Template literals ---
  {
    name: 'Wave5.4: empty template literal',
    fn: async () => {
      const t = await analyze('var s = ``;', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.4: plain template literal (no interp)',
    fn: async () => {
      const t = await analyze('var s = `hello world`;', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.4: template with single interpolation',
    fn: async () => {
      const t = await analyze('var x = 1; var s = `value is ${x}`;', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.4: tainted expression in template propagates',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; document.body.innerHTML = `<a>${x}</a>`;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5.4: multiple interpolations, single flow',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; document.body.innerHTML = `pre ${x} mid ${x} post`;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5.4: all-concrete template folds',
    fn: async () => {
      const t = await analyze(
        'var s = `foo${1}bar${"qux"}baz`; document.body.innerHTML = s;',
        { typeDB: TDB });
      // No taint — the template folds to a constant.
      assertEqual(t.taintFlows.length, 0);
    },
  },

  // --- Optional chaining ---
  {
    name: 'Wave5.5: `a?.b` parses and lowers',
    fn: async () => {
      const t = await analyze('var a = { b: 1 }; var x = a?.b;', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.5: `a?.[k]` parses and lowers',
    fn: async () => {
      const t = await analyze('var a = [1, 2]; var x = a?.[0];', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.5: `f?.()` parses and lowers',
    fn: async () => {
      const t = await analyze('var f = null; var y = f?.(1, 2);', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.5: optional prop taints through',
    fn: async () => {
      // `location?.hash` still reads the source and flows to the sink.
      const t = await analyze(
        'var l = location; document.body.innerHTML = l?.hash;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5.5: chained optional access',
    fn: async () => {
      const t = await analyze(
        'var x = location?.hash?.length; var y = x;', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
];

module.exports = { tests };
