// scope.test.js — Wave 2 regression coverage for JS scope rules.
//
// Wave 2 introduces:
//   * Frame kinds (function vs block) so `var` finds the nearest
//     function frame and `let`/`const` bind in the innermost frame.
//   * Binding kinds (var / let / const / function / param).
//   * Hoisting pre-pass that walks each function body (and the
//     top-level program) for `var` and `function` declarations
//     and pre-emits their initial bindings at the entry block.
//     This makes `f(); function f(){}` and `x = 1; var x = 2`
//     correct.
//   * Block-scoping for let/const via pushBlockFrame/popFrame
//     around every BlockStatement.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { buildModule, OP } = require('../src/ir.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- var hoisting ---
  {
    name: 'Wave2: var reference before declaration is hoisted',
    fn: async () => {
      // `x = 1` at the top must bind to the hoisted x; the later
      // `var x = 2` updates the same hoisted binding rather than
      // creating a new one. Analysis must not raise an
      // opaque-call for an unresolved `x`.
      const t = await analyze('x = 1; var x = 2;', { typeDB: TDB });
      const unresolved = t.assumptions.filter(
        a => a.reason === 'opaque-call' &&
             (a.details || a.message || '').includes('x'));
      assertEqual(unresolved.length, 0,
        'x should be hoisted, not unresolved');
    },
  },
  {
    name: 'Wave2: var inside nested block is function-scoped',
    fn: async () => {
      const t = await analyze(
        '{ var x = location.hash; } document.body.innerHTML = x;',
        { typeDB: TDB });
      // var x survives the block_exit because var is
      // function-scoped.
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave2: var inside if is function-scoped',
    fn: async () => {
      // `var` inside an if's consequent is hoisted to the
      // function scope and visible after the if.
      const t = await analyze(
        'if (true) { var x = location.hash; } document.body.innerHTML = x;',
        { typeDB: TDB });
      assert(t.taintFlows.length >= 1);
    },
  },

  // --- function hoisting ---
  {
    name: 'Wave2: function called before declaration (top-level)',
    fn: async () => {
      const t = await analyze(
        'f(); function f() { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave2: function hoisting inside another function',
    fn: async () => {
      const t = await analyze(
        'function outer() { inner(); function inner() { document.body.innerHTML = location.hash; } } outer();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave2: function declaration module contains exactly one inner fn',
    fn: () => {
      // Ensure hoisting does not double-create the function.
      // Before Wave 2 this test would pass accidentally because
      // lowerFunctionDecl ran once; after adding hoisting we
      // must skip the second lowering via _hoistedFnNodes.
      const m = buildModule('f(); function f() { return 1; } f();', 'a.js');
      const fFuncs = m.functions.filter(fn => fn.name === 'f');
      assertEqual(fFuncs.length, 1, 'exactly one function named f');
    },
  },

  // --- let / const parsing + block scoping ---
  {
    name: 'Wave2: let declaration parses and binds',
    fn: async () => {
      const t = await analyze('let x = "hi"; var y = x;', { typeDB: TDB });
      assertEqual(t.partial, false);
      // Should NOT raise an opaque-call for x.
      const unresolved = t.assumptions.filter(
        a => a.reason === 'opaque-call');
      assertEqual(unresolved.length, 0);
    },
  },
  {
    name: 'Wave2: const declaration parses and binds',
    fn: async () => {
      const t = await analyze('const x = "hi"; var y = x;', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave2: let is block-scoped (invisible after block exit)',
    fn: async () => {
      // `let x = location.hash` inside a block should NOT survive
      // the block_exit. The outer `y = x` reference resolves to
      // an unknown global → raises opaque-call.
      const t = await analyze(
        '{ let x = location.hash; } var y = x;',
        { typeDB: TDB });
      const unresolved = t.assumptions.filter(a => a.reason === 'opaque-call');
      assert(unresolved.length >= 1,
        'expected opaque-call for out-of-scope let, got ' + unresolved.length);
    },
  },
  {
    name: 'Wave2: const is block-scoped',
    fn: async () => {
      const t = await analyze(
        '{ const x = 1; } var y = x;',
        { typeDB: TDB });
      const unresolved = t.assumptions.filter(a => a.reason === 'opaque-call');
      assert(unresolved.length >= 1);
    },
  },
  {
    name: 'Wave2: let in inner block shadows var in outer scope',
    fn: async () => {
      // Inside the block, `x` refers to the let; outside, the var.
      const t = await analyze(
        'var x = "outer"; { let x = "inner"; var innerRef = x; } var outerRef = x;',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },

  // --- sanity: no regression on function body lowering ---
  {
    name: 'Wave2: parameter binding works alongside hoisting',
    fn: async () => {
      const t = await analyze(
        'function f(x) { return x + 1; } var y = f(location.hash);',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
];

module.exports = { tests };
