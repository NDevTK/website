// destructure.test.js — Wave 5.2 + 5.3 regression coverage.
//
// Wave 5.2 + 5.3 lands:
//   * Destructuring patterns in var/let/const declarations
//     and in function parameters (ObjectPattern, ArrayPattern,
//     AssignmentPattern for defaults, RestElement for rest).
//   * Default parameters `function f(x = 1)`.
//   * Rest parameters `function f(...args)`.
//   * Spread arguments `f(...args)` — conservative opaque.
//   * Array and object literals with precise field tracking.
//   * Object shorthand properties and computed keys (computed
//     keys fall through to opaque).
//
// The IR builder desugars destructuring into a sequence of
// GetProp / GetIndex instructions + leaf-identifier bindings
// via a shared bindDestructuringTarget helper that recurses
// over nested patterns.
//
// Object / array literals lower to an ALLOC instruction with
// the fields map pre-populated so downstream reads can pick
// up per-field taint precisely.
//
// Shared-heap inter-procedural calls: the callee's initial
// state now overlays the caller's heap so an ObjectRef passed
// as an argument can be dereferenced by the callee's
// destructuring pattern.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- Array / object literals ---
  {
    name: 'Wave5: object literal tracks per-field taint',
    fn: async () => {
      const t = await analyze(
        'var o = {a: location.hash, b: "safe"}; document.body.innerHTML = o.a;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5: object literal safe field → no flow',
    fn: async () => {
      const t = await analyze(
        'var o = {a: location.hash, b: "safe"}; document.body.innerHTML = o.b;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave5: object literal shorthand property',
    fn: async () => {
      const t = await analyze(
        'var a = location.hash; var o = {a}; document.body.innerHTML = o.a;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5: array literal tracks index taint',
    fn: async () => {
      const t = await analyze(
        'var arr = [location.hash, "safe"]; document.body.innerHTML = arr[0];',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },

  // --- Var destructuring ---
  {
    name: 'Wave5: object destructuring var binds fields',
    fn: async () => {
      const t = await analyze(
        'var o = {a: location.hash, b: "safe"}; var {a, b} = o; document.body.innerHTML = a;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5: object destructuring with rename',
    fn: async () => {
      const t = await analyze(
        'var o = {a: location.hash}; var {a: renamed} = o; document.body.innerHTML = renamed;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5: array destructuring var binds elements',
    fn: async () => {
      const t = await analyze(
        'var arr = [location.hash, "safe"]; var [x, y] = arr; document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5: array destructuring with hole',
    fn: async () => {
      const t = await analyze(
        'var arr = ["safe", location.hash]; var [, y] = arr; document.body.innerHTML = y;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },

  // --- Destructuring parameters ---
  {
    name: 'Wave5: object destructuring parameter',
    fn: async () => {
      const t = await analyze(
        'function f({a}) { document.body.innerHTML = a; } f({a: location.hash});',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5: array destructuring parameter',
    fn: async () => {
      const t = await analyze(
        'function f([a, b]) { document.body.innerHTML = a; } f([location.hash, 1]);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },

  // --- Default / rest parameters ---
  {
    name: 'Wave5: default parameter parses',
    fn: async () => {
      const t = await analyze(
        'function f(x = 1) { return x; } var y = f();',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5: rest parameter parses',
    fn: async () => {
      const t = await analyze(
        'function f(...args) { return args; } var y = f(1, 2, 3);',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },

  // --- Spread arguments ---
  {
    name: 'Wave5: spread arg in call falls back to opaque',
    fn: async () => {
      const t = await analyze(
        'function f(a, b) { return a + b; } var arr = [1, 2]; var y = f(...arr);',
        { typeDB: TDB });
      // No crash; the call returns an opaque value (we don't
      // know the expanded arity precisely).
      assertEqual(t.partial, false);
    },
  },
];

module.exports = { tests };
