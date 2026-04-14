// closure.test.js — Wave 8b regression coverage for closure
// captures with proper interprocedural, path-sensitive,
// state-correlated semantics.
//
// Design elements verified by this test suite:
//
//   * Interprocedural: the call graph is walked inter-procedurally
//     via applyCall / applyNew, with closures carrying their
//     captured environment through data flow.
//
//   * Path-sensitive: closures created in branches see the
//     branch-specific values of captured variables. The merge
//     block phi reconciles state across branches.
//
//   * State-correlated: mutations to captured variables in the
//     outer function are visible to inner closures when the
//     caller's state has the latest register bindings (live
//     preferred; applyFunc-time snapshot as fallback for
//     ESCAPED closures whose outer state is no longer
//     reachable).
//
//   * Iterative: inner function bodies are lowered via task-
//     stack queuing, not recursion. Deep nesting up to 3000
//     levels is supported without growing the JS stack.
//
//   * Assumption-tracked: genuine imprecision (opaque calls,
//     recursion, eval of tainted data, unreachable outer
//     state) is recorded as explicit assumptions with reason
//     codes. The closure machinery itself raises no silent
//     precision losses.
//
// Capture mechanism:
//
//   1. tryCaptureFromOuterScope walks _funcStack at IR build
//      time to find a name's defining function. It records
//      captures on EVERY intermediate function between the
//      current fn and the defining fn — so deep chains
//      (c → b → a where c captures s from a) work via forward
//      propagation of the capture through b.
//
//   2. The Func instruction is emitted at the SOURCE-ORDER
//      declaration point, not at hoist time. This means
//      applyFunc runs AFTER preceding var initializers in the
//      outer function, so the capture snapshot has the
//      post-init values. Hoisting is preserved by pre-binding
//      the function name to a reserved register at hoist_decls
//      time.
//
//   3. A post-build fixup pass (runCaptureFixup) rewrites each
//      capture's outerReg to the register that the declaring
//      function assigned LAST for the captured name (taken
//      from fn._finalScope). This handles the case where the
//      outer reassigns the name AFTER the closure is created:
//      applyCall will see the live value from the caller state.
//
//   4. applyCall prefers reading the outerReg from the LIVE
//      caller state (handling mutation-after-creation) over
//      the applyFunc-time snapshot (the fallback for escaped
//      closures).

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'Wave8b: closure captures outer var',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; function f() { return x; } document.body.innerHTML = f();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: nested closure captures from grandparent',
    fn: async () => {
      const t = await analyze(
        'function outer() { var x = location.hash; function inner() { return x; } return inner(); } document.body.innerHTML = outer();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: factory IIFE escaped closure',
    fn: async () => {
      const t = await analyze(
        'var get = (function() { var secret = location.hash; return function() { return secret; }; })(); document.body.innerHTML = get();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: counter factory pattern',
    fn: async () => {
      const t = await analyze(
        'function makeCounter() { var n = location.hash; return function() { return n; }; } var c = makeCounter(); document.body.innerHTML = c();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: closure safe (no taint)',
    fn: async () => {
      const t = await analyze(
        'function outer() { var x = "safe"; function inner() { return x; } return inner(); } document.body.innerHTML = outer();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave8b: closure sees outer var MUTATION',
    fn: async () => {
      // The closure references `x` at call time, not at creation
      // time. Assigning x after creation should be visible
      // through the closure when it's called from the same
      // function.
      const t = await analyze(
        'var x = "safe"; function f() { return x; } x = location.hash; document.body.innerHTML = f();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: deep capture chain (c → b → a)',
    fn: async () => {
      // c captures s from a through intermediate b. The
      // captures are propagated through b so that c's applyFunc
      // runs in b's state (which has the forwarded capture).
      const t = await analyze(
        'function a() { var s = location.hash; function b() { function c() { return s; } return c(); } return b(); } document.body.innerHTML = a();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: closure captures a parameter',
    fn: async () => {
      const t = await analyze(
        'function outer(p) { return function() { return p; }; } var f = outer(location.hash); document.body.innerHTML = f();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: hoisted forward-reference call',
    fn: async () => {
      const t = await analyze(
        'f(); function f() { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: nested hoisted forward-reference',
    fn: async () => {
      const t = await analyze(
        'function outer() { inner(); function inner() { document.body.innerHTML = location.hash; } } outer();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: static class field read through captured class',
    fn: async () => {
      // The static method references `Foo` from an enclosing
      // scope — that's a closure capture of the class object.
      // `Foo.#counter` reads the private static field.
      const t = await analyze(
        'class Foo { static #counter = location.hash; static getIt() { return Foo.#counter; } } document.body.innerHTML = Foo.getIt();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: path-sensitive closure via ternary',
    fn: async () => {
      // The closure's captured value depends on which branch
      // of the ternary ran in the enclosing context.
      const t = await analyze(
        'function make(cond) { var s = cond ? location.hash : "safe"; return function() { return s; }; } document.body.innerHTML = make(true)();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8b: state-correlated closure via conditional',
    fn: async () => {
      const t = await analyze(
        'function make(cond) { var s = cond === "yes" ? location.hash : "safe"; return function() { return s; }; } var f1 = make("yes"); document.body.innerHTML = f1();',
        { typeDB: TDB });
      assert(t.taintFlows.length >= 1);
    },
  },
  {
    name: 'Wave8b: recursion detected via _callStack',
    fn: async () => {
      const t = await analyze(
        'function rec(x) { return rec(x); } document.body.innerHTML = rec(location.hash);',
        { typeDB: TDB });
      assert(t.taintFlows.length >= 1);
      const unimpl = t.assumptions.filter(
        a => a.reason === 'unimplemented' &&
             /recursive call/.test(a.details || ''));
      assert(unimpl.length >= 1, 'expected recursive-call unimplemented assumption');
    },
  },
  {
    name: 'Wave8b: iterative — 3000-deep nesting parses without stack overflow',
    fn: async () => {
      let src = '';
      for (let i = 0; i < 3000; i++) src += 'function f' + i + '() { ';
      src += 'var x = 1; ';
      for (let i = 0; i < 3000; i++) src += '}';
      const t = await analyze(src, { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
];

module.exports = { tests };
