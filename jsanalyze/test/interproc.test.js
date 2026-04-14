// interproc.test.js — Phase C1 regression coverage.
//
// C1 walks user function calls inter-procedurally:
//   * applyCall now detects when the callee is a Closure
//     pointing to a user function in the module, then walks
//     the callee's CFG with the caller's argument values
//     bound to its params.
//   * The callee's exit state contributes its return value(s)
//     to the call site.
//   * Sinks that fire inside the callee are appended to the
//     shared ctx.taintFlows.
//   * Recursive calls (callee already on _callStack) fall
//     back to opaque + an unimplemented assumption.
//
// These tests exercise behaviour that was previously
// over-approximated to "opaque call inherits all arg labels".

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'C1: function passing tainted arg to sink fires flow',
    fn: async () => {
      const t = await analyze(
        'function leak(x) { document.body.innerHTML = x; } leak(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'expected 1 cross-function flow');
      assertEqual(t.taintFlows[0].source[0].label, 'url');
      assertEqual(t.taintFlows[0].sink.kind, 'html');
    },
  },
  {
    name: 'C1: function discarding arg and returning constant blocks flow',
    fn: async () => {
      // The function ignores its argument and returns a static
      // string. C1 should walk the body and see the return value
      // is provably untainted.
      const t = await analyze(
        'function safe(x) { return "static"; } ' +
        'document.body.innerHTML = safe(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0, 'function returns clean → no flow');
    },
  },
  {
    name: 'C1: identity function preserves taint',
    fn: async () => {
      const t = await analyze(
        'function id(x) { return x; } ' +
        'document.body.innerHTML = id(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'id function preserves taint');
    },
  },
  {
    name: 'C1: function with branched return — tainted path produces flow',
    fn: async () => {
      // One branch returns the tainted arg, the other returns
      // a clean string. The join must preserve the taint label.
      const t = await analyze(
        'function check(x) { if (x === "admin") return x; return "ok"; } ' +
        'document.body.innerHTML = check(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'branched return joins taint');
    },
  },
  {
    name: 'C1: function with both branches clean → no flow',
    fn: async () => {
      // Both branches return concrete clean strings — the
      // tainted argument never reaches a sink even though it
      // drives the branch.
      const t = await analyze(
        'function check(x) { if (x === "admin") return "evil"; return "ok"; } ' +
        'document.body.innerHTML = check(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0, 'no path returns the taint');
    },
  },
  {
    name: 'C1: nested function calls (a calls b which sinks)',
    fn: async () => {
      const t = await analyze(
        'function inner(y) { document.body.innerHTML = y; } ' +
        'function outer(x) { inner(x); } ' +
        'outer(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'nested call propagates taint');
    },
  },
  {
    name: 'C1: function with multiple returns joined',
    fn: async () => {
      // Two explicit returns; the join is the value used at
      // the call site.
      const t = await analyze(
        'function pick(x, y) { if (x === "a") return x; return y; } ' +
        'document.body.innerHTML = pick(location.hash, location.search);',
        { typeDB: TDB });
      // Both possible returns are tainted, so the flow fires.
      assertEqual(t.taintFlows.length, 1, 'multi-return join carries taint');
    },
  },
  {
    name: 'C1: function called with a clean arg → no flow even if it sinks',
    fn: async () => {
      // The function blindly sinks its arg, but the caller
      // passes a static literal. No flow expected.
      const t = await analyze(
        'function sink(x) { document.body.innerHTML = x; } sink("static");',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0, 'static arg → no taint');
    },
  },
  {
    name: 'C1: same function called twice with different arg shapes',
    fn: async () => {
      // First call clean, second call tainted. We expect 1 flow
      // (from the tainted call). This verifies that walking the
      // function twice with different states doesn't leak taint
      // backwards.
      const t = await analyze(
        'function maybeSink(x) { document.body.innerHTML = x; } ' +
        'maybeSink("clean"); ' +
        'maybeSink(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1,
        'only the tainted call fires; clean call is fine');
    },
  },
  {
    name: 'C1: recursion detected via _callStack raises unimplemented',
    fn: async () => {
      // With closure captures (Wave 8b), the inner reference to
      // `rec` resolves precisely — it's the same function the
      // caller is currently analysing. applyCall's _callStack
      // guard detects the cycle and conservatively unions all
      // argument labels into the return, raising an explicit
      // `unimplemented: recursive call` assumption so the
      // imprecision is auditable.
      const t = await analyze(
        'function rec(x) { return rec(x); } ' +
        'document.body.innerHTML = rec(location.hash);',
        { typeDB: TDB });
      // The fallback keeps the url label so the sink still
      // fires.
      assert(t.taintFlows.length >= 1, 'fallback flow expected');
      // The recursion-fallback assumption lives under
      // `unimplemented`.
      const unimpl = t.assumptions.filter(
        a => a.reason === 'unimplemented' &&
             /recursive call/.test(a.details || ''));
      assert(unimpl.length >= 1, 'expected recursive-call unimplemented assumption');
    },
  },
];

module.exports = { tests };
