// wave10.test.js — B4 (multi-variant worklist) regression coverage.
//
// Wave 10 lifts the worklist from a single in-state per block
// to a set of variants per block. Each variant is a full State
// with its own pathCond. Joins at merge points preserve variant
// identity (same predecessor) rather than collapsing to a
// pointwise join, so cross-register correlation survives merges:
//
//   if (c) { x = 1; y = "a"; } else { x = 2; y = "b"; }
//   if (x === 1) { sink(y); }
//
// Under the old pointwise-joined state, y = oneOf("a","b") in
// the merge, the `x === 1` refines x but not y, and a sink on y
// fires with a joined-in "b" that the x===1 path can never
// actually see. Wave 10 keeps the two branches as distinct
// variants, so refining x to 1 eliminates the x=2 variant
// entirely — the y="b" shape disappears with it and the sink
// doesn't fire.
//
// Back-edge widening at loop headers collapses per-iteration
// variants into a single widening variant so loops still
// terminate in reasonable time (a 1000-iteration counter loop
// must not spawn 1000 variants).

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- Cross-register correlation through if/else merges ---
  {
    name: 'Wave10: correlated (kind, data) — safe branch has no flow',
    fn: async () => {
      const t = await analyze(
        'var x, y;' +
        'if (location.hash === "a") { x = 1; y = "clean"; }' +
        'else                        { x = 2; y = location.search; }' +
        'if (x === 1) { document.body.innerHTML = y; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0,
        'x===1 eliminates the x=2 variant; only the clean y survives');
    },
  },
  {
    name: 'Wave10: correlated (kind, data) — dirty branch still fires',
    fn: async () => {
      const t = await analyze(
        'var x, y;' +
        'if (location.hash === "a") { x = 1; y = "clean"; }' +
        'else                        { x = 2; y = location.search; }' +
        'if (x === 2) { document.body.innerHTML = y; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1,
        'x===2 keeps the tainted y variant; sink fires');
    },
  },
  {
    name: 'Wave10: 3-way merge — kind==="safe" has no flow',
    fn: async () => {
      const t = await analyze(
        'var kind, data;' +
        'if (location.hash === "a") { kind = "safe"; data = "clean1"; }' +
        'else if (location.hash === "b") { kind = "dirty"; data = location.search; }' +
        'else { kind = "safe"; data = "clean2"; }' +
        'if (kind === "safe") { document.body.innerHTML = data; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0,
        'nested if/else preserves correlation through both merge points');
    },
  },
  {
    name: 'Wave10: 3-way merge — kind==="dirty" fires',
    fn: async () => {
      const t = await analyze(
        'var kind, data;' +
        'if (location.hash === "a") { kind = "safe"; data = "clean1"; }' +
        'else if (location.hash === "b") { kind = "dirty"; data = location.search; }' +
        'else { kind = "safe"; data = "clean2"; }' +
        'if (kind === "dirty") { document.body.innerHTML = data; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave10: uncorrelated sink still fires (sanity)',
    fn: async () => {
      // No refinement in front of the sink → both variants
      // contribute and the tainted y variant produces a flow.
      const t = await analyze(
        'var x, y;' +
        'if (location.hash === "a") { x = 1; y = "clean"; }' +
        'else                        { x = 2; y = location.search; }' +
        'document.body.innerHTML = y;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1,
        'no refinement → tainted variant still fires');
    },
  },
  {
    name: 'Wave10: per-variant pathFormula on the surviving flow',
    fn: async () => {
      const t = await analyze(
        'var x, y;' +
        'if (location.hash === "a") { x = 1; y = "clean"; }' +
        'else                        { x = 2; y = location.search; }' +
        'if (x === 2) { document.body.innerHTML = y; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
      const f = t.taintFlows[0];
      // pathFormula should mention the hash===a branch being
      // FALSE (x = 2 reachability) and x===2 being TRUE.
      // Wave 10 propagates these as a conjunction via variant
      // pathConds.
      assert(f.pathFormula, 'flow has pathFormula');
      const e = f.pathFormula.expr;
      assert(/hash/.test(e), 'pathFormula references the source: ' + e);
    },
  },

  // --- Loop termination / widening ---
  {
    name: 'Wave10: 1000-iteration counter loop terminates',
    fn: async () => {
      // This is the back-edge widening stress test. Without
      // widening at loop headers, each iteration would spawn a
      // new variant with a distinct x value, blowing the
      // variant count to 1000 and making analysis take ~100s.
      // With back-edge widening the per-iteration variants
      // collapse into a single widening variant and the loop
      // converges in a few milliseconds.
      const start = Date.now();
      const t = await analyze(
        'var x = 0; while (x < 1000) { x = x + 1; }',
        { typeDB: TDB });
      const elapsed = Date.now() - start;
      assertEqual(t.partial, false);
      assert(elapsed < 2000, '1000-iter loop must converge in <2s, took ' + elapsed + 'ms');
    },
  },
  {
    name: 'Wave10: loop with in-body tainted sink still fires',
    fn: async () => {
      const t = await analyze(
        'for (var i = 0; i < 10; i++) { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assert(t.taintFlows.length >= 1, 'loop-body sink fires');
    },
  },

  // --- Existing e2e paths remain unaffected ---
  {
    name: 'Wave10: simple tainted sink still fires (no regression)',
    fn: async () => {
      const t = await analyze(
        'document.body.innerHTML = location.hash;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave10: concrete-true branch still prunes dead successor',
    fn: async () => {
      const t = await analyze(
        'if (true) { document.body.innerHTML = location.hash; } else { document.body.innerHTML = "safe"; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1,
        'true branch is taken; only the tainted sink is reachable');
    },
  },
];

module.exports = { tests };
