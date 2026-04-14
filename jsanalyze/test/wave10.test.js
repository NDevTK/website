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
const D = require('../src/domain.js');
const { buildModule } = require('../src/ir.js');
const { analyseFunction } = require('../src/worklist.js');
const { AssumptionTracker } = require('../src/assumptions.js');
const { assert, assertEqual } = require('./run.js');

// Walk a program through analyseFunction and return the module
// plus ctx so tests can inspect per-function state (e.g. the
// C3 summary cache).
async function walk(src) {
  const module = buildModule(src, 'test.js');
  const ctx = {
    module,
    assumptions: new AssumptionTracker(),
    typeDB: TDB,
    nextObjId: 0,
    taintFlows: [],
    nextFlowId: 1,
  };
  await analyseFunction(module, module.top, D.createState(), ctx);
  return { module, ctx };
}

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

  // --- C3: state-correlated function summary cache ---
  {
    name: 'Wave10 C3: identical calls collapse to one cache entry',
    fn: async () => {
      // `id("a")` called three times with identical args — the
      // second and third calls hit the cache and don't walk
      // the body a second time.
      const { module } = await walk(
        'function id(x) { return x + "x"; } ' +
        'var a = id("a"); var b = id("a"); var c = id("a");');
      const fn = module.functions.find(f => f.name === 'id');
      assert(fn._summaryCache, 'id has a summary cache');
      assertEqual(fn._summaryCache.size, 1,
        'three identical calls collapse to one cache entry');
    },
  },
  {
    name: 'Wave10 C3: distinct arg shapes produce distinct cache entries',
    fn: async () => {
      const { module } = await walk(
        'function wrap(x) { return "p:" + x; } ' +
        'var a = wrap("clean1"); var b = wrap("clean2"); var c = wrap("clean1");');
      const fn = module.functions.find(f => f.name === 'wrap');
      // Two distinct arg shapes ("clean1", "clean2") → two
      // cache entries; the third call hits the "clean1" entry.
      assertEqual(fn._summaryCache.size, 2,
        'distinct arg shapes produce distinct cache entries');
    },
  },
  {
    name: 'Wave10 C3: cache-hit call still returns correct taint',
    fn: async () => {
      // The cache reuses the walked body's return shape — if
      // the body launders taint via a prefix concat, the
      // cached return value still carries the argument's
      // labels and the downstream sink still fires.
      const t = await analyze(
        'function wrap(x) { return "p:" + x; } ' +
        'var a = wrap("clean"); ' +
        'var b = wrap(location.hash); ' +
        'document.body.innerHTML = b;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1,
        'tainted second call produces its own summary, not the clean first one');
    },
  },
  {
    name: 'Wave10 C3: state-correlated split across B4 variants',
    fn: async () => {
      // Under B4 the caller splits into two variants (one per
      // if/else branch). Each variant calls `wrap` with a
      // different arg shape. C3 caches per-variant input, so
      // `wrap` gets two distinct summaries — one per caller
      // variant — and the cross-register correlation survives.
      const { module } = await walk(
        'function wrap(x) { return "p:" + x; }' +
        'var y;' +
        'if (location.hash === "a") { y = wrap("clean"); }' +
        'else                        { y = wrap(location.search); }' +
        'document.body.innerHTML = y;');
      const fn = module.functions.find(f => f.name === 'wrap');
      assertEqual(fn._summaryCache.size, 2,
        'two caller variants → two state-correlated summaries');
    },
  },
  {
    name: 'Wave10 C3: recursion still falls through unimpl fallback',
    fn: async () => {
      // The cycle guard (_callStack) fires before the cache
      // check — recursive calls still raise the unimplemented
      // assumption and never cache a self-recursive summary.
      const t = await analyze(
        'function rec(x) { return rec(x); } document.body.innerHTML = rec(location.hash);',
        { typeDB: TDB });
      const unimpl = t.assumptions.filter(
        a => a.reason === 'unimplemented' && /recursive call/.test(a.details || ''));
      assert(unimpl.length >= 1, 'recursion fallback fires');
    },
  },
  {
    name: 'Wave10 C3: 100 identical calls walk the body only once',
    fn: async () => {
      let src = 'function id(x) { return x + "!"; } ';
      for (let i = 0; i < 100; i++) src += 'var r' + i + ' = id("a");';
      const { module } = await walk(src);
      const fn = module.functions.find(f => f.name === 'id');
      // One cache entry for 100 calls means 99 cache hits.
      assertEqual(fn._summaryCache.size, 1);
    },
  },
];

module.exports = { tests };
