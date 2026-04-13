// path-cond.test.js — B3 regression coverage.
//
// B3 records per-block path conditions in the worklist:
//   * Each successor of a non-concrete BRANCH gets the source
//     block's pathCond conjoined with the branch's cond formula
//     (true successor) or its negation (false successor).
//   * Multi-predecessor blocks accumulate via disjunction.
//   * Concrete-truth branches collapse to a single successor —
//     the dead branch's pathCond is never updated.
//   * The current block's pathCond is exposed to transfer
//     functions via ctx.currentPathCond, which emitTaintFlow
//     stores on the flow record as `pathFormula`.
//
// Tests assert behaviour through both the public analyze() API
// (taint flows carry pathFormula) and direct worklist inspection
// (per-block pathConds map for finer-grained coverage).

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const D = require('../src/domain.js');
const { buildModule } = require('../src/ir.js');
const { analyseFunction } = require('../src/worklist.js');
const { AssumptionTracker } = require('../src/assumptions.js');
const { assert, assertEqual } = require('./run.js');

// Helper to run the worklist directly on a snippet. Returns
// { module, result } where result.pathConds is the per-block
// path-condition map.
function walk(code) {
  const module = buildModule(code, '<input>.js');
  const ctx = {
    module,
    assumptions: new AssumptionTracker(),
    typeDB: TDB,
    nextObjId: 0,
    taintFlows: [],
    nextFlowId: 1,
  };
  const result = analyseFunction(module, module.top, D.createState(), ctx);
  return { module, ctx, result };
}

// Find the pathCond expression for the block containing a
// specific instruction (matched by source-position substring).
// Returns null if not found.
function pathCondAtPos(walked, posSubstr) {
  for (const [bid, block] of walked.module.top.cfg.blocks) {
    for (const instr of block.instructions) {
      const loc = walked.module.sourceMap.get(instr._id);
      if (loc && loc.pos != null) {
        const src = walked.module.name; // not the source itself; need indexable form
        // Match by finding the substring in the original source slice
        // is awkward without the source on hand — instead, look for
        // the inner source slice via the sourceText we passed in.
      }
    }
  }
  return null;
}

const tests = [
  {
    name: 'B3: entry block is unconditionally reachable (pathCond = null/top)',
    fn: () => {
      const w = walk('var x = 1;');
      // Entry block should have pathCond = null (top).
      const entry = w.module.top.cfg.entry;
      const pc = w.result.pathConds.get(entry);
      assertEqual(pc, null, 'entry pathCond must be null/top');
    },
  },
  {
    name: 'B3: linear (no branch) program → all blocks have null pathCond',
    fn: () => {
      const w = walk('var x = location.hash; var y = x + "a";');
      for (const [bid, pc] of w.result.pathConds) {
        assertEqual(pc, null, 'block ' + bid + ' should have top pathCond');
      }
    },
  },
  {
    name: 'B3: simple if-else produces conjoined branch conditions',
    fn: () => {
      const w = walk('var x = location.hash; if (x === "admin") { var y = 1; } else { var z = 2; }');
      // Find blocks with non-null pathConds. There should be a
      // true branch with `(= |Location.hash_N| "admin")` and a
      // false branch with `(not (= ...))`.
      let trueExpr = null, falseExpr = null;
      for (const [bid, pc] of w.result.pathConds) {
        if (!pc) continue;
        const e = pc.expr;
        if (/^\(= \|Location\.hash_\d+\| "admin"\)$/.test(e)) trueExpr = e;
        if (/^\(not \(= \|Location\.hash_\d+\| "admin"\)\)$/.test(e)) falseExpr = e;
      }
      assert(trueExpr, 'expected true-edge formula, got: ' +
        JSON.stringify(Array.from(w.result.pathConds.values()).map(p => p && p.expr)));
      assert(falseExpr, 'expected false-edge formula');
    },
  },
  {
    name: 'B3: nested if produces conjunctions',
    fn: () => {
      const w = walk(
        'var x = location.hash; var y = location.search; ' +
        'if (x === "admin") { if (y === "secret") { var z = x; } }');
      // Look for an `(and (= ... "admin") (= ... "secret"))` formula.
      let conjunction = null;
      for (const [bid, pc] of w.result.pathConds) {
        if (!pc) continue;
        const e = pc.expr;
        if (e.indexOf('"admin"') !== -1 && e.indexOf('"secret"') !== -1 &&
            e.indexOf('and') !== -1) {
          conjunction = e;
          break;
        }
      }
      assert(conjunction, 'expected nested conjunction, got: ' +
        JSON.stringify(Array.from(w.result.pathConds.values()).map(p => p && p.expr)));
    },
  },
  {
    name: 'B3: post-if join produces disjunctive merge',
    fn: () => {
      const w = walk(
        'var x = location.hash; if (x === "admin") { var a = 1; } else { var b = 2; } var c = 3;');
      // The block containing `var c = 3` is a join successor and
      // should have pathCond = (or (= ...) (not (= ...))). That's
      // logically equivalent to `true` but we don't simplify.
      let joinExpr = null;
      for (const [bid, pc] of w.result.pathConds) {
        if (!pc) continue;
        const e = pc.expr;
        if (e.startsWith('(or ') && e.indexOf('"admin"') !== -1) {
          joinExpr = e;
          break;
        }
      }
      assert(joinExpr, 'expected disjunctive join, got: ' +
        JSON.stringify(Array.from(w.result.pathConds.values()).map(p => p && p.expr)));
    },
  },
  {
    name: 'B3: concrete-true if collapses to single successor (no pathCond growth)',
    fn: () => {
      // `if (true)` — the false branch should never be enqueued.
      const w = walk('var x = location.hash; if (true) { var y = x; } var z = 0;');
      // No block should have a pathCond mentioning `true` — the
      // truthiness check short-circuits before formula construction.
      for (const [bid, pc] of w.result.pathConds) {
        if (!pc) continue;
        // A non-null pathCond is suspicious for a concrete-true branch.
        // (Tolerated only if the formula is a tautology / trivial.)
        // We DO expect all pathConds to be null since no branch
        // contributed a non-trivial cond.
        assertEqual(pc, null, 'concrete-true should not record a pathCond, got: ' + pc.expr);
      }
    },
  },
  {
    name: 'B3: taint flow inside if carries pathFormula',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; if (x === "admin") { document.body.innerHTML = x; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'one flow expected');
      const f = t.taintFlows[0];
      assert(f.pathFormula, 'flow should carry pathFormula');
      assert(/admin/.test(f.pathFormula.expr),
        'pathFormula should reference the branch test, got: ' + f.pathFormula.expr);
      assert(f.valueFormula, 'flow should carry valueFormula');
      assert(/Location\.hash/.test(f.valueFormula.expr),
        'valueFormula should reference the source sym, got: ' + f.valueFormula.expr);
    },
  },
  {
    name: 'B3: top-level taint flow has null pathFormula',
    fn: async () => {
      // No branch above the sink → pathFormula should be null
      // (unconditional).
      const t = await analyze(
        'var x = location.hash; document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'one flow expected');
      const f = t.taintFlows[0];
      assertEqual(f.pathFormula, null, 'unconditional flow has null pathFormula');
      assert(f.valueFormula, 'flow still has valueFormula');
    },
  },
  {
    name: 'B3: nested-if taint flow has conjunctive pathFormula',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; var y = location.search; ' +
        'if (x === "admin") { if (y === "secret") { document.body.innerHTML = x; } }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'one flow expected');
      const f = t.taintFlows[0];
      assert(f.pathFormula, 'has pathFormula');
      const e = f.pathFormula.expr;
      assert(e.indexOf('admin') !== -1 && e.indexOf('secret') !== -1,
        'pathFormula should mention both branch conds, got: ' + e);
      // The `and` binds the two equalities.
      assert(e.indexOf('and') !== -1,
        'pathFormula should be a conjunction, got: ' + e);
    },
  },
  {
    name: 'B3: else-branch flow carries the negated condition',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; if (x === "admin") { var a = 1; } else { document.body.innerHTML = x; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'one flow expected');
      const f = t.taintFlows[0];
      assert(f.pathFormula, 'has pathFormula');
      const e = f.pathFormula.expr;
      assert(e.startsWith('(not '),
        'else-branch pathFormula should be a negation, got: ' + e);
      assert(/admin/.test(e), 'should still reference the original cond');
    },
  },
];

module.exports = { tests };
