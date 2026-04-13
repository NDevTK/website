// loop.test.js — Wave 3 regression coverage for loops.
//
// Wave 3 lands lowering for while / do-while / for loops plus
// break / continue. Loops are handled by the worklist's normal
// monotone fixpoint — each back edge re-enqueues the header,
// and the finite-height Value lattice guarantees termination.
// Wave 0's Disjunct factory dedupes variants by structural key,
// so the lattice remains finite-height even in the presence of
// per-path type tracking.
//
// Precision features tested:
//   * Header phis merge pre-loop values with body-exit values
//     (and with per-continue sources for while-loops).
//   * Break sources contribute a separate exit-block phi so the
//     post-loop scope sees the value at the break point, not the
//     header's normal-exit value.
//   * Tainted assignments inside a loop body propagate through
//     the phi to post-loop sinks.
//   * update expressions in for-loops (`i++` / `i--`) work
//     via the UpdateExpression → BinOp desugaring.
//   * Nested loops converge without stack growth.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { buildModule, OP } = require('../src/ir.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- convergence / termination ---
  {
    name: 'Wave3: simple while loop terminates',
    fn: async () => {
      const t = await analyze('var i = 0; while (i < 3) { i = i + 1; }', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave3: for loop with i++ terminates',
    fn: async () => {
      const t = await analyze('for (var i = 0; i < 3; i++) { var x = i; }', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave3: do-while loop terminates',
    fn: async () => {
      const t = await analyze('var i = 0; do { i = i + 1; } while (i < 3);', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave3: nested loops converge',
    fn: async () => {
      const t = await analyze(
        'for (var i = 0; i < 2; i++) { for (var j = 0; j < 2; j++) { var k = i + j; } }',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },

  // --- CFG shape ---
  {
    name: 'Wave3: while loop creates header/body/exit + back edge',
    fn: () => {
      const m = buildModule('var i = 0; while (i < 3) { i = i + 1; }', 'a.js');
      const cfg = m.top.cfg;
      assert(cfg.blocks.size >= 4, 'at least 4 blocks');
      // Find the header block: it has a Branch terminator and
      // is a successor of the pred (init) block.
      let header = null;
      for (const [, b] of cfg.blocks) {
        if (b.terminator && b.terminator.op === OP.BRANCH) {
          header = b;
          break;
        }
      }
      assert(header, 'found a header with Branch');
      // Back edge: some block jumps back to the header.
      let hasBackEdge = false;
      for (const [, b] of cfg.blocks) {
        if (b.terminator && b.terminator.op === OP.JUMP &&
            b.terminator.target === header.id && b !== header) {
          hasBackEdge = true;
          break;
        }
      }
      assert(hasBackEdge, 'has back edge to header');
    },
  },
  {
    name: 'Wave3: while header has a phi for the loop variable',
    fn: () => {
      const m = buildModule('var i = 0; while (i < 3) { i = i + 1; }', 'a.js');
      let hasPhi = false;
      for (const [, b] of m.top.cfg.blocks) {
        for (const instr of b.instructions) {
          if (instr.op === OP.PHI) { hasPhi = true; break; }
        }
      }
      assert(hasPhi, 'loop header has a phi');
    },
  },

  // --- Tainted flows through loops ---
  {
    name: 'Wave3: tainted value assigned in loop body flows to post-loop sink',
    fn: async () => {
      const t = await analyze(
        'var items = "safe"; ' +
        'for (var i = 0; i < 3; i++) { items = location.hash; } ' +
        'document.body.innerHTML = items;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave3: loop with only safe assignments produces no flow',
    fn: async () => {
      const t = await analyze(
        'var x; ' +
        'for (var i = 0; i < 3; i++) { x = "step"; } ' +
        'document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave3: tainted sink inside loop body fires',
    fn: async () => {
      const t = await analyze(
        'for (var i = 0; i < 3; i++) { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },

  // --- break / continue ---
  {
    name: 'Wave3: break carries post-assignment value to post-loop',
    fn: async () => {
      // `x = location.hash; break;` — the break carries the
      // tainted x out of the loop through the exit-block phi.
      const t = await analyze(
        'var x = "safe"; ' +
        'while (true) { x = location.hash; break; } ' +
        'document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave3: continue skips the rest of the body',
    fn: async () => {
      const t = await analyze(
        'var x = "safe"; var i = 0; ' +
        'while (i < 3) { ' +
        '  i = i + 1; ' +
        '  if (i === 2) { continue; } ' +
        '  x = location.hash; ' +
        '} ' +
        'document.body.innerHTML = x;',
        { typeDB: TDB });
      // x can still be tainted from the non-continue iterations.
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave3: nested loops carry taint through multiple back edges',
    fn: async () => {
      const t = await analyze(
        'var x = "safe"; ' +
        'for (var i = 0; i < 2; i++) { ' +
        '  for (var j = 0; j < 2; j++) { ' +
        '    x = location.hash; ' +
        '  } ' +
        '} ' +
        'document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },

  // --- Update expressions ---
  {
    name: 'Wave3: UpdateExpression i++ parses and lowers',
    fn: () => {
      const m = buildModule('var i = 0; i++;', 'a.js');
      // Just verify no throw and the module is well-formed.
      assertEqual(m.top.cfg.blocks.size >= 1, true);
    },
  },
  {
    name: 'Wave3: UpdateExpression --i (prefix) parses',
    fn: () => {
      const m = buildModule('var i = 5; --i;', 'a.js');
      assertEqual(m.top.cfg.blocks.size >= 1, true);
    },
  },
];

module.exports = { tests };
