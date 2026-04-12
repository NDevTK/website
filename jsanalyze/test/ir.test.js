'use strict';

const { buildModule, OP } = require('../src/ir.js');
const { assert, assertEqual } = require('./run.js');

// Helper: collect all instructions in a module's top function
// (across all blocks) in CFG order.
function allInstructions(module) {
  const out = [];
  for (const [, block] of module.top.cfg.blocks) {
    for (const instr of block.instructions) out.push(instr);
    if (block.terminator) out.push(block.terminator);
  }
  return out;
}

function opsOf(module) {
  return allInstructions(module).map(i => i.op);
}

const tests = [
  {
    name: 'buildModule: empty program',
    fn: () => {
      const m = buildModule('', 'empty.js');
      assert(m.top, 'top function exists');
      const entry = m.top.cfg.blocks.get(m.top.cfg.entry);
      assert(entry, 'entry block exists');
      assert(entry.terminator, 'entry block has terminator');
      assertEqual(entry.terminator.op, OP.RETURN);
    },
  },
  {
    name: 'buildModule: single literal',
    fn: () => {
      const m = buildModule('var x = 42;', 'a.js');
      const ops = opsOf(m);
      assert(ops.includes(OP.CONST), 'has Const');
      assert(ops.includes(OP.RETURN), 'has Return');
    },
  },
  {
    name: 'buildModule: binary op',
    fn: () => {
      const m = buildModule('var x = 1 + 2;', 'a.js');
      const ops = opsOf(m);
      // Two Const for the literals (1 and 2) plus one for the
      // implicit `undefined` returned at the end of the program.
      assertEqual(ops.filter(o => o === OP.CONST).length, 3, 'three Const instrs (two literals + implicit undefined return)');
      assert(ops.includes(OP.BIN_OP), 'has BinOp');
    },
  },
  {
    name: 'buildModule: if/else creates 4 blocks + phi',
    fn: () => {
      const m = buildModule('var x; if (true) x = 1; else x = 2; var y = x;', 'a.js');
      // Blocks: entry (branch), then, else, merge, tail
      const nBlocks = m.top.cfg.blocks.size;
      assert(nBlocks >= 4, 'at least 4 blocks, got ' + nBlocks);
      const ops = opsOf(m);
      assert(ops.includes(OP.BRANCH), 'has Branch');
      assert(ops.includes(OP.PHI), 'has Phi at merge');
    },
  },
  {
    name: 'buildModule: function declaration creates Func',
    fn: () => {
      const m = buildModule('function f(a) { return a + 1; } var g = f;', 'a.js');
      assertEqual(m.functions.length, 2, 'top + one function');
      const inner = m.functions.find(f => f.name === 'f');
      assert(inner, 'function f exists');
      assert(inner.cfg, 'f has CFG');
      assertEqual(inner.params.length, 1, 'f has one param');
    },
  },
  {
    name: 'buildModule: call expression',
    fn: () => {
      const m = buildModule('foo(1, 2);', 'a.js');
      const ops = opsOf(m);
      assert(ops.includes(OP.CALL), 'has Call');
    },
  },
  {
    name: 'buildModule: unimplemented node becomes Opaque',
    fn: () => {
      // `for` loops aren't lowered yet → becomes an opaque stmt.
      const m = buildModule('for (var i = 0; i < 3; i++) {}', 'a.js');
      const ops = opsOf(m);
      assert(ops.includes(OP.OPAQUE), 'has Opaque for unimplemented for-loop');
    },
  },
  {
    name: 'buildModule: every block has a terminator',
    fn: () => {
      const m = buildModule('var x = 1; if (x) var y = 2;', 'a.js');
      for (const [, block] of m.top.cfg.blocks) {
        assert(block.terminator, 'block ' + block.id + ' has terminator');
      }
    },
  },
  {
    name: 'buildModule: sourceMap populated',
    fn: () => {
      const m = buildModule('var x = 1;', 'a.js');
      const firstConst = allInstructions(m).find(i => i.op === OP.CONST);
      assert(firstConst._id, 'instr has _id');
      const loc = m.sourceMap.get(firstConst._id);
      assert(loc, 'location recorded in sourceMap');
      assertEqual(loc.file, 'a.js');
    },
  },
];

module.exports = { tests };
