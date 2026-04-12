'use strict';

const { computeBinOp, evalJsBinOp, applyInstruction } = require('../src/transfer.js');
const D = require('../src/domain.js');
const { AssumptionTracker } = require('../src/assumptions.js');
const { OP } = require('../src/ir.js');
const { assert, assertEqual } = require('./run.js');

function ctx() {
  const module = {
    sourceMap: new Map(),
    name: 'test',
  };
  return {
    module,
    assumptions: new AssumptionTracker(),
    typeDB: null,
    nextObjId: 0,
    onCall: null,
  };
}

const tests = [
  {
    name: 'evalJsBinOp: numeric +',
    fn: () => assertEqual(evalJsBinOp('+', 1, 2), 3),
  },
  {
    name: 'evalJsBinOp: string concat',
    fn: () => assertEqual(evalJsBinOp('+', 'a', 'b'), 'ab'),
  },
  {
    name: 'evalJsBinOp: comparison',
    fn: () => {
      assertEqual(evalJsBinOp('<', 1, 2), true);
      assertEqual(evalJsBinOp('>=', 5, 3), true);
      assertEqual(evalJsBinOp('===', 1, '1'), false);
    },
  },
  {
    name: 'computeBinOp: concrete + concrete = folded concrete',
    fn: () => {
      const r = computeBinOp('+', D.concrete(1), D.concrete(2), null);
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 3);
    },
  },
  {
    name: 'computeBinOp: concrete + oneOf = broadcast',
    fn: () => {
      const r = computeBinOp('+', D.concrete(10), D.oneOf([1, 2]), null);
      assertEqual(r.kind, 'oneOf');
      const set = new Set(r.values);
      assert(set.has(11));
      assert(set.has(12));
    },
  },
  {
    name: 'computeBinOp: oneOf + oneOf = cartesian product',
    fn: () => {
      const r = computeBinOp('+', D.oneOf([1, 2]), D.oneOf([10, 20]), null);
      assertEqual(r.kind, 'oneOf');
      const set = new Set(r.values);
      assert(set.has(11)); assert(set.has(21));
      assert(set.has(12)); assert(set.has(22));
    },
  },
  {
    name: 'computeBinOp: opaque + anything = opaque',
    fn: () => {
      const r = computeBinOp('+', D.opaque([1]), D.concrete(5), null);
      assertEqual(r.kind, 'opaque');
    },
  },
  {
    name: 'applyInstruction: Const',
    fn: () => {
      const c = ctx();
      const s0 = D.createState();
      const instr = { op: OP.CONST, dest: '%r1', value: 42, _id: 1 };
      const s1 = applyInstruction(c, s0, instr);
      assertEqual(D.getReg(s1, '%r1').value, 42);
    },
  },
  {
    name: 'applyInstruction: BinOp folds',
    fn: () => {
      const c = ctx();
      let s = D.createState();
      s = applyInstruction(c, s, { op: OP.CONST, dest: '%r1', value: 10, _id: 1 });
      s = applyInstruction(c, s, { op: OP.CONST, dest: '%r2', value: 20, _id: 2 });
      s = applyInstruction(c, s, { op: OP.BIN_OP, dest: '%r3', operator: '+', left: '%r1', right: '%r2', _id: 3 });
      assertEqual(D.getReg(s, '%r3').value, 30);
    },
  },
  {
    name: 'applyInstruction: UnOp typeof',
    fn: () => {
      const c = ctx();
      let s = D.createState();
      s = applyInstruction(c, s, { op: OP.CONST, dest: '%r1', value: 'hi', _id: 1 });
      s = applyInstruction(c, s, { op: OP.UN_OP, dest: '%r2', operator: 'typeof', operand: '%r1', _id: 2 });
      assertEqual(D.getReg(s, '%r2').value, 'string');
    },
  },
  {
    name: 'applyInstruction: GetGlobal raises opaque-call assumption',
    fn: () => {
      const c = ctx();
      const s0 = D.createState();
      const s1 = applyInstruction(c, s0, {
        op: OP.GET_GLOBAL, dest: '%r1', name: 'someGlobal', _id: 1,
      });
      assertEqual(D.getReg(s1, '%r1').kind, 'opaque');
      const snap = c.assumptions.snapshot();
      assertEqual(snap.length, 1);
      assertEqual(snap[0].reason, 'opaque-call');
    },
  },
  {
    name: 'applyInstruction: Opaque instr raises assumption with given reason',
    fn: () => {
      const c = ctx();
      const s0 = D.createState();
      const s1 = applyInstruction(c, s0, {
        op: OP.OPAQUE, dest: '%r1',
        reason: 'unimplemented',
        details: 'test opaque',
        _id: 1,
      });
      const v = D.getReg(s1, '%r1');
      assertEqual(v.kind, 'opaque');
      const snap = c.assumptions.snapshot();
      assertEqual(snap.length, 1);
      assertEqual(snap[0].reason, 'unimplemented');
      assertEqual(snap[0].details, 'test opaque');
    },
  },
];

module.exports = { tests };
