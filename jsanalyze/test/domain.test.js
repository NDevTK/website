'use strict';

const D = require('../src/domain.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'bottom < concrete',
    fn: () => {
      assert(D.leq(D.bottom(), D.concrete(1)));
      assert(!D.leq(D.concrete(1), D.bottom()));
    },
  },
  {
    name: 'concrete < top',
    fn: () => {
      assert(D.leq(D.concrete(1), D.top()));
      assert(!D.leq(D.top(), D.concrete(1)));
    },
  },
  {
    name: 'concrete == concrete for same value',
    fn: () => {
      assert(D.equals(D.concrete(1), D.concrete(1)));
      assert(!D.equals(D.concrete(1), D.concrete(2)));
    },
  },
  {
    name: 'join concrete + concrete = oneOf',
    fn: () => {
      const r = D.join(D.concrete(1), D.concrete(2));
      assertEqual(r.kind, 'oneOf');
      assertEqual(r.values.length, 2);
    },
  },
  {
    name: 'join concrete + same concrete = concrete',
    fn: () => {
      const r = D.join(D.concrete(1), D.concrete(1));
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 1);
    },
  },
  {
    name: 'join oneOf + concrete extends set when types match',
    fn: () => {
      // Same JS type (number) → OneOf extension is precise.
      const a = D.oneOf([1, 2], 'number');
      const b = D.concrete(3, 'number');
      const r = D.join(a, b);
      assertEqual(r.kind, 'oneOf');
      assertEqual(r.values.length, 3);
    },
  },
  {
    name: 'join oneOf + concrete with mismatched types → disjunct',
    fn: () => {
      // String + number → must NOT collapse type info; produce a
      // Disjunct so per-path type tracking survives the join.
      const a = D.oneOf([1, 2], 'number');
      const b = D.concrete('hi', 'string');
      const r = D.join(a, b);
      assertEqual(r.kind, 'disjunct');
      assertEqual(r.variants.length, 2);
    },
  },
  {
    name: 'join interval + interval = bounding interval',
    fn: () => {
      const r = D.join(D.interval(1, 5), D.interval(3, 10));
      assertEqual(r.kind, 'interval');
      assertEqual(r.lo, 1);
      assertEqual(r.hi, 10);
    },
  },
  {
    name: 'join bottom + x = x',
    fn: () => {
      const r = D.join(D.bottom(), D.concrete(42));
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 42);
    },
  },
  {
    name: 'join top + x = top',
    fn: () => {
      const r = D.join(D.top(), D.concrete(1));
      assertEqual(r.kind, 'top');
    },
  },
  {
    name: 'opaque + concrete → disjunct preserving per-variant shape',
    fn: () => {
      // Mixed Opaque + Concrete must NOT collapse to opaque(null);
      // we keep both variants so per-path type tracking and sink
      // resolution can still see the concrete on its branch.
      const a = D.opaque([1, 2]);
      const b = D.concrete(5);
      const r = D.join(a, b);
      assertEqual(r.kind, 'disjunct');
      assertEqual(r.variants.length, 2);
      // Both variants are accessible.
      const kinds = r.variants.map(v => v.kind).sort();
      assertEqual(kinds[0], 'concrete');
      assertEqual(kinds[1], 'opaque');
    },
  },
  {
    name: 'opaque + opaque unions assumption chains',
    fn: () => {
      const a = D.opaque([1, 2]);
      const b = D.opaque([3, 2]);
      const r = D.join(a, b);
      assertEqual(r.kind, 'opaque');
      assertEqual(r.assumptionIds.length, 3);
    },
  },
  {
    name: 'truthiness: concrete true/false',
    fn: () => {
      assertEqual(D.truthiness(D.concrete(true)), true);
      assertEqual(D.truthiness(D.concrete(false)), false);
      assertEqual(D.truthiness(D.concrete(0)), false);
      assertEqual(D.truthiness(D.concrete(1)), true);
      assertEqual(D.truthiness(D.concrete('')), false);
      assertEqual(D.truthiness(D.concrete('x')), true);
      assertEqual(D.truthiness(D.concrete(null)), false);
      assertEqual(D.truthiness(D.concrete(undefined)), false);
    },
  },
  {
    name: 'truthiness: oneOf all-truthy = true',
    fn: () => {
      assertEqual(D.truthiness(D.oneOf([1, 2, 'x'])), true);
    },
  },
  {
    name: 'truthiness: oneOf mixed = null',
    fn: () => {
      assertEqual(D.truthiness(D.oneOf([0, 1])), null);
    },
  },
  {
    name: 'truthiness: interval [1,5] = true',
    fn: () => {
      assertEqual(D.truthiness(D.interval(1, 5)), true);
    },
  },
  {
    name: 'truthiness: interval [-5,-1] = true (non-zero)',
    fn: () => {
      assertEqual(D.truthiness(D.interval(-5, -1)), true);
    },
  },
  {
    name: 'truthiness: interval [0,0] = false',
    fn: () => {
      assertEqual(D.truthiness(D.interval(0, 0)), false);
    },
  },
  {
    name: 'truthiness: interval [-1,1] = null',
    fn: () => {
      assertEqual(D.truthiness(D.interval(-1, 1)), null);
    },
  },
  {
    name: 'State setReg and getReg',
    fn: () => {
      const s0 = D.createState();
      const s1 = D.setReg(s0, '%r1', D.concrete(42));
      assertEqual(D.getReg(s1, '%r1').value, 42);
      assertEqual(D.getReg(s0, '%r1').kind, 'bottom', 'original state unchanged');
    },
  },
  {
    name: 'joinStates: union of regs',
    fn: () => {
      const a = D.setReg(D.createState(), '%r1', D.concrete(1));
      const b = D.setReg(D.createState(), '%r1', D.concrete(2));
      const j = D.joinStates(a, b);
      assertEqual(D.getReg(j, '%r1').kind, 'oneOf');
    },
  },
  {
    name: 'joinStates: preserves non-conflicting regs',
    fn: () => {
      const a = D.setReg(D.createState(), '%r1', D.concrete(1));
      const b = D.setReg(D.createState(), '%r2', D.concrete(2));
      const j = D.joinStates(a, b);
      assertEqual(D.getReg(j, '%r1').value, 1);
      assertEqual(D.getReg(j, '%r2').value, 2);
    },
  },
];

module.exports = { tests };
