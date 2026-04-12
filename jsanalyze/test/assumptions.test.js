'use strict';

const { AssumptionTracker, REASONS, SEVERITIES } = require('../src/assumptions.js');
const { assert, assertEqual, assertThrows } = require('./run.js');

const tests = [
  {
    name: 'raise: assigns stable id and defaults severity',
    fn: () => {
      const t = new AssumptionTracker();
      const a = t.raise(REASONS.NETWORK, 'fetch call', { file: 'a.js', line: 1, col: 0, pos: 0 });
      assertEqual(a.id, 1);
      assertEqual(a.reason, 'network');
      assertEqual(a.severity, 'precision');
      const b = t.raise(REASONS.UNIMPLEMENTED, 'for-of', { file: 'a.js', line: 2, col: 0, pos: 10 });
      assertEqual(b.id, 2);
      assertEqual(b.severity, 'soundness');
    },
  },
  {
    name: 'raise: rejects unknown reason',
    fn: () => {
      const t = new AssumptionTracker();
      assertThrows(() => t.raise('made-up', 'x', { file: 'a.js', line: 1, col: 0, pos: 0 }));
    },
  },
  {
    name: 'raise: rejects empty details',
    fn: () => {
      const t = new AssumptionTracker();
      assertThrows(() => t.raise(REASONS.NETWORK, '', { file: 'a.js', line: 1, col: 0, pos: 0 }));
    },
  },
  {
    name: 'raise: requires location',
    fn: () => {
      const t = new AssumptionTracker();
      assertThrows(() => t.raise(REASONS.NETWORK, 'x', null));
    },
  },
  {
    name: 'raise: chain is preserved',
    fn: () => {
      const t = new AssumptionTracker();
      const a = t.raise(REASONS.NETWORK, 'first', { file: 'a.js', line: 1, col: 0, pos: 0 });
      const b = t.raise(REASONS.OPAQUE_CALL, 'second', { file: 'a.js', line: 2, col: 0, pos: 10 }, { chain: [a.id] });
      assertEqual(b.chain.length, 1);
      assertEqual(b.chain[0], a.id);
    },
  },
  {
    name: 'snapshot: returns frozen array',
    fn: () => {
      const t = new AssumptionTracker();
      t.raise(REASONS.NETWORK, 'x', { file: 'a.js', line: 1, col: 0, pos: 0 });
      const snap = t.snapshot();
      assertEqual(snap.length, 1);
      assert(Object.isFrozen(snap), 'snapshot should be frozen');
    },
  },
  {
    name: 'stats: counts by reason',
    fn: () => {
      const t = new AssumptionTracker();
      t.raise(REASONS.NETWORK, 'a', { file: 'a.js', line: 1, col: 0, pos: 0 });
      t.raise(REASONS.NETWORK, 'b', { file: 'a.js', line: 2, col: 0, pos: 1 });
      t.raise(REASONS.UNIMPLEMENTED, 'c', { file: 'a.js', line: 3, col: 0, pos: 2 });
      const stats = t.stats();
      assertEqual(stats['network'], 2);
      assertEqual(stats['unimplemented'], 1);
    },
  },
  {
    name: 'filter: custom predicate',
    fn: () => {
      const t = new AssumptionTracker();
      t.raise(REASONS.NETWORK, 'a', { file: 'a.js', line: 1, col: 0, pos: 0 });
      t.raise(REASONS.UNIMPLEMENTED, 'b', { file: 'b.js', line: 2, col: 0, pos: 1 });
      const net = t.filter(a => a.reason === 'network');
      assertEqual(net.length, 1);
      assertEqual(net[0].details, 'a');
    },
  },
  {
    name: 'REASONS frozen and covers all spec reasons',
    fn: () => {
      assert(Object.isFrozen(REASONS));
      const required = ['network', 'user-input', 'randomness', 'timing',
        'unsolvable-math', 'unimplemented', 'dynamic-code', 'opaque-call',
        'external-module', 'runtime-type', 'heap-escape'];
      const have = new Set(Object.values(REASONS));
      for (const r of required) assert(have.has(r), 'missing reason: ' + r);
    },
  },
];

module.exports = { tests };
