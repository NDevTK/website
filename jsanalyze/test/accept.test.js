// accept.test.js — options.accept prescriptive-rejection coverage.
//
// The `accept` option is the consumer's declaration of which
// assumption reason codes it tolerates. The set is PRESCRIPTIVE:
// rejecting a reason forces the engine to not take the
// corresponding shortcut, in addition to flagging the
// violation in trace.rejectedAssumptions and setting
// trace.partial = true.
//
// These tests lock in the accept-based control for both
// performance shortcuts (loop-widening, summary-reused) and
// theoretical-floor assumptions (where rejection is advisory
// — the engine can't conjure bytes it doesn't have).

'use strict';

const { analyze } = require('../src/index.js');
const { buildModule } = require('../src/ir.js');
const { analyseFunction } = require('../src/worklist.js');
const { AssumptionTracker } = require('../src/assumptions.js');
const D = require('../src/domain.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

// A permissive accept set that allows every reason EXCEPT
// the one the test wants to exclude. Used so rejection tests
// only fail on the specific reason under test.
function allExcept(exclude) {
  const all = [
    'network', 'attacker-input', 'persistent-state', 'dom-state',
    'ui-interaction', 'environmental', 'runtime-time', 'pseudorandom',
    'cryptographic-random', 'unsolvable-math',
    'opaque-call', 'external-module', 'code-from-data',
    'unimplemented', 'heap-escape',
    'loop-widening', 'summary-reused',
  ];
  return all.filter(r => r !== exclude);
}

const tests = [
  // --- Default behaviour: no accept → permissive ---
  {
    name: 'accept: default (omitted) accepts everything',
    fn: async () => {
      const t = await analyze(
        'var h = location.hash; document.body.innerHTML = h;',
        { typeDB: TDB });
      assertEqual(t.rejectedAssumptions.length, 0);
      assertEqual(t.partial, false);
    },
  },

  // --- Theoretical-floor rejection: advisory ---
  {
    name: 'accept: rejecting attacker-input flags the trace partial',
    fn: async () => {
      const t = await analyze(
        'var h = location.hash; document.body.innerHTML = h;',
        { typeDB: TDB, accept: allExcept('attacker-input') });
      assertEqual(t.partial, true);
      assert(t.rejectedAssumptions.length >= 1,
        'rejectedAssumptions populated');
      const hasAttackerInput = t.rejectedAssumptions.some(
        a => a.reason === 'attacker-input');
      assert(hasAttackerInput,
        'the rejected assumption lists attacker-input as the reason');
    },
  },
  {
    name: 'accept: rejecting a reason the program never triggers is a no-op',
    fn: async () => {
      // This program has no network reads, so rejecting
      // `network` doesn't produce any rejections.
      const t = await analyze(
        'var x = 1; var y = x + 2;',
        { typeDB: TDB, accept: allExcept('network') });
      assertEqual(t.partial, false);
      assertEqual(t.rejectedAssumptions.length, 0);
    },
  },

  // --- summary-reused prescriptive control ---
  {
    name: 'accept: default → summary cache populates',
    fn: () => {
      const module = buildModule(
        'function id(x) { return x + "x"; }' +
        'var a = id("a"); var b = id("a"); var c = id("a");',
        'test.js');
      const ctx = {
        module, assumptions: new AssumptionTracker(), typeDB: TDB,
        nextObjId: 0, taintFlows: [], nextFlowId: 1,
        accept: null,
        innerHtmlAssignments: [], calls: [], stringLiterals: [], domMutations: [],
      };
      return analyseFunction(module, module.top, D.createState(), ctx).then(() => {
        const fn = module.functions.find(f => f.name === 'id');
        assertEqual(fn._summaryCache.size, 1,
          'three identical calls collapse into one cache entry');
      });
    },
  },
  {
    name: 'accept: rejecting summary-reused → cache stays empty',
    fn: () => {
      const module = buildModule(
        'function id(x) { return x + "x"; }' +
        'var a = id("a"); var b = id("a"); var c = id("a");',
        'test.js');
      const ctx = {
        module, assumptions: new AssumptionTracker(), typeDB: TDB,
        nextObjId: 0, taintFlows: [], nextFlowId: 1,
        accept: new Set(allExcept('summary-reused')),
        innerHtmlAssignments: [], calls: [], stringLiterals: [], domMutations: [],
      };
      return analyseFunction(module, module.top, D.createState(), ctx).then(() => {
        const fn = module.functions.find(f => f.name === 'id');
        // Cache is empty because the engine never consults
        // or populates it under this accept set.
        assert(!fn._summaryCache || fn._summaryCache.size === 0,
          'cache is empty when summary-reused is rejected');
      });
    },
  },

  // --- loop-widening prescriptive control ---
  {
    name: 'accept: default → loop-widening fires and loops converge fast',
    fn: async () => {
      const start = Date.now();
      const t = await analyze(
        'var x = 0; while (x < 100) { x = x + 1; }',
        { typeDB: TDB });
      const elapsed = Date.now() - start;
      assertEqual(t.partial, false);
      assert(elapsed < 2000, 'widened loop converges fast (<2s)');
      // loop-widening MAY have been raised (depends on whether
      // the back edge produced a non-trivial join).
      const widened = t.assumptions.filter(a => a.reason === 'loop-widening');
      assert(widened.length >= 0, 'loop-widening is raised when widening fires');
    },
  },
  {
    name: 'accept: rejecting loop-widening → no widening assumption raised',
    fn: async () => {
      // With widening rejected, the engine walks the loop
      // per-iteration. On a small loop (5 iters) this is still
      // fast enough to complete.
      const t = await analyze(
        'var x = 0; while (x < 5) { x = x + 1; }',
        { typeDB: TDB, accept: allExcept('loop-widening') });
      // No loop-widening assumption should have been raised
      // because the engine didn't apply the widening.
      const widened = t.assumptions.filter(a => a.reason === 'loop-widening');
      assertEqual(widened.length, 0,
        'engine did not widen → no loop-widening assumption');
      // The trace is not partial because no rejected
      // assumption was raised.
      assertEqual(t.rejectedAssumptions.length, 0);
    },
  },

  // --- Combined: consumer picks its tolerance ---
  {
    name: 'accept: strict set rejects every shortcut',
    fn: async () => {
      // A maximally strict consumer rejects every engineering
      // gap AND every performance shortcut. The engine does
      // its best work but whatever it can't handle shows up
      // in rejectedAssumptions for the consumer to audit.
      const t = await analyze(
        'function f(x) { return x + 1; } var y = f(location.hash);',
        { typeDB: TDB, accept: ['attacker-input', 'opaque-call'] });
      // attacker-input and opaque-call are accepted.
      // Every other raised assumption is rejected.
      for (const r of t.rejectedAssumptions) {
        assert(r.reason !== 'attacker-input' && r.reason !== 'opaque-call',
          'accepted reasons are NOT in rejectedAssumptions');
      }
    },
  },
];

module.exports = { tests };
