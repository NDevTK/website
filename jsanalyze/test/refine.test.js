// refine.test.js — B5 regression coverage.
//
// B5 narrows the operand of a refinable comparison on each
// successor of a Branch terminator:
//
//   on `if (x === lit)` true  branch: x ← refineEq(x, lit)
//   on `if (x === lit)` false branch: x ← refineNeq(x, lit)
//
// When the refinement collapses a register to Bottom (the
// branch is statically infeasible), the dead successor is not
// enqueued at all and any sinks inside it are unreachable —
// directly eliminating the false-positive flow.
//
// Refinement is only applied across `===`, `==`, `!==`, `!=`
// where one operand is a primitive Concrete and the other is
// a register. Opaque values are left alone (the path-condition
// formula carries the constraint to the SMT layer for those).

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const D = require('../src/domain.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- domain-level refinement helpers ---
  {
    name: 'B5 domain: refineEq on Concrete matching → preserved',
    fn: () => {
      const v = D.concrete('admin', 'string');
      const r = D.refineEq(v, 'admin');
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 'admin');
    },
  },
  {
    name: 'B5 domain: refineEq on Concrete mismatch → Bottom',
    fn: () => {
      const v = D.concrete('user', 'string');
      const r = D.refineEq(v, 'admin');
      assertEqual(r.kind, 'bottom');
    },
  },
  {
    name: 'B5 domain: refineEq on OneOf containing → Concrete',
    fn: () => {
      const v = D.oneOf(['a', 'b', 'c'], 'string');
      const r = D.refineEq(v, 'b');
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 'b');
    },
  },
  {
    name: 'B5 domain: refineEq on OneOf not containing → Bottom',
    fn: () => {
      const v = D.oneOf(['a', 'b'], 'string');
      const r = D.refineEq(v, 'c');
      assertEqual(r.kind, 'bottom');
    },
  },
  {
    name: 'B5 domain: refineEq on Opaque → unchanged',
    fn: () => {
      const v = D.opaque([], 'String');
      const r = D.refineEq(v, 'admin');
      assertEqual(r.kind, 'opaque');
      assertEqual(r, v);
    },
  },
  {
    name: 'B5 domain: refineNeq on Concrete matching → Bottom',
    fn: () => {
      const v = D.concrete('admin', 'string');
      const r = D.refineNeq(v, 'admin');
      assertEqual(r.kind, 'bottom');
    },
  },
  {
    name: 'B5 domain: refineNeq on Concrete mismatch → preserved',
    fn: () => {
      const v = D.concrete('user', 'string');
      const r = D.refineNeq(v, 'admin');
      assertEqual(r.kind, 'concrete');
    },
  },
  {
    name: 'B5 domain: refineNeq on OneOf removes the literal',
    fn: () => {
      const v = D.oneOf(['a', 'b', 'c'], 'string');
      const r = D.refineNeq(v, 'b');
      assertEqual(r.kind, 'oneOf');
      const set = new Set(r.values);
      assert(set.has('a') && set.has('c'));
      assert(!set.has('b'));
    },
  },
  {
    name: 'B5 domain: refineNeq on OneOf collapses to Concrete when one remains',
    fn: () => {
      const v = D.oneOf(['a', 'b'], 'string');
      const r = D.refineNeq(v, 'a');
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 'b');
    },
  },
  {
    name: 'B5 domain: refineNeq emptying OneOf → Bottom',
    fn: () => {
      const v = D.oneOf(['a'], 'string');
      const r = D.refineNeq(v, 'a');
      assertEqual(r.kind, 'bottom');
    },
  },
  {
    name: 'B5 domain: refineEq Bottom → Bottom',
    fn: () => {
      assertEqual(D.refineEq(D.bottom(), 'x').kind, 'bottom');
      assertEqual(D.refineNeq(D.bottom(), 'x').kind, 'bottom');
    },
  },
  {
    name: 'B5 domain: refineEq preserves labels on Concrete passthrough',
    fn: () => {
      const v = D.concrete('admin', 'string', null, ['url']);
      const r = D.refineEq(v, 'admin');
      assert(r.labels.has('url'), 'labels should survive refinement');
    },
  },
  {
    name: 'B5 domain: refineEq preserves labels when collapsing OneOf',
    fn: () => {
      const v = D.oneOf(['a', 'b'], 'string', null, ['url']);
      const r = D.refineEq(v, 'a');
      assertEqual(r.kind, 'concrete');
      assert(r.labels.has('url'), 'labels should transfer to refined Concrete');
    },
  },

  // --- end-to-end via analyze() ---
  {
    name: 'B5 e2e: contradictory concrete branch eliminates the flow',
    fn: async () => {
      // x is statically "user"; the `x === "admin"` branch is dead,
      // so the sink inside it never fires.
      const t = await analyze(
        'var x = "user"; if (x === "admin") { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0, 'dead branch should produce no flow');
    },
  },
  {
    name: 'B5 e2e: matching concrete branch keeps the flow',
    fn: async () => {
      const t = await analyze(
        'var x = "admin"; if (x === "admin") { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'matching branch should fire flow');
    },
  },
  {
    name: 'B5 e2e: phi-merged OneOf — impossible-value branch eliminated',
    fn: async () => {
      // After the phi, x is OneOf("a","b"). The `x === "c"` branch
      // is statically infeasible.
      const t = await analyze(
        'var y = location.hash; var x = "a"; if (y === "yes") { x = "b"; } ' +
        'if (x === "c") { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0, 'OneOf with no matching value → branch dead');
    },
  },
  {
    name: 'B5 e2e: phi-merged OneOf — matching value keeps the flow',
    fn: async () => {
      const t = await analyze(
        'var y = location.hash; var x = "a"; if (y === "yes") { x = "b"; } ' +
        'if (x === "a") { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'OneOf containing literal → flow fires');
    },
  },
  {
    name: 'B5 e2e: !== refinement on else branch',
    fn: async () => {
      // x is "admin"; `if (x !== "admin") { ... } else { sink }`
      // — the else branch fires.
      const t = await analyze(
        'var x = "admin"; if (x !== "admin") { var a = 1; } ' +
        'else { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'else branch reachable');
    },
  },
  {
    name: 'B5 e2e: !== refinement true branch dead when concrete matches',
    fn: async () => {
      const t = await analyze(
        'var x = "admin"; if (x !== "admin") { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0, 'x !== "admin" is statically false');
    },
  },
  {
    name: 'B5 e2e: opaque source comparison — refinement leaves flow intact',
    fn: async () => {
      // x = location.hash (opaque). The lattice can't refine an
      // opaque, so both branches stay live and the path condition
      // formula carries the constraint instead.
      const t = await analyze(
        'var x = location.hash; if (x === "admin") { document.body.innerHTML = x; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'opaque branch flows through');
      const f = t.taintFlows[0];
      assert(f.pathFormula, 'flow has pathFormula');
      assert(/admin/.test(f.pathFormula.expr),
        'pathFormula references the literal');
    },
  },
  {
    name: 'B5 e2e: literal-on-the-left works (admin === x)',
    fn: async () => {
      // The refinement detects the literal on either side.
      const t = await analyze(
        'var x = "user"; if ("admin" === x) { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0, 'left-literal still triggers refinement');
    },
  },
];

module.exports = { tests };
