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

  // --- Numeric range refinement + key narrowing ---
  //
  // These lock in the proper computed-index-read behaviour.
  // Before: applyGetIndex took the join-all-fields shortcut
  // for any non-concrete key and raised a blanket
  // `imprecise-index` assumption. After: the domain's
  // OneOf + Interval lattice narrows the key via
  // refineNumericRange, and the index read returns the
  // join of ONLY the reachable fields — no assumption
  // needed. imprecise-index is only raised when the key
  // is genuinely opaque (Opaque / unbounded Top).
  {
    name: 'refineNumericRange: OneOf < 3 prunes values ≥ 3',
    fn: () => {
      const v = D.oneOf([0, 1, 2, 3, 4], 'number');
      const refined = D.refineNumericRange(v, '<', 3);
      assertEqual(refined.kind, 'oneOf');
      assertEqual(JSON.stringify(refined.values), '[0,1,2]');
    },
  },
  {
    name: 'refineNumericRange: Interval < 5 shrinks hi to 4',
    fn: () => {
      const v = D.interval(0, 10);
      const refined = D.refineNumericRange(v, '<', 5);
      assertEqual(refined.kind, 'interval');
      assertEqual(refined.lo, 0);
      assertEqual(refined.hi, 4);
    },
  },
  {
    name: 'refineNumericRange: Concrete violating range → Bottom',
    fn: () => {
      const v = D.concrete(7, 'number');
      const refined = D.refineNumericRange(v, '<', 5);
      assertEqual(refined.kind, 'bottom');
    },
  },
  // Widening: a ⊽ b. No iteration cap, no numeric
  // threshold; finiteness comes from the lattice itself
  // (±Infinity on intervals, subsumption on OneOfs,
  // absorbing Top for non-numeric).
  {
    name: 'widen: growing upper bound extrapolates to +Infinity',
    fn: () => {
      const old = D.interval(0, 2);
      const newly = D.interval(0, 3);
      const w = D.widen(old, newly);
      assertEqual(w.kind, 'interval');
      assertEqual(w.lo, 0);
      assert(w.hi === Number.POSITIVE_INFINITY,
        'hi widened to +Infinity: ' + w.hi);
    },
  },
  {
    name: 'widen: stable bounds → result === join (no growth)',
    fn: () => {
      const a = D.interval(0, 3);
      const b = D.interval(0, 3);
      const w = D.widen(a, b);
      // Stable in both dimensions → no extrapolation.
      assertEqual(w.kind, 'interval');
      assertEqual(w.lo, 0);
      assertEqual(w.hi, 3);
    },
  },
  {
    name: 'widen: Concrete + Concrete number bounds lift and widen',
    fn: () => {
      const a = D.concrete(0, 'number');
      const b = D.concrete(1, 'number');
      const w = D.widen(a, b);
      // Growing hi dimension; extrapolate to +Infinity.
      assertEqual(w.kind, 'interval');
      assertEqual(w.lo, 0);
      assert(w.hi === Number.POSITIVE_INFINITY,
        'hi widened to +Infinity');
    },
  },
  {
    name: 'widen: OneOf subsumed by old → stable',
    fn: () => {
      const old = D.oneOf([0, 1, 2], 'number');
      const newly = D.oneOf([1, 2], 'number');
      const w = D.widen(old, newly);
      // newly ⊆ old → widen returns old unchanged
      assertEqual(w.kind, 'oneOf');
      assertEqual(JSON.stringify(w.values), '[0,1,2]');
    },
  },
  {
    name: 'widen with refineNumericRange: ∞ interval shrinks to loop bound',
    fn: () => {
      // After widening a loop counter becomes
      // Interval(0, +Infinity). Refinement on `i < 3`
      // brings it back to Interval(0, 2) — precise again.
      const widened = D.widen(
        D.interval(0, 0),
        D.interval(0, 1));
      assert(widened.hi === Number.POSITIVE_INFINITY);
      const refined = D.refineNumericRange(widened, '<', 3);
      assertEqual(refined.kind, 'interval');
      assertEqual(refined.lo, 0);
      assertEqual(refined.hi, 2);
    },
  },
  {
    name: 'applyGetIndex narrows for concrete-bound loop: no imprecise-index',
    fn: async () => {
      // Concrete bound `i < 3` — widening + refinement
      // produce Interval(0, 2) at the body. applyGetIndex's
      // Interval case enumerates fields 0/1/2 exactly.
      // No imprecise-index is raised.
      const t = await analyze([
        'var items = ["a", "b", location.search];',
        'var html = "";',
        'for (var i = 0; i < 3; i++) { html += items[i]; }',
        'document.body.innerHTML = html;',
      ].join('\n'), { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1, 'taint flow is emitted');
      const hasImprecise = t.assumptions.some(a =>
        a.details.indexOf('imprecise-index') === 0);
      assert(!hasImprecise,
        'concrete-bound narrowing avoids imprecise-index: ' +
        t.assumptions.filter(a => a.details.indexOf('imprecise-index') === 0)
          .map(a => a.details).join(', '));
    },
  },
  {
    name: 'applyGetIndex: opaque-bound loop narrows by field enumeration',
    fn: async () => {
      // Opaque bound `i < items.length` — refinement
      // cannot shrink the widened interval because
      // `items.length` isn't a concrete number, so the
      // loop counter stays at Interval(0, +Infinity) at
      // the body. applyGetIndex's Case 3 then iterates
      // the cell's existing numeric fields (0, 1, 2)
      // filtered by "falls in the interval range" and
      // joins those exactly — structurally bounded by the
      // heap, not by a numeric cap. Taint propagates
      // precisely without raising imprecise-index.
      const t = await analyze([
        'var items = ["a", "b", location.search];',
        'var html = "";',
        'for (var i = 0; i < items.length; i++) { html += items[i]; }',
        'document.body.innerHTML = html;',
      ].join('\n'), { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1,
        'taint propagates from items[2] = location.search');
      const hasImprecise = t.assumptions.some(a =>
        a.details.indexOf('imprecise-index') === 0);
      assert(!hasImprecise,
        'field-enumeration narrowing avoids imprecise-index even for opaque bounds: ' +
        t.assumptions.filter(a => a.details.indexOf('imprecise-index') === 0)
          .map(a => a.details).join(', '));
    },
  },
  {
    name: 'applyGetIndex fallback: items[window.foo] DOES raise imprecise-index',
    fn: async () => {
      // Truly opaque key — the narrowing can't apply and
      // the fallback raises imprecise-index so strict mode
      // sees the imprecision.
      const t = await analyze([
        'var items = ["a", "b", location.search];',
        'document.body.innerHTML = items[window.foo];',
      ].join('\n'), { typeDB: TDB });
      const hasImprecise = t.assumptions.some(a =>
        a.details.indexOf('imprecise-index') === 0);
      assert(hasImprecise, 'opaque key must raise imprecise-index');
    },
  },
];

module.exports = { tests };
