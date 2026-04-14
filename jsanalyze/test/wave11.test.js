// wave11.test.js — Phase D / Z3 refutation regression coverage.
//
// Wave 11 adds a real Z3 SMT solver as a post-pass over the
// completed trace. Flows whose pathFormula is provably `unsat`
// under Z3 are removed from `trace.taintFlows` and recorded in
// `trace.refutedFlows` so consumers can audit what was dropped.
//
// Z3 is a required dependency (z3-solver npm package). There
// is no fallback — if the solver can't load, analysis fails
// loudly because the "proper interprocedural, path-sensitive,
// state-correlated" contract depends on a real decision
// procedure, not a hand-rolled approximation.
//
// The refutation pipeline is:
//
//   1. transfer.applyCall seeds each callee's entry state with
//      the caller's current pathCond, so any flow fired inside
//      a callee carries the full path from the outermost
//      caller down to the sink.
//
//   2. worklist.analyseFunction preserves the seeded pathCond
//      (no longer forces it to null at entry), letting the
//      per-variant fixpoint refine it along local branches.
//
//   3. After analysis completes, index.analyze invokes
//      z3.refuteTrace, which submits each flow's pathFormula
//      to a fresh Z3 Solver via fromString + check. UNSAT
//      verdicts drop the flow; SAT and UNKNOWN keep it.
//
// These tests lock in the interprocedural, path-sensitive,
// and state-correlated properties of the refutation pipeline.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'Wave11: simple unconditional flow is not refuted',
    fn: async () => {
      const t = await analyze(
        'document.body.innerHTML = location.hash;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
      assertEqual((t.refutedFlows || []).length, 0,
        'unconditional flow has a null pathFormula, not checkable');
    },
  },
  {
    name: 'Wave11: guarded flow with a satisfiable path is kept',
    fn: async () => {
      const t = await analyze(
        'var h = location.hash;' +
        'if (h === "admin") { document.body.innerHTML = h; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1,
        'h === "admin" is satisfiable (h = "admin") so the flow stays');
    },
  },
  {
    name: 'Wave11: contradictory nested if refuted by Z3',
    fn: async () => {
      // `h === "a"` and `h === "b"` cannot both hold; the
      // nested sink is unreachable. refineEq already kills
      // this at the lattice level (h collapses to Bottom on
      // the inner branch), so Z3 sees zero flows — BUT the
      // test still documents the invariant so we notice if
      // refinement ever stops catching it.
      const t = await analyze(
        'var h = location.hash;' +
        'if (h === "a") { if (h === "b") { document.body.innerHTML = h; } }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0,
        'contradictory path produces no flow');
    },
  },
  {
    name: 'Wave11: cross-variable contradiction refuted by Z3',
    fn: async () => {
      // Two distinct sources constrained to equal each other
      // AND to two distinct literals. No lattice-level
      // refinement kills this because the operands are
      // opaque Symbols, not concretes — Z3 is the first
      // engine component to notice.
      //
      //   h === s ∧ h === "x" ∧ s === "y"
      //
      // is UNSAT under string theory.
      const t = await analyze(
        'var h = location.hash;' +
        'var s = location.search;' +
        'if (h === s) { if (h === "x") { if (s === "y") { document.body.innerHTML = h; } } }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0,
        'three-way contradiction refuted');
      assert((t.refutedFlows || []).length >= 1,
        'refuted flow recorded on trace');
    },
  },
  {
    name: 'Wave11: interprocedural contradiction refuted',
    fn: async () => {
      // The caller narrows `h` to "a" and then to "b" before
      // calling `sink`. Under the interprocedural path-cond
      // seeding (applyCall propagates caller pathCond into
      // callee entry), the flow emitted inside `sink` carries
      // the full conjunction  h === "a" ∧ h === "b", which
      // Z3 refutes.
      const t = await analyze(
        'function sink(v) { document.body.innerHTML = v; }' +
        'var h = location.hash;' +
        'if (h === "a") { if (h === "b") { sink(h); } }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0,
        'interprocedural contradiction is refuted');
    },
  },
  {
    name: 'Wave11: legitimate interprocedural flow still fires',
    fn: async () => {
      const t = await analyze(
        'function sink(v) { document.body.innerHTML = v; }' +
        'sink(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1,
        'unconditional interproc flow is not refuted');
    },
  },
  {
    name: 'Wave11: B4 + Z3 — cross-variant refutation',
    fn: async () => {
      // B4 keeps the two branches distinct; each variant has
      // its own pathCond. The sink inside `if (x === 1)`
      // fires only on the variant where x=1 AND y=clean, so
      // no tainted flow reaches it in the first place. Z3
      // has nothing to refute — this is a regression guard
      // that the B4 + Z3 combination doesn't double-count.
      const t = await analyze(
        'var x, y;' +
        'if (location.hash === "a") { x = 1; y = "clean"; }' +
        'else                        { x = 2; y = location.search; }' +
        'if (x === 1) { document.body.innerHTML = y; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave11: refutedFlows array exposed when flows dropped',
    fn: async () => {
      const t = await analyze(
        'var h = location.hash;' +
        'var s = location.search;' +
        'if (h === s) { if (h === "x") { if (s === "y") { document.body.innerHTML = h; } } }',
        { typeDB: TDB });
      assert(Array.isArray(t.refutedFlows), 'refutedFlows is an array');
      assert(t.refutedFlows.length >= 1);
      const f = t.refutedFlows[0];
      assert(f.pathFormula, 'refuted flow still carries its pathFormula');
      assert(f.id != null, 'refuted flow has a stable id');
    },
  },
  {
    name: 'Wave11: Z3 handles string-concat value formulas',
    fn: async () => {
      // The sink value is a str.++ composite. Z3 evaluates
      // the pathFormula that references the same source sym.
      // This verifies the formula-emission path handles
      // concatenation cleanly.
      const t = await analyze(
        'var h = location.hash;' +
        'if (h === "evil") { document.body.innerHTML = "prefix:" + h; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1,
        'h === "evil" is satisfiable; flow is not refuted');
    },
  },
];

module.exports = { tests };
