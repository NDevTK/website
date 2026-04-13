// type-narrow.test.js — Wave 1 regression coverage.
//
// Wave 1 extends B5 branch refinement with runtime type-check
// predicates:
//
//   typeof:     `if (typeof x === "string")` narrows x on each
//               branch via refineByType / refineNotByType
//   instanceof: `if (x instanceof T)` narrows x by walking the
//               TypeDB `extends` chain via refineInstanceof /
//               refineNotInstanceof
//
// Both cases collapse contradictory branches to Bottom so the
// dead successor is dropped entirely from the worklist. The
// Disjunct fan-out from Wave 0 means a multi-type receiver gets
// narrowed to the variants that actually satisfy the check —
// the iframe|anchor Disjunct becomes just the anchor variant
// inside `if (el instanceof HTMLAnchorElement)`.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const D = require('../src/domain.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- Domain-level: refineByType ---
  {
    name: 'Wave1 domain: refineByType Concrete matching → preserved',
    fn: () => {
      const r = D.refineByType(D.concrete('hi'), 'string');
      assertEqual(r.kind, 'concrete');
    },
  },
  {
    name: 'Wave1 domain: refineByType Concrete mismatch → Bottom',
    fn: () => {
      const r = D.refineByType(D.concrete(42), 'string');
      assertEqual(r.kind, 'bottom');
    },
  },
  {
    name: 'Wave1 domain: refineByType OneOf filters by JS type',
    fn: () => {
      const r = D.refineByType(D.oneOf(['a', 'b']), 'string');
      assertEqual(r.kind, 'oneOf');
      assertEqual(r.values.length, 2);
    },
  },
  {
    name: 'Wave1 domain: refineByType Opaque(String) vs number → Bottom',
    fn: () => {
      const v = D.opaque([], 'String');
      assertEqual(D.refineByType(v, 'number').kind, 'bottom');
      assertEqual(D.refineByType(v, 'string').kind, 'opaque');
    },
  },
  {
    name: 'Wave1 domain: refineByType Opaque(HTMLElement) vs object → preserved',
    fn: () => {
      const v = D.opaque([], 'HTMLElement');
      assertEqual(D.refineByType(v, 'object').kind, 'opaque');
      assertEqual(D.refineByType(v, 'string').kind, 'bottom');
    },
  },
  {
    name: 'Wave1 domain: refineByType on disjunct filters variants',
    fn: () => {
      const str = D.concrete('hi');
      const num = D.concrete(42);
      const disj = D.disjunct([str, num]);
      const r = D.refineByType(disj, 'string');
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 'hi');
    },
  },
  {
    name: 'Wave1 domain: refineNotByType on Concrete matching → Bottom',
    fn: () => {
      assertEqual(D.refineNotByType(D.concrete('hi'), 'string').kind, 'bottom');
    },
  },
  {
    name: 'Wave1 domain: refineByType Closure → function only',
    fn: () => {
      const v = D.closure('F1', []);
      assertEqual(D.refineByType(v, 'function').kind, 'closure');
      assertEqual(D.refineByType(v, 'object').kind, 'bottom');
    },
  },

  // --- Domain-level: refineInstanceof ---
  {
    name: 'Wave1 domain: refineInstanceof along extends chain',
    fn: () => {
      const v = D.opaque([], 'HTMLAnchorElement');
      const r = D.refineInstanceof(v, 'HTMLElement', TDB);
      assertEqual(r.kind, 'opaque');  // preserved (is in chain)
    },
  },
  {
    name: 'Wave1 domain: refineInstanceof unrelated type → Bottom',
    fn: () => {
      const v = D.opaque([], 'HTMLAnchorElement');
      const r = D.refineInstanceof(v, 'HTMLIFrameElement', TDB);
      assertEqual(r.kind, 'bottom');
    },
  },
  {
    name: 'Wave1 domain: refineInstanceof unknown typeName → preserved',
    fn: () => {
      const v = D.opaque([], null);
      assertEqual(D.refineInstanceof(v, 'HTMLElement', TDB).kind, 'opaque');
    },
  },
  {
    name: 'Wave1 domain: refineInstanceof Concrete primitive → Bottom',
    fn: () => {
      assertEqual(D.refineInstanceof(D.concrete('a'), 'HTMLElement', TDB).kind, 'bottom');
    },
  },
  {
    name: 'Wave1 domain: refineInstanceof on disjunct filters to matching',
    fn: () => {
      const anchor = D.opaque([1], 'HTMLAnchorElement');
      const iframe = D.opaque([2], 'HTMLIFrameElement');
      const disj = D.disjunct([anchor, iframe]);
      const r = D.refineInstanceof(disj, 'HTMLAnchorElement', TDB);
      assertEqual(r.kind, 'opaque');
      assertEqual(r.typeName, 'HTMLAnchorElement');
    },
  },
  {
    name: 'Wave1 domain: refineNotInstanceof is the inverse',
    fn: () => {
      const v = D.opaque([], 'HTMLAnchorElement');
      assertEqual(D.refineNotInstanceof(v, 'HTMLElement', TDB).kind, 'bottom');
      assertEqual(D.refineNotInstanceof(v, 'HTMLIFrameElement', TDB).kind, 'opaque');
    },
  },
  {
    name: 'Wave1 domain: refineNotInstanceof Concrete → preserved',
    fn: () => {
      // Primitives never satisfy instanceof, so the negation holds.
      assertEqual(D.refineNotInstanceof(D.concrete('a'), 'HTMLElement', TDB).kind, 'concrete');
    },
  },
  {
    name: 'Wave1 domain: typeChainIncludes walks extends chain',
    fn: () => {
      assert(D.typeChainIncludes(TDB, 'HTMLAnchorElement', 'HTMLElement'));
      assert(D.typeChainIncludes(TDB, 'HTMLAnchorElement', 'Element'));
      assert(D.typeChainIncludes(TDB, 'HTMLAnchorElement', 'HTMLAnchorElement'));
      assert(!D.typeChainIncludes(TDB, 'HTMLAnchorElement', 'HTMLIFrameElement'));
    },
  },

  // --- End-to-end via analyze() ---
  {
    name: 'Wave1 e2e: typeof contradictory branch eliminates flow',
    fn: async () => {
      const t = await analyze(
        'var x = 42; if (typeof x === "string") { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave1 e2e: typeof matching branch keeps flow',
    fn: async () => {
      const t = await analyze(
        'var x = "hi"; if (typeof x === "string") { document.body.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave1 e2e: typeof on opaque String source accepts string check',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; if (typeof x === "string") { document.body.innerHTML = x; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave1 e2e: typeof on opaque String source rejects number check',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; if (typeof x === "number") { document.body.innerHTML = x; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave1 e2e: instanceof on anchor — href sink fires',
    fn: async () => {
      const t = await analyze(
        'var el = document.createElement("a"); ' +
        'if (el instanceof HTMLAnchorElement) { el.href = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
      assertEqual(t.taintFlows[0].sink.prop, 'href');
    },
  },
  {
    name: 'Wave1 e2e: instanceof wrong type — branch dead',
    fn: async () => {
      const t = await analyze(
        'var el = document.createElement("a"); ' +
        'if (el instanceof HTMLIFrameElement) { el.src = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave1 e2e: instanceof narrows disjunct receiver to matching variant',
    fn: async () => {
      // el is Disjunct(HTMLAnchorElement, HTMLIFrameElement).
      // Inside `if (el instanceof HTMLAnchorElement)`, el refines
      // to just the anchor variant; el.href = ... fires one flow.
      const t = await analyze(
        'var el;' +
        'if (location.hash === "a") { el = document.createElement("a"); }' +
        'else                       { el = document.createElement("iframe"); }' +
        'if (el instanceof HTMLAnchorElement) { el.href = location.search; }',
        { typeDB: TDB });
      const hrefFlows = t.taintFlows.filter(f => f.sink.prop === 'href');
      assertEqual(hrefFlows.length, 1);
    },
  },
  {
    name: 'Wave1 e2e: instanceof along chain (HTMLElement accepts anchor)',
    fn: async () => {
      const t = await analyze(
        'var el = document.createElement("a"); ' +
        'if (el instanceof HTMLElement) { el.innerHTML = location.hash; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave1 e2e: typeof on mixed-type disjunct picks one variant',
    fn: async () => {
      // x is Disjunct(string, number). typeof x === "string"
      // narrows to the string variant only on the true branch.
      // No taint involved, but the analysis must not crash.
      const t = await analyze(
        'var x;' +
        'if (location.hash === "a") { x = "hello"; }' +
        'else                       { x = 42; }' +
        'if (typeof x === "string") { var y = x; }',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
];

module.exports = { tests };
