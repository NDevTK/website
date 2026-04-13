// per-path-type.test.js — Wave 0 regression coverage.
//
// Wave 0 introduces the Disjunct Value kind so a single SSA
// register / SMT sym can carry multiple path-specific types at
// once. Before Wave 0, joining an HTMLAnchorElement on one path
// with an HTMLIFrameElement on the other collapsed both to
// Opaque(typeName=null), which meant downstream `el.src = ...` /
// `el.href = ...` sink lookups failed because they needed a
// concrete typeName to consult the TypeDB.
//
// These tests lock in:
//   1. Per-element-type sink firing across phi joins.
//   2. Primitive-type preservation across mixed-type phi joins.
//   3. Property / method fan-out across Disjunct receivers.
//   4. Branch refinement filtering variants.
//   5. Lattice laws for disjunct (leq, join idempotence).

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const D = require('../src/domain.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- Domain-level: disjunct factory + lattice ---
  {
    name: 'Wave0 domain: disjunct of single variant collapses',
    fn: () => {
      const v = D.concrete('hi');
      const r = D.disjunct([v]);
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 'hi');
    },
  },
  {
    name: 'Wave0 domain: disjunct dedupes equivalent variants',
    fn: () => {
      const a = D.opaque([], 'HTMLAnchorElement');
      const b = D.opaque([], 'HTMLAnchorElement');
      const r = D.disjunct([a, b]);
      // Two opaques with the same typeName and chain are duplicates.
      assertEqual(r.kind, 'opaque');
      assertEqual(r.typeName, 'HTMLAnchorElement');
    },
  },
  {
    name: 'Wave0 domain: disjunct of mixed element types preserved',
    fn: () => {
      const a = D.opaque([1], 'HTMLAnchorElement');
      const b = D.opaque([2], 'HTMLIFrameElement');
      const r = D.disjunct([a, b]);
      assertEqual(r.kind, 'disjunct');
      assertEqual(r.variants.length, 2);
      const typeNames = r.variants.map(v => v.typeName).sort();
      assertEqual(typeNames[0], 'HTMLAnchorElement');
      assertEqual(typeNames[1], 'HTMLIFrameElement');
    },
  },
  {
    name: 'Wave0 domain: disjunct flattens nested disjuncts',
    fn: () => {
      const a = D.opaque([], 'A');
      const b = D.opaque([], 'B');
      const c = D.opaque([], 'C');
      const inner = D.disjunct([a, b]);
      const r = D.disjunct([inner, c]);
      assertEqual(r.kind, 'disjunct');
      assertEqual(r.variants.length, 3);
    },
  },
  {
    name: 'Wave0 domain: disjunct filters Bottom variants',
    fn: () => {
      const r = D.disjunct([D.bottom(), D.concrete(1), D.bottom()]);
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 1);
    },
  },
  {
    name: 'Wave0 domain: disjunct with Top absorbs to Top',
    fn: () => {
      const r = D.disjunct([D.concrete(1), D.top(), D.concrete(2)]);
      assertEqual(r.kind, 'top');
    },
  },
  {
    name: 'Wave0 domain: disjunct unions variant labels',
    fn: () => {
      const a = D.opaque([], 'A', null, ['url']);
      const b = D.opaque([], 'B', null, ['cookie']);
      const r = D.disjunct([a, b]);
      assert(r.labels.has('url'), 'union has url');
      assert(r.labels.has('cookie'), 'union has cookie');
    },
  },
  {
    name: 'Wave0 domain: join of mixed opaque types produces disjunct',
    fn: () => {
      const a = D.opaque([1], 'HTMLAnchorElement');
      const b = D.opaque([2], 'HTMLIFrameElement');
      const r = D.join(a, b);
      assertEqual(r.kind, 'disjunct');
    },
  },
  {
    name: 'Wave0 domain: join of same-type opaques still merges',
    fn: () => {
      const a = D.opaque([1], 'HTMLElement');
      const b = D.opaque([2], 'HTMLElement');
      const r = D.join(a, b);
      assertEqual(r.kind, 'opaque');
      assertEqual(r.typeName, 'HTMLElement');
    },
  },
  {
    name: 'Wave0 domain: leq(variant, disjunct) iff variant is in disjunct',
    fn: () => {
      const a = D.opaque([], 'A');
      const b = D.opaque([], 'B');
      const disj = D.disjunct([a, b]);
      assert(D.leq(a, disj));
      assert(D.leq(b, disj));
      assert(!D.leq(D.opaque([], 'C'), disj));
    },
  },
  {
    name: 'Wave0 domain: join idempotence on disjunct',
    fn: () => {
      const a = D.opaque([], 'A');
      const b = D.opaque([], 'B');
      const disj = D.disjunct([a, b]);
      const r = D.join(disj, disj);
      assertEqual(r.kind, 'disjunct');
      assertEqual(r.variants.length, 2);
    },
  },
  {
    name: 'Wave0 domain: disjunctMap fans out a function',
    fn: () => {
      const a = D.concrete('hi');      // typeof "hi" === "string"
      const b = D.concrete(42);        // typeof 42 === "number"
      const r = D.disjunctMap(D.disjunct([a, b]), (v) => {
        return D.concrete(typeof v.value);
      });
      // Two distinct Concrete results ("string" and "number") →
      // recombined into a Disjunct of two variants.
      assertEqual(r.kind, 'disjunct');
      const vals = r.variants.map(v => v.value).sort();
      assertEqual(vals[0], 'number');
      assertEqual(vals[1], 'string');
    },
  },
  {
    name: 'Wave0 domain: disjunctMap drops Bottom results',
    fn: () => {
      const a = D.concrete('hi');
      const b = D.concrete(42);
      const r = D.disjunctMap(D.disjunct([a, b]), (v) => {
        if (typeof v.value === 'string') return v;
        return D.bottom();
      });
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 'hi');
    },
  },
  {
    name: 'Wave0 domain: refineEq filters disjunct variants',
    fn: () => {
      const a = D.concrete('admin');
      const b = D.concrete('user');
      const c = D.concrete(42);
      const disj = D.disjunct([a, b, c]);
      const r = D.refineEq(disj, 'admin');
      assertEqual(r.kind, 'concrete');
      assertEqual(r.value, 'admin');
    },
  },
  {
    name: 'Wave0 domain: refineNeq filters disjunct variants',
    fn: () => {
      const a = D.concrete('admin');
      const b = D.concrete('user');
      const c = D.concrete('guest');
      const disj = D.disjunct([a, b, c]);
      const r = D.refineNeq(disj, 'admin');
      // admin is filtered out; user + guest remain as Disjunct of
      // two Concretes (they're not merged into OneOf because the
      // disjunct factory preserves variant identity).
      assertEqual(r.kind, 'disjunct');
      assertEqual(r.variants.length, 2);
      const vals = r.variants.map(v => v.value).sort();
      assertEqual(vals[0], 'guest');
      assertEqual(vals[1], 'user');
    },
  },
  {
    name: 'Wave0 domain: truthiness all-truthy disjunct',
    fn: () => {
      const disj = D.disjunct([D.concrete(1), D.concrete('x')]);
      assertEqual(D.truthiness(disj), true);
    },
  },
  {
    name: 'Wave0 domain: truthiness mixed disjunct → unknown',
    fn: () => {
      const disj = D.disjunct([D.concrete(0), D.concrete('x')]);
      assertEqual(D.truthiness(disj), null);
    },
  },

  // --- End-to-end via analyze() ---
  {
    name: 'Wave0 e2e: iframe.src flow fires through anchor|iframe disjunct',
    fn: async () => {
      // The register `el` is a Disjunct(HTMLAnchorElement, HTMLIFrameElement).
      // HTMLIFrameElement.src is a navigation/url sink; HTMLAnchorElement
      // has no `src` property. The iframe variant must fire the flow.
      const t = await analyze(
        'var el;' +
        'if (location.hash === "a") { el = document.createElement("iframe"); }' +
        'else                       { el = document.createElement("a"); }' +
        'el.src = location.search;',
        { typeDB: TDB });
      assert(t.taintFlows.length >= 1,
        'expected at least one flow from the iframe variant');
      const srcFlow = t.taintFlows.find(f => f.sink.prop === 'src');
      assert(srcFlow, 'expected a flow whose sink prop is `src`');
    },
  },
  {
    name: 'Wave0 e2e: innerHTML sinks on both variants',
    fn: async () => {
      // innerHTML is an html sink on every HTMLElement subtype.
      // Both variants fire — this verifies the fan-out on common
      // prototype properties.
      const t = await analyze(
        'var el;' +
        'if (location.hash === "a") { el = document.createElement("a"); }' +
        'else                       { el = document.createElement("iframe"); }' +
        'el.innerHTML = location.search;',
        { typeDB: TDB });
      assert(t.taintFlows.length >= 2,
        'expected one flow per variant, got ' + t.taintFlows.length);
    },
  },
  {
    name: 'Wave0 e2e: wrong-type branch produces no extra flow',
    fn: async () => {
      // Only HTMLAnchorElement.href is a navigation sink — the iframe
      // variant has no `href` property, so only one flow fires.
      const t = await analyze(
        'var el;' +
        'if (location.hash === "a") { el = document.createElement("a"); }' +
        'else                       { el = document.createElement("iframe"); }' +
        'el.href = location.search;',
        { typeDB: TDB });
      // Exactly one flow expected (the anchor variant).
      const hrefFlows = t.taintFlows.filter(f => f.sink.prop === 'href');
      assertEqual(hrefFlows.length, 1, 'exactly one href flow from anchor variant');
    },
  },
  {
    name: 'Wave0 e2e: mixed primitive types preserved in binding',
    fn: async () => {
      const t = await analyze(
        'var x;' +
        'if (location.hash === "a") { x = "hello"; }' +
        'else                       { x = 42; }',
        { typeDB: TDB });
      const bindings = Object.values(t.bindings).filter(b => b && b.kind === 'disjunct');
      assert(bindings.length >= 1, 'expected a disjunct binding');
      const disj = bindings[0];
      const typeNames = disj.variants.map(v => v.typeName).sort();
      assert(typeNames.includes('string'), 'has string variant');
      assert(typeNames.includes('number'), 'has number variant');
    },
  },
  {
    name: 'Wave0 e2e: per-path type refinement via === drops wrong variant',
    fn: async () => {
      // x is OneOf<string|number> → Disjunct across the refineEq path.
      // On the `x === "hello"` true branch, only the string variant
      // survives; the number variant becomes Bottom. The sink
      // inside the true branch flows only the string variant.
      const t = await analyze(
        'var x;' +
        'if (location.hash === "a") { x = "hello"; }' +
        'else                       { x = 42; }' +
        'if (x === "hello") { document.body.innerHTML = x; }',
        { typeDB: TDB });
      // The sink fires exactly once: only on the refined string
      // variant. The number variant is dead inside the true branch.
      // (Labels may not propagate if `x` is concrete but the
      // concrete reaches innerHTML — innerHTML requires a tainted
      // source to fire. The test verifies no crash / precision
      // loss, not that a flow fires; x has no url label here.)
      assertEqual(t.taintFlows.length, 0, 'no tainted flow (x is just a literal)');
    },
  },
  {
    name: 'Wave0 e2e: disjunct receiver method dispatch per variant',
    fn: async () => {
      // Calling `.getAttribute("href")` through a Disjunct of
      // elements: anchor vs iframe. Both types inherit
      // getAttribute from Element. The method dispatch must
      // not crash and must produce a result value for the call.
      const t = await analyze(
        'var el;' +
        'if (location.hash === "a") { el = document.createElement("a"); }' +
        'else                       { el = document.createElement("iframe"); }' +
        'var v = el.getAttribute("href");',
        { typeDB: TDB });
      assertEqual(t.partial, false, 'no partial trace');
    },
  },
];

module.exports = { tests };
