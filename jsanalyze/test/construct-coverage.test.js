// construct-coverage.test.js — every JavaScript construct must
// carry taint.
//
// A static analyser fails in two ways. It can report something
// wrong, which a reviewer notices. Or it can report NOTHING for
// code it silently declined to understand — and "no findings"
// is exactly what a clean file looks like. The second failure
// mode is the dangerous one, and it is what a parser or IR gap
// produces: `for (const el of els) el.innerHTML = untrusted`
// analysed to zero findings, with no error and no assumption.
//
// So each case below runs the same flow — `location.hash` into
// an html sink — through one language construct. If the
// construct is dropped anywhere in parse → IR → transfer, the
// flow disappears and the case fails. The negative cases matter
// just as much: they pin down that we are tracking a real
// dataflow rather than blanket-tainting everything.
//
// Add a case here whenever the engine learns a new construct.

'use strict';

const assert = require('assert');
const { analyze } = require('../src/index.js');

const SINK = 'document.body.innerHTML = h;';

// Constructs that must carry `location.hash` to the sink.
const CARRIES_TAINT = {
  // --- baseline ---
  'plain assignment':    'var h = location.hash; ' + SINK,

  // --- loops ---
  'for':                 'var h=""; for (var i=0;i<1;i++) { h = location.hash; } ' + SINK,
  'while':               'var h=""; var i=0; while (i<1) { h = location.hash; i++; } ' + SINK,
  'do-while':            'var h=""; var i=0; do { h = location.hash; i++; } while (i<1); ' + SINK,
  'do-while body value': 'var h=""; do { h = location.hash; } while (0); ' + SINK,
  'for-of':              'var h=""; for (const x of [location.hash]) { h = x; } ' + SINK,
  'for-of bare target':  'var x; var h=""; for (x of [location.hash]) { h = x; } ' + SINK,
  'for-of destructured': 'var h=""; for (const {v} of [{v:location.hash}]) { h = v; } ' + SINK,
  'for-of nested':       'var h=""; for (const a of [[location.hash]]) { for (const b of a) { h = b; } } ' + SINK,
  'for-of sink inside':  'for (const x of [location.hash]) { document.body.innerHTML = x; }',
  'for-in':              'var o = {a: location.hash}; var h=""; for (var k in o) { h = o[k]; } ' + SINK,
  'labeled break':       'var h=""; outer: for (var i=0;i<1;i++) { h = location.hash; break outer; } ' + SINK,

  // --- accessors ---
  'object getter':       'var o = { get v() { return location.hash; } }; var h = o.v; ' + SINK,
  'object setter':       'var o = { set v(x) { this._x = x; } }; o.v = location.hash; var h = o._x; ' + SINK,
  'class getter':        'class C { get v() { return location.hash; } } var c = new C(); var h = c.v; ' + SINK,
  'sink inside getter':  'var o = { get v(){ document.body.innerHTML = location.hash; } }; var z = o.v;',
  'sink inside setter':  'var o = { set v(x){ document.body.innerHTML = x; } }; o.v = location.hash;',

  // --- classes ---
  'class method':        'class C { m(){ return location.hash; } } var h = new C().m(); ' + SINK,
  'class field':         'class C { f = location.hash; } var h = new C().f; ' + SINK,
  'class private field': 'class C { #p = location.hash; get(){ return this.#p; } } var h = new C().get(); ' + SINK,
  'class static field':  'class C { static s = location.hash; } var h = C.s; ' + SINK,
  'class extends':       'class A { m(){ return location.hash; } } class B extends A {} var h = new B().m(); ' + SINK,
  'class expression':    'var C = class { m(){ return location.hash; } }; var h = new C().m(); ' + SINK,
  'named class expr':    'var C = class Q { m(){ return location.hash; } }; var h = new C().m(); ' + SINK,
  'constructor this':    'function C(){ this.v = location.hash; } var h = new C().v; ' + SINK,

  // --- functions ---
  'arrow concise':       'var f = () => location.hash; var h = f(); ' + SINK,
  'arrow block':         'var f = () => { return location.hash; }; var h = f(); ' + SINK,
  'iife':                'var h = (function(){ return location.hash; })(); ' + SINK,
  'default param':       'function f(x = location.hash){return x;} var h = f(); ' + SINK,
  'rest param':          'function f(...a){return a[0];} var h = f(location.hash); ' + SINK,
  'spread call':         'function f(x){return x;} var h = f(...[location.hash]); ' + SINK,
  'sink in generator':   'function* g(){ document.body.innerHTML = location.hash; } g();',

  // --- async ---
  'async fn + then':     'async function f(){ return location.hash; } f().then(function(h){ ' + SINK + ' });',
  'async arrow + then':  'var f = async () => location.hash; f().then(function(h){ ' + SINK + ' });',
  'await value':         'async function g(){ return location.hash; } async function f(){ var h = await g(); ' + SINK + ' } f();',
  'async iife':          '(async function(){ var h = location.hash; ' + SINK + ' })();',
  'then callback body':  'fetch("/x").then(function(r){ document.body.innerHTML = location.hash; });',
  'then resolution':     'fetch("/x").then(function(r){ document.body.innerHTML = r; });',
  'catch callback body': 'fetch("/x").catch(function(e){ document.body.innerHTML = location.hash; });',

  // --- destructuring ---
  'array destructure':   'var [h] = [location.hash]; ' + SINK,
  'object destructure':  'var {v: h} = {v: location.hash}; ' + SINK,
  'nested destructure':  'var {a:{b:h}} = {a:{b:location.hash}}; ' + SINK,
  'destructure default': 'var {v: h = location.hash} = {}; ' + SINK,
  'shorthand default':   'var {h = location.hash} = {}; ' + SINK,
  'string-key pattern':  'var {"a-b": h} = {"a-b": location.hash}; ' + SINK,
  'param destructure':   'function f({v}){return v;} var h = f({v:location.hash}); ' + SINK,

  // --- expressions ---
  'comma operator':      'var h = (0, location.hash); ' + SINK,
  'comma side effect':   'var t=""; var h = (t = location.hash, t); ' + SINK,
  'ternary':             'var h = 1 ? location.hash : ""; ' + SINK,
  'optional chain':      'var o = {a:{b:location.hash}}; var h = o?.a?.b; ' + SINK,
  'nullish coalesce':    'var h = null ?? location.hash; ' + SINK,
  'nullish assign':      'var h = null; h ??= location.hash; ' + SINK,
  'logical or assign':   'var h = ""; h ||= location.hash; ' + SINK,
  'template literal':    'var h = `${location.hash}`; ' + SINK,
  'tagged template':     'function t(s,v){return v;} var h = t`x${location.hash}`; ' + SINK,
  'tagged template arg': 'function t(s,v){ document.body.innerHTML = v; } t`x${location.hash}`;',
  'array spread':        'var a = [...[location.hash]]; var h = a[0]; ' + SINK,
  'object spread':       'var o = {...{v: location.hash}}; var h = o.v; ' + SINK,
  'computed key':        'var k="v"; var o = {[k]: location.hash}; var h = o.v; ' + SINK,
  'shorthand method':    'var o = { m(){ return location.hash; } }; var h = o.m(); ' + SINK,
  'shorthand property':  'var v = location.hash; var o = {v}; var h = o.v; ' + SINK,

  // --- statements ---
  'try/catch':           'var h=""; try { h = location.hash; } catch (e) {} ' + SINK,
  'try/finally':         'var h=""; try { h = location.hash; } finally {} ' + SINK,
  'switch':              'var h=""; switch (1) { case 1: h = location.hash; break; } ' + SINK,
  'block scope':         '{ let h = location.hash; ' + SINK + ' }',

  // --- typed DOM iterables ---
  'NodeList index':      'document.querySelectorAll("a")[0].innerHTML = location.hash;',
  'for-of NodeList':     'for (const el of document.querySelectorAll("a")) { el.innerHTML = location.hash; }',
};

// Constructs where the same shape carries NO taint. These guard
// against "everything is tainted", which would make the suite
// above pass for the wrong reason.
const CARRIES_NOTHING = {
  'for-of over constants':  'var h="safe"; for (const x of [1,2]) { } ' + SINK,
  'do-while no write':      'var h="safe"; var i=0; do { i++; } while (i<1); ' + SINK,
  'clean getter':           'var o = { get v() { return "safe"; } }; document.body.innerHTML = o.v;',
  'data property shadows':  'var o = { get v(){ return location.hash; } }; o.v = "safe";',
  'clean async':            'async function f(){ return "safe"; } f().then(function(h){ ' + SINK + ' });',
  'unrelated dataset key':  'document.getElementById("o").dataset.a = location.hash;' +
                            'document.body.innerHTML = document.getElementById("o").dataset.b;',
  'distinct elements':      'document.getElementById("a").dataset.v = location.hash;' +
                            'eval(document.getElementById("b").dataset.v);',
};

// Constructs the engine must PARSE without failing, even where
// it cannot follow the value. A parse error is not a local
// problem: index.js abandons the whole file, so one unsupported
// construct erases every finding in it.
const MUST_PARSE = {
  'generator declaration': 'function* g(){ yield location.hash; } var x = g();',
  'generator expression':  'var g = function*(){ yield 1; }; g();',
  'bare yield':            'function* g(){ yield; } g();',
  'async arrow IIFE':      '(async () => { await Promise.resolve(1); })();',
  'async method':          'var o = { async m(){ return 1; } }; o.m();',
  'new.target':            'function C(){ if (new.target) { this.v = 1; } } new C();',
  'async as identifier':   'var async = 1; var y = async; f(async);',
  'call named async':      'function async(x){ return x; } async(1);',
  'labelled continue':     'outer: for (var i=0;i<2;i++) { continue outer; }',
  'nested new chain':      'function A(){ this.b = function(){ return 1; }; } var r = new A().b();',
  'regex with slash':      'var r = /a\\/b/g; var h = location.hash; ' + SINK,

  // Real-world shapes this parser could not read. Each of these
  // failed on the repo's OWN sources, so every finding in those
  // files was silently absent.
  //
  // The string cases are one bug: a string whose CONTENTS spell
  // an operator was treated as that operator.
  'string "+" compared':   'if (op === "+") { f(); }',
  'string "+" case label': 'switch (op) { case "+": return 1; }',
  'string "typeof"':       'if (x === "typeof" && y) { f(); }',
  'string "!" argument':   'f("!");',
  'operator strings mixed': 'var op = a === "++" ? "+" : "-";',
  'unary ops still work':  'var a = !x; var b = ~y; var c = -z + +w; ' +
                           'var d = typeof q; var e = void 0; delete o.p;',
  // Reserved words are legal property keys — the engine's own
  // TypeDB is written with `extends:`.
  'keyword object keys':   'var o = { extends: 1, default: 2, class: 3, in: 4, for: 5 };',
  // Trailing commas are what every formatter emits.
  'trailing comma call':   'f(a, b,);',
  'trailing comma params': 'function g(a, b,) { return a; }',
  'trailing comma arrow':  'var f = (a, b,) => a;',
  'for await':             'for await (const x of y) { f(x); }',
  'yield array':           'function* g(){ yield [1, 2]; }',
  'yield parenthesised':   'function* g(){ yield (1); }',

  // Shapes taken from production bundles (React, jQuery, lodash,
  // Vue, Angular, d3, moment, three.js, Babel, TypeScript,
  // Monaco). Every one of them failed, and each failure cost the
  // whole bundle. Minifiers and bundlers emit these constantly;
  // hand-written source almost never does, which is why they
  // stayed invisible until the parser was run over real code.
  'nested ternary consequent': 'var x = a ? b ? 1 : 2 : 3;',
  'ternary chain deep':        'var x = a?b?c?1:2:3:4;',
  'sequence in if':            'if (a = f(), a !== X) { g(); }',
  'sequence in while':         'while (a = f(), a) { g(); }',
  'sequence statement':        'a(), b(), c();',
  'do-while comma body':       'do t = f(t), g(t); while (t);',
  'for-in bare identifier':    'for (c in a) { f(c); }',
  'for-in member target':      'for (o.p in a) { f(); }',
  'for-in comma right':        'for (n in o = f(o), o) { g(n); }',
  'no-in in for init':         'for (var i = ("x" in o); i; ) break;',
  'no-in inside call':         'for (var i = f("x" in o); i; ) break;',
  'no-in in nested body':      'for (var f = function(){ if ("x" in o) g(); }; 0; ) break;',
  'arrow object pattern':      'var f = ({a, b}) => a;',
  'arrow array pattern':       'var f = ([x, y]) => x;',
  'arrow rest param':          'var f = (a, ...rest) => a;',
  'arrow nested pattern':      'var f = ({a: x = 1, ...r}) => x;',
  'arrow deep pattern':        'var f = ([[[[x]]]]) => x;',
  'class keyword method':      'class C { delete(t){ return t; } new(){ return 1; } }',
  'class computed method':     'class C { [Symbol.iterator](){ return 1; } }',
  'object literal key method': 'var o = { "src/a.ts"(){ return 1; } };',
  'object computed method':    'var o = { [k](){ return 1; } };',
  'object generator method':   'var o = { *g(){ yield 1; } };',
  'object computed generator': 'var o = { *[Symbol.iterator](){ yield 1; } };',
  'object async method':       'var o = { async m(){ return 1; } };',
  'async as plain key':        'var o = { async: 1, get: 2, set: 3 };',
  'pattern keyword key':       'var {mixins: n, extends: r} = t;',
};

function makeFlowTest(name, src, expectFlow) {
  return {
    name: 'construct: ' + name + (expectFlow ? '' : ' (no flow)'),
    fn: async () => {
      const trace = await analyze(src);
      assert.deepStrictEqual(trace.warnings, [],
        'must analyse without warnings; got: ' +
        trace.warnings.map(w => w.message).join('; '));
      const flows = trace.taintFlows.length;
      if (expectFlow) {
        assert.ok(flows > 0,
          'the flow must survive this construct — zero findings here means ' +
          'the construct was silently dropped, not that the code is safe');
      } else {
        assert.strictEqual(flows, 0,
          'expected no flow, got ' + flows +
          ' — a finding here means taint is being over-propagated');
      }
    },
  };
}

const tests = [];
for (const name in CARRIES_TAINT) {
  tests.push(makeFlowTest(name, CARRIES_TAINT[name], true));
}
for (const name in CARRIES_NOTHING) {
  tests.push(makeFlowTest(name, CARRIES_NOTHING[name], false));
}
for (const name in MUST_PARSE) {
  tests.push({
    name: 'parses: ' + name,
    fn: async () => {
      const trace = await analyze(MUST_PARSE[name]);
      const parseErrors = trace.warnings.filter(w => /parse\/IR error/.test(w.message));
      assert.deepStrictEqual(parseErrors, [],
        'a parse error abandons the whole file, taking every finding in it: ' +
        parseErrors.map(w => w.message).join('; '));
    },
  });
}

module.exports = { tests };
