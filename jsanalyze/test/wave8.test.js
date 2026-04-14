// wave8.test.js — Wave 8 regression coverage.
//
// Wave 8 replaces conservative "unimplemented" fallbacks with
// precise lowerings for:
//
//   * Rest parameters — `function f(...args) { ... }`: applyCall
//     collects excess args into a fresh Array ObjectRef.
//   * Spread arguments — `f(a, ...b, c)`: applyCall's
//     expandSpreadArgs helper reads the spread source's
//     integer-keyed fields and fans out positional args.
//   * Array-literal spread — `[0, ...src, 99]`: applyAlloc
//     merges the spread source's elements into the new array.
//   * Object-literal spread — `{...src, a: 1}`: applyAlloc
//     copies the spread source's fields into the new object.
//   * Object-literal computed keys — `{[k]: v}`: applyAlloc
//     evaluates each computed key register at runtime.
//   * Object/array rest destructuring — `var {a, ...rest} = o`
//     and `var [x, ...rest] = arr`: a dedicated ALLOC with
//     `restSource` + `restOmit` / `restSliceFrom` hints.
//   * Catch parameter binding — the thrown expression flows
//     into the catch param via a phi over explicit throw sites.
//     Destructuring patterns on the catch param are supported.
//   * Destructuring assignment — `[a, b] = arr` and `({a} = o)`.
//     The parser's ArrayExpression / ObjectExpression on the
//     left-hand side is reinterpreted as a pattern via
//     `exprToPattern`.
//   * Compound member assignment — `obj.prop += val`,
//     `obj[k] += val`: read old, BinOp, write back.
//   * Update expressions on member targets — `obj.prop++`,
//     `obj[k]--`: same read-modify-write pattern.
//   * Implicit global creation — `x = 1;` at module top level
//     where x wasn't declared. Binds in the top function frame
//     with an ENVIRONMENTAL assumption.
//   * Computed method call — `obj[k](args)`: emit_call_member_index
//     task emits GetIndex before emit_call.
//   * Private class fields and methods — `#name` tokens are
//     stored as regular fields with a `#` prefix on the name.
//   * Getters/setters in object literals — stored under
//     `__get_<name>__` / `__set_<name>__` so accessor bodies
//     are still walked for taint.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'Wave8: rest param collects args into array',
    fn: async () => {
      const t = await analyze(
        'function f(...args) { document.body.innerHTML = args[0]; } f(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: rest param with leading fixed args',
    fn: async () => {
      const t = await analyze(
        'function f(a, ...rest) { document.body.innerHTML = rest[0]; } f("safe", location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: spread in call expands positional args',
    fn: async () => {
      const t = await analyze(
        'function f(a, b) { document.body.innerHTML = b; } var arr = ["safe", location.hash]; f(...arr);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: spread + rest roundtrip',
    fn: async () => {
      const t = await analyze(
        'function f(...args) { document.body.innerHTML = args[1]; } var arr = ["safe", location.hash]; f(...arr);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: array literal with spread merges elements',
    fn: async () => {
      const t = await analyze(
        'var src = [location.hash, "safe"]; var arr = [0, ...src, 99]; document.body.innerHTML = arr[1];',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: object literal with spread merges fields',
    fn: async () => {
      const t = await analyze(
        'var src = {a: location.hash}; var o = {b: 1, ...src}; document.body.innerHTML = o.a;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: computed key object literal',
    fn: async () => {
      const t = await analyze(
        'var k = "x"; var o = {[k]: location.hash}; document.body.innerHTML = o.x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: object rest destructuring',
    fn: async () => {
      const t = await analyze(
        'var o = {a: 1, b: location.hash, c: 2}; var {a, ...rest} = o; document.body.innerHTML = rest.b;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: object rest destructuring omits named fields',
    fn: async () => {
      const t = await analyze(
        'var o = {a: location.hash, b: "safe"}; var {a, ...rest} = o; document.body.innerHTML = rest.a;',
        { typeDB: TDB });
      // `a` was destructured away, so rest.a is undefined, no flow.
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave8: array rest destructuring',
    fn: async () => {
      const t = await analyze(
        'var arr = [0, location.hash, 2]; var [x, ...rest] = arr; document.body.innerHTML = rest[0];',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: catch parameter binds explicit throw value',
    fn: async () => {
      const t = await analyze(
        'try { throw location.hash; } catch (e) { document.body.innerHTML = e; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: catch param destructuring',
    fn: async () => {
      const t = await analyze(
        'try { throw { x: location.hash }; } catch ({x}) { document.body.innerHTML = x; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: multiple throws produce catch-param phi',
    fn: async () => {
      const t = await analyze(
        'try { if (1) throw location.hash; else throw "safe"; } catch (e) { document.body.innerHTML = e; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: destructuring array assignment',
    fn: async () => {
      const t = await analyze(
        'var x; var y; [x, y] = [location.hash, "safe"]; document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: destructuring object assignment',
    fn: async () => {
      const t = await analyze(
        'var a; ({a} = {a: location.hash}); document.body.innerHTML = a;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: member compound assignment (obj.prop += val)',
    fn: async () => {
      const t = await analyze(
        'var o = {x: "safe"}; o.x = location.hash; o.x += "!"; document.body.innerHTML = o.x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: update on member target (obj.prop++)',
    fn: async () => {
      const t = await analyze('var o = {x: 0}; o.x++; var y = o.x;', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave8: implicit global creation via assignment',
    fn: async () => {
      const t = await analyze(
        'x = location.hash; document.body.innerHTML = x;', { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: obj[key](args) computed method call',
    fn: async () => {
      const t = await analyze(
        'var obj = { m: function(x) { document.body.innerHTML = x; } }; var k = "m"; obj[k](location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: private class field flows',
    fn: async () => {
      const t = await analyze(
        'class Foo { #x = location.hash; get() { return this.#x; } } var f = new Foo(); document.body.innerHTML = f.get();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: private class method',
    fn: async () => {
      const t = await analyze(
        'class Foo { constructor(x) { this.x = x; } #h() { return this.x; } expose() { return this.#h(); } } var f = new Foo(location.hash); document.body.innerHTML = f.expose();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave8: object literal getter stored under mangled name',
    fn: async () => {
      // The getter function body runs when invoked via the
      // mangled name; the flow propagates through the returned
      // location.hash.
      const t = await analyze(
        'var o = { get x() { return location.hash; } }; document.body.innerHTML = o.__get_x__();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
];

module.exports = { tests };
