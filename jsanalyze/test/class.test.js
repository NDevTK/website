// class.test.js — Wave 6 regression coverage.
//
// Wave 6 lands JavaScript class lowering. The parser recognises
// `class Name [extends Parent] { body }` and the body is parsed
// into MethodDefinition / PropertyDefinition nodes. The IR
// builder desugars each class into:
//
//   1. A FunctionDeclaration whose body is a synthesized block
//      of `this.field = init;` and `this.method = function(){...}`
//      statements, followed by the original constructor body.
//   2. One SetProp per static method / field, emitted after the
//      class declaration, with the class register as receiver.
//
// `new ClassName(args)` allocates a fresh ObjectRef, walks the
// (synthesised) constructor body with `this` bound to the new
// object, and returns the object. applyGetThis reads
// ctx._currentThisValue which is set by applyNew / applyCall.
// Method calls `obj.method(args)` bind `this` to the receiver
// via the same ctx._currentThisValue mechanism.
//
// The caller's state adopts the callee's heap writes after a
// constructor / method walk completes, so side effects on
// `this` inside a method are visible to subsequent reads.
//
// Known limitations (raise soundness assumptions, don't fire
// flows precisely):
//   * `extends` chain is not modeled — super lookups fall
//     through to the opaque path.
//   * Static methods / fields are SetProp'd on the class
//     register, which is a Closure. Without a heap cell for
//     the class, the writes are lost (heap-escape). Direct
//     taint through a static method body does NOT propagate
//     to its caller in this wave.
//   * Private fields (`#x`), getters/setters parse but are
//     skipped by the IR builder.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- Parse acceptance ---
  {
    name: 'Wave6: empty class parses',
    fn: async () => {
      const t = await analyze('class Foo {}', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave6: class with constructor parses',
    fn: async () => {
      const t = await analyze(
        'class Foo { constructor(x) { this.x = x; } }', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave6: class with instance method parses',
    fn: async () => {
      const t = await analyze(
        'class Foo { constructor(x) { this.x = x; } getX() { return this.x; } }',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave6: class with extends parses and walks parent ctor',
    fn: async () => {
      const t = await analyze(
        'class Parent { constructor() { this.p = 1; } } ' +
        'class Child extends Parent { constructor() { super(); this.c = 2; } } ' +
        'var x = new Child();',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave6: extends — parent ctor fields visible on child instance',
    fn: async () => {
      const t = await analyze(
        'class Parent { constructor(x) { this.tainted = x; } } ' +
        'class Child extends Parent { constructor(x) { super(x); } } ' +
        'var c = new Child(location.hash); document.body.innerHTML = c.tainted;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave6: extends — parent instance method inherited',
    fn: async () => {
      const t = await analyze(
        'class Parent { ' +
        '  constructor(x) { this.x = x; this.getX = function() { return this.x; }; } ' +
        '} ' +
        'class Child extends Parent { ' +
        '  constructor(x) { super(x); } ' +
        '} ' +
        'var c = new Child(location.hash); document.body.innerHTML = c.getX();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave6: extends chain of 3 classes',
    fn: async () => {
      const t = await analyze(
        'class A { constructor(x) { this.a = x; } } ' +
        'class B extends A { constructor(x) { super(x); } } ' +
        'class C extends B { constructor(x) { super(x); } } ' +
        'var c = new C(location.hash); document.body.innerHTML = c.a;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave6: super.method(args) reads inherited method via this',
    fn: async () => {
      // Parent installs getTaint on this; Child extends and
      // can call `super.getTaint()` which reads the inherited
      // method on the instance.
      const t = await analyze(
        'class Parent { ' +
        '  constructor(x) { this.x = x; this.getTaint = function() { return this.x; }; } ' +
        '} ' +
        'class Child extends Parent { ' +
        '  constructor(x) { super(x); } ' +
        '  echo() { return super.getTaint(); } ' +
        '} ' +
        'var c = new Child(location.hash); document.body.innerHTML = c.echo();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },

  // --- Instantiation ---
  {
    name: 'Wave6: new Foo() returns an object',
    fn: async () => {
      const t = await analyze(
        'class Foo { constructor() { this.x = 1; } } var f = new Foo();',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },

  // --- Taint flows through class fields / methods ---
  {
    name: 'Wave6: constructor field write + instance read flows taint',
    fn: async () => {
      const t = await analyze(
        'class Foo { constructor(x) { this.x = x; } } ' +
        'var f = new Foo(location.hash); document.body.innerHTML = f.x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave6: instance method returning tainted field',
    fn: async () => {
      const t = await analyze(
        'class Foo { ' +
        '  constructor(x) { this.x = x; } ' +
        '  getX() { return this.x; } ' +
        '} ' +
        'var f = new Foo(location.hash); document.body.innerHTML = f.getX();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave6: instance method with safe return produces no flow',
    fn: async () => {
      const t = await analyze(
        'class Foo { ' +
        '  constructor(x) { this.x = x; } ' +
        '  getSafe() { return "ok"; } ' +
        '} ' +
        'var f = new Foo(location.hash); document.body.innerHTML = f.getSafe();',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave6: class expression works',
    fn: async () => {
      const t = await analyze(
        'var Foo = class { constructor(x) { this.x = x; } }; ' +
        'var f = new Foo(location.hash); document.body.innerHTML = f.x;',
        { typeDB: TDB });
      // Class expressions parse; if f.x propagates taint this
      // fires; otherwise we still want partial=false.
      assertEqual(t.partial, false);
    },
  },
];

module.exports = { tests };
