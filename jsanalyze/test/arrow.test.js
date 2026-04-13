// arrow.test.js — Wave 5.1 regression coverage.
//
// Arrow functions are lowered via the same machinery as
// FunctionExpression: the parser builds an ArrowFunctionExpression
// AST node; the IR builder synthesises a FunctionDeclaration-shaped
// body (wrapping concise expression bodies in a BlockStatement +
// ReturnStatement) and delegates to lowerFunctionDecl.
//
// Parser responsibilities:
//   * Single-identifier arrow `x => body` (no parens)
//   * Zero-param `() => body`
//   * Paren params `(x) => body`, `(x, y) => body`
//   * Block bodies `(x) => { ... }`
//   * Distinguish `(x)` paren expression from `(x) => ...` by
//     peeking the token after the closing `)`
//
// Lowering responsibilities: same as FunctionExpression.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'Wave5.1: single-ident arrow parses and lowers',
    fn: async () => {
      const t = await analyze('var f = x => x + 1; var y = f(2);', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.1: paren-ident arrow',
    fn: async () => {
      const t = await analyze('var f = (x) => x + 1; var y = f(2);', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.1: zero-param arrow',
    fn: async () => {
      const t = await analyze('var f = () => 42; var y = f();', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.1: multi-param arrow',
    fn: async () => {
      const t = await analyze('var f = (a, b) => a + b; var y = f(1, 2);', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.1: block-body arrow',
    fn: async () => {
      const t = await analyze('var f = (x) => { return x + 1; }; var y = f(2);', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.1: arrow sinking tainted arg fires flow',
    fn: async () => {
      const t = await analyze(
        'var sink = (x) => { document.body.innerHTML = x; }; sink(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5.1: arrow returning tainted arg fires flow',
    fn: async () => {
      const t = await analyze(
        'var id = (x) => x; document.body.innerHTML = id(location.hash);',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5.1: arrow as callback receives and sinks taint',
    fn: async () => {
      const t = await analyze(
        'var run = (cb) => cb(location.hash); run((x) => { document.body.innerHTML = x; });',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave5.1: paren expression still works (not an arrow)',
    fn: async () => {
      const t = await analyze('var x = (1 + 2) * 3;', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave5.1: comma paren expression works',
    fn: async () => {
      // `(a, b)` is a SequenceExpression that evaluates to `b`.
      const t = await analyze('var x = (1, 2);', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
];

module.exports = { tests };
