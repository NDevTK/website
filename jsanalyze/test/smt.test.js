// smt.test.js — coverage for the SMT formula AST primitives.
//
// Verifies that constructors produce well-formed SMT-LIB
// expressions, that const-folding short-circuits, that sort
// upgrades happen on cross-type comparisons, and that
// incompatible flags propagate.

'use strict';

const S = require('../src/smt.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- mkSym / mkConst ---
  {
    name: 'mkSym: produces named symbol with Int default sort',
    fn: () => {
      const x = S.mkSym('x');
      assertEqual(x.expr, '|x|');
      assertEqual(x.sorts.x, 'Int');
      assertEqual(x.symName, 'x');
      assertEqual(x.isBool, false);
    },
  },
  {
    name: 'mkConst: number',
    fn: () => {
      const c = S.mkConst(42);
      assertEqual(c.expr, '42');
      assertEqual(c.value.kind, 'int');
      assertEqual(c.value.val, 42);
    },
  },
  {
    name: 'mkConst: negative number wrapped in (- ...)',
    fn: () => {
      const c = S.mkConst(-7);
      assertEqual(c.expr, '(- 7)');
      assertEqual(c.value.val, -7);
    },
  },
  {
    name: 'mkConst: boolean',
    fn: () => {
      assertEqual(S.mkConst(true).expr, 'true');
      assertEqual(S.mkConst(false).expr, 'false');
      assert(S.mkConst(true).isBool);
    },
  },
  {
    name: 'mkConst: string',
    fn: () => {
      const c = S.mkConst('hello');
      assertEqual(c.expr, '"hello"');
      assertEqual(c.value.val, 'hello');
      assert(c.stringResult);
    },
  },
  {
    name: 'mkConst: string with embedded quote escapes',
    fn: () => {
      const c = S.mkConst('say "hi"');
      assertEqual(c.expr, '"say ""hi"""');
    },
  },

  // --- mkNot / mkAnd / mkOr folding ---
  {
    name: 'mkNot: const fold',
    fn: () => {
      assertEqual(S.mkNot(S.mkConst(true)).value.val, false);
      assertEqual(S.mkNot(S.mkConst(false)).value.val, true);
    },
  },
  {
    name: 'mkAnd: const fold short-circuits',
    fn: () => {
      const sym = S.mkSym('x');
      assertEqual(S.mkAnd(S.mkConst(false), sym).value.val, false);
      assertEqual(S.mkAnd(S.mkConst(true), sym), sym);
      assertEqual(S.mkAnd(sym, S.mkConst(true)), sym);
    },
  },
  {
    name: 'mkOr: const fold short-circuits',
    fn: () => {
      const sym = S.mkSym('x');
      assertEqual(S.mkOr(S.mkConst(true), sym).value.val, true);
      assertEqual(S.mkOr(S.mkConst(false), sym), sym);
    },
  },
  {
    name: 'mkAnd: null operand returns the other',
    fn: () => {
      const sym = S.mkSym('x');
      assertEqual(S.mkAnd(null, sym), sym);
      assertEqual(S.mkAnd(sym, null), sym);
    },
  },

  // --- mkCmp ---
  {
    name: 'mkCmp: concrete fold',
    fn: () => {
      assertEqual(S.mkCmp('<', S.mkConst(1), S.mkConst(2)).value.val, true);
      assertEqual(S.mkCmp('===', S.mkConst('a'), S.mkConst('a')).value.val, true);
      assertEqual(S.mkCmp('===', S.mkConst('a'), S.mkConst('b')).value.val, false);
      assertEqual(S.mkCmp('!==', S.mkConst(1), S.mkConst('1')).value.val, true);
    },
  },
  {
    name: 'mkCmp: cross-kind === folds without sort mismatch',
    fn: () => {
      // false === "svg" should fold to false at construction
      // time, NOT produce an SMT formula that Z3 would reject.
      const r = S.mkCmp('===', S.mkConst(false), S.mkConst('svg'));
      assertEqual(r.value.val, false);
    },
  },
  {
    name: 'mkCmp: sym vs string upgrades sym to String sort',
    fn: () => {
      const x = S.mkSym('x');
      const cmp = S.mkCmp('===', x, S.mkConst('admin'));
      assertEqual(cmp.expr, '(= |x| "admin")');
      assertEqual(cmp.sorts.x, 'String');
      assert(cmp.isBool);
    },
  },
  {
    name: 'mkCmp: sym vs int keeps Int sort',
    fn: () => {
      const x = S.mkSym('x');
      const cmp = S.mkCmp('<', x, S.mkConst(5));
      assertEqual(cmp.expr, '(< |x| 5)');
      assertEqual(cmp.sorts.x, 'Int');
    },
  },
  {
    name: 'mkCmp: !== produces (not (= ...))',
    fn: () => {
      const x = S.mkSym('x');
      const cmp = S.mkCmp('!==', x, S.mkConst('a'));
      assertEqual(cmp.expr, '(not (= |x| "a"))');
    },
  },

  // --- String theory ---
  {
    name: 'mkConcat: concrete fold',
    fn: () => {
      const c = S.mkConcat(S.mkConst('foo'), S.mkConst('bar'));
      assertEqual(c.value.val, 'foobar');
    },
  },
  {
    name: 'mkConcat: sym + literal upgrades sym to String',
    fn: () => {
      const x = S.mkSym('x');
      const c = S.mkConcat(x, S.mkConst('!'));
      assertEqual(c.expr, '(str.++ |x| "!")');
      assertEqual(c.sorts.x, 'String');
      assert(c.stringResult);
    },
  },
  {
    name: 'mkLength: concrete fold',
    fn: () => {
      assertEqual(S.mkLength(S.mkConst('hello')).value.val, 5);
    },
  },
  {
    name: 'mkLength: sym becomes (str.len |x|)',
    fn: () => {
      const x = S.mkSym('x');
      const len = S.mkLength(x);
      assertEqual(len.expr, '(str.len |x|)');
      assertEqual(len.sorts.x, 'String');
    },
  },
  {
    name: 'mkContains: concrete fold true',
    fn: () => {
      assertEqual(S.mkContains(S.mkConst('hello world'), S.mkConst('world')).value.val, true);
    },
  },
  {
    name: 'mkContains: concrete fold false',
    fn: () => {
      assertEqual(S.mkContains(S.mkConst('hello'), S.mkConst('xyz')).value.val, false);
    },
  },
  {
    name: 'mkContains: sym + literal',
    fn: () => {
      const x = S.mkSym('x');
      const c = S.mkContains(x, S.mkConst('admin'));
      assertEqual(c.expr, '(str.contains |x| "admin")');
      assertEqual(c.sorts.x, 'String');
    },
  },
  {
    name: 'mkPrefixOf: concrete fold',
    fn: () => {
      assertEqual(S.mkPrefixOf(S.mkConst('http'), S.mkConst('https://x')).value.val, true);
      assertEqual(S.mkPrefixOf(S.mkConst('http'), S.mkConst('ftp://x')).value.val, false);
    },
  },
  {
    name: 'mkSuffixOf: concrete fold',
    fn: () => {
      assertEqual(S.mkSuffixOf(S.mkConst('.html'), S.mkConst('a.html')).value.val, true);
      assertEqual(S.mkSuffixOf(S.mkConst('.html'), S.mkConst('a.txt')).value.val, false);
    },
  },
  {
    name: 'mkSubstr: concrete fold',
    fn: () => {
      // substr("hello", 1, 3) = "ell"
      const r = S.mkSubstr(S.mkConst('hello'), S.mkConst(1), S.mkConst(3));
      assertEqual(r.value.val, 'ell');
    },
  },

  // --- mkArith ---
  {
    name: 'mkArith: concrete fold',
    fn: () => {
      assertEqual(S.mkArith('+', S.mkConst(1), S.mkConst(2)).value.val, 3);
      assertEqual(S.mkArith('-', S.mkConst(10), S.mkConst(3)).value.val, 7);
      assertEqual(S.mkArith('*', S.mkConst(4), S.mkConst(5)).value.val, 20);
      assertEqual(S.mkArith('/', S.mkConst(15), S.mkConst(4)).value.val, 3);
      assertEqual(S.mkArith('%', S.mkConst(15), S.mkConst(4)).value.val, 3);
    },
  },
  {
    name: 'mkArith: division by zero returns sym formula (no fold)',
    fn: () => {
      const r = S.mkArith('/', S.mkConst(10), S.mkConst(0));
      // Should not fold; should produce a (div ...) expression.
      assert(r);
      assert(!r.value);
    },
  },
  {
    name: 'mkArith: sym + Int',
    fn: () => {
      const x = S.mkSym('x');
      const r = S.mkArith('+', x, S.mkConst(1));
      assertEqual(r.expr, '(+ |x| 1)');
      assertEqual(r.sorts.x, 'Int');
    },
  },
  {
    name: 'mkArith: sym × String → incompatible',
    fn: () => {
      // Force x to String first via a comparison, then try arith.
      const x = S.mkSym('x');
      const cmpResult = S.mkCmp('===', x, S.mkConst('admin'));
      // Build a new sym that shares the sort — easiest: re-cmp.
      // Then arith on x (now declared String elsewhere).
      const xString = { ...x, sorts: { x: 'String' } };
      const r = S.mkArith('+', xString, S.mkConst(1));
      assert(r.incompatible, 'mixing String sym with Int arith should be incompatible');
    },
  },

  // --- hasSym ---
  {
    name: 'hasSym: sym formula has syms',
    fn: () => assert(S.hasSym(S.mkSym('x'))),
  },
  {
    name: 'hasSym: const formula has no syms',
    fn: () => assert(!S.hasSym(S.mkConst(42))),
  },
  {
    name: 'hasSym: derived formula carries syms',
    fn: () => {
      const x = S.mkSym('x');
      const cmp = S.mkCmp('<', x, S.mkConst(5));
      assert(S.hasSym(cmp));
    },
  },

  // --- emitDeclarations ---
  {
    name: 'emitDeclarations: empty for const',
    fn: () => assertEqual(S.emitDeclarations(S.mkConst(42)), ''),
  },
  {
    name: 'emitDeclarations: produces declare-const for sym',
    fn: () => {
      const x = S.mkSym('myVar');
      const cmp = S.mkCmp('===', x, S.mkConst('admin'));
      const decls = S.emitDeclarations(cmp);
      assertEqual(decls, '(declare-const |myVar| String)');
    },
  },
  {
    name: 'emitDeclarations: multiple syms',
    fn: () => {
      const x = S.mkSym('x');
      const y = S.mkSym('y');
      const cmp = S.mkCmp('<', x, y);
      const decls = S.emitDeclarations(cmp);
      assert(decls.includes('|x|'));
      assert(decls.includes('|y|'));
    },
  },

  // --- Composability ---
  {
    name: 'Composability: nested conjunction',
    fn: () => {
      const x = S.mkSym('x');
      const a = S.mkCmp('===', x, S.mkConst('admin'));
      const b = S.mkCmp('!==', x, S.mkConst(''));
      const both = S.mkAnd(a, b);
      assertEqual(both.expr, '(and (= |x| "admin") (not (= |x| "")))');
      assertEqual(both.sorts.x, 'String');
    },
  },
  {
    name: 'Composability: contains + length predicate',
    fn: () => {
      const u = S.mkSym('url');
      // (and (str.contains url "<script>") (> (str.len url) 10))
      const has = S.mkContains(u, S.mkConst('<script>'));
      const len = S.mkLength(u);
      const long = S.mkCmp('>', len, S.mkConst(10));
      const both = S.mkAnd(has, long);
      assert(both.expr.includes('str.contains'));
      assert(both.expr.includes('str.len'));
    },
  },
];

module.exports = { tests };
