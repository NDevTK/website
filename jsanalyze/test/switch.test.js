// switch.test.js — Wave 9 regression coverage.
//
// Wave 9 lowers JS switch statements into a CFG shape of
// chained equality tests + per-case body blocks + explicit
// fall-through + exit block for `break`. Semantics:
//
//   * The discriminant is evaluated once in the pred block.
//   * Non-default cases are tested in source order via a
//     chain of `disc === caseValue` branches; each miss
//     falls through to the next test block.
//   * If all non-default tests fail, control jumps to the
//     default body (if any) or the exit block.
//   * Case bodies run in source order. A body's last block
//     falls through to the NEXT case body unless terminated
//     (typically by `break`, which jumps to the exit).
//   * `break` inside a case jumps to the exit block via the
//     _loopStack mechanism shared with loops.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'Wave9: basic switch parses and lowers',
    fn: async () => {
      const t = await analyze('var x = "a"; switch (x) { case "a": break; case "b": break; }', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave9: case body firing tainted sink',
    fn: async () => {
      const t = await analyze(
        'switch (location.hash) { case "a": document.body.innerHTML = location.hash; break; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave9: default branch fires tainted sink',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; switch (x) { case "a": break; default: document.body.innerHTML = x; break; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave9: default-only switch',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; switch (x) { default: document.body.innerHTML = x; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave9: default in the middle',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; switch (x) { case "a": break; default: document.body.innerHTML = x; break; case "b": break; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave9: fall-through into next case',
    fn: async () => {
      const t = await analyze(
        'var x = "a"; switch (x) { case "a": case "b": document.body.innerHTML = location.hash; break; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave9: fall-through from non-default into default',
    fn: async () => {
      const t = await analyze(
        'var x = location.hash; switch ("a") { case "a": var y = 1; default: document.body.innerHTML = x; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave9: break prevents fall-through',
    fn: async () => {
      const t = await analyze(
        'switch ("match") { case "match": var y = 1; break; case "other": document.body.innerHTML = location.hash; break; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave9: no matching case, no default',
    fn: async () => {
      const t = await analyze(
        'switch ("nope") { case "a": var y = 1; break; } var z = 2;',
        { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave9: switch inside function with closure capture',
    fn: async () => {
      const t = await analyze(
        'function handle(kind) { var x = location.hash; switch (kind) { case "a": return x; default: return "safe"; } } document.body.innerHTML = handle("a");',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
];

module.exports = { tests };
