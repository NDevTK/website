'use strict';

const { parseModule, parseAuto, locFromNode } = require('../src/parse.js');
const { assert, assertEqual, assertThrows } = require('./run.js');

const tests = [
  {
    name: 'parseModule: empty source',
    fn: () => {
      const ast = parseModule('', 'empty.js');
      assertEqual(ast.type, 'Program');
      assertEqual(ast.body.length, 0);
    },
  },
  {
    name: 'parseModule: var declaration',
    fn: () => {
      const ast = parseModule('var x = 1;', 'a.js');
      assertEqual(ast.body.length, 1);
      assertEqual(ast.body[0].type, 'VariableDeclaration');
      assertEqual(ast.body[0].declarations[0].id.name, 'x');
    },
  },
  {
    name: 'parseModule: syntax error throws with location',
    fn: () => {
      let caught = null;
      try { parseModule('var = ;', 'bad.js'); }
      catch (e) { caught = e; }
      assert(caught !== null, 'expected error');
      assert(caught.message.includes('bad.js'), 'error should contain filename');
    },
  },
  {
    name: 'parseAuto: top-level return parses as a ReturnStatement',
    fn: () => {
      // The iterative parser is permissive about top-level return
      // — it produces a ReturnStatement node rather than throwing.
      // The IR builder handles top-level returns as function exits
      // of the synthetic top function.
      const r = parseAuto('return 42;', 'x.js');
      assertEqual(r.ast.type, 'Program');
      assertEqual(r.ast.body[0].type, 'ReturnStatement');
    },
  },
  {
    name: 'parseAuto: unsupported import becomes UnimplementedStatement',
    fn: () => {
      // ES module import/export are on the phase-7 roadmap. Until
      // they're implemented the parser emits an explicit marker
      // node so the IR builder can raise an `unimplemented`
      // soundness assumption at the right location.
      const r = parseAuto('import x from "y";', 'x.js');
      assertEqual(r.ast.type, 'Program');
      assertEqual(r.ast.body[0].type, 'UnimplementedStatement');
      assertEqual(r.ast.body[0].kind, 'import');
    },
  },
  {
    name: 'locFromNode: produces line/col/pos',
    fn: () => {
      const ast = parseModule('var x = 1;\nvar y = 2;', 'a.js');
      const loc = locFromNode(ast.body[1], 'a.js');
      assertEqual(loc.file, 'a.js');
      assertEqual(loc.line, 2);
      assertEqual(loc.col, 0);
      assert(loc.pos > 0);
    },
  },
];

module.exports = { tests };
