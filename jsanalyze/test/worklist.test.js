'use strict';

const { buildModule } = require('../src/ir.js');
const { analyseFunction } = require('../src/worklist.js');
const { AssumptionTracker } = require('../src/assumptions.js');
const D = require('../src/domain.js');
const { overlayEntries } = require('../src/domain.js');
const { assert, assertEqual } = require('./run.js');

function analyse(source) {
  const module = buildModule(source, 'test.js');
  const ctx = {
    module,
    assumptions: new AssumptionTracker(),
    typeDB: null,
    nextObjId: 0,
    onCall: null,
  };
  const initial = D.createState();
  const result = analyseFunction(module, module.top, initial, ctx);
  return { module, ctx, result };
}

// Find the register a top-level `var NAME = ...` ends up in. We
// scan the top function's entry block for a Const (or other value-
// producing instr) whose source location line matches the var decl.
// Simpler: just return all exit-state registers so the test can
// inspect them.
function exitRegs(res) {
  return res.result.exitState.regs;
}

// Find the last Const-produced register in the module's top block
// (for simple "var x = LITERAL" checks).
function lastRegWithValue(module, state, predicate) {
  for (const [, block] of module.top.cfg.blocks) {
    for (const instr of block.instructions) {
      if (instr.dest) {
        const v = D.getReg(state, instr.dest);
        if (v && v.kind !== 'bottom' && predicate(v)) return v;
      }
    }
  }
  return null;
}

const tests = [
  {
    name: 'analyse: var x = 42 → register holds concrete 42',
    fn: () => {
      const r = analyse('var x = 42;');
      const v = lastRegWithValue(r.module, r.result.exitState,
        v => v.kind === 'concrete' && v.value === 42);
      assert(v, 'expected a register holding 42');
    },
  },
  {
    name: 'analyse: var z = 1 + 2 → register holds concrete 3',
    fn: () => {
      const r = analyse('var z = 1 + 2;');
      const v = lastRegWithValue(r.module, r.result.exitState,
        v => v.kind === 'concrete' && v.value === 3);
      assert(v, 'expected a register holding 3');
    },
  },
  {
    name: 'analyse: var z = "a" + "b" → register holds "ab"',
    fn: () => {
      const r = analyse('var z = "a" + "b";');
      const v = lastRegWithValue(r.module, r.result.exitState,
        v => v.kind === 'concrete' && v.value === 'ab');
      assert(v, 'expected "ab"');
    },
  },
  {
    name: 'analyse: var x = 1; var y = x + 1 → y holds 2',
    fn: () => {
      const r = analyse('var x = 1; var y = x + 1;');
      const v = lastRegWithValue(r.module, r.result.exitState,
        v => v.kind === 'concrete' && v.value === 2);
      assert(v, 'expected 2');
    },
  },
  {
    name: 'analyse: if/else with phi joins to oneOf',
    fn: () => {
      const r = analyse('var x; if (cond) x = 1; else x = 2;');
      // The merged x should be oneOf {1, 2}.
      let found = false;
      for (const [, v] of overlayEntries(r.result.exitState.regs)) {
        if (v.kind === 'oneOf') {
          const set = new Set(v.values);
          if (set.has(1) && set.has(2)) { found = true; break; }
        }
      }
      assert(found, 'expected phi to produce oneOf {1,2}');
    },
  },
  {
    name: 'analyse: concrete-true branch prunes else',
    fn: () => {
      const r = analyse('var x; if (true) x = 1; else x = 2;');
      // Only the true branch runs, so x should be concrete(1), not oneOf.
      const v = lastRegWithValue(r.module, r.result.exitState,
        v => v.kind === 'concrete' && v.value === 1);
      assert(v, 'expected x to be concrete(1)');
      // Confirm no oneOf on the same name (only the true side was taken).
      let sawOneOf = false;
      for (const [, v] of overlayEntries(r.result.exitState.regs)) {
        if (v.kind === 'oneOf') sawOneOf = true;
      }
      assert(!sawOneOf, 'should not have produced a phi join');
    },
  },
  {
    name: 'analyse: concrete-false branch prunes then',
    fn: () => {
      const r = analyse('var x; if (false) x = 1; else x = 2;');
      const v = lastRegWithValue(r.module, r.result.exitState,
        v => v.kind === 'concrete' && v.value === 2);
      assert(v, 'expected x to be concrete(2)');
    },
  },
  {
    name: 'analyse: terminates on deeply nested expressions',
    fn: () => {
      // 1000-term chain. acorn itself uses recursive descent, so
      // the upper bound on expression nesting is acorn's stack
      // limit (~1000 on Node's default stack). The IR builder
      // and worklist are both iterative above that bound.
      let src = 'var x = 1';
      for (let i = 0; i < 500; i++) src += ' + ' + i;
      src += ';';
      const r = analyse(src);
      assert(r.result.exitState, 'produced exit state for 500-level expression');
    },
  },
  {
    name: 'analyse: terminates on 5000-deep nested function declarations',
    fn: () => {
      // Stress test for the iterative function lowering. The
      // legacy code recursed via `lowerFunctionDecl → drainWork
      // → lower_stmt → lowerFunctionDecl` and overflowed at
      // ~5000 nesting levels. After G1 the lowering pushes
      // enter_function / leave_function tasks onto the shared
      // work stack, so any depth works in flat time.
      let src = '';
      for (let i = 0; i < 5000; i++) src += 'function f' + i + '(){';
      for (let i = 0; i < 5000; i++) src += '}';
      const r = analyse(src);
      assert(r.result.exitState, 'produced exit state for 5000-deep nested fns');
    },
  },
  {
    name: 'analyse: terminates on 5000 sequential statements',
    fn: () => {
      // Flat-but-long program: this is the workload where the
      // iterative worklist and IR builder actually matter. acorn
      // handles sequential statements trivially; the engine must
      // walk all 5000 without blowing the JS stack.
      let src = '';
      for (let i = 0; i < 5000; i++) src += 'var x' + i + ' = ' + i + ';';
      const r = analyse(src);
      assert(r.result.exitState, 'produced exit state for 5000 sequential decls');
    },
  },
  {
    name: 'analyse: terminates on deeply nested if/else',
    fn: () => {
      let src = 'var x = 0;';
      for (let i = 0; i < 50; i++) src += 'if (x) { x = x + 1; } else { x = x - 1; }';
      const r = analyse(src);
      assert(r.result.exitState, 'produced exit state for 50-deep if chain');
    },
  },
  {
    name: 'analyse: unresolved global raises opaque-call assumption',
    fn: () => {
      const r = analyse('var x = someUnknown;');
      const snap = r.ctx.assumptions.snapshot();
      const hasOpaque = snap.some(a => a.reason === 'opaque-call');
      assert(hasOpaque, 'expected opaque-call assumption for someUnknown');
    },
  },
  {
    name: 'analyse: unimplemented statement raises soundness assumption',
    fn: () => {
      // `try` is still unimplemented (Wave 4 territory). Loops
      // became supported in Wave 3.
      const r = analyse('try { x = 1; } catch (e) { x = 2; }');
      const snap = r.ctx.assumptions.snapshot();
      const hasUnimpl = snap.some(a => a.reason === 'unimplemented');
      assert(hasUnimpl, 'expected unimplemented assumption for try-statement');
      const unimpl = snap.find(a => a.reason === 'unimplemented');
      assertEqual(unimpl.severity, 'soundness');
    },
  },
];

module.exports = { tests };
