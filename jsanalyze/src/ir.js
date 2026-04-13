// ir.js — SSA intermediate representation and AST→IR builder
//
// The rest of the engine operates on the IR, not the AST.
// Every analysis pass dispatches on IR instruction kinds.
//
// Design constraints:
//  - SSA: every register is written exactly once
//  - Iterative builder: no recursion; a worklist walks AST nodes
//  - All source locations preserved via sourceMap
//  - Unimplemented AST kinds raise an `unimplemented` assumption
//    and emit an `Opaque` instruction — the IR is always valid

'use strict';

const { parseModule, locFromNode } = require('./parse.js');
const { REASONS } = require('./assumptions.js');

// --- Instruction kinds (opcodes) -----------------------------------------
//
// Closed enumeration. Adding a new kind requires a transfer function in
// transfer.js and a source-level lowering in this file. Order here is
// purely for readability; callers dispatch on the string.
const OP = Object.freeze({
  // Value-producing
  CONST:        'Const',
  ALLOC:        'Alloc',
  FUNC:         'Func',
  PHI:          'Phi',
  BIN_OP:       'BinOp',
  UN_OP:        'UnOp',
  GET_PROP:     'GetProp',
  GET_INDEX:    'GetIndex',
  GET_GLOBAL:   'GetGlobal',
  GET_THIS:     'GetThis',
  GET_ARGS:     'GetArguments',
  CALL:         'Call',
  NEW:          'New',
  CAST:         'Cast',
  OPAQUE:       'Opaque',

  // Side-effecting (no dest)
  SET_PROP:     'SetProp',
  SET_INDEX:    'SetIndex',
  SET_GLOBAL:   'SetGlobal',
  DELETE_PROP:  'DeleteProp',
  DELETE_INDEX: 'DeleteIndex',

  // Terminators
  JUMP:         'Jump',
  BRANCH:       'Branch',
  RETURN:       'Return',
  THROW:        'Throw',
  SWITCH:       'Switch',
  UNREACHABLE:  'Unreachable',
});

const TERMINATOR_KINDS = new Set([
  OP.JUMP, OP.BRANCH, OP.RETURN, OP.THROW, OP.SWITCH, OP.UNREACHABLE,
]);

// --- Core types ----------------------------------------------------------
//
// A Module owns functions; a Function owns a CFG; a CFG owns blocks; a
// block owns instructions. Everything is plain data — no classes — so
// consumers can freeze, clone, or serialise freely.

function createModule(name) {
  return {
    name: name || '<anon>',
    functions: [],
    top: null,              // set by the builder to the top-level function
    sourceMap: new Map(),   // InstrId → Location
    nextInstrId: 1,
    nextBlockId: 1,
    nextFunctionId: 1,
    nextRegister: 1,
  };
}

function createFunction(module, name, paramNames) {
  const id = 'F' + (module.nextFunctionId++);
  const fn = {
    id,
    name: name || null,
    params: [],             // registers bound to caller args
    paramNames: paramNames ? paramNames.slice() : [],
    thisReg: null,
    cfg: null,              // set after buildCFG
    captures: [],           // registers from enclosing scopes
    returns: [],            // registers that flow into `return`
    isGenerator: false,
    isAsync: false,
    location: null,         // source location of the function
  };
  module.functions.push(fn);
  return fn;
}

function createBlock(module) {
  return {
    id: 'B' + (module.nextBlockId++),
    instructions: [],
    terminator: null,
    preds: [],
    succs: [],
  };
}

// Fresh SSA register. Registers are globally unique within a module so
// cross-function summaries can reference them without ambiguity.
function newRegister(module) {
  return '%r' + (module.nextRegister++);
}

// Attach a location to the next instruction emitted on `block`.
function emit(module, block, instr, loc) {
  instr._id = module.nextInstrId++;
  if (loc) module.sourceMap.set(instr._id, loc);
  if (TERMINATOR_KINDS.has(instr.op)) {
    if (block.terminator) {
      throw new Error(
        'ir: block ' + block.id + ' already has a terminator ' + block.terminator.op
      );
    }
    block.terminator = instr;
  } else {
    if (block.terminator) {
      throw new Error(
        'ir: instructions cannot be added to block ' + block.id +
        ' after its terminator ' + block.terminator.op
      );
    }
    block.instructions.push(instr);
  }
  return instr;
}

// Wire a CFG edge from src to dst. Both directions are stored so
// transfer functions can look up predecessors for phi resolution.
function addEdge(src, dst) {
  if (!src.succs.includes(dst.id)) src.succs.push(dst.id);
  if (!dst.preds.includes(src.id)) dst.preds.push(src.id);
}

// --- Scope map: source names → current SSA register --------------------
//
// The AST→IR lowering is purely syntactic but needs to resolve
// identifier references to the register holding the most recent
// value. A ScopeMap is a stack of frames (one per lexical scope).
// Variable lookups walk outward.
//
// Captures: when an inner function references an outer name, the
// outer register is added to the inner function's captures list so
// the closure knows what to copy at call time.

function createScopeMap() {
  return { frames: [Object.create(null)] };
}
function pushFrame(scope) { scope.frames.push(Object.create(null)); }
function popFrame(scope)  { scope.frames.pop(); }
function defineName(scope, name, reg) {
  scope.frames[scope.frames.length - 1][name] = reg;
}
function lookupName(scope, name) {
  for (let i = scope.frames.length - 1; i >= 0; i--) {
    if (name in scope.frames[i]) return scope.frames[i][name];
  }
  return null;
}
// Update (reassignment) — finds the nearest existing binding and
// replaces its register. If none exists, creates a new binding in
// the current frame (covers implicit globals in sloppy mode).
function updateName(scope, name, reg) {
  for (let i = scope.frames.length - 1; i >= 0; i--) {
    if (name in scope.frames[i]) { scope.frames[i][name] = reg; return i; }
  }
  scope.frames[scope.frames.length - 1][name] = reg;
  return scope.frames.length - 1;
}

// --- Iterative AST walker -----------------------------------------------
//
// The builder drives a work stack of tasks. Each task is either:
//   { kind: 'stmt', node, block }    — lower a statement into `block`
//   { kind: 'expr', node, block,
//     resume: (reg, block) => void } — lower an expression, then call
//                                      resume with the resulting register
//                                      and the block the expression ended in
//   { kind: 'resume', fn, args }     — call a deferred resume fn
//
// Using a work stack keeps the builder non-recursive so deeply nested
// source cannot blow the call stack. All recursion in the builder
// bottoms out via tasks pushed onto `_work`.

function buildModule(source, filename) {
  const ast = parseModule(source, filename, { sourceType: 'script' });
  const module = createModule(filename || '<anon>');

  // Top-level program = an implicit function with no params.
  const topFn = createFunction(module, '<top>', []);
  module.top = topFn;

  const scope = createScopeMap();
  const entry = createBlock(module);
  topFn.cfg = { entry: entry.id, exit: null, blocks: new Map([[entry.id, entry]]) };

  const ctx = {
    module,
    filename,
    fn: topFn,
    scope,
    blocks: topFn.cfg.blocks,
    currentBlock: entry,
    // Stack of enclosing catch targets: when an instruction inside a
    // try body throws, control transfers to the top of this stack.
    // Empty means "uncaught → module exit".
    catchStack: [],
  };

  lowerProgram(ctx, ast);

  // Ensure the top-level function has an exit block: any fall-through
  // at the end of the program becomes an implicit `Return(undefined)`.
  if (ctx.currentBlock && !ctx.currentBlock.terminator) {
    const undefReg = newRegister(module);
    emit(module, ctx.currentBlock, {
      op: OP.CONST, dest: undefReg, value: undefined,
    }, null);
    emit(module, ctx.currentBlock, {
      op: OP.RETURN, value: undefReg,
    }, null);
  }
  topFn.cfg.exit = ctx.currentBlock ? ctx.currentBlock.id : entry.id;

  validateModule(module);
  return module;
}

// --- Statement lowering (iterative) -------------------------------------
//
// The statement lowerer is driven by an explicit work stack on
// ctx._work. Each task is `{ kind, ... }` and maps to a step in the
// statement's lowering state machine. No lowering function recurses
// into another — they all push tasks instead.
//
// Tasks:
//   lower_stmt(node)         — dispatch a single statement node.
//   after_stmt               — post-statement bookkeeping (kill dead blocks).
//   block_enter              — push a scope frame for a block.
//   block_exit               — pop the scope frame.
//   if_after_then(ctx)       — resume an if-statement after the consequent.
//   if_after_else(ctx)       — resume an if-statement after the alternate.
//   if_merge(ctx)            — emit phi nodes at the merge block.
//   prog_after_stmt          — top-level post-statement dead-block handling.

function lowerProgram(ctx, programNode) {
  // Seed the work stack with a lower_stmt task for each top-level
  // statement, in reverse order so the bottom of the stack is the
  // first statement (LIFO: last pushed = first popped).
  ctx._work = [];
  for (let i = programNode.body.length - 1; i >= 0; i--) {
    ctx._work.push({ kind: 'prog_after_stmt' });
    ctx._work.push({ kind: 'lower_stmt', node: programNode.body[i] });
  }
  drainWork(ctx);
}

// drainWork — the central dispatch loop. Pops tasks from ctx._work
// and runs each; tasks may push more tasks. Terminates when the
// stack is empty.
function drainWork(ctx) {
  while (ctx._work.length > 0) {
    const task = ctx._work.pop();
    stepStmtTask(ctx, task);
  }
}

function stepStmtTask(ctx, task) {
  switch (task.kind) {
    case 'lower_stmt':       return lowerStatement(ctx, task.node);
    case 'block_enter':      pushFrame(ctx.scope); return;
    case 'block_exit':       popFrame(ctx.scope); return;
    case 'after_stmt':       return afterStmtStep(ctx);
    case 'prog_after_stmt':  return progAfterStmtStep(ctx);
    case 'if_after_then':    return ifAfterThenStep(ctx, task);
    case 'if_after_else':    return ifAfterElseStep(ctx, task);
    case 'if_merge':         return ifMergeStep(ctx, task);
    case 'set_block':        ctx.currentBlock = task.block; return;
    case 'enter_function':   return enterFunctionStep(ctx, task);
    case 'leave_function':   return leaveFunctionStep(ctx, task);
    default:
      throw new Error('ir: unknown statement task ' + task.kind);
  }
}

function afterStmtStep(ctx) {
  if (ctx.currentBlock && ctx.currentBlock.terminator) {
    const dead = createBlock(ctx.module);
    ctx.blocks.set(dead.id, dead);
    ctx.currentBlock = dead;
  }
}

function progAfterStmtStep(ctx) {
  afterStmtStep(ctx);
}

// lowerStatement now dispatches one statement and returns without
// recursing into child statements. Children are queued as tasks.
function lowerStatement(ctx, node) {
  const loc = locFromNode(node, ctx.filename);
  switch (node.type) {
    case 'VariableDeclaration': return lowerVarDecl(ctx, node, loc);
    case 'ExpressionStatement': {
      lowerExpression(ctx, node.expression);
      return;
    }
    case 'BlockStatement': return enqueueBlock(ctx, node);
    case 'IfStatement':         return beginIf(ctx, node, loc);
    case 'ReturnStatement':     return lowerReturn(ctx, node, loc);
    case 'FunctionDeclaration': return lowerFunctionDecl(ctx, node, loc);
    case 'EmptyStatement':      return;
    case 'UnimplementedStatement': {
      const dest = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.OPAQUE,
        dest,
        reason: REASONS.UNIMPLEMENTED,
        details: 'statement kind not yet implemented: ' + (node.kind || 'unknown'),
        affects: null,
      }, loc);
      return;
    }
    default:
      return lowerUnimplementedStmt(ctx, node, loc);
  }
}

// Enqueue a BlockStatement's body: push block_enter, then each
// statement in reverse order (each followed by after_stmt), then
// block_exit at the bottom.
function enqueueBlock(ctx, node) {
  // LIFO order: we want the first body stmt to run first, so push
  // block_exit first, then each stmt in reverse with after_stmt.
  ctx._work.push({ kind: 'block_exit' });
  for (let i = node.body.length - 1; i >= 0; i--) {
    ctx._work.push({ kind: 'after_stmt' });
    ctx._work.push({ kind: 'lower_stmt', node: node.body[i] });
  }
  ctx._work.push({ kind: 'block_enter' });
}

// --- If statement -------------------------------------------------------
//
// Lowering produces: predBlock (Branch), thenBlock, elseBlock?,
// mergeBlock. The consequent and alternate are lowered as child
// statement tasks that run in between the phase transitions.

function beginIf(ctx, node, loc) {
  const condReg = lowerExpression(ctx, node.test);
  const predBlock = ctx.currentBlock;

  const thenBlock = createBlock(ctx.module);
  ctx.blocks.set(thenBlock.id, thenBlock);
  addEdge(predBlock, thenBlock);

  const elseBlock = node.alternate ? createBlock(ctx.module) : null;
  if (elseBlock) {
    ctx.blocks.set(elseBlock.id, elseBlock);
    addEdge(predBlock, elseBlock);
  }

  const mergeBlock = createBlock(ctx.module);
  ctx.blocks.set(mergeBlock.id, mergeBlock);

  emit(ctx.module, predBlock, {
    op: OP.BRANCH,
    cond: condReg,
    trueTarget: thenBlock.id,
    falseTarget: elseBlock ? elseBlock.id : mergeBlock.id,
  }, loc);
  if (!elseBlock) addEdge(predBlock, mergeBlock);

  // Snapshot the scope for phi generation at the merge.
  const entryScope = snapshotScope(ctx.scope);

  // Schedule the if's lowering as a sequence of tasks:
  //   1. (running on currentBlock = thenBlock) lower consequent
  //   2. if_after_then (records thenExit, restores scope, sets
  //      currentBlock to elseBlock if present else mergeBlock)
  //   3. (if elseBlock) lower alternate
  //   4. if_after_else (records elseExit, restores scope)
  //   5. if_merge (emits phis on mergeBlock)
  //
  // We push in reverse (LIFO) so the first step runs next.

  const ifCtx = {
    startLoc: loc,
    predBlock,
    thenBlock,
    elseBlock,
    mergeBlock,
    entryScope,
    thenExitBlock: null,
    thenScope: null,
    elseExitBlock: null,
    elseScope: null,
  };

  // Push in reverse so they pop in this order:
  //   set currentBlock = thenBlock
  //   lower consequent
  //   if_after_then
  //   (else branch)
  //   if_merge
  ctx._work.push({ kind: 'if_merge', ifCtx });
  if (elseBlock) {
    ctx._work.push({ kind: 'if_after_else', ifCtx });
    ctx._work.push({ kind: 'after_stmt' });
    ctx._work.push({ kind: 'lower_stmt', node: node.alternate });
    ctx._work.push({ kind: 'if_after_then', ifCtx, hasElse: true });
  } else {
    ctx._work.push({ kind: 'if_after_then', ifCtx, hasElse: false });
  }
  ctx._work.push({ kind: 'after_stmt' });
  ctx._work.push({ kind: 'lower_stmt', node: node.consequent });
  // Set currentBlock to thenBlock before the consequent runs.
  ctx.currentBlock = thenBlock;
}

function ifAfterThenStep(ctx, task) {
  const c = task.ifCtx;
  c.thenExitBlock = ctx.currentBlock;
  c.thenScope = snapshotScope(ctx.scope);
  restoreScope(ctx.scope, c.entryScope);
  if (!c.thenExitBlock.terminator) {
    emit(ctx.module, c.thenExitBlock, {
      op: OP.JUMP, target: c.mergeBlock.id,
    }, null);
    addEdge(c.thenExitBlock, c.mergeBlock);
  }
  if (task.hasElse) {
    // Set currentBlock to elseBlock; the next task (lower_stmt)
    // will run on that block.
    ctx.currentBlock = c.elseBlock;
  } else {
    // No else branch — jump straight to merge block handling.
    ctx.currentBlock = c.mergeBlock;
  }
}

function ifAfterElseStep(ctx, task) {
  const c = task.ifCtx;
  c.elseExitBlock = ctx.currentBlock;
  c.elseScope = snapshotScope(ctx.scope);
  restoreScope(ctx.scope, c.entryScope);
  if (!c.elseExitBlock.terminator) {
    emit(ctx.module, c.elseExitBlock, {
      op: OP.JUMP, target: c.mergeBlock.id,
    }, null);
    addEdge(c.elseExitBlock, c.mergeBlock);
  }
  ctx.currentBlock = c.mergeBlock;
}

function ifMergeStep(ctx, task) {
  const c = task.ifCtx;
  const loc = c.startLoc;
  // Determine which predecessor scopes contribute to the merge.
  const phiBlocks = c.elseExitBlock
    ? [[c.thenExitBlock, c.thenScope], [c.elseExitBlock, c.elseScope]]
    : [[c.thenExitBlock, c.thenScope], [c.predBlock, c.entryScope]];

  const allNames = new Set();
  for (const [, s] of phiBlocks) {
    for (const f of s.frames) for (const k in f) allNames.add(k);
  }
  for (const name of allNames) {
    const incoming = [];
    for (const [exitBlock, exitScope] of phiBlocks) {
      const reg = lookupInSnapshot(exitScope, name);
      if (reg != null) incoming.push({ pred: exitBlock.id, value: reg });
    }
    if (incoming.length === 0) continue;
    const first = incoming[0].value;
    const allSame = incoming.every(i => i.value === first);
    if (allSame) {
      updateName(ctx.scope, name, first);
      continue;
    }
    const dest = newRegister(ctx.module);
    emit(ctx.module, c.mergeBlock, {
      op: OP.PHI, dest, incoming,
    }, loc);
    updateName(ctx.scope, name, dest);
  }
}

function lowerVarDecl(ctx, node, loc) {
  // `var x = 1, y = 2;` → one emit per declarator.
  for (const decl of node.declarations) {
    if (decl.id.type !== 'Identifier') {
      // Destructuring — not yet implemented.
      lowerUnimplementedStmt(ctx, decl, loc);
      continue;
    }
    let reg;
    if (decl.init) {
      reg = lowerExpression(ctx, decl.init);
    } else {
      reg = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.CONST, dest: reg, value: undefined,
      }, loc);
    }
    defineName(ctx.scope, decl.id.name, reg);
  }
}

function lowerReturn(ctx, node, loc) {
  let reg = null;
  if (node.argument) reg = lowerExpression(ctx, node.argument);
  else {
    reg = newRegister(ctx.module);
    emit(ctx.module, ctx.currentBlock, {
      op: OP.CONST, dest: reg, value: undefined,
    }, loc);
  }
  emit(ctx.module, ctx.currentBlock, {
    op: OP.RETURN, value: reg,
  }, loc);
  ctx.fn.returns.push(reg);
}

// lowerFunctionDecl — emit a FUNC instruction in the OUTER block
// immediately, then defer the body lowering by pushing
// `enter_function`, body tasks, and `leave_function` onto
// ctx._work.
//
// The function is iterative: no JS recursion. drainWork pops
// the deferred tasks in order, switching ctx into the function's
// scope at enter_function and back out at leave_function. Nested
// function declarations push more tasks the same way, so any
// depth of nesting works without growing the JS call stack.
//
// Returns the FUNC instruction's `dest` register so callers
// (function declarations and function expressions) can
// immediately use the closure value.
function lowerFunctionDecl(ctx, node, loc) {
  const params = node.params.map(p =>
    p.type === 'Identifier' ? p.name : null
  );
  const fn = createFunction(ctx.module, node.id && node.id.name, params);
  fn.isAsync = !!node.async;
  fn.isGenerator = !!node.generator;
  fn.location = loc;

  // Allocate the function's own CFG with an entry block. The
  // body tasks (run later via the deferred work stack) will
  // populate it.
  const fnEntry = createBlock(ctx.module);
  fn.cfg = { entry: fnEntry.id, exit: null, blocks: new Map([[fnEntry.id, fnEntry]]) };

  // Emit the FUNC instruction in the OUTER block right now so
  // the closure value is available to subsequent statements at
  // declaration order. The captures list is empty until closure
  // capture tracking lands in Phase C.
  const dest = newRegister(ctx.module);
  emit(ctx.module, ctx.currentBlock, {
    op: OP.FUNC, dest, functionId: fn.id, captures: [],
  }, loc);
  // For function declarations, bind the source name in the
  // outer scope right away. For function expressions
  // (node.id === null) the caller pushes `dest` onto its own
  // results stack.
  if (node.id) defineName(ctx.scope, node.id.name, dest);

  // Push the deferred body tasks onto the SHARED work stack.
  // LIFO order so they pop in this sequence:
  //
  //   1. enter_function — install fn / fresh scope / params /
  //      currentBlock=fnEntry
  //   2. body statements (each followed by after_stmt)
  //   3. leave_function — implicit return + restore outer ctx
  //
  // No recursion: drainWork's existing while-loop processes
  // them in order.
  ctx._work.push({ kind: 'leave_function', fn });
  if (node.body && node.body.type === 'BlockStatement') {
    for (let i = node.body.body.length - 1; i >= 0; i--) {
      ctx._work.push({ kind: 'after_stmt' });
      ctx._work.push({ kind: 'lower_stmt', node: node.body.body[i] });
    }
  }
  ctx._work.push({ kind: 'enter_function', fn });
  return dest;
}

// enter_function — called when the deferred function-body
// tasks reach the top of the work stack. Snapshots the outer
// ctx state, installs the function's own state (fresh scope,
// the function's blocks Map, currentBlock = entry), and binds
// the parameters as fresh registers in the new scope.
function enterFunctionStep(ctx, task) {
  if (!ctx._funcStack) ctx._funcStack = [];
  ctx._funcStack.push({
    fn: ctx.fn,
    scope: ctx.scope,
    blocks: ctx.blocks,
    currentBlock: ctx.currentBlock,
    catchStack: ctx.catchStack,
  });
  const fn = task.fn;
  ctx.fn = fn;
  ctx.scope = createScopeMap();
  ctx.blocks = fn.cfg.blocks;
  ctx.currentBlock = fn.cfg.blocks.get(fn.cfg.entry);
  ctx.catchStack = [];
  // Bind params in the new scope. The param register list on
  // `fn.params` is appended here so it's populated by the time
  // any caller starts walking the body.
  for (const name of fn.paramNames) {
    if (!name) continue;
    const reg = newRegister(ctx.module);
    fn.params.push(reg);
    defineName(ctx.scope, name, reg);
  }
}

// leave_function — adds the implicit `return undefined` at end
// of body, sets fn.cfg.exit, then restores the outer ctx state
// from the snapshot pushed at enter_function time.
function leaveFunctionStep(ctx, task) {
  const fn = task.fn;
  if (ctx.currentBlock && !ctx.currentBlock.terminator) {
    const undefReg = newRegister(ctx.module);
    emit(ctx.module, ctx.currentBlock, {
      op: OP.CONST, dest: undefReg, value: undefined,
    }, null);
    emit(ctx.module, ctx.currentBlock, {
      op: OP.RETURN, value: undefReg,
    }, null);
    fn.returns.push(undefReg);
  }
  fn.cfg.exit = ctx.currentBlock ? ctx.currentBlock.id : fn.cfg.entry;
  if (!ctx._funcStack || ctx._funcStack.length === 0) {
    throw new Error('ir: leave_function with empty _funcStack');
  }
  const saved = ctx._funcStack.pop();
  ctx.fn = saved.fn;
  ctx.scope = saved.scope;
  ctx.blocks = saved.blocks;
  ctx.currentBlock = saved.currentBlock;
  ctx.catchStack = saved.catchStack;
}

function lowerUnimplementedStmt(ctx, node, loc) {
  const reg = newRegister(ctx.module);
  emit(ctx.module, ctx.currentBlock, {
    op: OP.OPAQUE,
    dest: reg,
    reason: REASONS.UNIMPLEMENTED,
    details: 'statement kind not yet implemented: ' + node.type,
    affects: null,
  }, loc);
}

// --- Expression lowering ------------------------------------------------
//
// lowerExpression is the public entry point. It delegates to an
// iterative work-stack lowerer so deeply nested expression trees
// (e.g. `1 + 2 + ... + 10000`) do not blow the JS call stack.
//
// The iterative lowerer maintains two stacks:
//   tasks[]   — pending work items (see below)
//   results[] — register results produced so far
//
// When a task completes, it pushes its output register onto
// results. Higher-level tasks then pop their operand registers
// from results and emit the combining instruction.

function lowerExpression(ctx, node) {
  return lowerExpressionIter(ctx, node);
}

function lowerExpressionIter(ctx, root) {
  const tasks = [{ kind: 'visit', node: root }];
  const results = [];

  while (tasks.length > 0) {
    const task = tasks.pop();
    switch (task.kind) {
      case 'visit': {
        visitNode(ctx, task.node, tasks, results);
        break;
      }
      case 'emit_binop': {
        const rightReg = results.pop();
        const leftReg = results.pop();
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.BIN_OP,
          dest,
          operator: task.operator,
          left: leftReg,
          right: rightReg,
        }, task.loc);
        results.push(dest);
        break;
      }
      case 'emit_unop': {
        const operandReg = results.pop();
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.UN_OP,
          dest,
          operator: task.operator,
          operand: operandReg,
        }, task.loc);
        results.push(dest);
        break;
      }
      case 'emit_member_prop': {
        const objReg = results.pop();
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.GET_PROP, dest, object: objReg, propName: task.propName,
        }, task.loc);
        results.push(dest);
        break;
      }
      case 'emit_member_index': {
        const keyReg = results.pop();
        const objReg = results.pop();
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.GET_INDEX, dest, object: objReg, key: keyReg,
        }, task.loc);
        results.push(dest);
        break;
      }
      case 'emit_call': {
        // Pop nArgs from results (these were pushed left-to-right, so
        // in task execution order they come off in reverse).
        const argRegs = [];
        for (let i = 0; i < task.nArgs; i++) argRegs.unshift(results.pop());
        let thisReg = null;
        if (task.hasThis) thisReg = results.pop();
        const calleeReg = results.pop();
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.CALL,
          dest,
          callee: calleeReg,
          args: argRegs,
          thisArg: thisReg,
          // Syntactic hints for sink classification:
          //
          //   methodName — when lowered from `obj.method(args)`,
          //     names the method so the transfer function can
          //     look up `thisType.methods[methodName].sink`
          //     without re-walking the IR.
          //
          //   calleeName — when lowered from a bare-identifier
          //     call like `eval(x)`, names the global so the
          //     transfer function can resolve it through
          //     `db.roots[calleeName]` and then check
          //     `.call.sink` on the resulting type.
          //
          // These are optional and only used for classification;
          // the call's runtime semantics still go through the
          // callee register's Value as before.
          methodName: task.methodName || null,
          calleeName: task.calleeName || null,
        }, task.loc);
        results.push(dest);
        break;
      }
      case 'emit_call_member_prop': {
        // After-thought: before emit_call runs, we needed to fetch
        // the method on `this`. We do that here: pop `this`, emit
        // GetProp, push the method register, and push `this` back.
        //
        // This is used by the CallExpression lowering below: when
        // the callee is `obj.method(args)`, the IR needs GetProp to
        // produce the method register before the args are evaluated.
        const objReg = results[results.length - 1];  // peek (leave `this` on stack)
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.GET_PROP, dest, object: objReg, propName: task.propName,
        }, task.loc);
        // Swap: [..., this] → [..., callee, this] (callee below this for emit_call)
        const thisReg = results.pop();
        results.push(dest);
        results.push(thisReg);
        break;
      }
      case 'emit_new': {
        const argRegs = [];
        for (let i = 0; i < task.nArgs; i++) argRegs.unshift(results.pop());
        const ctorReg = results.pop();
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.NEW, dest, ctor: ctorReg, args: argRegs,
        }, task.loc);
        results.push(dest);
        break;
      }
      case 'emit_assign': {
        // Simple identifier assignment: `x = expr`. The RHS register
        // is on top of results. Bind x to it.
        const rhsReg = results[results.length - 1];  // leave as final result
        updateName(ctx.scope, task.name, rhsReg);
        break;
      }
      case 'emit_assign_compound': {
        // Compound: `x += rhs`. Pop rhs, lookup current x, emit
        // BinOp, bind new reg to x.
        const rhsReg = results.pop();
        const lhsReg = lookupName(ctx.scope, task.name);
        if (lhsReg == null) {
          // Unresolved lhs — emit opaque.
          const dest = newRegister(ctx.module);
          emit(ctx.module, ctx.currentBlock, {
            op: OP.OPAQUE, dest,
            reason: REASONS.UNIMPLEMENTED,
            details: 'compound assignment to unresolved identifier ' + task.name,
            affects: null,
          }, task.loc);
          results.push(dest);
          break;
        }
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.BIN_OP,
          dest,
          operator: task.operator,
          left: lhsReg,
          right: rhsReg,
        }, task.loc);
        updateName(ctx.scope, task.name, dest);
        results.push(dest);
        break;
      }
      case 'emit_set_prop': {
        // `obj.prop = val` → tasks pushed: visit obj, visit val
        // (in that order). When emit_set_prop runs, results holds
        // [..., objReg, valReg]. Pop val, pop obj, emit SET_PROP.
        // The expression's value is the RHS (JS semantics:
        // assignment expressions evaluate to the assigned value),
        // so we re-push the val register as the result.
        const valReg = results.pop();
        const objReg = results.pop();
        emit(ctx.module, ctx.currentBlock, {
          op: OP.SET_PROP,
          object: objReg,
          propName: task.propName,
          value: valReg,
        }, task.loc);
        results.push(valReg);
        break;
      }
      case 'emit_set_index': {
        // `obj[key] = val` → tasks pushed: visit obj, visit key,
        // visit val. Results: [..., objReg, keyReg, valReg].
        const valReg = results.pop();
        const keyReg = results.pop();
        const objReg = results.pop();
        emit(ctx.module, ctx.currentBlock, {
          op: OP.SET_INDEX,
          object: objReg,
          key: keyReg,
          value: valReg,
        }, task.loc);
        results.push(valReg);
        break;
      }
      default:
        throw new Error('ir: unknown task kind ' + task.kind);
    }
  }

  if (results.length !== 1) {
    // Should not happen if visitNode is correct. Fall back gracefully.
    if (results.length === 0) {
      const dest = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.CONST, dest, value: undefined,
      }, locFromNode(root, ctx.filename));
      return dest;
    }
    return results[results.length - 1];
  }
  return results[0];
}

// visitNode: first-visit dispatch for an AST node. Pushes follow-up
// tasks onto `tasks` (in reverse order, because tasks is a stack)
// and either pushes immediate results or leaves them to be produced
// by the follow-up tasks.
function visitNode(ctx, node, tasks, results) {
  const loc = locFromNode(node, ctx.filename);
  switch (node.type) {
    case 'Literal': {
      const dest = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.CONST, dest, value: node.value,
      }, loc);
      results.push(dest);
      return;
    }
    case 'Identifier': {
      const existing = lookupName(ctx.scope, node.name);
      if (existing != null) { results.push(existing); return; }
      const dest = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.GET_GLOBAL, dest, name: node.name,
      }, loc);
      results.push(dest);
      return;
    }
    case 'ThisExpression': {
      const dest = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, { op: OP.GET_THIS, dest }, loc);
      results.push(dest);
      return;
    }
    case 'BinaryExpression':
    case 'LogicalExpression': {
      // Queue the emit, then the operands in reverse order so the
      // stack pops them left, right (LIFO: right pushed last = popped first? no;
      // tasks is a stack, we push right first then left so left is on top and
      // processed first, producing left result first, then right).
      tasks.push({ kind: 'emit_binop', operator: node.operator, loc });
      tasks.push({ kind: 'visit', node: node.right });
      tasks.push({ kind: 'visit', node: node.left });
      return;
    }
    case 'UnaryExpression': {
      tasks.push({ kind: 'emit_unop', operator: node.operator, loc });
      tasks.push({ kind: 'visit', node: node.argument });
      return;
    }
    case 'MemberExpression': {
      if (node.computed) {
        tasks.push({ kind: 'emit_member_index', loc });
        tasks.push({ kind: 'visit', node: node.property });
        tasks.push({ kind: 'visit', node: node.object });
      } else {
        tasks.push({ kind: 'emit_member_prop', propName: node.property.name, loc });
        tasks.push({ kind: 'visit', node: node.object });
      }
      return;
    }
    case 'AssignmentExpression': {
      // Identifier target: plain var reassignment. The value is
      // bound to the identifier's SSA register and also returned
      // as the expression's result.
      if (node.left.type === 'Identifier') {
        if (node.operator === '=') {
          tasks.push({ kind: 'emit_assign', name: node.left.name, loc });
          tasks.push({ kind: 'visit', node: node.right });
        } else {
          tasks.push({
            kind: 'emit_assign_compound',
            name: node.left.name,
            operator: node.operator.slice(0, -1),
            loc,
          });
          tasks.push({ kind: 'visit', node: node.right });
        }
        return;
      }
      // Member target: `obj.prop = val` or `obj[key] = val`.
      // We only support `=` here; compound member assignments
      // fall to the unimplemented path for now.
      if (node.left.type === 'MemberExpression' && node.operator === '=') {
        if (node.left.computed) {
          // obj[key] = val → visit obj, visit key, visit val,
          // then emit_set_index pops all three.
          tasks.push({ kind: 'emit_set_index', loc });
          tasks.push({ kind: 'visit', node: node.right });
          tasks.push({ kind: 'visit', node: node.left.property });
          tasks.push({ kind: 'visit', node: node.left.object });
        } else {
          // obj.prop = val → visit obj, visit val, emit_set_prop
          // captures the prop name from the AST.
          tasks.push({
            kind: 'emit_set_prop',
            propName: node.left.property.name,
            loc,
          });
          tasks.push({ kind: 'visit', node: node.right });
          tasks.push({ kind: 'visit', node: node.left.object });
        }
        return;
      }
      // Anything else (destructuring targets, compound member
      // assignment, ...) is currently unimplemented.
      const dest = lowerUnimplementedExpr(ctx, node, loc);
      results.push(dest);
      return;
    }
    case 'CallExpression': {
      const nArgs = node.arguments.length;
      const hasMemberCallee = node.callee.type === 'MemberExpression';
      if (hasMemberCallee) {
        // obj.method(args) — need to produce:
        //   visit obj      → this register on stack
        //   peek this, GetProp → callee register; keep this
        //   visit each arg
        //   emit_call with hasThis=true
        // Thread the method name through so the CALL
        // instruction carries it for sink classification.
        const methodName = !node.callee.computed && node.callee.property
          ? node.callee.property.name
          : null;
        tasks.push({ kind: 'emit_call', nArgs, hasThis: true, loc, methodName });
        for (let i = nArgs - 1; i >= 0; i--) {
          tasks.push({ kind: 'visit', node: node.arguments[i] });
        }
        if (node.callee.computed) {
          // obj[key](args) — lower as: visit obj, visit key, emit_member_index,
          // then visit args, then emit_call (with thisArg = obj we need to save).
          // Too complex for the minimal slice — fall back to opaque for now.
          const dest = lowerUnimplementedExpr(ctx, node, loc);
          results.push(dest);
          // Need to drain the already-pushed tasks so the stack stays clean.
          // Since we just pushed emit_call + nArgs visits, pop them back off.
          for (let i = 0; i < nArgs + 1; i++) tasks.pop();
          return;
        }
        tasks.push({
          kind: 'emit_call_member_prop',
          propName: node.callee.property.name,
          loc,
        });
        tasks.push({ kind: 'visit', node: node.callee.object });
      } else {
        // plain call — visit callee, visit args, emit_call.
        // For a bare-identifier callee we capture the name so
        // sink classification can resolve the global through
        // the TypeDB (e.g. `eval(x)` → GlobalEval.call.sink).
        const calleeName = node.callee.type === 'Identifier'
          ? node.callee.name
          : null;
        tasks.push({ kind: 'emit_call', nArgs, hasThis: false, loc, calleeName });
        for (let i = nArgs - 1; i >= 0; i--) {
          tasks.push({ kind: 'visit', node: node.arguments[i] });
        }
        tasks.push({ kind: 'visit', node: node.callee });
      }
      return;
    }
    case 'NewExpression': {
      const nArgs = node.arguments.length;
      tasks.push({ kind: 'emit_new', nArgs, loc });
      for (let i = nArgs - 1; i >= 0; i--) {
        tasks.push({ kind: 'visit', node: node.arguments[i] });
      }
      tasks.push({ kind: 'visit', node: node.callee });
      return;
    }
    case 'FunctionExpression':
    case 'ArrowFunctionExpression': {
      // Function expressions reuse the same lowering path as
      // function declarations: lowerFunctionDecl emits the FUNC
      // instruction in the CURRENT (outer) block immediately
      // and returns its dest register, then defers the body
      // lowering by pushing enter_function / body / leave_function
      // tasks onto ctx._work. The deferred body runs later when
      // drainWork pops those tasks; the expression iterator just
      // needs the dest register, which is valid right now.
      //
      // Iterative: no recursive drainWork call. Nested function
      // expressions push more deferred tasks the same way; any
      // nesting depth is supported without growing the JS call
      // stack.
      const syntheticDecl = {
        type: 'FunctionDeclaration',
        id: null,
        params: node.params,
        body: node.body && node.body.type === 'BlockStatement'
          ? node.body
          : { type: 'BlockStatement', body: [{ type: 'ReturnStatement', argument: node.body, loc: node.loc, start: node.start, end: node.end }], loc: node.loc, start: node.start, end: node.end },
        async: !!node.async,
        generator: !!node.generator,
        loc: node.loc,
        start: node.start,
        end: node.end,
      };
      const dest = lowerFunctionDecl(ctx, syntheticDecl, loc);
      results.push(dest);
      return;
    }
    default: {
      const dest = lowerUnimplementedExpr(ctx, node, loc);
      results.push(dest);
      return;
    }
  }
}

function lowerUnimplementedExpr(ctx, node, loc) {
  const dest = newRegister(ctx.module);
  emit(ctx.module, ctx.currentBlock, {
    op: OP.OPAQUE,
    dest,
    reason: REASONS.UNIMPLEMENTED,
    details: 'expression kind not yet implemented: ' + node.type,
    affects: null,
  }, loc);
  return dest;
}

// --- Scope snapshots for phi generation ---------------------------------

function snapshotScope(scope) {
  return { frames: scope.frames.map(f => Object.assign(Object.create(null), f)) };
}
function restoreScope(scope, snap) {
  scope.frames = snap.frames.map(f => Object.assign(Object.create(null), f));
}
function lookupInSnapshot(snap, name) {
  for (let i = snap.frames.length - 1; i >= 0; i--) {
    if (name in snap.frames[i]) return snap.frames[i][name];
  }
  return null;
}

// --- Module validation --------------------------------------------------

function validateModule(module) {
  for (const fn of module.functions) {
    if (!fn.cfg) throw new Error('ir: function ' + fn.id + ' has no cfg');
    for (const [blockId, block] of fn.cfg.blocks) {
      if (!block.terminator) {
        throw new Error('ir: block ' + blockId + ' in ' + fn.id + ' has no terminator');
      }
      for (const instr of block.instructions) {
        if (!instr.op) throw new Error('ir: instr missing op in ' + blockId);
        if (TERMINATOR_KINDS.has(instr.op)) {
          throw new Error('ir: terminator ' + instr.op + ' in middle of block ' + blockId);
        }
      }
    }
  }
}

module.exports = {
  OP,
  TERMINATOR_KINDS,
  buildModule,
  createModule,
  createFunction,
  createBlock,
  newRegister,
  emit,
  addEdge,
  validateModule,
  // Exposed for tests
  lowerExpression,
  lowerStatement,
};
