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
// Each scope frame is tagged with its lexical kind:
//
//   { kind: 'function', bindings: { name → binding } }
//   { kind: 'block',    bindings: { name → binding } }
//
// A binding records both the current SSA register AND the
// declaration kind that created it:
//
//   { reg, kind: 'var' | 'let' | 'const' | 'function' | 'param' }
//
// Declaration kind drives several JS semantics:
//
//   * `var` and `function` are FUNCTION-scoped: defineVar walks
//     outward until it finds the nearest 'function' frame, so
//     `{ var x = 1; } x` is visible.
//   * `let` and `const` are BLOCK-scoped: defineLet/defineConst
//     only touch the innermost (block or function) frame. A
//     post-pop reference becomes unbound.
//   * Reassigning a `const` binding raises an explicit
//     assumption — the value lattice still updates (we stay
//     sound) but the imprecision is visible.
//   * TDZ: let/const declarations seed the binding with a
//     frozen Opaque(TDZ) sentinel at block entry; a reference
//     that hits the sentinel instead of a real value carries
//     the TDZ assumption forward.

const BIND = Object.freeze({
  VAR:      'var',
  LET:      'let',
  CONST:    'const',
  FUNCTION: 'function',
  PARAM:    'param',
});

function createScopeMap() {
  return { frames: [{ kind: 'function', bindings: Object.create(null) }] };
}
function pushFunctionFrame(scope) {
  scope.frames.push({ kind: 'function', bindings: Object.create(null) });
}
function pushBlockFrame(scope) {
  scope.frames.push({ kind: 'block', bindings: Object.create(null) });
}
function popFrame(scope) { scope.frames.pop(); }

// Find the nearest enclosing 'function' frame index (or 0 if none).
function nearestFunctionFrame(scope) {
  for (let i = scope.frames.length - 1; i >= 0; i--) {
    if (scope.frames[i].kind === 'function') return i;
  }
  return 0;
}

// var / function / param binding: define in the nearest function frame.
function defineHoisted(scope, name, reg, kind) {
  const i = nearestFunctionFrame(scope);
  scope.frames[i].bindings[name] = { reg, kind };
}
// let / const binding: define in the innermost (block or function) frame.
function defineLexical(scope, name, reg, kind) {
  const i = scope.frames.length - 1;
  scope.frames[i].bindings[name] = { reg, kind };
}

// Legacy catch-all. Defaults to var-style (function-scoped).
function defineName(scope, name, reg) {
  defineHoisted(scope, name, reg, BIND.VAR);
}

// Walk frames innermost-outward; return the register only.
function lookupName(scope, name) {
  for (let i = scope.frames.length - 1; i >= 0; i--) {
    const b = scope.frames[i].bindings[name];
    if (b) return b.reg;
  }
  return null;
}

// Full lookup: returns the binding record ({reg, kind}) or null.
function lookupBinding(scope, name) {
  for (let i = scope.frames.length - 1; i >= 0; i--) {
    const b = scope.frames[i].bindings[name];
    if (b) return b;
  }
  return null;
}

// Update (reassignment) — finds the nearest existing binding and
// replaces it with a fresh record. We do NOT mutate the existing
// binding object because scope snapshots hold shallow references
// to the same binding objects; mutating in place would retroactively
// change the captured then/else scopes used to emit phis.
//
// const reassignment is tolerated at the IR level (the transfer
// still tracks the new value), but the caller may want to raise an
// assumption about it. If no binding exists we create one in the
// nearest FUNCTION frame (implicit global in sloppy mode).
function updateName(scope, name, reg) {
  for (let i = scope.frames.length - 1; i >= 0; i--) {
    const b = scope.frames[i].bindings[name];
    if (b) {
      scope.frames[i].bindings[name] = { reg, kind: b.kind };
      return { frameIndex: i, kind: b.kind };
    }
  }
  const fi = nearestFunctionFrame(scope);
  scope.frames[fi].bindings[name] = { reg, kind: BIND.VAR };
  return { frameIndex: fi, kind: BIND.VAR };
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
  // Hoist var and function declarations at the program level so
  // they are visible to any earlier reference (matches JS's
  // hoisting semantics: `f(); function f(){}` and `x = 1; var x`
  // both work). The hoist task runs first because it's at the
  // bottom of the LIFO stack.
  ctx._work.push({ kind: 'hoist_decls', bodyNodes: programNode.body });
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
    case 'block_enter':      pushBlockFrame(ctx.scope); return;
    case 'block_exit':       popFrame(ctx.scope); return;
    case 'after_stmt':       return afterStmtStep(ctx);
    case 'prog_after_stmt':  return progAfterStmtStep(ctx);
    case 'if_after_then':    return ifAfterThenStep(ctx, task);
    case 'if_after_else':    return ifAfterElseStep(ctx, task);
    case 'if_merge':         return ifMergeStep(ctx, task);
    case 'set_block':        ctx.currentBlock = task.block; return;
    case 'enter_function':   return enterFunctionStep(ctx, task);
    case 'leave_function':   return leaveFunctionStep(ctx, task);
    case 'hoist_decls':      return hoistDeclarationsStep(ctx, task);
    case 'finish_loop_body': return finishLoopBodyStep(ctx, task);
    case 'finish_do_while_cond': return finishDoWhileCondStep(ctx, task);
    case 'finish_try_body':    return finishTryBodyStep(ctx, task);
    case 'finish_try_catch':   return finishTryCatchStep(ctx, task);
    case 'finish_try_finally': return finishTryFinallyStep(ctx, task);
    default:
      throw new Error('ir: unknown statement task ' + task.kind);
  }
}

// --- Hoisting ----------------------------------------------------------
//
// `hoist_decls` pre-scans a list of statement AST nodes for:
//
//   1. FunctionDeclarations at this level (not inside inner
//      functions): creates each function, emits its Func instr in
//      the current block, and binds the name in the enclosing
//      function frame.
//
//   2. VariableDeclarations with kind === 'var': pre-binds each
//      name to an `undefined` concrete in the enclosing function
//      frame. This matches JS var-hoisting: `x` is defined from
//      the top of the function, with value `undefined` until the
//      init runs.
//
// Recursion: we walk down into nested block-like statements
// (BlockStatement, IfStatement, TryStatement, etc.) to find
// hoisted declarations, but STOP at any FunctionDeclaration or
// FunctionExpression or ArrowFunctionExpression because those
// start a new function scope.
function hoistDeclarationsStep(ctx, task) {
  const bodyNodes = task.bodyNodes || [];
  // Step 1: pre-scan for var names and hoist them as undefined.
  const varNames = new Set();
  collectHoistedVarNames(bodyNodes, varNames);
  for (const name of varNames) {
    // Skip names that are already bound (e.g. parameter names).
    // Parameter bindings take precedence over a `var` of the
    // same name; the var just becomes a no-op.
    if (lookupBinding(ctx.scope, name)) continue;
    const reg = newRegister(ctx.module);
    emit(ctx.module, ctx.currentBlock, {
      op: OP.CONST, dest: reg, value: undefined,
    }, null);
    defineHoisted(ctx.scope, name, reg, BIND.VAR);
  }
  // Step 2: pre-scan for FunctionDeclarations. For each, create
  // the function, emit its Func instr in the current block, bind
  // the name, and push the body-lowering tasks so the nested
  // function's CFG gets populated in the same drain loop.
  //
  // The walk stops at any inner function boundary.
  const fnDecls = [];
  collectHoistedFunctionDecls(bodyNodes, fnDecls);
  for (const fnNode of fnDecls) {
    // Re-use lowerFunctionDecl: it creates the function, emits
    // Func in ctx.currentBlock, binds the name, and pushes the
    // enter/body/leave tasks. We just need to make sure the
    // function's name doesn't get rebound by the regular
    // FunctionDeclaration case of lowerStatement later — we
    // handle that with the `_hoisted` set below.
    if (!ctx._hoistedFnNodes) ctx._hoistedFnNodes = new Set();
    ctx._hoistedFnNodes.add(fnNode);
    lowerFunctionDecl(ctx, fnNode, locFromNode(fnNode, ctx.filename));
  }
}

// Collect var names from a statement list. Descends into nested
// BlockStatement / IfStatement / LabeledStatement / SwitchStatement
// / TryStatement (the places where `var` might appear), but
// stops at any function boundary.
function collectHoistedVarNames(nodes, out) {
  const stack = nodes.slice().reverse();
  while (stack.length > 0) {
    const n = stack.pop();
    if (!n) continue;
    if (n.type === 'VariableDeclaration' && n.kind === 'var') {
      for (const d of n.declarations) {
        if (d.id && d.id.type === 'Identifier') out.add(d.id.name);
      }
      continue;
    }
    if (n.type === 'BlockStatement') {
      for (let i = n.body.length - 1; i >= 0; i--) stack.push(n.body[i]);
      continue;
    }
    if (n.type === 'IfStatement') {
      if (n.alternate) stack.push(n.alternate);
      if (n.consequent) stack.push(n.consequent);
      continue;
    }
    if (n.type === 'LabeledStatement') {
      stack.push(n.body);
      continue;
    }
    if (n.type === 'ForStatement' || n.type === 'ForInStatement' ||
        n.type === 'ForOfStatement' || n.type === 'WhileStatement' ||
        n.type === 'DoWhileStatement') {
      if (n.init && n.init.type === 'VariableDeclaration' && n.init.kind === 'var') {
        for (const d of n.init.declarations) {
          if (d.id && d.id.type === 'Identifier') out.add(d.id.name);
        }
      }
      if (n.body) stack.push(n.body);
      continue;
    }
    if (n.type === 'SwitchStatement') {
      for (const c of n.cases) {
        for (let i = c.consequent.length - 1; i >= 0; i--) stack.push(c.consequent[i]);
      }
      continue;
    }
    if (n.type === 'TryStatement') {
      if (n.block) stack.push(n.block);
      if (n.handler && n.handler.body) stack.push(n.handler.body);
      if (n.finalizer) stack.push(n.finalizer);
      continue;
    }
    // Function boundaries stop the walk: FunctionDeclaration /
    // FunctionExpression / ArrowFunctionExpression. We DO walk
    // into the function's body separately when we hoist it.
    // Other statement kinds (Expression, Return, Break, etc.)
    // don't contain `var` bindings we care about.
  }
}

// Collect FunctionDeclaration nodes at the current function's
// top level (not inside nested functions). Walks the same shape
// tree as collectHoistedVarNames but matches FunctionDeclaration
// instead. Order is preserved so hoisted functions appear in
// source-order in the IR.
function collectHoistedFunctionDecls(nodes, out) {
  // BFS to preserve source order at each level; DFS into blocks.
  const stack = nodes.slice().reverse();
  while (stack.length > 0) {
    const n = stack.pop();
    if (!n) continue;
    if (n.type === 'FunctionDeclaration') {
      out.push(n);
      continue;
    }
    if (n.type === 'BlockStatement') {
      for (let i = n.body.length - 1; i >= 0; i--) stack.push(n.body[i]);
      continue;
    }
    if (n.type === 'IfStatement') {
      if (n.alternate) stack.push(n.alternate);
      if (n.consequent) stack.push(n.consequent);
      continue;
    }
    if (n.type === 'LabeledStatement') { stack.push(n.body); continue; }
    if (n.type === 'ForStatement' || n.type === 'ForInStatement' ||
        n.type === 'ForOfStatement' || n.type === 'WhileStatement' ||
        n.type === 'DoWhileStatement') {
      if (n.body) stack.push(n.body);
      continue;
    }
    if (n.type === 'SwitchStatement') {
      for (const c of n.cases) {
        for (let i = c.consequent.length - 1; i >= 0; i--) stack.push(c.consequent[i]);
      }
      continue;
    }
    if (n.type === 'TryStatement') {
      if (n.block) stack.push(n.block);
      if (n.handler && n.handler.body) stack.push(n.handler.body);
      if (n.finalizer) stack.push(n.finalizer);
      continue;
    }
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
    case 'FunctionDeclaration': {
      // If this declaration was already hoisted by a hoist_decls
      // task, skip it — the function has been created, its Func
      // instr emitted, and its body tasks queued. Re-lowering
      // would create a duplicate function and clobber the binding.
      if (ctx._hoistedFnNodes && ctx._hoistedFnNodes.has(node)) return;
      return lowerFunctionDecl(ctx, node, loc);
    }
    case 'ClassDeclaration':
    case 'ClassExpression':    return lowerClassDeclaration(ctx, node, loc);
    case 'WhileStatement':     return beginWhile(ctx, node, loc);
    case 'DoWhileStatement':   return beginDoWhile(ctx, node, loc);
    case 'ForStatement':       return beginFor(ctx, node, loc);
    case 'BreakStatement':     return lowerBreak(ctx, node, loc);
    case 'ContinueStatement':  return lowerContinue(ctx, node, loc);
    case 'TryStatement':       return beginTry(ctx, node, loc);
    case 'ThrowStatement':     return lowerThrow(ctx, node, loc);
    case 'WithStatement':      return lowerWith(ctx, node, loc);
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
    for (const k of allNamesInSnapshot(s)) allNames.add(k);
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

// --- Class lowering -----------------------------------------------------
//
// A class desugars into a constructor function whose body is:
//
//     (original constructor body)
//     this.method1 = function(...) { ... };
//     this.method2 = function(...) { ... };
//     ...
//     this.field1 = <field-init>;
//     ...
//
// which preserves the observable effects (instance methods are
// accessible as properties of `this`) using existing IR
// machinery (FunctionDeclaration + SetProp).
//
// Static members become properties of the class identifier:
//
//     ClassName.staticMethod = function(...) { ... };
//
// emitted OUTSIDE the constructor, after the class declaration.
//
// `extends` and `super` are not yet modeled precisely — we
// raise an unimplemented assumption and otherwise treat the
// class as standalone.
//
// Fields default to `undefined` if no initializer; otherwise
// we emit the initializer expression in the constructor prolog.
//
// Private (`#x`) members and getters/setters are parsed as
// UnimplementedClassMember nodes in the AST; we raise a
// soundness assumption and skip them.
function lowerClassDeclaration(ctx, node, loc) {
  const className = node.id && node.id.name;

  // Extends: lower the parent class expression to a register.
  // applyNew walks the __parent__ chain automatically so parent
  // constructors run before the child's.
  let parentReg = null;
  if (node.superClass) {
    parentReg = lowerExpression(ctx, node.superClass);
  }

  const members = (node.body && node.body.body) || [];
  let ctorDef = null;
  const instanceMembers = [];
  const staticMembers = [];
  for (const m of members) {
    if (!m) continue;
    if (m.type === 'MethodDefinition' && m.kind === 'constructor') {
      ctorDef = m;
      continue;
    }
    if (m.type === 'MethodDefinition' || m.type === 'PropertyDefinition') {
      (m.static ? staticMembers : instanceMembers).push(m);
      continue;
    }
    if (m.type === 'UnimplementedClassMember') {
      ctx.assumptions.raise(
        REASONS.UNIMPLEMENTED,
        'class member kind `' + m.kind + '` not yet modeled',
        loc
      );
      continue;
    }
  }

  // Build the synthesised constructor body:
  //   instance field/method assignments first, then original
  //   constructor body.
  const instanceAssigns = [];
  for (const m of instanceMembers) {
    const keyName = m.key.type === 'Identifier' ? m.key.name : null;
    if (!keyName) continue;
    let valueNode;
    if (m.type === 'MethodDefinition') {
      valueNode = m.value;  // FunctionExpression
    } else {
      valueNode = m.value || { type: 'Literal', value: undefined };
    }
    // Emit `this.keyName = valueNode;` as an ExpressionStatement
    // containing an AssignmentExpression.
    instanceAssigns.push(mkExprStmt(mkAssignThis(keyName, valueNode, loc)));
  }

  const origCtorBody = ctorDef && ctorDef.value && ctorDef.value.body
    && ctorDef.value.body.body
    ? ctorDef.value.body.body
    : [];
  const ctorParams = ctorDef && ctorDef.value ? ctorDef.value.params : [];

  const syntheticBody = {
    type: 'BlockStatement',
    body: instanceAssigns.concat(origCtorBody),
    loc: node.body ? node.body.loc : null,
    start: node.start || 0,
    end: node.end || 0,
  };

  const syntheticDecl = {
    type: 'FunctionDeclaration',
    id: className ? { type: 'Identifier', name: className, loc: node.id ? node.id.loc : null, start: node.id ? node.id.start : 0, end: node.id ? node.id.end : 0 } : null,
    params: ctorParams,
    body: syntheticBody,
    async: false,
    generator: false,
    loc: node.loc,
    start: node.start || 0,
    end: node.end || 0,
  };

  const ctorReg = lowerFunctionDecl(ctx, syntheticDecl, loc);

  // Build a heap-allocated "class object" that holds both the
  // constructor closure (under the reserved `__ctor__` field)
  // and every static method / field. This makes static members
  // work precisely: `ClassName.staticMethod()` becomes a
  // regular member access on a real ObjectRef, which applyCall
  // already resolves to the stored closure and walks.
  //
  // The class NAME is bound to this class object (not to the
  // bare constructor closure). `new ClassName(args)` sees an
  // ObjectRef at the ctor position and applyNew's ObjectRef
  // branch reads `__ctor__` to recover the real constructor.
  //
  // Pre-lower each static member into its register so we can
  // build the ALLOC's fields map atomically.
  const fields = new Map();
  fields.set('__ctor__', ctorReg);
  if (parentReg != null) fields.set('__parent__', parentReg);
  for (const m of staticMembers) {
    const keyName = m.key.type === 'Identifier' ? m.key.name : null;
    if (!keyName) continue;
    let valueReg;
    if (m.type === 'MethodDefinition') {
      valueReg = lowerExpression(ctx, m.value);
    } else {
      valueReg = m.value ? lowerExpression(ctx, m.value) : emitUndefinedConst(ctx, loc);
    }
    fields.set(keyName, valueReg);
  }
  const classObjReg = newRegister(ctx.module);
  emit(ctx.module, ctx.currentBlock, {
    op: OP.ALLOC,
    dest: classObjReg,
    kind: 'Class',
    // Attach the class name so applyNew can use it as the
    // `typeName` of the instance it creates.
    className: className || null,
    fields,
  }, loc);

  // Bind the class name to the class object in the outer scope.
  if (className) {
    defineHoisted(ctx.scope, className, classObjReg, BIND.FUNCTION);
  }

  // ClassExpression case: push the register onto the expression
  // results stack.
  if (node.type === 'ClassExpression' && ctx._classExprResult != null) {
    ctx._classExprResult = classObjReg;
  }
}

function emitUndefinedConst(ctx, loc) {
  const reg = newRegister(ctx.module);
  emit(ctx.module, ctx.currentBlock, {
    op: OP.CONST, dest: reg, value: undefined,
  }, loc);
  return reg;
}

// Synthesis helpers for the class desugaring — build tiny AST
// snippets that mirror `this.key = value;`. Because the class
// desugaring creates nodes programmatically, we leave `loc` as
// null: locFromNode returns a safe `{file: filename, line: 0,
// ...}` placeholder when loc is absent.
function mkExprStmt(expr) {
  return {
    type: 'ExpressionStatement',
    expression: expr,
    loc: null,
    start: 0, end: 0,
  };
}

function mkAssignThis(key, valueNode /*, loc */) {
  return {
    type: 'AssignmentExpression',
    operator: '=',
    left: {
      type: 'MemberExpression',
      object: { type: 'ThisExpression', loc: null, start: 0, end: 0 },
      property: { type: 'Identifier', name: key, loc: null, start: 0, end: 0 },
      computed: false,
      optional: false,
      loc: null, start: 0, end: 0,
    },
    right: valueNode,
    loc: null, start: 0, end: 0,
  };
}

// --- Loop lowering ------------------------------------------------------
//
// All loop forms share the same CFG backbone:
//
//   predBlock (falls through) → headerBlock (branch on cond)
//     headerBlock.trueTarget  = bodyBlock
//     headerBlock.falseTarget = exitBlock
//   bodyBlock → ... → headerBlock  (back edge)
//
// Phi nodes at the header merge the pre-loop values with the
// body's output values. To insert them correctly we have to
// precompute which names the body assigns — we walk the body
// AST and collect written identifier names (stopping at
// nested function boundaries).
//
// `break` and `continue` jump to the loop's exitBlock and
// continueTarget respectively. We track these on a
// ctx._loopStack so nested loops work.
//
// The worklist's monotone fixpoint handles loop convergence:
// each back edge re-enqueues the header with the joined state,
// and the finite-height Value lattice guarantees termination.
// No iteration cap is needed — divergence would be a lattice
// bug that should surface as a hang rather than silent
// imprecision.

function beginWhile(ctx, node, loc) {
  const predBlock = ctx.currentBlock;

  // Pre-scan the body AST for names that get assigned inside
  // (not counting inner functions). These need phi nodes at
  // the header so references inside the loop see a register
  // that joins the pre-loop and body-exit values.
  const loopDefs = new Set();
  collectAssignedNames([node.body], loopDefs);

  // Allocate header, body, and exit blocks.
  const headerBlock = createBlock(ctx.module);
  ctx.blocks.set(headerBlock.id, headerBlock);
  addEdge(predBlock, headerBlock);

  const bodyBlock = createBlock(ctx.module);
  ctx.blocks.set(bodyBlock.id, bodyBlock);
  addEdge(headerBlock, bodyBlock);

  const exitBlock = createBlock(ctx.module);
  ctx.blocks.set(exitBlock.id, exitBlock);
  addEdge(headerBlock, exitBlock);

  // Fall through from predBlock to header.
  emit(ctx.module, predBlock, {
    op: OP.JUMP, target: headerBlock.id,
  }, loc);

  // Emit a Phi at the header for each loop-def name, with one
  // incoming entry (from predBlock) for now. The second incoming
  // (from the body exit) is appended in finishLoopBodyStep.
  const phis = [];  // { name, destReg, instr }
  for (const name of loopDefs) {
    const currentReg = lookupName(ctx.scope, name);
    if (currentReg == null) continue;  // hoist should have bound it; skip
    const destReg = newRegister(ctx.module);
    const phiInstr = {
      op: OP.PHI,
      dest: destReg,
      incoming: [{ pred: predBlock.id, value: currentReg }],
    };
    emit(ctx.module, headerBlock, phiInstr, loc);
    updateName(ctx.scope, name, destReg);
    phis.push({ name, destReg, instr: phiInstr });
  }

  // Now lower the cond in the header block. It reads phi-bound
  // registers where applicable.
  ctx.currentBlock = headerBlock;
  const condReg = lowerExpression(ctx, node.test);
  emit(ctx.module, headerBlock, {
    op: OP.BRANCH,
    cond: condReg,
    trueTarget: bodyBlock.id,
    falseTarget: exitBlock.id,
  }, loc);

  // Push the loop context so break/continue know their targets,
  // and so finish_loop_body can find the phi list.
  if (!ctx._loopStack) ctx._loopStack = [];
  ctx._loopStack.push({
    headerBlock,
    bodyBlock,
    exitBlock,
    continueTarget: headerBlock,
    phis,
  });

  // Switch to the body block and queue body lowering + finish.
  ctx.currentBlock = bodyBlock;
  ctx._work.push({ kind: 'finish_loop_body', loc });
  ctx._work.push({ kind: 'after_stmt' });
  ctx._work.push({ kind: 'lower_stmt', node: node.body });
}

function beginDoWhile(ctx, node, loc) {
  const predBlock = ctx.currentBlock;

  const loopDefs = new Set();
  collectAssignedNames([node.body], loopDefs);

  // do-while: bodyBlock runs first (always at least once), then
  // condBlock evaluates the test, branches back to bodyBlock or
  // forward to exitBlock.
  //
  //   predBlock → bodyBlock → condBlock (branch)
  //     condBlock.trueTarget  = bodyBlock   (back edge)
  //     condBlock.falseTarget = exitBlock
  const bodyBlock = createBlock(ctx.module);
  ctx.blocks.set(bodyBlock.id, bodyBlock);
  addEdge(predBlock, bodyBlock);

  const condBlock = createBlock(ctx.module);
  ctx.blocks.set(condBlock.id, condBlock);
  addEdge(bodyBlock, condBlock);

  const exitBlock = createBlock(ctx.module);
  ctx.blocks.set(exitBlock.id, exitBlock);
  addEdge(condBlock, exitBlock);

  emit(ctx.module, predBlock, {
    op: OP.JUMP, target: bodyBlock.id,
  }, loc);

  // Phis at bodyBlock: pre-loop entry + back edge from condBlock.
  const phis = [];
  for (const name of loopDefs) {
    const currentReg = lookupName(ctx.scope, name);
    if (currentReg == null) continue;
    const destReg = newRegister(ctx.module);
    const phiInstr = {
      op: OP.PHI,
      dest: destReg,
      incoming: [{ pred: predBlock.id, value: currentReg }],
    };
    emit(ctx.module, bodyBlock, phiInstr, loc);
    updateName(ctx.scope, name, destReg);
    phis.push({ name, destReg, instr: phiInstr });
  }

  if (!ctx._loopStack) ctx._loopStack = [];
  ctx._loopStack.push({
    headerBlock: bodyBlock,      // phis live here; continue re-enters body
    bodyBlock,
    exitBlock,
    condBlock,
    continueTarget: condBlock,
    phis,
    isDoWhile: true,
    testNode: node.test,
  });

  ctx.currentBlock = bodyBlock;
  ctx._work.push({ kind: 'finish_do_while_cond', loc });
  ctx._work.push({ kind: 'after_stmt' });
  ctx._work.push({ kind: 'lower_stmt', node: node.body });
}

function beginFor(ctx, node, loc) {
  // For statement: `for (init; test; update) body`
  //
  // Any of init, test, update may be null. We desugar to a while
  // loop by lowering init in the pred block, then building the
  // same header/body/exit structure, with `update` lowered in a
  // dedicated updateBlock that sits on the back edge:
  //
  //   predBlock → initLowered → headerBlock (branch on test)
  //   bodyBlock → updateBlock → headerBlock
  //
  // If init is a VariableDeclaration, lower it as a regular
  // statement (it may be var/let/const — for simple for-loops we
  // don't create a separate lexical block, which is a known
  // imprecision for `for (let i; ...)` but sound).
  const predBlock = ctx.currentBlock;

  // Lower init (if any) directly into the predBlock.
  if (node.init) {
    if (node.init.type === 'VariableDeclaration') {
      lowerVarDecl(ctx, node.init, loc);
    } else {
      lowerExpression(ctx, node.init);
    }
  }

  // Collect names assigned inside body OR update — both need phis
  // at the header because they flow back through the header on
  // the next iteration.
  const loopDefs = new Set();
  collectAssignedNames([node.body], loopDefs);
  if (node.update) collectAssignedNamesFromExpression(node.update, loopDefs);

  const headerBlock = createBlock(ctx.module);
  ctx.blocks.set(headerBlock.id, headerBlock);
  addEdge(ctx.currentBlock, headerBlock);

  const bodyBlock = createBlock(ctx.module);
  ctx.blocks.set(bodyBlock.id, bodyBlock);
  addEdge(headerBlock, bodyBlock);

  const updateBlock = createBlock(ctx.module);
  ctx.blocks.set(updateBlock.id, updateBlock);
  addEdge(bodyBlock, updateBlock);

  const exitBlock = createBlock(ctx.module);
  ctx.blocks.set(exitBlock.id, exitBlock);
  addEdge(headerBlock, exitBlock);

  emit(ctx.module, ctx.currentBlock, {
    op: OP.JUMP, target: headerBlock.id,
  }, loc);
  const initExitBlock = ctx.currentBlock;

  // Phis at header: incoming from init-exit + update-exit.
  const phis = [];
  for (const name of loopDefs) {
    const currentReg = lookupName(ctx.scope, name);
    if (currentReg == null) continue;
    const destReg = newRegister(ctx.module);
    const phiInstr = {
      op: OP.PHI,
      dest: destReg,
      incoming: [{ pred: initExitBlock.id, value: currentReg }],
    };
    emit(ctx.module, headerBlock, phiInstr, loc);
    updateName(ctx.scope, name, destReg);
    phis.push({ name, destReg, instr: phiInstr });
  }

  // Lower test in header (it reads phi-bound regs).
  ctx.currentBlock = headerBlock;
  let condReg;
  if (node.test) {
    condReg = lowerExpression(ctx, node.test);
  } else {
    // No test → always true (infinite loop). Emit a constant true.
    condReg = newRegister(ctx.module);
    emit(ctx.module, headerBlock, {
      op: OP.CONST, dest: condReg, value: true,
    }, loc);
  }
  emit(ctx.module, headerBlock, {
    op: OP.BRANCH,
    cond: condReg,
    trueTarget: bodyBlock.id,
    falseTarget: exitBlock.id,
  }, loc);

  if (!ctx._loopStack) ctx._loopStack = [];
  ctx._loopStack.push({
    headerBlock,
    bodyBlock,
    updateBlock,       // where `continue` lands (runs update then header)
    exitBlock,
    continueTarget: updateBlock,
    phis,
    updateNode: node.update,
  });

  ctx.currentBlock = bodyBlock;
  ctx._work.push({ kind: 'finish_loop_body', loc });
  ctx._work.push({ kind: 'after_stmt' });
  ctx._work.push({ kind: 'lower_stmt', node: node.body });
}

// finish_loop_body — runs after the body has been lowered for
// while / for loops. Closes the back edge, appends incoming phi
// entries for the body-exit and any `continue` sources, and
// adds phi nodes at the exit block for `break`-source values
// that disagree with the header-normal exit.
function finishLoopBodyStep(ctx, task) {
  const loop = ctx._loopStack.pop();
  const bodyExitBlock = ctx.currentBlock;

  // --- Body exit: route through updateBlock (for-loop) or
  // directly back to the header (while).
  let backEdgeSource = bodyExitBlock;
  if (loop.updateBlock) {
    if (!bodyExitBlock.terminator) {
      emit(ctx.module, bodyExitBlock, {
        op: OP.JUMP, target: loop.updateBlock.id,
      }, task.loc);
      addEdge(bodyExitBlock, loop.updateBlock);
    }
    // `continue` sources also jump to updateBlock, NOT header,
    // for for-loops. They're already recorded in continueSources
    // with a Jump to continueTarget (= updateBlock).
    ctx.currentBlock = loop.updateBlock;
    if (loop.updateNode) {
      lowerExpression(ctx, loop.updateNode);
    }
    backEdgeSource = ctx.currentBlock;
  }

  if (!backEdgeSource.terminator) {
    emit(ctx.module, backEdgeSource, {
      op: OP.JUMP, target: loop.headerBlock.id,
    }, task.loc);
    addEdge(backEdgeSource, loop.headerBlock);
  }

  // --- Header phi completion.
  //
  // Each phi gets incoming entries for:
  //   1. The body-exit path (via backEdgeSource).
  //   2. For while-loops: each `continue` source block (those
  //      jump directly to the header).
  //   3. For for-loops: continue sources jump to updateBlock,
  //      which then flows to backEdgeSource above, so they're
  //      already covered.
  for (const phi of loop.phis) {
    const finalReg = lookupName(ctx.scope, phi.name);
    if (finalReg != null) {
      phi.instr.incoming.push({ pred: backEdgeSource.id, value: finalReg });
    }
    // For while-loops (no updateBlock), continue sources bypass
    // the body-exit and reach the header directly.
    if (!loop.updateBlock && loop.continueSources) {
      for (const src of loop.continueSources) {
        const reg = lookupInSnapshot(src.scope, phi.name);
        if (reg != null) {
          phi.instr.incoming.push({ pred: src.block.id, value: reg });
        }
      }
    }
  }

  // --- Exit block phi nodes.
  //
  // The exit block has at least one predecessor (the header's
  // false-target edge for while/for loops). For every `break`
  // source, we also add an incoming edge. If a name's value at
  // the break source differs from its header-out value, we emit
  // a phi at the exit block to merge them.
  //
  // The header-out value of a name is just the phi dest (names
  // in loop.phis) or the scope's current reg (names not in the
  // phi list).
  const exitPreds = [
    { block: loop.headerBlock, kind: 'header-normal' },
  ];
  if (loop.breakSources) {
    for (const src of loop.breakSources) {
      exitPreds.push({ block: src.block, kind: 'break', scope: src.scope });
    }
  }

  // Collect the set of names to reconcile at the exit block.
  // For each loop-phi name, we always emit an exit phi if there
  // are any break sources (the break side carries the body's
  // assigned value, the header side carries the phi dest).
  // Also reconcile names that the break sources touch but the
  // header phis don't (rare in practice but sound).
  const exitNames = new Set();
  if (loop.breakSources && loop.breakSources.length > 0) {
    for (const phi of loop.phis) exitNames.add(phi.name);
    for (const src of loop.breakSources) {
      for (const k of allNamesInSnapshot(src.scope)) exitNames.add(k);
    }
  }

  for (const name of exitNames) {
    const headerReg = lookupName(ctx.scope, name);   // phi dest or unchanged
    const incomings = [];
    if (headerReg != null) {
      incomings.push({ pred: loop.headerBlock.id, value: headerReg });
    }
    for (const src of loop.breakSources) {
      const reg = lookupInSnapshot(src.scope, name);
      if (reg != null) {
        incomings.push({ pred: src.block.id, value: reg });
      }
    }
    if (incomings.length === 0) continue;
    const allSame = incomings.every(i => i.value === incomings[0].value);
    if (allSame) {
      updateName(ctx.scope, name, incomings[0].value);
      continue;
    }
    const dest = newRegister(ctx.module);
    emit(ctx.module, loop.exitBlock, {
      op: OP.PHI, dest, incoming: incomings,
    }, task.loc);
    updateName(ctx.scope, name, dest);
  }

  // For loops with no break sources, just restore the scope
  // bindings to the phi dests so post-loop code sees the phi
  // values.
  if (!loop.breakSources || loop.breakSources.length === 0) {
    for (const phi of loop.phis) {
      updateName(ctx.scope, phi.name, phi.destReg);
    }
  }

  ctx.currentBlock = loop.exitBlock;
}

// finish_do_while_cond — runs after a do-while's body has been
// lowered. Falls through to condBlock, evaluates the test, emits
// the Branch, and closes phis + break-exit reconciliation.
function finishDoWhileCondStep(ctx, task) {
  const loop = ctx._loopStack.pop();
  const bodyExitBlock = ctx.currentBlock;

  if (!bodyExitBlock.terminator) {
    emit(ctx.module, bodyExitBlock, {
      op: OP.JUMP, target: loop.condBlock.id,
    }, task.loc);
  }
  ctx.currentBlock = loop.condBlock;
  const condReg = lowerExpression(ctx, loop.testNode);
  emit(ctx.module, loop.condBlock, {
    op: OP.BRANCH,
    cond: condReg,
    trueTarget: loop.bodyBlock.id,    // back edge
    falseTarget: loop.exitBlock.id,
  }, task.loc);
  addEdge(loop.condBlock, loop.bodyBlock);

  // Body-exit phi incomings (via condBlock's back edge).
  for (const phi of loop.phis) {
    const finalReg = lookupName(ctx.scope, phi.name);
    if (finalReg != null) {
      phi.instr.incoming.push({ pred: loop.condBlock.id, value: finalReg });
    }
  }
  // `continue` in do-while jumps to condBlock (the continueTarget),
  // which then re-tests and may loop back. The condBlock's only
  // active incoming is the body exit, so continues contribute
  // values through that path already.

  // Break reconciliation at the exit block (same pattern as
  // finishLoopBodyStep). Exit preds: condBlock's false path
  // plus each break source.
  const exitPreds = [
    { block: loop.condBlock, kind: 'cond-normal' },
  ];
  if (loop.breakSources) {
    for (const src of loop.breakSources) {
      exitPreds.push({ block: src.block, kind: 'break', scope: src.scope });
    }
  }
  const exitNames = new Set();
  if (loop.breakSources && loop.breakSources.length > 0) {
    for (const phi of loop.phis) exitNames.add(phi.name);
    for (const src of loop.breakSources) {
      for (const k of allNamesInSnapshot(src.scope)) exitNames.add(k);
    }
  }
  for (const name of exitNames) {
    const headerReg = lookupName(ctx.scope, name);
    const incomings = [];
    if (headerReg != null) {
      incomings.push({ pred: loop.condBlock.id, value: headerReg });
    }
    for (const src of loop.breakSources) {
      const reg = lookupInSnapshot(src.scope, name);
      if (reg != null) incomings.push({ pred: src.block.id, value: reg });
    }
    if (incomings.length === 0) continue;
    const allSame = incomings.every(i => i.value === incomings[0].value);
    if (allSame) { updateName(ctx.scope, name, incomings[0].value); continue; }
    const dest = newRegister(ctx.module);
    emit(ctx.module, loop.exitBlock, {
      op: OP.PHI, dest, incoming: incomings,
    }, task.loc);
    updateName(ctx.scope, name, dest);
  }
  if (!loop.breakSources || loop.breakSources.length === 0) {
    for (const phi of loop.phis) {
      updateName(ctx.scope, phi.name, phi.destReg);
    }
  }

  ctx.currentBlock = loop.exitBlock;
}

function lowerBreak(ctx, node, loc) {
  if (!ctx._loopStack || ctx._loopStack.length === 0) {
    lowerUnimplementedStmt(ctx, node, loc);
    return;
  }
  const loop = ctx._loopStack[ctx._loopStack.length - 1];
  emit(ctx.module, ctx.currentBlock, {
    op: OP.JUMP, target: loop.exitBlock.id,
  }, loc);
  addEdge(ctx.currentBlock, loop.exitBlock);
  // Record the break source: the block, and a snapshot of the
  // current scope bindings. finishLoopBodyStep uses these to add
  // phi nodes at the exit block for names that differ between the
  // loop's normal exit path (header-false) and each break point.
  if (!loop.breakSources) loop.breakSources = [];
  loop.breakSources.push({
    block: ctx.currentBlock,
    scope: snapshotScope(ctx.scope),
  });
}

function lowerContinue(ctx, node, loc) {
  if (!ctx._loopStack || ctx._loopStack.length === 0) {
    lowerUnimplementedStmt(ctx, node, loc);
    return;
  }
  const loop = ctx._loopStack[ctx._loopStack.length - 1];
  const target = loop.continueTarget;
  emit(ctx.module, ctx.currentBlock, {
    op: OP.JUMP, target: target.id,
  }, loc);
  addEdge(ctx.currentBlock, target);
  // Record the continue source the same way. For while/do-while
  // loops, continueTarget === headerBlock, so the header phi
  // needs an extra incoming from this source. For for-loops,
  // continueTarget is the updateBlock; the header phi will
  // receive the value via the update→header back edge after
  // update runs.
  if (!loop.continueSources) loop.continueSources = [];
  loop.continueSources.push({
    block: ctx.currentBlock,
    scope: snapshotScope(ctx.scope),
  });
}

// emitScopePhis — merges a set of predecessor scopes at a merge
// block and emits phi nodes for any name whose value differs
// between predecessors. Updates ctx.scope to bind each name to
// either the single common register (if all preds agree) or the
// newly-emitted phi dest.
//
// `preds` is an array of {block, scope} records. Each scope is
// a snapshot (see snapshotScope). The merge block is where
// phis get emitted.
//
// This is the factored-out version of ifMergeStep's phi logic,
// used by try/catch/finally merges so the same algorithm handles
// every 2+-way join. The if-merge still uses its own inline
// version for now to avoid churning a well-tested code path.
function emitScopePhis(ctx, mergeBlock, preds, loc) {
  const allNames = new Set();
  for (const p of preds) {
    for (const k of allNamesInSnapshot(p.scope)) allNames.add(k);
  }
  for (const name of allNames) {
    const incoming = [];
    for (const p of preds) {
      const reg = lookupInSnapshot(p.scope, name);
      if (reg != null) incoming.push({ pred: p.block.id, value: reg });
    }
    if (incoming.length === 0) continue;
    const first = incoming[0].value;
    const allSame = incoming.every(i => i.value === first);
    if (allSame) {
      updateName(ctx.scope, name, first);
      continue;
    }
    const dest = newRegister(ctx.module);
    emit(ctx.module, mergeBlock, {
      op: OP.PHI, dest, incoming,
    }, loc);
    updateName(ctx.scope, name, dest);
  }
}

// --- try / catch / finally lowering -------------------------------------
//
// CFG shape for `try { A } catch/e/ { B } finally { C }`:
//
//     predBlock → tryBlock
//     tryBlock exits (normal)  → finallyBlock (if finally exists)
//                                 OR mergeBlock
//     tryBlock "throws"        → catchBlock (if catch exists)
//                                 OR finallyBlock
//     catchBlock exits         → finallyBlock (if finally exists)
//                                 OR mergeBlock
//     catchBlock "throws"      → finallyBlock / outer handler
//                                 (re-raised)
//     finallyBlock exits       → mergeBlock (normal) OR outer
//                                 handler (re-raised)
//     mergeBlock               → subsequent code
//
// Approximation: we conservatively model every statement in the
// try block as potentially throwing. Since we can't enumerate
// per-statement exception edges without exploding the CFG, we
// add ONE edge from tryBlock's entry to catchBlock (catch sees
// the pre-try scope) AND one edge from tryBlock's exit to
// catchBlock (catch sees the post-try scope). The catch block's
// phis merge both — a safe upper bound on the reachable
// assignments.
//
// Throw routing: ctx._catchStack is a stack of catch targets.
// `throw` emits a Jump to the top-of-stack catch block, or a
// THROW terminator if no catch is in scope (uncaught).
//
// The catch parameter is bound as an Opaque value at catch
// entry. For soundness we mark it with an assumption so
// consumers see the imprecision.

function beginTry(ctx, node, loc) {
  const tryBlock = createBlock(ctx.module);
  ctx.blocks.set(tryBlock.id, tryBlock);
  addEdge(ctx.currentBlock, tryBlock);
  emit(ctx.module, ctx.currentBlock, {
    op: OP.JUMP, target: tryBlock.id,
  }, loc);
  const entryScope = snapshotScope(ctx.scope);
  const predBlock = ctx.currentBlock;

  const catchBlock = node.handler ? createBlock(ctx.module) : null;
  if (catchBlock) ctx.blocks.set(catchBlock.id, catchBlock);

  const finallyBlock = node.finalizer ? createBlock(ctx.module) : null;
  if (finallyBlock) ctx.blocks.set(finallyBlock.id, finallyBlock);

  const mergeBlock = createBlock(ctx.module);
  ctx.blocks.set(mergeBlock.id, mergeBlock);

  // Add the "any statement in try may throw" edge from predBlock
  // to catchBlock. The catch sees the pre-try scope through this.
  if (catchBlock) {
    addEdge(predBlock, catchBlock);
  } else if (finallyBlock) {
    addEdge(predBlock, finallyBlock);
  }

  // Push the catch target onto the catch stack so any `throw`
  // inside the try body routes to it (or to finally if no catch).
  if (!ctx._catchStack) ctx._catchStack = [];
  const throwTarget = catchBlock || finallyBlock || null;
  ctx._catchStack.push({ block: throwTarget, scope: entryScope });

  // Lower the try body in tryBlock.
  ctx.currentBlock = tryBlock;
  ctx._work.push({
    kind: 'finish_try_body',
    loc,
    tryBlock,
    catchBlock,
    finallyBlock,
    mergeBlock,
    entryScope,
    handler: node.handler,
    finalizer: node.finalizer,
  });
  ctx._work.push({ kind: 'after_stmt' });
  ctx._work.push({ kind: 'lower_stmt', node: node.block });
}

// finish_try_body — runs after the try body has been lowered.
// Records the try-exit scope, sets up the catch block (binding
// the catch parameter as an opaque value), and queues the
// catch body lowering.
function finishTryBodyStep(ctx, task) {
  const tryExitBlock = ctx.currentBlock;
  const tryExitScope = snapshotScope(ctx.scope);

  // Pop the catch-stack entry we pushed at beginTry.
  if (ctx._catchStack && ctx._catchStack.length > 0) {
    ctx._catchStack.pop();
  }

  // Route the try exit: normally we'd Jump to finally/merge,
  // but we also need the catch block to be reachable by the
  // worklist (to model the "any stmt may throw" over-
  // approximation). We emit an Opaque "maybe-threw" cond and
  // a Branch to { catch, normal-target }. Both successors are
  // reachable (the cond is opaque), so the catch block gets
  // visited and its phis see the try-exit state.
  //
  // For programs that throw partway through the try body, this
  // is unsound at the per-statement granularity (catch won't
  // see partial assignments before the throw point). A precise
  // model would split the try body into one block per potentially
  // -throwing statement; we defer that until consumers need it.
  if (!tryExitBlock.terminator) {
    const normalTarget = task.finallyBlock || task.mergeBlock;
    if (task.catchBlock) {
      const condReg = newRegister(ctx.module);
      emit(ctx.module, tryExitBlock, {
        op: OP.OPAQUE,
        dest: condReg,
        reason: REASONS.UNIMPLEMENTED,
        details: 'try body may throw — both catch and normal targets modeled',
        affects: null,
      }, task.loc);
      emit(ctx.module, tryExitBlock, {
        op: OP.BRANCH,
        cond: condReg,
        trueTarget: task.catchBlock.id,
        falseTarget: normalTarget.id,
      }, task.loc);
      addEdge(tryExitBlock, task.catchBlock);
      addEdge(tryExitBlock, normalTarget);
    } else {
      emit(ctx.module, tryExitBlock, {
        op: OP.JUMP, target: normalTarget.id,
      }, task.loc);
      addEdge(tryExitBlock, normalTarget);
    }
  }

  if (task.catchBlock && task.handler) {
    // Switch to the catch block, bind the catch parameter, and
    // queue the catch body lowering.
    ctx.currentBlock = task.catchBlock;
    // Restore the pre-try scope: the catch sees names as they
    // were before try started. This is the conservative
    // approximation — precise modeling would phi each name
    // between the pre-try and try-exit scopes.
    restoreScope(ctx.scope, task.entryScope);
    pushBlockFrame(ctx.scope);

    // Bind the catch parameter.
    if (task.handler.param && task.handler.param.type === 'Identifier') {
      const paramReg = newRegister(ctx.module);
      emit(ctx.module, task.catchBlock, {
        op: OP.OPAQUE, dest: paramReg,
        reason: REASONS.UNIMPLEMENTED,
        details: 'catch parameter binding: exception value is opaque',
        affects: task.handler.param.name,
      }, task.loc);
      defineLexical(ctx.scope, task.handler.param.name, paramReg, BIND.LET);
    }

    ctx._work.push({
      kind: 'finish_try_catch',
      loc: task.loc,
      catchBlock: task.catchBlock,
      finallyBlock: task.finallyBlock,
      mergeBlock: task.mergeBlock,
      tryExitScope,
      tryExitBlock,
      finalizer: task.finalizer,
      entryScope: task.entryScope,
    });
    ctx._work.push({ kind: 'after_stmt' });
    ctx._work.push({ kind: 'lower_stmt', node: task.handler.body });
    return;
  }

  // No catch — jump straight to finish_try_finally (or merge).
  if (task.finallyBlock) {
    ctx.currentBlock = task.finallyBlock;
    restoreScope(ctx.scope, tryExitScope);
    ctx._work.push({
      kind: 'finish_try_finally',
      loc: task.loc,
      finallyBlock: task.finallyBlock,
      mergeBlock: task.mergeBlock,
    });
    ctx._work.push({ kind: 'after_stmt' });
    ctx._work.push({ kind: 'lower_stmt', node: task.finalizer });
    return;
  }
  ctx.currentBlock = task.mergeBlock;
}

function finishTryCatchStep(ctx, task) {
  const catchExitBlock = ctx.currentBlock;
  // Snapshot the catch-exit scope BEFORE popping the block frame
  // so the catch param's register is still visible (if we ever
  // needed it). We don't currently use param-from-catch-scope
  // after this point.
  const catchExitScope = snapshotScope(ctx.scope);
  popFrame(ctx.scope);  // pop the block frame we pushed for catch param

  // Jump from catch exit to finally (or merge).
  const afterCatchTarget = task.finallyBlock || task.mergeBlock;
  if (!catchExitBlock.terminator) {
    emit(ctx.module, catchExitBlock, {
      op: OP.JUMP, target: afterCatchTarget.id,
    }, task.loc);
    addEdge(catchExitBlock, afterCatchTarget);
  }

  if (task.finallyBlock) {
    // Enter the finally block. Finally must run on every
    // reachable exit path. The finally block's in-state is the
    // join of try-exit and catch-exit — we model this by
    // emitting phis at finally-entry for any name that differs
    // between the two scopes.
    ctx.currentBlock = task.finallyBlock;
    emitScopePhis(ctx, task.finallyBlock, [
      { block: task.tryExitBlock,  scope: task.tryExitScope },
      { block: catchExitBlock,     scope: catchExitScope },
    ], task.loc);
    ctx._work.push({
      kind: 'finish_try_finally',
      loc: task.loc,
      finallyBlock: task.finallyBlock,
      mergeBlock: task.mergeBlock,
    });
    ctx._work.push({ kind: 'after_stmt' });
    ctx._work.push({ kind: 'lower_stmt', node: task.finalizer });
    return;
  }

  // No finally — merge try-exit and catch-exit scopes at
  // mergeBlock. Emit phis for any name that differs.
  ctx.currentBlock = task.mergeBlock;
  emitScopePhis(ctx, task.mergeBlock, [
    { block: task.tryExitBlock, scope: task.tryExitScope },
    { block: catchExitBlock,    scope: catchExitScope },
  ], task.loc);
}

function finishTryFinallyStep(ctx, task) {
  const finallyExitBlock = ctx.currentBlock;
  if (!finallyExitBlock.terminator) {
    emit(ctx.module, finallyExitBlock, {
      op: OP.JUMP, target: task.mergeBlock.id,
    }, task.loc);
    addEdge(finallyExitBlock, task.mergeBlock);
  }
  ctx.currentBlock = task.mergeBlock;
}

// `with (obj) body` — legacy dynamic scope extension. We
// evaluate `obj` for its side effects and raise an
// UNIMPLEMENTED assumption flagging the precision gap
// (identifier → property lookups through the with-object are
// not modeled). The body is lowered as a regular statement.
// Taint flows through explicit statements in the body; only
// implicit dynamic lookups are imprecise.
function lowerWith(ctx, node, loc) {
  if (node.object) lowerExpression(ctx, node.object);
  ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    'with statement — dynamic scope extension not modeled; identifier-as-property lookups through the with object fall back to the enclosing scope',
    loc
  );
  // Lower the body inline. It's already a single Statement
  // (typically a BlockStatement).
  if (node.body) {
    ctx._work.push({ kind: 'lower_stmt', node: node.body });
  }
}

function lowerThrow(ctx, node, loc) {
  // Lower the argument expression (its side effects may matter
  // for taint propagation even though the value is thrown).
  if (node.argument) {
    lowerExpression(ctx, node.argument);
  }
  // Route to the enclosing catch if any.
  if (ctx._catchStack && ctx._catchStack.length > 0) {
    const target = ctx._catchStack[ctx._catchStack.length - 1].block;
    if (target) {
      emit(ctx.module, ctx.currentBlock, {
        op: OP.JUMP, target: target.id,
      }, loc);
      addEdge(ctx.currentBlock, target);
      return;
    }
  }
  // Uncaught throw: emit a THROW terminator so the worklist
  // stops walking this path. We don't model where it goes.
  emit(ctx.module, ctx.currentBlock, {
    op: OP.THROW,
  }, loc);
}

// --- Helpers for loop lowering ------------------------------------------

// collectAssignedNames(nodes, out)
//
// Walks a list of statement AST nodes and collects the names of
// all identifiers that are (a) declared via `var` (function-scoped)
// or (b) the target of an AssignmentExpression. Stops at nested
// function boundaries. Used by loop lowering to compute which
// names need phi nodes at the loop header.
function collectAssignedNames(nodes, out) {
  const stack = nodes.slice().reverse();
  while (stack.length > 0) {
    const n = stack.pop();
    if (!n) continue;
    if (n.type === 'VariableDeclaration') {
      for (const d of n.declarations) {
        if (d.id && d.id.type === 'Identifier') out.add(d.id.name);
      }
      continue;
    }
    if (n.type === 'ExpressionStatement') {
      collectAssignedNamesFromExpression(n.expression, out);
      continue;
    }
    if (n.type === 'BlockStatement') {
      for (let i = n.body.length - 1; i >= 0; i--) stack.push(n.body[i]);
      continue;
    }
    if (n.type === 'IfStatement') {
      if (n.consequent) stack.push(n.consequent);
      if (n.alternate) stack.push(n.alternate);
      continue;
    }
    if (n.type === 'ForStatement' || n.type === 'WhileStatement' ||
        n.type === 'DoWhileStatement') {
      if (n.init && n.init.type === 'VariableDeclaration') {
        for (const d of n.init.declarations) {
          if (d.id && d.id.type === 'Identifier') out.add(d.id.name);
        }
      }
      if (n.update) collectAssignedNamesFromExpression(n.update, out);
      if (n.body) stack.push(n.body);
      continue;
    }
    if (n.type === 'ForInStatement' || n.type === 'ForOfStatement') {
      if (n.left && n.left.type === 'VariableDeclaration') {
        for (const d of n.left.declarations) {
          if (d.id && d.id.type === 'Identifier') out.add(d.id.name);
        }
      } else if (n.left && n.left.type === 'Identifier') {
        out.add(n.left.name);
      }
      if (n.body) stack.push(n.body);
      continue;
    }
    if (n.type === 'LabeledStatement') { stack.push(n.body); continue; }
    if (n.type === 'TryStatement') {
      if (n.block) stack.push(n.block);
      if (n.handler && n.handler.body) stack.push(n.handler.body);
      if (n.finalizer) stack.push(n.finalizer);
      continue;
    }
    if (n.type === 'SwitchStatement') {
      for (const c of n.cases) {
        for (let i = c.consequent.length - 1; i >= 0; i--) stack.push(c.consequent[i]);
      }
      continue;
    }
    // Function boundaries and other statements don't assign
    // outer names we need to track.
  }
}

function collectAssignedNamesFromExpression(node, out) {
  // Recursive walk via stack to stay iterative.
  const stack = [node];
  while (stack.length > 0) {
    const n = stack.pop();
    if (!n) continue;
    if (n.type === 'AssignmentExpression') {
      if (n.left && n.left.type === 'Identifier') out.add(n.left.name);
      stack.push(n.right);
      continue;
    }
    if (n.type === 'UpdateExpression') {
      // `i++` / `++i` / `i--` / `--i` all reassign i.
      if (n.argument && n.argument.type === 'Identifier') out.add(n.argument.name);
      continue;
    }
    if (n.type === 'BinaryExpression' || n.type === 'LogicalExpression') {
      stack.push(n.left); stack.push(n.right); continue;
    }
    if (n.type === 'UnaryExpression') { stack.push(n.argument); continue; }
    if (n.type === 'ConditionalExpression') {
      stack.push(n.test); stack.push(n.consequent); stack.push(n.alternate);
      continue;
    }
    if (n.type === 'CallExpression' || n.type === 'NewExpression') {
      stack.push(n.callee);
      if (n.arguments) for (const a of n.arguments) stack.push(a);
      continue;
    }
    if (n.type === 'MemberExpression') {
      stack.push(n.object);
      if (n.computed && n.property) stack.push(n.property);
      continue;
    }
    if (n.type === 'SequenceExpression') {
      for (const e of n.expressions) stack.push(e);
      continue;
    }
    // Identifiers, literals, function expressions, etc. don't
    // assign to outer names.
  }
}

function lowerVarDecl(ctx, node, loc) {
  // node.kind is 'var', 'let', or 'const'. The parser sets it to
  // 'var' by default if not explicitly tagged (historical node
  // shape).
  const declKind = node.kind || 'var';
  const bindingKind = declKind === 'let' ? BIND.LET
    : declKind === 'const' ? BIND.CONST
    : BIND.VAR;

  for (const decl of node.declarations) {
    let reg;
    if (decl.init) {
      reg = lowerExpression(ctx, decl.init);
    } else {
      reg = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.CONST, dest: reg, value: undefined,
      }, loc);
    }
    // Destructure the binding target. For plain identifiers
    // this just defines the name; for ObjectPattern / ArrayPattern
    // / AssignmentPattern we recursively emit property reads
    // and defaults.
    bindDestructuringTarget(ctx, decl.id, reg, bindingKind, loc);
  }
}

// bindDestructuringTarget — recursively bind a destructuring
// pattern against a source register. Handles:
//   Identifier         — plain binding
//   ObjectPattern      — emit GetProp per property, recurse
//   ArrayPattern       — emit GetIndex per element, recurse
//   AssignmentPattern  — default value: `if (src === undefined) src = default`
//   RestElement        — opaque binding (remaining fields/elements)
//
// `srcReg` is the register holding the source value. `kind` is
// the BIND.* kind (var/let/const/param) so the leaf Identifier
// bindings end up in the correct scope frame.
function bindDestructuringTarget(ctx, target, srcReg, kind, loc) {
  if (!target) return;
  if (target.type === 'Identifier') {
    if (kind === BIND.VAR || kind === BIND.PARAM) {
      defineHoisted(ctx.scope, target.name, srcReg, kind);
    } else {
      defineLexical(ctx.scope, target.name, srcReg, kind);
    }
    return;
  }
  if (target.type === 'AssignmentPattern') {
    // `target = default`: if srcReg is undefined, use the default.
    // We produce a new register holding either the src or the
    // default, then recurse on target.left.
    //
    // Emitted shape (conservative, non-branching):
    //   defaultReg = <default expression>
    //   resolvedReg = UnOp('??', srcReg, defaultReg)  // if exists
    //   — but we don't have `??` as a BinOp, so we use the
    //   transfer-level approximation: just bind to the source
    //   register AND also lower the default expression so any
    //   side effects are captured. The lattice-level precision
    //   loss is tracked via an UNIMPLEMENTED assumption marking
    //   the default as a fallback value.
    const defReg = lowerExpression(ctx, target.right);
    // Emit an opaque "default resolution" marker so consumers
    // see the imprecision. The resulting register merges src
    // and def via a Phi-like Disjunct at the Value level, which
    // we approximate as a new Opaque that inherits labels from
    // both.
    const mergedReg = newRegister(ctx.module);
    emit(ctx.module, ctx.currentBlock, {
      op: OP.BIN_OP,
      dest: mergedReg,
      operator: '??',   // nullish coalescing — transfer falls through to OneOf/join
      left: srcReg,
      right: defReg,
    }, loc);
    bindDestructuringTarget(ctx, target.left, mergedReg, kind, loc);
    return;
  }
  if (target.type === 'ObjectPattern') {
    for (const prop of target.properties) {
      if (prop.type === 'RestElement') {
        // Rest element in an object pattern: the remaining
        // properties get collected into a fresh object whose
        // shape we can't precisely compute. Bind as an opaque.
        const restReg = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.OPAQUE,
          dest: restReg,
          reason: REASONS.UNIMPLEMENTED,
          details: 'object rest element — remaining properties not precisely tracked',
          affects: null,
        }, loc);
        bindDestructuringTarget(ctx, prop.argument, restReg, kind, loc);
        continue;
      }
      if (prop.type !== 'Property') continue;
      const keyName = prop.key.type === 'Identifier' ? prop.key.name
        : prop.key.type === 'Literal' ? String(prop.key.value) : null;
      if (keyName == null) continue;  // computed keys: skip
      const elemReg = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.GET_PROP, dest: elemReg, object: srcReg, propName: keyName,
      }, loc);
      bindDestructuringTarget(ctx, prop.value, elemReg, kind, loc);
    }
    return;
  }
  if (target.type === 'ArrayPattern') {
    for (let i = 0; i < target.elements.length; i++) {
      const elem = target.elements[i];
      if (elem == null) continue;  // hole
      if (elem.type === 'RestElement') {
        const restReg = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.OPAQUE,
          dest: restReg,
          reason: REASONS.UNIMPLEMENTED,
          details: 'array rest element — remaining elements not precisely tracked',
          affects: null,
        }, loc);
        bindDestructuringTarget(ctx, elem.argument, restReg, kind, loc);
        break;
      }
      // Emit a Const(i) for the index and a GET_INDEX.
      const idxReg = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.CONST, dest: idxReg, value: i,
      }, loc);
      const elemReg = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.GET_INDEX, dest: elemReg, object: srcReg, key: idxReg,
      }, loc);
      bindDestructuringTarget(ctx, elem, elemReg, kind, loc);
    }
    return;
  }
  // Unknown target shape — record as unimplemented.
  const r = newRegister(ctx.module);
  emit(ctx.module, ctx.currentBlock, {
    op: OP.OPAQUE,
    dest: r,
    reason: REASONS.UNIMPLEMENTED,
    details: 'destructuring target shape not yet modeled: ' + target.type,
    affects: null,
  }, loc);
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
  // Attach the full param AST nodes so enterFunctionStep can do
  // destructuring / default / rest binding, not just simple
  // identifier params.
  fn.paramNodes = node.params.slice();
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
  // outer scope right away AS a 'function' binding (hoisted
  // into the nearest function frame — ES semantics). Function
  // expressions (node.id === null) have no outer binding; the
  // caller pushes `dest` onto its own results stack.
  if (node.id) defineHoisted(ctx.scope, node.id.name, dest, BIND.FUNCTION);

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
    // Hoist nested function/var declarations in this function's
    // body so they're visible from the top of the body. Runs
    // after enter_function (pops above it on the LIFO stack) and
    // before the body statements.
    ctx._work.push({ kind: 'hoist_decls', bodyNodes: node.body.body });
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
  // Bind params in the new scope. For each formal parameter:
  //   1. Allocate a fresh `paramReg` — this is the register the
  //      caller binds to when applyCall passes an argument.
  //   2. If the parameter is a plain Identifier, bind its name
  //      directly to paramReg.
  //   3. Otherwise (ObjectPattern / ArrayPattern / AssignmentPattern
  //      / RestElement) recursively destructure paramReg into
  //      the leaf identifier names via bindDestructuringTarget.
  //
  // Params live in the function frame (kind='function') so
  // later `var` declarations with the same name rebind them
  // rather than shadow.
  const paramNodes = fn.paramNodes || [];
  for (let i = 0; i < paramNodes.length; i++) {
    const p = paramNodes[i];
    const paramReg = newRegister(ctx.module);
    fn.params.push(paramReg);
    if (!p) continue;
    if (p.type === 'Identifier') {
      defineHoisted(ctx.scope, p.name, paramReg, BIND.PARAM);
      continue;
    }
    if (p.type === 'RestElement') {
      // Rest param: bind the argument to an opaque that
      // represents the "remaining args" array. Precise modeling
      // would require arity-aware call site handling.
      const restReg = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, {
        op: OP.OPAQUE, dest: restReg,
        reason: REASONS.UNIMPLEMENTED,
        details: 'rest parameter — remaining arguments as opaque array',
        affects: null,
      }, fn.location);
      bindDestructuringTarget(ctx, p.argument, restReg, BIND.PARAM, fn.location);
      continue;
    }
    // Default / destructuring param: recursively bind.
    bindDestructuringTarget(ctx, p, paramReg, BIND.PARAM, fn.location);
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
      case 'emit_template': {
        // Pop nExprs expression regs (pushed in source order),
        // then emit literal Consts for the quasi pieces and
        // alternate BinOp('+') to build the final string.
        //
        // Pattern for N expressions (quasis = q0..qN):
        //   acc = q0
        //   acc = acc + e0
        //   acc = acc + q1
        //   acc = acc + e1
        //   ... until acc = acc + qN
        //
        // If all operands are concrete strings, the BinOp
        // transfer const-folds the whole thing to a single
        // Concrete at the lattice level.
        const exprRegs = [];
        for (let i = 0; i < task.nExprs; i++) exprRegs.unshift(results.pop());
        const quasiRegs = task.quasiValues.map(v => {
          const r = newRegister(ctx.module);
          emit(ctx.module, ctx.currentBlock, {
            op: OP.CONST, dest: r, value: v,
          }, task.loc);
          return r;
        });
        let acc = quasiRegs[0];
        for (let i = 0; i < task.nExprs; i++) {
          // acc = acc + exprRegs[i]
          let dest = newRegister(ctx.module);
          emit(ctx.module, ctx.currentBlock, {
            op: OP.BIN_OP, dest, operator: '+', left: acc, right: exprRegs[i],
          }, task.loc);
          acc = dest;
          // acc = acc + quasiRegs[i+1]
          dest = newRegister(ctx.module);
          emit(ctx.module, ctx.currentBlock, {
            op: OP.BIN_OP, dest, operator: '+', left: acc, right: quasiRegs[i + 1],
          }, task.loc);
          acc = dest;
        }
        results.push(acc);
        break;
      }
      case 'emit_const': {
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.CONST, dest, value: task.value,
        }, task.loc);
        results.push(dest);
        break;
      }
      case 'emit_array_alloc': {
        // Pop nElements regs (pushed in source order). Build a
        // fields map keyed by integer string ("0", "1", ...)
        // and emit an ALLOC instruction.
        const elemRegs = [];
        for (let i = 0; i < task.nElements; i++) elemRegs.unshift(results.pop());
        const fields = new Map();
        for (let i = 0; i < elemRegs.length; i++) {
          fields.set(String(i), elemRegs[i]);
        }
        // Length field makes `.length` reads correct for
        // concrete-sized arrays.
        const lengthReg = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.CONST, dest: lengthReg, value: elemRegs.length,
        }, task.loc);
        fields.set('length', lengthReg);
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.ALLOC, dest, kind: 'Array', fields,
        }, task.loc);
        results.push(dest);
        break;
      }
      case 'emit_object_alloc': {
        // Pop nProperties regs (pushed in source order). Build a
        // fields map keyed by the Property keys (collected at
        // visit time). Keys whose lookup is null (computed, spread)
        // are omitted.
        const nProps = task.keys.length;
        const valRegs = [];
        for (let i = 0; i < nProps; i++) valRegs.unshift(results.pop());
        const fields = new Map();
        for (let i = 0; i < nProps; i++) {
          if (task.keys[i] != null) fields.set(task.keys[i], valRegs[i]);
        }
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.ALLOC, dest, kind: 'Object', fields,
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
      case 'emit_update_ident': {
        // `x++` / `++x` / `x--` / `--x` on an Identifier target.
        // Desugar: emit a Const(1), BinOp(+/-), bind result to x.
        // Expression-result semantics (prefix returns new, postfix
        // returns old) are approximated: we always push the new
        // value onto `results`. A consumer that distinguishes
        // prefix vs postfix semantically would need a richer
        // model — tracked as an imprecision.
        const lhsReg = lookupName(ctx.scope, task.name);
        if (lhsReg == null) {
          const dest = newRegister(ctx.module);
          emit(ctx.module, ctx.currentBlock, {
            op: OP.OPAQUE, dest,
            reason: REASONS.UNIMPLEMENTED,
            details: 'update on unresolved identifier ' + task.name,
            affects: null,
          }, task.loc);
          results.push(dest);
          break;
        }
        const oneReg = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.CONST, dest: oneReg, value: 1,
        }, task.loc);
        const newReg = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.BIN_OP,
          dest: newReg,
          operator: task.op,
          left: lhsReg,
          right: oneReg,
        }, task.loc);
        updateName(ctx.scope, task.name, newReg);
        // Push the new value (prefix semantics). A post-increment
        // would ideally push the old value; we approximate.
        results.push(newReg);
        break;
      }
      case 'emit_unimplemented_expr': {
        const dest = newRegister(ctx.module);
        emit(ctx.module, ctx.currentBlock, {
          op: OP.OPAQUE, dest,
          reason: REASONS.UNIMPLEMENTED,
          details: task.details,
          affects: null,
        }, task.loc);
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
    case 'Super': {
      // `super` in expression position refers to the parent
      // class object of the enclosing class. applyNew handles
      // automatic parent-ctor chain walking so an explicit
      // `super()` call in a child constructor is effectively a
      // no-op that passes taint through. For method-level
      // `super.method(args)` references, the parent's method is
      // stored on `this` during construction (parent ctor runs
      // first, setting its methods; child ctor may override).
      // The common read pattern `super.x` can therefore be
      // rewritten to `this.x` since both classes store their
      // members on the instance.
      //
      // We emit a GET_THIS so downstream MemberExpression /
      // CallExpression access resolves through the instance.
      // This is sound: a super lookup always hits a method
      // defined in an ancestor, which the ctor chain walk
      // installed on the instance.
      const dest = newRegister(ctx.module);
      emit(ctx.module, ctx.currentBlock, { op: OP.GET_THIS, dest }, loc);
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
    case 'UpdateExpression': {
      // `x++` / `++x` / `x--` / `--x`: desugar to an assignment.
      // The semantics are:
      //   prefix:  x = x + 1; return x
      //   postfix: tmp = x; x = x + 1; return tmp
      // For precision we only track the updated value of x. The
      // return-value distinction between prefix and postfix is
      // approximated — a future refinement can model it exactly
      // by keeping a pre-update snapshot.
      //
      // The AST argument is usually an Identifier or a
      // MemberExpression. For identifiers we emit a Const(1),
      // a BinOp(+/-), and an assign-name. For member targets we
      // currently fall through to unimplemented.
      const op = node.operator === '++' ? '+' : '-';
      if (node.argument.type === 'Identifier') {
        tasks.push({ kind: 'emit_update_ident',
          name: node.argument.name, op, prefix: node.prefix, loc });
        return;
      }
      tasks.push({ kind: 'emit_unimplemented_expr',
        details: 'UpdateExpression on non-identifier target', loc });
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
      // Spread in arguments: `f(...args)`. We don't know the
      // expanded arity so we can't bind the callee's param
      // registers. Fall back to an opaque call result. Taint
      // is conservatively propagated by the caller's general
      // "arg labels flow to return" rule in applyCall.
      for (const arg of node.arguments) {
        if (arg && arg.type === 'SpreadElement') {
          const dest = lowerUnimplementedExpr(ctx, node, loc);
          results.push(dest);
          return;
        }
      }
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
    case 'TemplateLiteral': {
      // Desugar `` `a ${x} b ${y} c` `` into:
      //   "a" + x + "b" + y + "c"
      // This routes through the existing BinOp('+') transfer
      // which handles string concatenation + taint propagation
      // + SMT formula construction (str.++ with per-operand
      // formulas). Purely concrete pieces fold away via the
      // normal const-fold path.
      //
      // Empty template `` `` `` lowers to a single Const string.
      const quasis = node.quasis || [];
      const exprs = node.expressions || [];
      if (quasis.length === 0) {
        tasks.push({ kind: 'emit_const', value: '', loc });
        return;
      }
      // Build a post-order task sequence:
      //   visit e0, emit_concat(quasi0, ...) — but we need left-
      //   associative string concat with alternating literals and
      //   expressions.
      //
      // Simpler approach: emit the first quasi as a Const, then
      // for each (expr_i, quasi_{i+1}) pair, emit:
      //   tmp = accum + expr_i     (BinOp +)
      //   accum = tmp + quasi_{i+1}
      //
      // We express this on the task stack via an emit_template
      // finish task that pops the expression regs and the quasi
      // values (pre-materialized as const regs) and builds the
      // concat chain.
      tasks.push({
        kind: 'emit_template',
        quasiValues: quasis.map(q => q.value.cooked || ''),
        nExprs: exprs.length,
        loc,
      });
      for (let i = exprs.length - 1; i >= 0; i--) {
        tasks.push({ kind: 'visit', node: exprs[i] });
      }
      return;
    }
    case 'ArrayExpression': {
      // Lower `[a, b, c]` to an ALLOC with integer-keyed fields.
      // Holes (undefined element) and SpreadElement lose
      // precision: a spread makes subsequent indices opaque
      // because we don't know the spread source's length.
      //
      // We visit each non-spread element and pass a list of
      // (index, reg) pairs to emit_array_alloc via the results
      // stack: push all element regs first (in reverse), then
      // emit_array_alloc pops them and builds the fields map.
      const elements = node.elements || [];
      // Figure out whether any spread is present. If so we mark
      // the whole array as opaque to be sound.
      let hasSpread = false;
      for (const e of elements) {
        if (e && e.type === 'SpreadElement') { hasSpread = true; break; }
      }
      if (hasSpread) {
        const dest = lowerUnimplementedExpr(ctx, node, loc);
        results.push(dest);
        return;
      }
      // Filter out holes for now — a hole reads undefined.
      const nonHole = elements.filter(e => e != null);
      tasks.push({ kind: 'emit_array_alloc', nElements: nonHole.length, loc });
      for (let i = nonHole.length - 1; i >= 0; i--) {
        tasks.push({ kind: 'visit', node: nonHole[i] });
      }
      return;
    }
    case 'ObjectExpression': {
      // Lower `{a: 1, b: 2, ...c}` to an ALLOC with the key=>reg
      // map. Spread and computed keys lose precision (fall back
      // to opaque).
      const properties = node.properties || [];
      let unsupported = false;
      for (const p of properties) {
        if (p.type === 'SpreadElement') { unsupported = true; break; }
        if (p.computed) { unsupported = true; break; }
        if (p.kind !== 'init') { unsupported = true; break; }  // getters / setters
      }
      if (unsupported) {
        const dest = lowerUnimplementedExpr(ctx, node, loc);
        results.push(dest);
        return;
      }
      const keys = properties.map(p => {
        if (p.key.type === 'Identifier') return p.key.name;
        if (p.key.type === 'Literal') return String(p.key.value);
        return null;
      });
      tasks.push({ kind: 'emit_object_alloc', keys, loc });
      for (let i = properties.length - 1; i >= 0; i--) {
        tasks.push({ kind: 'visit', node: properties[i].value });
      }
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

// Shallow-clone each frame so the snapshot captures the current
// binding registers without aliasing future mutations. Frames
// are now {kind, bindings}; we copy both.
function snapshotScope(scope) {
  return {
    frames: scope.frames.map(f => ({
      kind: f.kind,
      bindings: Object.assign(Object.create(null), f.bindings),
    })),
  };
}
function restoreScope(scope, snap) {
  scope.frames = snap.frames.map(f => ({
    kind: f.kind,
    bindings: Object.assign(Object.create(null), f.bindings),
  }));
}
// Walk a snapshot (innermost first) and return the register for
// `name`, or null. Mirrors lookupName but operates on a frozen
// snapshot captured at a specific program point.
function lookupInSnapshot(snap, name) {
  for (let i = snap.frames.length - 1; i >= 0; i--) {
    const b = snap.frames[i].bindings[name];
    if (b) return b.reg;
  }
  return null;
}
// Iterate all bound names in a snapshot. Used by if-merge to
// compute the set of names that need phi merging.
function allNamesInSnapshot(snap) {
  const out = new Set();
  for (const f of snap.frames) {
    for (const k in f.bindings) out.add(k);
  }
  return out;
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
