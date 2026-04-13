// worklist.js — iterative fixpoint engine
//
// The worklist algorithm drives a monotone fixpoint over the CFG
// of each function. It processes basic blocks in FIFO order,
// joining incoming edge states, applying the transfer function,
// and queueing successors whose inState grew.
//
// Strictly iterative: no recursion. Deeply nested functions and
// large call graphs cannot blow the JavaScript call stack. The
// call stack stored in State handles interprocedural context.

'use strict';

const { OP } = require('./ir.js');
const D = require('./domain.js');
const { applyInstruction } = require('./transfer.js');
const SMT = require('./smt.js');

// Analyse one function to a fixpoint. Returns:
//   { blockStates: Map<BlockId, State>, exitState: State }
//
// Arguments:
//   module:      the IR module
//   fn:          the function to analyse
//   initialState: the State at the entry block (params pre-bound)
//   ctx:         the analysis context (assumption tracker, TypeDB, ...)
//
// Iteration order: reverse postorder from the entry. This visits
// every block after all its forward predecessors (except on back
// edges from loops), so the common straight-line case converges
// in a single pass. Back-edge changes still re-enqueue successors
// via the monotone-growth check, guaranteeing eventual fixpoint
// termination.
// Build (or reuse) the function's def map: register → instruction
// that writes it. SSA gives us the invariant that every register
// has at most one def, so this is a simple map. Cached on the
// function so we only build it once.
function buildDefs(fn) {
  if (fn._defs) return fn._defs;
  const defs = new Map();
  for (const [, block] of fn.cfg.blocks) {
    for (const instr of block.instructions) {
      if (instr.dest != null) defs.set(instr.dest, instr);
    }
  }
  fn._defs = defs;
  return defs;
}

function analyseFunction(module, fn, initialState, ctx) {
  const cfg = fn.cfg;
  const blockStates = new Map();     // BlockId → in-state (joined across all predecessors)
  const outStates = new Map();       // BlockId → out-state (after transfer)
  const defs = buildDefs(fn);

  // B3: per-block path conditions. Each entry is an SMT formula
  // representing the disjunction of the conditions under which
  // the block is reachable (one disjunct per incoming edge).
  // The entry block has pathCond = null which represents
  // unconditional reachability ("true").
  //
  // Tracked as a side channel so it does NOT participate in the
  // data-lattice fixpoint check — the lattice convergence is on
  // register/heap shape only. Path conditions are derived
  // information used by sink classification, taint flow refutation,
  // and the future SMT layer (Phase D).
  //
  // Stable-when-the-lattice-is-stable: every time a block is
  // re-enqueued because its data lattice grew, we re-derive the
  // edge condition and OR it into the target's pathCond. Once
  // the data lattice reaches fixpoint, no new edges get added
  // and the path conditions also stabilise.
  const pathConds = new Map();       // BlockId → Formula | null

  // Compute reverse postorder once so the worklist visits blocks
  // in topological-forward order. blockOrder[blockId] → integer
  // index; lower = process earlier.
  const blockOrder = computeReversePostorder(cfg);

  // Priority queue keyed by blockOrder. We use a sorted array
  // with binary insertion because the CFG sizes are small
  // relative to a full heap's overhead.
  const pending = [];    // sorted by blockOrder ascending
  const queued = new Set();

  // OR a new edge formula into the target block's path
  // condition. `edgePathCond` is the formula representing the
  // condition under which control flow reaches `blockId` along
  // the edge being processed (typically: the source block's
  // pathCond conjoined with the edge's branch condition). A
  // null `edgePathCond` represents unconditional reachability
  // and collapses the target's pathCond to null too.
  //
  // Returns true iff the target's pathCond grew, so callers can
  // decide whether downstream consumers need a refresh. (The
  // worklist itself only re-enqueues based on the data lattice;
  // pathConds are read-only for the fixpoint.)
  function orPathCond(blockId, edgePathCond) {
    if (!pathConds.has(blockId)) {
      pathConds.set(blockId, edgePathCond);
      return true;
    }
    const existing = pathConds.get(blockId);
    if (existing === null) return false;       // already top
    if (edgePathCond === null) {
      pathConds.set(blockId, null);
      return true;
    }
    // Both non-null: union them via OR. Cheap dedup: if the
    // existing expression already contains the new one verbatim
    // (e.g. successive iterations of the same edge), don't
    // re-OR.
    if (existing.expr === edgePathCond.expr) return false;
    const merged = SMT.mkOr(existing, edgePathCond);
    if (merged && merged.expr === existing.expr) return false;
    pathConds.set(blockId, merged);
    return true;
  }

  // enqueue(blockId, incoming, edgePathCond?)
  //
  // edgePathCond, when present, is the formula that must hold
  // for control flow to reach `blockId` along this edge. The
  // target block's accumulated pathCond is ORed with this value.
  // Default (omitted) means "unconditional edge" — the target's
  // pathCond becomes null (top).
  function enqueue(blockId, incoming, edgePathCond) {
    // Update pathConds first; this is independent of whether
    // the data lattice grew.
    orPathCond(blockId, edgePathCond === undefined ? null : edgePathCond);

    const existing = blockStates.get(blockId);
    const joined = existing ? D.joinStates(existing, incoming) : incoming;
    if (existing && D.stateEquals(existing, joined)) return;
    blockStates.set(blockId, joined);
    if (queued.has(blockId)) return;
    queued.add(blockId);
    // Insert into `pending` keeping it sorted by blockOrder.
    const order = blockOrder.get(blockId);
    let lo = 0, hi = pending.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (blockOrder.get(pending[mid]) <= order) lo = mid + 1;
      else hi = mid;
    }
    pending.splice(lo, 0, blockId);
  }
  function dequeue() {
    const b = pending.shift();
    queued.delete(b);
    return b;
  }

  // Entry block is unconditionally reachable.
  enqueue(cfg.entry, initialState, null);

  // No iteration cap. The lattice is monotone with finite height
  // — each register draws from a Value lattice whose height is
  // bounded by the number of distinct concrete values observed
  // in the program — so ascending chains terminate. An iteration
  // cap would mask a bug in the lattice ops by cutting off the
  // fixpoint early, producing silently unsound results. If the
  // fixpoint doesn't terminate, that is a bug the user must see
  // by having the analysis hang rather than silently give up.
  while (pending.length > 0) {
    const blockId = dequeue();
    const block = cfg.blocks.get(blockId);
    if (!block) continue;
    const inState = blockStates.get(blockId);
    let state = resolvePhis(block, inState, blockStates, outStates);

    // Expose the current block's path condition to the transfer
    // functions so sink emission can attach it to the resulting
    // taint flow record. This is a side channel — transfer.js
    // is not allowed to mutate it; it's read-only context.
    const currentPathCond = pathConds.has(blockId) ? pathConds.get(blockId) : null;
    const prevPathCond = ctx.currentPathCond;
    ctx.currentPathCond = currentPathCond;
    ctx.currentBlockId = blockId;

    // Intra-block fast path: unfreeze the state so register writes
    // mutate the Map in place instead of cloning on every instr.
    // This turns the per-block transfer cost from O(instrs × regs)
    // into O(instrs). We re-freeze before the state leaves the
    // block so joins at merge points still see an immutable value.
    state = D.unfreezeState(state);
    for (const instr of block.instructions) {
      state = applyInstruction(ctx, state, instr);
    }
    state = D.freezeState(state);

    ctx.currentPathCond = prevPathCond;

    outStates.set(blockId, state);

    // Handle the terminator: queue successors with their appropriate
    // incoming state. Each enqueue also propagates a per-edge
    // path-condition formula derived from this block's accumulated
    // pathCond and (for branches) the branch test.
    const term = block.terminator;
    if (!term) continue;

    // The path condition under which control flow reaches this
    // block. null = unconditionally reachable.
    const blockPathCond = pathConds.has(blockId) ? pathConds.get(blockId) : null;

    switch (term.op) {
      case OP.JUMP: {
        // Unconditional edge: target inherits this block's pathCond.
        enqueue(term.target, state, blockPathCond);
        break;
      }
      case OP.BRANCH: {
        const cond = D.getReg(state, term.cond);
        const truthy = D.truthiness(cond);
        // Layer 1-2 reachability: concrete truth value decides both
        // successors unambiguously. The "taken" successor inherits
        // the block's pathCond unchanged; the other side is dead.
        if (truthy === true) {
          enqueue(term.trueTarget, state, blockPathCond);
        } else if (truthy === false) {
          enqueue(term.falseTarget, state, blockPathCond);
        } else {
          // Unknown: both successors are reachable. Build the
          // edge formula from the cond value's symbolic formula
          // (B2 ensures most condition values carry one) and
          // conjoin it with the source block's pathCond.
          //
          // True edge:  blockPathCond ∧ cond
          // False edge: blockPathCond ∧ ¬cond
          //
          // If cond has no formula, we fall back to passing the
          // source pathCond unchanged on both sides — which is
          // sound (we just lose precision on this branch).
          const condForm = (cond && cond.formula) ? cond.formula : null;
          let trueEdge, falseEdge;
          if (condForm) {
            trueEdge = blockPathCond
              ? SMT.mkAnd(blockPathCond, condForm)
              : condForm;
            const negCond = SMT.mkNot(condForm);
            falseEdge = blockPathCond
              ? SMT.mkAnd(blockPathCond, negCond)
              : negCond;
          } else {
            trueEdge = blockPathCond;
            falseEdge = blockPathCond;
          }

          // B5 + Wave 1: refine the operand registers on each
          // successor. Look up the def of `term.cond` to see if
          // it's a refinable comparison (=== / !== / == / !=),
          // an `instanceof`, or a `typeof x === "..."` pattern.
          // If yes, narrow the operand (or the inner typeof
          // operand) so a contradictory branch becomes Bottom
          // and the dead successor is dropped from the worklist.
          const trueState = refineForBranch(state, term.cond, defs, true, ctx.typeDB);
          const falseState = refineForBranch(state, term.cond, defs, false, ctx.typeDB);

          // After refinement, check whether a successor's state
          // contains a Bottom register that the branch test
          // depends on — that successor is dead. (We only mark
          // a successor dead when refinement collapsed the
          // refined register itself to Bottom, not other regs.)
          const trueDead = refinementContradicts(state, trueState);
          const falseDead = refinementContradicts(state, falseState);

          if (!trueDead) enqueue(term.trueTarget, trueState, trueEdge);
          if (!falseDead) enqueue(term.falseTarget, falseState, falseEdge);
        }
        break;
      }
      case OP.RETURN: {
        // Nothing to do — the function's exit state is the join of
        // all Return-terminator blocks. We collect them below.
        break;
      }
      case OP.THROW: {
        // TODO: route to enclosing catch. For now, uncaught throws
        // terminate analysis of the path.
        break;
      }
      case OP.SWITCH: {
        // Switch-case path conditions are not yet refined per
        // case (B3 only handles binary branches). Each successor
        // inherits the source pathCond unchanged.
        for (const c of term.cases) enqueue(c.target, state, blockPathCond);
        if (term.default) enqueue(term.default, state, blockPathCond);
        break;
      }
      case OP.UNREACHABLE: break;
      default:
        throw new Error('worklist: unknown terminator ' + term.op);
    }
  }

  // Collect the exit state: join the out-states of every block
  // that ends in Return. If the function has no explicit return
  // (void function), the exit is whatever block falls through.
  let exitState = null;
  for (const [blockId, block] of cfg.blocks) {
    const t = block.terminator;
    if (t && t.op === OP.RETURN) {
      const s = outStates.get(blockId);
      if (s) exitState = exitState ? D.joinStates(exitState, s) : s;
    }
  }
  if (!exitState) exitState = outStates.get(cfg.exit) || initialState;

  return { blockStates, outStates, exitState, pathConds };
}

// B5: refine the state across a branch edge. If `condReg` is
// the result of a refinable BinOp (=== / !== / == / !=), narrow
// the operand registers in the returned state so a contradiction
// reduces them to Bottom. `taken` distinguishes the true vs
// false successor.
//
// Refinement rules:
//   x === lit  on true:  x ← refineEq(x, lit)
//   x === lit  on false: x ← refineNeq(x, lit)
//   x !== lit  on true:  x ← refineNeq(x, lit)
//   x !== lit  on false: x ← refineEq(x, lit)
//
// "lit" is detected as a Concrete operand whose value type is
// a primitive (string / number / boolean / null / undefined).
// "x" is the OTHER operand register. If neither operand is a
// concrete literal, no refinement is performed.
//
// Returns a fresh State (the input is untouched) so the caller
// can pass refined states to each successor independently.
function refineForBranch(state, condReg, defs, taken, db) {
  const def = defs.get(condReg);
  if (!def) return state;
  if (def.op !== OP.BIN_OP) return state;
  const op = def.operator;

  // --- instanceof refinement ---
  //
  // `x instanceof Ctor` — the BinOp's left is the value, right
  // is the constructor reference. On the true successor x is
  // narrowed via refineInstanceof; on the false successor via
  // refineNotInstanceof. The constructor name is recovered by
  // walking back to the def of the right operand (typically a
  // GetGlobal whose `name` is the ctor identifier).
  if (op === 'instanceof') {
    const ctorName = resolveCtorName(state, defs, def.right);
    if (!ctorName) return state;
    const varReg = def.left;
    const varValue = D.getReg(state, varReg);
    if (!varValue) return state;
    const refined = taken
      ? D.refineInstanceof(varValue, ctorName, db)
      : D.refineNotInstanceof(varValue, ctorName, db);
    if (refined === varValue) return state;
    return D.setReg(state, varReg, refined);
  }

  // --- equality / inequality refinement (+ typeof) ---
  const isEq  = (op === '===' || op === '==');
  const isNeq = (op === '!==' || op === '!=');
  if (!isEq && !isNeq) return state;

  const lv = D.getReg(state, def.left);
  const rv = D.getReg(state, def.right);
  // Find the literal side and the variable side.
  let varReg = null;
  let lit = undefined;
  if (lv && lv.kind === D.V.CONCRETE && isPrimitive(lv.value)) {
    varReg = def.right;
    lit = lv.value;
  } else if (rv && rv.kind === D.V.CONCRETE && isPrimitive(rv.value)) {
    varReg = def.left;
    lit = rv.value;
  } else {
    return state;
  }

  const varValue = D.getReg(state, varReg);
  if (!varValue) return state;

  // --- typeof refinement ---
  //
  // If the variable side's def is a UnOp(typeof, x), and the
  // literal is a string, this is `typeof x === "string"`. Refine
  // x by type instead of by equality on the typeof result — the
  // underlying register is x, not the result of typeof.
  const varDef = defs.get(varReg);
  if (varDef && varDef.op === OP.UN_OP && varDef.operator === 'typeof' &&
      typeof lit === 'string') {
    const innerReg = varDef.operand;
    const innerValue = D.getReg(state, innerReg);
    if (!innerValue) return state;
    let refined;
    if (isEq) {
      refined = taken
        ? D.refineByType(innerValue, lit)
        : D.refineNotByType(innerValue, lit);
    } else {
      refined = taken
        ? D.refineNotByType(innerValue, lit)
        : D.refineByType(innerValue, lit);
    }
    if (refined === innerValue) return state;
    return D.setReg(state, innerReg, refined);
  }

  let refined;
  if (isEq) {
    refined = taken ? D.refineEq(varValue, lit) : D.refineNeq(varValue, lit);
  } else {
    refined = taken ? D.refineNeq(varValue, lit) : D.refineEq(varValue, lit);
  }
  if (refined === varValue) return state;

  return D.setReg(state, varReg, refined);
}

// Resolve the constructor name on the right-hand side of an
// `instanceof` expression. The right side is typically a
// reference to a global constructor like `HTMLAnchorElement`,
// which the IR lowers as a GetGlobal whose `name` is the
// identifier. We look through the def chain to recover the name.
// A single level of GetProp (`window.HTMLAnchorElement`) is also
// resolved.
function resolveCtorName(state, defs, ctorReg) {
  const ctorDef = defs.get(ctorReg);
  if (!ctorDef) return null;
  if (ctorDef.op === OP.GET_GLOBAL) return ctorDef.name;
  if (ctorDef.op === OP.GET_PROP)   return ctorDef.propName;
  return null;
}

// True iff a primitive lattice value is a non-object — these are
// the only operands B5 refines across (x === "admin", x === 1,
// x === null, x === undefined, x === true).
function isPrimitive(v) {
  if (v === null || v === undefined) return true;
  const t = typeof v;
  return t === 'string' || t === 'number' || t === 'boolean';
}

// True iff `refined` contains a register that's been narrowed
// to Bottom relative to `original`. We compare the entire reg
// table for any new Bottom — a single bottom is enough to mark
// the successor as unreachable.
function refinementContradicts(original, refined) {
  if (original === refined) return false;
  for (const [reg, value] of D.overlayEntries(refined.regs)) {
    if (value && value.kind === D.V.BOTTOM) {
      const orig = D.getReg(original, reg);
      if (!orig || orig.kind !== D.V.BOTTOM) return true;
    }
  }
  return false;
}

// Compute reverse postorder of CFG blocks starting from the
// entry. Returns a Map<BlockId, integer> where smaller integers
// come earlier in the order. Implementation: iterative DFS with
// explicit stack, recording blocks in postorder, then reversing.
function computeReversePostorder(cfg) {
  const order = new Map();
  const postorder = [];
  const visited = new Set();
  // Explicit DFS stack: entries are {blockId, childIndex}.
  // childIndex tracks how many successors we've pushed so far.
  const stack = [{ blockId: cfg.entry, childIndex: 0 }];
  visited.add(cfg.entry);
  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    const block = cfg.blocks.get(top.blockId);
    if (!block) { stack.pop(); continue; }
    if (top.childIndex < block.succs.length) {
      const next = block.succs[top.childIndex++];
      if (!visited.has(next)) {
        visited.add(next);
        stack.push({ blockId: next, childIndex: 0 });
      }
      continue;
    }
    postorder.push(top.blockId);
    stack.pop();
  }
  // Reverse postorder: the last-finished block gets index 0.
  for (let i = 0; i < postorder.length; i++) {
    order.set(postorder[postorder.length - 1 - i], i);
  }
  // Any block not reached by the DFS (dead code) gets a high
  // index so it's processed last if it ever enters the queue.
  let nextUnreached = postorder.length;
  for (const [blockId] of cfg.blocks) {
    if (!order.has(blockId)) order.set(blockId, nextUnreached++);
  }
  return order;
}

// Resolve any Phi instructions at the start of `block` by picking
// the appropriate source register from each predecessor's out-state
// and joining them.
function resolvePhis(block, inState, blockStates, outStates) {
  let state = inState;
  for (const instr of block.instructions) {
    if (instr.op !== OP.PHI) break;   // phis are always at the top
    let merged = D.bottom();
    for (const { pred, value } of instr.incoming) {
      const predOut = outStates.get(pred);
      if (!predOut) continue;          // pred not yet walked — fine, monotone join will pick it up on a later iteration
      const v = D.getReg(predOut, value);
      merged = D.join(merged, v);
    }
    state = D.setReg(state, instr.dest, merged);
  }
  return state;
}

module.exports = {
  analyseFunction,
};
