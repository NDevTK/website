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
function analyseFunction(module, fn, initialState, ctx) {
  const cfg = fn.cfg;
  const blockStates = new Map();     // BlockId → in-state (joined across all predecessors)
  const outStates = new Map();       // BlockId → out-state (after transfer)

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
          if (condForm) {
            const trueEdge = blockPathCond
              ? SMT.mkAnd(blockPathCond, condForm)
              : condForm;
            const negCond = SMT.mkNot(condForm);
            const falseEdge = blockPathCond
              ? SMT.mkAnd(blockPathCond, negCond)
              : negCond;
            enqueue(term.trueTarget, state, trueEdge);
            enqueue(term.falseTarget, state, falseEdge);
          } else {
            enqueue(term.trueTarget, state, blockPathCond);
            enqueue(term.falseTarget, state, blockPathCond);
          }
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
