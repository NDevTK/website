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

const { OP, TERMINATOR_KINDS } = require('./ir.js');
const D = require('./domain.js');
const { applyInstruction } = require('./transfer.js');
const { REASONS } = require('./assumptions.js');

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

  // Compute reverse postorder once so the worklist visits blocks
  // in topological-forward order. blockOrder[blockId] → integer
  // index; lower = process earlier.
  const blockOrder = computeReversePostorder(cfg);

  // Priority queue keyed by blockOrder. We use a sorted array
  // with binary insertion because the CFG sizes are small
  // relative to a full heap's overhead.
  const pending = [];    // sorted by blockOrder ascending
  const queued = new Set();
  function enqueue(blockId, incoming) {
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

  enqueue(cfg.entry, initialState);

  // Hard iteration cap as a safety net. Monotone lattices with
  // finite ascending chains terminate without the cap, but the
  // cap protects against bugs in the lattice ops.
  const maxIterations = 100000;
  let iterations = 0;

  while (pending.length > 0) {
    if (++iterations > maxIterations) {
      ctx.assumptions.raise(
        REASONS.UNSOLVABLE_MATH,
        'worklist exceeded iteration cap of ' + maxIterations + ' — lattice may not be converging',
        { file: module.name, line: 0, col: 0, pos: 0 }
      );
      break;
    }
    const blockId = dequeue();
    const block = cfg.blocks.get(blockId);
    if (!block) continue;
    const inState = blockStates.get(blockId);
    let state = resolvePhis(block, inState, blockStates, outStates);

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

    outStates.set(blockId, state);

    // Handle the terminator: queue successors with their appropriate
    // incoming state.
    const term = block.terminator;
    if (!term) continue;
    switch (term.op) {
      case OP.JUMP: {
        enqueue(term.target, state);
        break;
      }
      case OP.BRANCH: {
        const cond = D.getReg(state, term.cond);
        const truthy = D.truthiness(cond);
        // Layer 1-2 reachability: concrete truth value decides both
        // successors unambiguously.
        if (truthy === true) {
          enqueue(term.trueTarget, state);
        } else if (truthy === false) {
          enqueue(term.falseTarget, state);
        } else {
          // Unknown: both successors are reachable. A future
          // refinement pass will narrow the state on each side
          // (refineWithCondition) — for now we pass the same state
          // to both, which is sound but not maximally precise.
          enqueue(term.trueTarget, state);
          enqueue(term.falseTarget, state);
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
        for (const c of term.cases) enqueue(c.target, state);
        if (term.default) enqueue(term.default, state);
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

  return { blockStates, outStates, exitState };
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
