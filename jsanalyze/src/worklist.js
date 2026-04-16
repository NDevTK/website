// worklist.js — iterative fixpoint engine (Wave 10 / B4: multi-variant)
//
// The worklist algorithm drives a monotone fixpoint over the CFG
// of each function. Each block carries a SET of variants rather
// than a single joined state. A variant is a full State with its
// own `path`: the SMT formula describing the reachability
// condition for this variant (the conjunction of every branch
// outcome that had to hold for execution to reach this point).
//
// Multi-variant worklist (B4)
// ---------------------------
//
// Before B4, every block had one in-state produced by pointwise-
// joining the predecessor states. Pointwise join loses cross-
// register correlation: after `if (c) { x = 1; y = "a"; } else
// { x = 2; y = "b"; }`, the joined state has x = oneOf(1,2) and
// y = oneOf("a","b"), and the analyzer no longer knows that
// x=1 implies y="a". A later `if (x === 1)` refines x to 1 but
// CAN'T refine y, so a sink on y inside the true branch fires
// spuriously.
//
// B4 keeps the two branches as separate variants all the way
// through the join. The `if (x === 1)` true branch eliminates
// the x=2 variant via refinement; only the x=1 variant (with
// y="a") survives into the sink. The cross-register correlation
// is preserved because each variant is a complete state, not a
// pointwise abstraction.
//
// Variants and equivalence
// ------------------------
//
// Two variants are equivalent iff their (regs, heap) are equal
// under `stateEquals`. `path` and `assumptionIds` are NOT part
// of the equivalence check — they are merged disjunctively
// (path via SMT OR, assumptionIds via set union) when
// equivalent variants collide.
//
// This keeps the variant count per block bounded by the number
// of distinct (regs, heap) shapes reachable at that block,
// which is finite because the underlying Value lattice has
// finite height. Back-edges from loops eventually either add a
// new shape (monotonic growth, terminates) or hit an existing
// one (fixpoint).
//
// Per-variant transfer
// --------------------
//
// Transfer functions are unchanged: they still operate on a
// single State at a time. The worklist loop processes each
// variant independently, restoring `ctx.currentPath` per
// variant so emitTaintFlow can attach the correct per-variant
// pathFormula to any flow it emits.
//
// Per-variant branching
// ---------------------
//
// A BRANCH terminator splits its parent variant into up to two
// children — one for each successor — refined according to the
// branch outcome. The true child's path conjoins the branch
// formula; the false child's conjoins its negation. Children
// that collapse to a Bottom register (statically infeasible)
// are not enqueued.
//
// Branch reachability cascade (D6 — 5-layer)
// ------------------------------------------
//
// Every branch check runs through the 5-layer cascade from
// DESIGN-DECISIONS.md §D6:
//
//   1. structural          — JUMP / UNREACHABLE terminators,
//                            both successors inherit the variant
//                            (O(1)).
//   2. constant fold       — truthiness() on a Concrete/OneOf
//                            cond value returns true/false/null
//                            (O(1)).
//   3. value-set refutation — refineEq/refineNeq on the branch
//                            operand when one side is a literal;
//                            contradictions collapse to Bottom
//                            (O(value-set size)).
//   4. path-sensitive propagation — the conjunction of earlier
//                            refinements is what actually sits
//                            in each successor's `path` and in
//                            its register values (O(refined vars)).
//   5. SMT (Z3)            — if layers 1-4 leave both successors
//                            reachable, ask Z3 whether
//                            (path ∧ cond) is SAT and
//                            (path ∧ ¬cond) is SAT. Edges whose
//                            SAT check returns `unsat` are
//                            statically infeasible and dropped.
//
// The cascade is short-circuited at the earliest layer that can
// decide. Layer 5 is only called when layers 1-4 return unknown.
//
// Exit state
// ----------
//
// The function's exit is the list of variants that reach a
// RETURN terminator. Callers that want a single joined view
// (e.g. top-level trace projection) use `joinExitVariants`.
// Callers that want per-path precision (e.g. C3 summary cache)
// iterate the variants directly.
//
// Strictly iterative: no recursion. Deep call graphs cannot
// blow the JavaScript call stack. The call stack stored in
// Each state's `callStack` frame list handles interprocedural
// cycle detection per D7 (see domain.callStackContains).

'use strict';

const { OP } = require('./ir.js');
const D = require('./domain.js');
const { applyInstruction } = require('./transfer.js');
const SMT = require('./smt.js');
const { REASONS } = require('./assumptions.js');

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

// Add `newState` to the variant list for `blockId`. Returns a
// descriptor: { added: boolean, variantIdx: number }.
//
// The equivalence check is on (regs, heap, fromBlock). Two
// variants that arrived from different predecessors keep
// separate entries even if their post-predecessor shapes happen
// to match, because their phis resolve against different
// incoming edges. Once phis are resolved and the state enters
// the block body, `fromBlock` is immaterial — we still use it
// for subsumption just to err toward precision.
//
//   * If an existing variant has the same (regs, heap) shape
//     AND the same `fromBlock`, we merge the newcomer's
//     `path` and assumptionIds via disjunction / union. If
//     the merge does not change the existing variant, `added`
//     is false and no re-processing is required.
//   * If the newcomer is a back-edge arrival at a loop header
//     (`wideningJoin === true`), we pointwise-join it with any
//     existing variant that also arrived on a back edge from
//     the same predecessor. This collapses iteration-count
//     differences into a single widening variant so loops
//     converge at the lattice level rather than spawning
//     per-iteration variants.
//   * Otherwise the newcomer is appended and `added` is true.
function insertVariant(blockVariants, blockId, newState, wideningJoin) {
  let list = blockVariants.get(blockId);
  if (!list) {
    list = [];
    blockVariants.set(blockId, list);
  }
  // Back-edge widening: fold into any variant with the same
  // _fromBlock regardless of (regs, heap) equality. Use the
  // domain's widen operator (D.widenStates), NOT join, so
  // per-register values that grew along a numeric axis
  // extrapolate to ±Infinity in one step. That gives the
  // lattice finite height without any iteration cap /
  // value-set cap / cartesian-product cap. See D14.
  if (wideningJoin) {
    for (let i = 0; i < list.length; i++) {
      const existing = list[i];
      if (existing._fromBlock !== newState._fromBlock) continue;
      const joined = D.widenStates(existing, newState);
      if (D.stateEquals(joined, existing)) {
        // Widening is a no-op: the existing variant already
        // subsumes the newcomer. Still merge path and
        // assumption ids in case those are the only things
        // that grew.
        const mergedPath = D.joinPaths(existing.path, newState.path);
        const pcChanged = (existing.path ? existing.path.expr : '') !==
          (mergedPath ? mergedPath.expr : '');
        if (!pcChanged) return { added: false, variantIdx: i };
        list[i] = Object.freeze({
          regs: existing.regs,
          heap: existing.heap,
          path: mergedPath,
          effects: existing.effects,
          assumptionIds: existing.assumptionIds,
          callStack: existing.callStack,
          _fromBlock: existing._fromBlock,
          _frozen: true,
        });
        return { added: true, variantIdx: i };
      }
      // Widening grew the variant — replace in place and
      // re-process. Preserve _fromBlock tag.
      list[i] = Object.freeze({
        regs: joined.regs,
        heap: joined.heap,
        path: joined.path,
        effects: joined.effects,
        assumptionIds: joined.assumptionIds,
        callStack: joined.callStack,
        _fromBlock: existing._fromBlock,
        _frozen: true,
      });
      return { added: true, variantIdx: i };
    }
    // First back-edge arrival at this header: append as-is.
    list.push(newState);
    return { added: true, variantIdx: list.length - 1 };
  }
  for (let i = 0; i < list.length; i++) {
    const existing = list[i];
    if (existing._fromBlock !== newState._fromBlock) continue;
    if (!D.stateEquals(existing, newState)) continue;
    const mergedPath = D.joinPaths(existing.path, newState.path);
    const existingPcKey = existing.path ? existing.path.expr : '';
    const mergedPcKey = mergedPath ? mergedPath.expr : '';
    const pcChanged = existingPcKey !== mergedPcKey;
    const seen = new Set(existing.assumptionIds);
    const mergedIds = existing.assumptionIds.slice();
    let idsChanged = false;
    for (const id of newState.assumptionIds) {
      if (!seen.has(id)) { seen.add(id); mergedIds.push(id); idsChanged = true; }
    }
    if (!pcChanged && !idsChanged) {
      return { added: false, variantIdx: i };
    }
    list[i] = Object.freeze({
      regs: existing.regs,
      heap: existing.heap,
      path: mergedPath,
      effects: existing.effects,
      assumptionIds: Object.freeze(mergedIds),
      callStack: existing.callStack,
      _fromBlock: existing._fromBlock,
      _frozen: true,
    });
    return { added: true, variantIdx: i };
  }
  list.push(newState);
  return { added: true, variantIdx: list.length - 1 };
}

// Tag a state with its arriving predecessor block so phi
// resolution at the target block can pick the correct incoming
// edge. `fromBlock` is null for the initial-state arrival at
// the function entry.
function withFromBlock(state, fromBlock) {
  return Object.freeze({
    regs: state.regs,
    heap: state.heap,
    path: state.path || null,
    effects: state.effects,
    assumptionIds: state.assumptionIds,
    callStack: state.callStack,
    _fromBlock: fromBlock,
    _frozen: true,
  });
}

// Join all variants in a list into a single State, pointwise.
// Used for backward-compatible projections (blockStates / exit
// state / reachability) where a consumer wants a single summary
// view rather than the per-variant list. The per-variant
// information is still available via `blockVariants`.
function joinVariantList(list) {
  if (!list || list.length === 0) return null;
  let s = list[0];
  for (let i = 1; i < list.length; i++) s = D.joinStates(s, list[i]);
  return s;
}

async function analyseFunction(module, fn, initialState, ctx) {
  const cfg = fn.cfg;
  // Track the currently-walking function so transfer.js can
  // key 'call' scope on the containing handler. Save/restore
  // around the whole walk so recursive / interprocedural calls
  // restore the outer function's id on return.
  const _savedFnId = ctx._currentFnId;
  ctx._currentFnId = fn.id;
  try {
    return await _analyseFunctionBody(module, fn, cfg, initialState, ctx);
  } finally {
    ctx._currentFnId = _savedFnId;
  }
}

async function _analyseFunctionBody(module, fn, cfg, initialState, ctx) {

  // Per-block in-state: each block holds a list of variants
  // merged from its predecessors. Equivalent shapes collapse;
  // distinct shapes stay separate so cross-register correlation
  // survives join points.
  const blockVariants = new Map();       // BlockId → Variant[]
  // Per-(block, variantIdx) out-state: the state produced after
  // running the block's instructions against that variant's
  // in-state. Used to resolve phis for successors and to collect
  // per-variant exit states for RETURN terminators.
  const variantOutStates = new Map();    // BlockId → Array<State>
  const defs = buildDefs(fn);

  // Legacy per-block path map, used by the tests (path-cond.test.js)
  // and by consumers that want a single-formula-per-block view.
  // It's the disjunction of every variant's `path` at the block
  // — equivalent to the old "OR over edge formulas" computation.
  const pathConds = new Map();           // BlockId → Formula | null

  // Reverse postorder so blocks are processed in topological-
  // forward order on the first pass.
  const blockOrder = computeReversePostorder(cfg);

  // Identify loop-header blocks and their back-edge predecessors.
  // A predecessor `P` of block `L` is a back-edge predecessor iff
  // blockOrder(P) >= blockOrder(L) (under the reverse-postorder
  // numbering, forward edges point to strictly-higher-numbered
  // successors, so an equal-or-lower-numbered predecessor is
  // reached from a back edge).
  //
  // backPreds: Map<BlockId, Set<PredBlockId>>
  //
  // At loop headers we MUST widen variants that arrive via a
  // back edge — otherwise every loop iteration produces a new
  // variant with a slightly-different register value, and the
  // fixpoint never terminates in reasonable time (1000-iter
  // loops explode to 1000 variants → ~100s walks). Forward-
  // edge variants (from the loop pre-header) are still kept
  // distinct so cross-register correlation across the merge
  // of pre-loop and post-loop states is preserved.
  const backPreds = new Map();
  for (const [bid, blk] of cfg.blocks) {
    for (const pred of blk.preds || []) {
      const predOrder = blockOrder.get(pred);
      const selfOrder = blockOrder.get(bid);
      if (predOrder == null || selfOrder == null) continue;
      if (predOrder >= selfOrder) {
        if (!backPreds.has(bid)) backPreds.set(bid, new Set());
        backPreds.get(bid).add(pred);
      }
    }
  }

  // Priority queue of (blockId, variantIdx) pairs to process,
  // keyed primarily by blockOrder (so forward blocks run before
  // back-edge re-enqueues). We use a plain array + sorted
  // insertion because CFG sizes are small.
  const pending = [];
  const queuedKeys = new Set();    // dedup: "blockId:variantIdx"

  function makeKey(blockId, variantIdx) {
    return blockId + ':' + variantIdx;
  }

  function enqueueVariant(blockId, variantIdx) {
    const key = makeKey(blockId, variantIdx);
    if (queuedKeys.has(key)) return;
    queuedKeys.add(key);
    const order = blockOrder.get(blockId) || 0;
    let lo = 0, hi = pending.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      const midOrder = blockOrder.get(pending[mid].blockId) || 0;
      if (midOrder <= order) lo = mid + 1;
      else hi = mid;
    }
    pending.splice(lo, 0, { blockId, variantIdx });
  }

  // Add a state to a block's variant list, re-enqueue if it's
  // a new or grown variant, and update the legacy pathConds
  // map from the merged block disjunction. `fromBlock`
  // identifies the predecessor block whose terminator is
  // enqueueing this edge — we eagerly resolve the target's
  // phis *here* at enqueue time, using the specific
  // predecessor's state, so each variant at `blockId` carries
  // its own correlated phi outputs rather than pulling from a
  // pooled predecessor out-state list. This is what preserves
  // cross-register correlation through nested join points.
  //
  // Back-edge widening: if the edge is a back edge (fromBlock
  // is a back-edge predecessor of blockId), the new variant
  // gets pointwise-joined with any existing variant that also
  // arrived via a back edge. This ensures loop iterations
  // converge to a single widening variant rather than producing
  // a fresh variant per iteration count. Forward edges from the
  // loop pre-header stay distinct.
  function enqueue(blockId, state, fromBlock) {
    const target = cfg.blocks.get(blockId);
    let baked = state;
    if (target && fromBlock != null) {
      baked = bakePhis(target, state, fromBlock);
    }
    let stamped = withFromBlock(baked, fromBlock);
    const isBackEdge = fromBlock != null && backPreds.has(blockId) &&
      backPreds.get(blockId).has(fromBlock);
    // Back-edge widening is a performance shortcut per D19.
    // The `accept` set decides whether the engine is allowed
    // to take it: if the consumer has opted out of
    // `loop-widening`, we skip the widening and insert the
    // back-edge variant as a normal distinct variant. Loops
    // then converge only at the value-lattice level (and can
    // take O(iterations) variants to reach fixpoint on
    // bounded loops) — the consumer explicitly accepted that
    // cost by rejecting the widening assumption.
    const widenAllowed = ctx.accept == null ||
      ctx.accept.has(REASONS.LOOP_WIDENING);
    if (isBackEdge && widenAllowed && ctx.assumptions) {
      const headerLoc = cfg.blocks.get(blockId) &&
        cfg.blocks.get(blockId).instructions[0] &&
        module.sourceMap.get(cfg.blocks.get(blockId).instructions[0]._id);
      const widenA = ctx.assumptions.raise(
        REASONS.LOOP_WIDENING,
        'loop header at block ' + blockId + ' widened back-edge variants into one (widening is finite but may over-approximate per-iteration state)',
        headerLoc || { file: module.name || '<input>', line: 0, col: 0, pos: 0 }
      );
      // Attach the widening assumption id to the incoming
      // variant's state so every taint flow emitted from this
      // loop body (via emitTaintFlow's ctx._stateAssumptionIds
      // read) carries it in `flow.assumptionIds`. The finding
      // chips in the UI then show "loop-widening" next to
      // sinks whose value depends on the widened fixpoint.
      const existingIds = stamped.assumptionIds || [];
      if (existingIds.indexOf(widenA.id) < 0) {
        stamped = Object.freeze(Object.assign({}, stamped, {
          assumptionIds: Object.freeze(existingIds.concat([widenA.id])),
        }));
      }
    }
    const { added, variantIdx } = insertVariant(
      blockVariants, blockId, stamped,
      isBackEdge && widenAllowed
    );
    // Update legacy pathConds projection: disjunction over all
    // variants at this block.
    const list = blockVariants.get(blockId);
    let disj = null;
    let anyNull = false;
    for (const v of list) {
      if (v.path == null) { anyNull = true; break; }
      disj = disj ? D.joinPaths(disj, v.path) : v.path;
    }
    pathConds.set(blockId, anyNull ? null : disj);

    if (added) enqueueVariant(blockId, variantIdx);
  }

  // Entry block is reachable under whatever `path` the caller
  // passed in — null for the top-level (outermost) function, a
  // non-trivial formula for a callee walked from
  // transfer.applyCall (the caller seeds the callee's initial
  // `path` with its own current path so any flow fired inside
  // the callee inherits the full interprocedural path
  // condition). We preserve `initialState.path` instead of
  // forcing it to null.
  enqueue(cfg.entry, initialState, null);

  // No iteration cap. The value lattice has finite height and
  // the per-block variant set is bounded by the distinct
  // (regs, heap) shapes reachable at that block, so the
  // fixpoint terminates without an artificial limit.
  while (pending.length > 0) {
    const { blockId, variantIdx } = pending.shift();
    queuedKeys.delete(makeKey(blockId, variantIdx));

    const block = cfg.blocks.get(blockId);
    if (!block) continue;
    const variants = blockVariants.get(blockId);
    if (!variants || variantIdx >= variants.length) continue;
    const inState = variants[variantIdx];

    // Phis were resolved eagerly at enqueue time (bakePhis).
    // For variants arriving via the initial-state entry where
    // fromBlock is null, there are no phis to resolve (the
    // function entry block has no predecessors in the CFG
    // sense, so its IR never contains phi instructions).
    let state = inState;

    // Expose the variant's path to the transfer functions so
    // sink emission attaches the correct per-variant pathFormula.
    // `ctx.currentPath` is a read-only side channel; transfer
    // functions must not mutate it.
    const currentPath = state.path;
    const prevPath = ctx.currentPath;
    ctx.currentPath = currentPath;
    ctx.currentBlockId = blockId;

    // Per-variant assumption ids: every assumption attached to
    // the variant's state (e.g. loop-widening raised when this
    // variant entered a loop header) surfaces on any taint
    // flow emitted while walking this block. emitTaintFlow
    // reads `ctx._stateAssumptionIds` and unions it with the
    // flowing value's own ids.
    const prevStateIds = ctx._stateAssumptionIds;
    ctx._stateAssumptionIds = state.assumptionIds || [];

    // Intra-block fast path: unfreeze, write in place, refreeze.
    // PHI instructions are already resolved by bakePhis at
    // enqueue time, so we skip them in the block body. Running
    // applyInstruction on a PHI would re-join across all
    // predecessors and clobber the per-variant values that
    // bakePhis just installed.
    //
    // applyInstruction is async — CALL / NEW walk user
    // functions via this same analyseFunction, which is async
    // for Z3 Layer 5. Every op returns Promise<State>; the
    // `await` here is the cost of proper async discipline
    // (one resolved-promise microtask per sync op), not an
    // optimisation knob to hack around.
    state = D.unfreezeState(state);
    for (const instr of block.instructions) {
      if (instr.op === OP.PHI) continue;
      state = await applyInstruction(ctx, state, instr);
    }
    state = D.freezeState(state);

    ctx.currentPath = prevPath;
    ctx._stateAssumptionIds = prevStateIds;

    // Stash the per-variant out-state for phi resolution in
    // successors and for exit collection.
    let outList = variantOutStates.get(blockId);
    if (!outList) { outList = []; variantOutStates.set(blockId, outList); }
    outList[variantIdx] = state;

    // Handle the terminator: queue each successor with a
    // refined / re-conditioned variant. The variant's `path` is
    // preserved across a JUMP and conjoined with the branch
    // outcome across a BRANCH.
    const term = block.terminator;
    if (!term) continue;

    const varPath = state.path;

    switch (term.op) {
      case OP.JUMP: {
        // Layer 1 (structural): unconditional edge, target
        // inherits this variant's `path`.
        enqueue(term.target, state, blockId);
        break;
      }
      case OP.BRANCH: {
        // D6: 5-layer reachability cascade. Every check goes
        // through all 5 layers in order, stopping at the first
        // layer that can decide.
        const cond = D.getReg(state, term.cond);
        // Layer 2 (constant fold): concrete truthiness decides
        // the branch unambiguously.
        const truthy = D.truthiness(cond);
        if (truthy === true) {
          enqueue(term.trueTarget, state, blockId);
          break;
        }
        if (truthy === false) {
          enqueue(term.falseTarget, state, blockId);
          break;
        }

        // Build the per-edge `path` formula: varPath ∧ cond for
        // the true edge, varPath ∧ ¬cond for the false edge.
        const condForm = (cond && cond.formula) ? cond.formula : null;
        let trueEdge = varPath, falseEdge = varPath;
        if (condForm) {
          trueEdge = varPath ? SMT.mkAnd(varPath, condForm) : condForm;
          const negCond = SMT.mkNot(condForm);
          falseEdge = varPath ? SMT.mkAnd(varPath, negCond) : negCond;
        }

        // Layers 3 + 4 (value-set refutation + path-sensitive
        // propagation): refineEq/refineNeq on the branch
        // operand when one side is a literal. Collapses
        // contradictory sides to Bottom.
        const trueState = refineForBranch(state, term.cond, defs, true, ctx.typeDB);
        const falseState = refineForBranch(state, term.cond, defs, false, ctx.typeDB);
        let trueDead = refinementContradicts(state, trueState);
        let falseDead = refinementContradicts(state, falseState);

        // Layer 5 (SMT): if both sides are still reachable
        // after value-level refinement, ask Z3 whether each
        // edge's `path` is satisfiable. UNSAT edges are dead.
        //
        // Skipped entirely when the consumer has accepted
        // 'smt-skipped' (ctx.solverCheckPathSat is null in
        // that case — the index.js wiring only binds it
        // when smt-skipped is NOT in the accept set).
        // Skipped also when the cond value has no symbolic
        // formula (no SMT representation, so Z3 can't help).
        if (!trueDead && !falseDead &&
            condForm &&
            ctx.solverCheckPathSat) {
          // Check trueEdge first: we need both to be checked
          // independently because different refinements can
          // land on different sides.
          if (SMT.hasSym(trueEdge) && !trueEdge.incompatible) {
            const verdict = await ctx.solverCheckPathSat(trueEdge);
            if (verdict === 'unsat') trueDead = true;
          }
          if (SMT.hasSym(falseEdge) && !falseEdge.incompatible) {
            const verdict = await ctx.solverCheckPathSat(falseEdge);
            if (verdict === 'unsat') falseDead = true;
          }
        }

        if (!trueDead) {
          enqueue(term.trueTarget, D.withPath(trueState, trueEdge), blockId);
        }
        if (!falseDead) {
          enqueue(term.falseTarget, D.withPath(falseState, falseEdge), blockId);
        }
        break;
      }
      case OP.RETURN: {
        // Nothing more to do — exit state is collected below.
        break;
      }
      case OP.THROW: {
        // TODO: route to enclosing catch. For now, uncaught throws
        // terminate analysis of the path.
        break;
      }
      case OP.SWITCH: {
        // Each case successor inherits the variant's `path`
        // unchanged. Per-case refinement of the discriminant
        // is handled at IR lowering time via explicit equality
        // tests (Wave 9 switch lowering).
        for (const c of term.cases) enqueue(c.target, state, blockId);
        if (term.default) enqueue(term.default, state, blockId);
        break;
      }
      case OP.UNREACHABLE: break;
      default:
        throw new Error('worklist: unknown terminator ' + term.op);
    }
  }

  // Backward-compatible blockStates view: pointwise join of each
  // block's variants. Consumers that want per-variant precision
  // can read `blockVariants` directly.
  const blockStates = new Map();
  const outStates = new Map();
  for (const [blockId, list] of blockVariants) {
    const joined = joinVariantList(list);
    if (joined) blockStates.set(blockId, joined);
  }
  for (const [blockId, list] of variantOutStates) {
    const joined = joinVariantList(list.filter(Boolean));
    if (joined) outStates.set(blockId, joined);
  }

  // Exit state: collect every variant that reached a RETURN
  // terminator. For backward compatibility we also expose a
  // joined `exitState` for consumers that want a single view.
  const exitVariants = [];
  for (const [blockId, block] of cfg.blocks) {
    const t = block.terminator;
    if (t && t.op === OP.RETURN) {
      const list = variantOutStates.get(blockId);
      if (list) for (const s of list) if (s) exitVariants.push(s);
    }
  }
  // If the function has no explicit Return-terminated block
  // (void function), fall back to the exit block's variants.
  if (exitVariants.length === 0) {
    const list = variantOutStates.get(cfg.exit);
    if (list) for (const s of list) if (s) exitVariants.push(s);
  }
  let exitState = null;
  for (const s of exitVariants) {
    exitState = exitState ? D.joinStates(exitState, s) : s;
  }
  if (!exitState) exitState = initialState;

  return {
    blockStates,
    outStates,
    exitState,
    exitVariants,
    blockVariants,
    pathConds,
  };
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

  // --- numeric-range refinement (<, <=, >, >=) ---
  //
  // `x < lit` on true:  x ← refineNumericRange(x, '<',  lit)
  // `x < lit` on false: x ← refineNumericRange(x, '>=', lit)
  // Same pattern for <=, >, >=.
  //
  // Without this, a loop `for (var i = 0; i < N; i++) …`
  // can't prune its counter — OneOf(i) grows monotonically
  // until the ONE_OF_CAP promotes it to Interval, and the
  // Interval itself has no upper bound because the branch
  // constraint isn't applied. The consequence is that
  // `items[i]` inside the loop body hits the imprecise-
  // index fallback despite the loop being fully analysable.
  // This restores proper convergence.
  const rangeOps = {
    '<':  { taken: '<',  notTaken: '>=' },
    '<=': { taken: '<=', notTaken: '>'  },
    '>':  { taken: '>',  notTaken: '<=' },
    '>=': { taken: '>=', notTaken: '<'  },
  };
  if (rangeOps[op]) {
    const lv0 = D.getReg(state, def.left);
    const rv0 = D.getReg(state, def.right);
    // Identify whichever side is a concrete numeric literal;
    // refine the OTHER side. When swapping, invert the
    // operator so the refinement remains semantically
    // `var OP literal`.
    let varReg, lit, effOp;
    if (rv0 && rv0.kind === D.V.CONCRETE && typeof rv0.value === 'number') {
      varReg = def.left;
      lit = rv0.value;
      effOp = op;
    } else if (lv0 && lv0.kind === D.V.CONCRETE && typeof lv0.value === 'number') {
      varReg = def.right;
      lit = lv0.value;
      // Invert: `lit < var` is equivalent to `var > lit`.
      effOp = { '<': '>', '<=': '>=', '>': '<', '>=': '<=' }[op];
    } else {
      return state;
    }
    const actualOp = taken ? effOp : rangeOps[effOp].notTaken;
    const varValue = D.getReg(state, varReg);
    if (!varValue) return state;
    const refined = D.refineNumericRange(varValue, actualOp, lit);
    if (refined === varValue) return state;
    return D.setReg(state, varReg, refined);
  }

  // --- equality / inequality refinement (+ typeof) ---
  const isEq  = (op === '===' || op === '==');
  const isNeq = (op === '!==' || op === '!=');
  if (!isEq && !isNeq) return state;

  const lv = D.getReg(state, def.left);
  const rv = D.getReg(state, def.right);
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

function resolveCtorName(state, defs, ctorReg) {
  const ctorDef = defs.get(ctorReg);
  if (!ctorDef) return null;
  if (ctorDef.op === OP.GET_GLOBAL) return ctorDef.name;
  if (ctorDef.op === OP.GET_PROP)   return ctorDef.propName;
  return null;
}

function isPrimitive(v) {
  if (v === null || v === undefined) return true;
  const t = typeof v;
  return t === 'string' || t === 'number' || t === 'boolean';
}

// True iff `refined` contains a register that's been narrowed
// to Bottom relative to `original`. A single bottom is enough
// to mark the successor as unreachable.
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

function computeReversePostorder(cfg) {
  const order = new Map();
  const postorder = [];
  const visited = new Set();
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
  for (let i = 0; i < postorder.length; i++) {
    order.set(postorder[postorder.length - 1 - i], i);
  }
  let nextUnreached = postorder.length;
  for (const [blockId] of cfg.blocks) {
    if (!order.has(blockId)) order.set(blockId, nextUnreached++);
  }
  return order;
}

// bakePhis — eagerly resolve the target block's phis using the
// predecessor variant's state, writing the phi dest registers
// into the outgoing state. Called at terminator time so each
// enqueued successor variant carries its own correlated phi
// values. After baking, `resolvePhis` at the target block is
// effectively a no-op (it sees the dest regs already bound).
//
// The phi's `incoming` list is keyed by predecessor block id;
// we pick the entry whose `pred` matches `fromBlock` and read
// the source register from `predState` (the outgoing state of
// the predecessor, NOT from any pooled variantOutStates list).
// This is exactly the semantics of SSA phi resolution at the
// predecessor side of the edge, and it preserves cross-register
// correlation because every variant carries its own register
// map into the target block.
//
// If no incoming matches the predecessor (shouldn't happen for
// a well-formed CFG, but we stay total just in case), the phi
// dest is left unchanged — the target's existing value (if any)
// is preserved.
function bakePhis(targetBlock, predState, fromBlock) {
  let state = predState;
  for (const instr of targetBlock.instructions) {
    if (instr.op !== OP.PHI) break;
    let selected = null;
    for (const { pred, value } of instr.incoming) {
      if (pred !== fromBlock) continue;
      const v = D.getReg(predState, value);
      selected = selected == null ? v : D.join(selected, v);
    }
    if (selected != null) {
      state = D.setReg(state, instr.dest, selected);
    }
  }
  return state;
}

// Resolve any Phi instructions at the start of `block` by
// picking the appropriate source register from the predecessor
// the incoming variant arrived from.
//
// Multi-variant semantics: each variant carries `_fromBlock`
// identifying the predecessor whose terminator enqueued it.
// The phi picks the value written in THAT predecessor's
// out-state — NOT the pointwise join across all predecessors
// — so cross-register correlation through the join point is
// preserved. After `if (c) { x=1; y="a"; } else { x=2; y="b"; }`,
// a variant arriving from the true-branch predecessor resolves
// its phis to { x=1, y="a" }, and a variant from the false-
// branch predecessor resolves to { x=2, y="b" } — two distinct
// variants at the join block. A later `if (x === 1)` can then
// refine away one of them entirely, eliminating spurious sink
// flows that would fire under the pointwise-joined y = oneOf.
//
// Per-predecessor precision: when multiple variants from the
// SAME predecessor contributed, we pointwise-join only those
// (they represent distinct paths ALREADY separated by earlier
// splits, and joining them here corresponds to the single
// source-level write at the predecessor's terminator).
//
// Fallback: if `_fromBlock` is null or unknown (initial entry
// state, or a variant whose origin got lost through an
// intermediate collapse), join across every predecessor's
// out-states. This stays sound — it's the old pointwise join.
function resolvePhis(block, inState, variantOutStates) {
  const from = inState._fromBlock;
  let state = inState;
  for (const instr of block.instructions) {
    if (instr.op !== OP.PHI) break;
    let merged = D.bottom();
    if (from != null) {
      // Find the incoming whose pred matches the variant's
      // arrival block.
      let matched = false;
      for (const { pred, value } of instr.incoming) {
        if (pred !== from) continue;
        matched = true;
        const predList = variantOutStates.get(pred);
        if (!predList) continue;
        for (const predOut of predList) {
          if (!predOut) continue;
          const v = D.getReg(predOut, value);
          merged = D.join(merged, v);
        }
      }
      if (!matched) {
        // No incoming matched our _fromBlock — fall back to
        // the pointwise join so the phi still has a value.
        for (const { pred, value } of instr.incoming) {
          const predList = variantOutStates.get(pred);
          if (!predList) continue;
          for (const predOut of predList) {
            if (!predOut) continue;
            const v = D.getReg(predOut, value);
            merged = D.join(merged, v);
          }
        }
      }
    } else {
      for (const { pred, value } of instr.incoming) {
        const predList = variantOutStates.get(pred);
        if (!predList) continue;
        for (const predOut of predList) {
          if (!predOut) continue;
          const v = D.getReg(predOut, value);
          merged = D.join(merged, v);
        }
      }
    }
    state = D.setReg(state, instr.dest, merged);
  }
  return state;
}

module.exports = {
  analyseFunction,
};
