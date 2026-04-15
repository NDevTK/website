// transfer.js — transfer functions per IR instruction kind
//
// A transfer function takes an incoming State and an IR instruction
// and returns the outgoing State. Transfer functions are pure — no
// side effects beyond raising Assumptions via the supplied tracker.
//
// Every instruction kind in OP has exactly one transfer function here.
// Unknown kinds throw — the IR builder is responsible for never
// producing them.

'use strict';

const { OP } = require('./ir.js');
const D = require('./domain.js');
const { REASONS } = require('./assumptions.js');
const TDB = require('./typedb.js');
const SMT = require('./smt.js');

// Lazy require for worklist.analyseFunction. We can't require it
// at module-load time because worklist.js requires transfer.js,
// creating a circular dependency. The first call resolves it.
let _analyseFunction = null;
function getAnalyseFunction() {
  if (!_analyseFunction) {
    _analyseFunction = require('./worklist.js').analyseFunction;
  }
  return _analyseFunction;
}

// Allocate (or look up) an SMT symbolic name for a source read.
// The name is tagged with the source label so a consumer that
// inspects the formula can tell which source it represents.
//
// Uses ctx.nextSymId for global uniqueness across the analysis
// and ctx._symCache as a memoization map keyed by
// `loc.pos + ':' + discriminator + ':' + label`. The
// discriminator distinguishes multiple source reads at the
// same source position (e.g. the IR builder records both
// `GetGlobal location` and the immediately following
// `GetProp .hash` at the same MemberExpression start position
// — without a discriminator they'd share a sym, which would
// make `location.hash` and `location.search` indistinguishable
// to the SMT layer).
//
// Two reads of the SAME source at the SAME logical address
// (e.g. two reads of `location.hash` in the same program)
// SHOULD share a sym — that's what makes path-condition
// correlation work. So the discriminator captures the address,
// not the call site.
function allocSourceSym(ctx, label, loc, discriminator, sort) {
  if (!ctx._symCache) ctx._symCache = new Map();
  const disc = discriminator || '';
  // Address-based key: same source, same address, same sym.
  // We deliberately ignore the loc.pos so that `location.hash`
  // read in two different statements still gets the same sym
  // and downstream branches can correlate them.
  const key = label + ':' + disc;
  let entry = ctx._symCache.get(key);
  if (entry) return SMT.mkSym(entry.name, entry.sort);
  if (ctx.nextSymId == null) ctx.nextSymId = 1;
  const name = (disc || label) + '_' + (ctx.nextSymId++);
  const s = sort || 'Int';
  ctx._symCache.set(key, { name, sort: s });
  return SMT.mkSym(name, s);
}

// Map a TypeDB readType string to the SMT sort used for the
// symbolic variable that represents the value. Anything other
// than `String` falls back to Int — Z3 can still solve
// arithmetic / comparison constraints on Int-sorted syms even
// when the underlying JS value is e.g. a number-like opaque.
function readTypeToSort(readType) {
  if (readType === 'String') return 'String';
  return 'Int';
}

// Produce the SMT formula for a Value: the value's attached
// formula if any, or a const-literal if the value is concrete,
// or null otherwise.
function formulaOf(value) {
  if (!value) return null;
  if (value.formula) return value.formula;
  if (value.kind === D.V.CONCRETE) {
    return SMT.mkConst(value.value);
  }
  return null;
}

// Map a TypeDB source label (from DB descriptors like
// `source: 'url'`) to the assumption reason code that explains
// why the value is opaque. This keeps the taint vocabulary (the
// labels attached to values) separate from the justification
// vocabulary (why the analyzer can't see the value).
//
// The mapping follows from docs/ASSUMPTIONS.md:
//
//   url / referrer / postMessage / window.name → attacker-input
//     (an attacker crafts the URL / source page / message and
//     delivers it; the user doesn't type the URL)
//
//   cookie / storage → persistent-state
//     (same-origin script writes to cookies / localStorage /
//     sessionStorage / IndexedDB; the analyzer doesn't know
//     what's there)
//
//   network → network
//     (bytes from fetch / XHR / WebSocket response)
//
//   file / dragdrop / clipboard → ui-interaction
//     (user actively drops a file, pastes data, picks a file
//     — active user cooperation)
//
// Unknown labels fall through to opaque-call with the label
// carried verbatim in the assumption details.
function sourceLabelToReason(label) {
  switch (label) {
    case 'url':
    case 'referrer':
    case 'postMessage':
    case 'window.name':
      return REASONS.ATTACKER_INPUT;
    case 'cookie':
    case 'storage':
      return REASONS.PERSISTENT_STATE;
    case 'network':
      return REASONS.NETWORK;
    case 'file':
    case 'dragdrop':
    case 'clipboard':
      return REASONS.UI_INTERACTION;
    default:
      return REASONS.OPAQUE_CALL;
  }
}

// --- TaintFlow emission ---------------------------------------------------
//
// When a transfer function detects a tainted value reaching a
// sink, it calls `emitTaintFlow` to record the flow into
// `ctx.taintFlows`. The flow carries:
//
//   - A unique id (assigned from ctx.nextFlowId).
//   - The source labels carried by the tainted value, each
//     paired with a best-effort location. Label locations come
//     from the value's `provenance` field; if absent, the sink
//     location is used as a fallback.
//   - The sink kind, prop name, severity, and location.
//   - The list of assumption ids the value accumulated on its
//     path from source to sink. Consumers use this to audit the
//     trust floor for each finding.
//
// B3: when a flow fires, the worklist exposes the current
// block's accumulated path via `ctx.currentPath`. We attach
// BOTH the block-level path AND the value's own formula (built
// up by computeBinOp / source reads) so the Z3 refutation layer
// has the full SMT context needed to refute the flow:
//
//   refutable iff
//     (path ∧ valueFormula ∧ <sink-shape-predicate>) is unsat
//
// The `pathConditions` array is the legacy shape (a list of
// human-readable strings) and is left empty for now. The
// machine-readable formulas live on `pathFormula` (current
// block) and `valueFormula` (the value at the sink).
function emitTaintFlow(ctx, sinkInfo, sinkLoc, value) {
  if (!ctx.taintFlows) return;
  if (!value || !value.labels || value.labels.size === 0) return;

  // Dedup key: a single flow is identified by its sink location,
  // sink kind+prop, and the set of source labels at the source
  // location. The worklist re-processes a block every time its
  // in-state grows (a normal consequence of loop fixpoint
  // iteration), so a SetProp / Call instruction inside a loop
  // body fires multiple times. Without dedup the trace gets N
  // copies of the same flow. The key is stable across re-fires
  // because the sink location is fixed by the instruction and
  // the label set stabilises once the lattice reaches fixpoint.
  if (!ctx._emittedFlowKeys) ctx._emittedFlowKeys = new Set();
  const labelsList = [];
  for (const l of value.labels) labelsList.push(l);
  labelsList.sort();
  const sinkKey = (sinkLoc ? sinkLoc.file + ':' + sinkLoc.pos : '?') +
    '|' + (sinkInfo.type || '') + '|' + (sinkInfo.prop || '') +
    '|' + labelsList.join(',');
  if (ctx._emittedFlowKeys.has(sinkKey)) return;
  ctx._emittedFlowKeys.add(sinkKey);

  // Extract sources from the value's labels. Each label gets a
  // location from the value's provenance (the deepest provenance
  // entry is the most recent — use it as the source location).
  const prov = (value.provenance && value.provenance.length > 0)
    ? value.provenance
    : [sinkLoc];
  const sources = [];
  for (const label of value.labels) {
    sources.push({
      label,
      location: prov[prov.length - 1] || sinkLoc,
    });
  }
  // Flow assumption ids are the union of:
  //
  //   * `value.assumptionIds` — assumptions attached to the
  //     specific value that reached the sink (imprecise-index
  //     over-approximations, Opaque source chains, widened
  //     Top envelopes).
  //
  //   * The current state's `_stateAssumptionIds` — per-block
  //     assumptions (loop-widening fired on back-edges, summary-
  //     reused flagged on summary cache hits) that apply to
  //     everything reaching the sink in this block.
  //
  // Keeping both sources prevents the "I saw widening happen
  // but the flow's audit trail is empty" problem. The UI
  // dedups by reason when rendering chips.
  const valueIds = value.assumptionIds ? value.assumptionIds.slice() : [];
  const blockIds = (ctx._stateAssumptionIds &&
                    ctx._stateAssumptionIds.length)
    ? ctx._stateAssumptionIds
    : [];
  const flowIds = valueIds.slice();
  if (blockIds.length > 0) {
    const seen = new Set(flowIds);
    for (const id of blockIds) {
      if (!seen.has(id)) { seen.add(id); flowIds.push(id); }
    }
  }
  const flow = {
    id: ctx.nextFlowId++,
    source: sources,
    sink: {
      kind: sinkInfo.type,
      prop: sinkInfo.prop,
      location: sinkLoc,
    },
    severity: sinkInfo.severity,
    pathConditions: [],            // legacy human-readable list — unused in B3
    pathFormula: ctx.currentPath || null,  // SMT formula for the block's reachability
    valueFormula: (value.formula) || null,     // SMT formula for the value at the sink
    assumptionIds: flowIds,
  };
  ctx.taintFlows.push(flow);
}

// Look up the source location for an instruction, falling back to
// a safe placeholder if the source map doesn't have an entry (tests
// and synthetic instructions may lack locations). AssumptionTracker
// requires a non-null location.
function instrLoc(ctx, instr) {
  const mapped = ctx.module.sourceMap && ctx.module.sourceMap.get(instr._id);
  if (mapped) return mapped;
  return {
    file: ctx.module.name || '<synthetic>',
    line: 0,
    col: 0,
    pos: 0,
  };
}

// --- Apply a single non-terminator instruction --------------------------
//
// Returns `Promise<State>`. The function is `async` because
// CALL and NEW walk user functions via `analyseFunction`, which
// is itself async to support Z3 as Layer 5 of the branch
// cascade (D6). Synchronous ops still return a State directly
// from their own helper; the `async` wrapper at this boundary
// auto-wraps those returns in a resolved Promise.
//
// Callers MUST await. Tests that construct a state manually and
// apply one or more instructions do so via:
//
//   state = await applyInstruction(ctx, state, instr);
//
// `ctx` carries the module, assumption tracker, and heap-
// allocation counter.
async function applyInstruction(ctx, state, instr) {
  switch (instr.op) {
    case OP.CONST: return applyConst(ctx, state, instr);
    case OP.BIN_OP: return applyBinOp(ctx, state, instr);
    case OP.UN_OP: return applyUnOp(ctx, state, instr);
    case OP.GET_GLOBAL: return applyGetGlobal(ctx, state, instr);
    case OP.GET_PROP: return applyGetProp(ctx, state, instr);
    case OP.GET_INDEX: return applyGetIndex(ctx, state, instr);
    case OP.GET_THIS: return applyGetThis(ctx, state, instr);
    case OP.GET_ARGS: return applyGetArgs(ctx, state, instr);
    case OP.SET_PROP: return applySetProp(ctx, state, instr);
    case OP.SET_INDEX: return applySetIndex(ctx, state, instr);
    case OP.SET_GLOBAL: return applySetGlobal(ctx, state, instr);
    case OP.ALLOC: return applyAlloc(ctx, state, instr);
    case OP.FUNC: return applyFunc(ctx, state, instr);
    case OP.CALL: return await applyCall(ctx, state, instr);
    case OP.NEW: return await applyNew(ctx, state, instr);
    case OP.CAST: return applyCast(ctx, state, instr);
    case OP.PHI: return state;  // phi is resolved at block-entry join time
    case OP.OPAQUE: return applyOpaqueInstr(ctx, state, instr);
    default:
      throw new Error('transfer: unknown op ' + instr.op);
  }
}

// --- Const --------------------------------------------------------------

function applyConst(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  // Concrete literals get an SMT formula immediately so any
  // downstream expression involving this register has a complete
  // symbolic representation. Booleans / numbers / strings all
  // fold to mkConst.
  const v = D.concrete(instr.value, undefined, loc);
  const withForm = D.withFormula(v, SMT.mkConst(instr.value));
  return D.setReg(state, instr.dest, withForm);
}

// --- BinOp --------------------------------------------------------------

function applyBinOp(ctx, state, instr) {
  const left = D.getReg(state, instr.left);
  const right = D.getReg(state, instr.right);
  const loc = instrLoc(ctx, instr);
  const result = computeBinOp(instr.operator, left, right, loc);
  return D.setReg(state, instr.dest, result);
}

function computeBinOp(op, a, b, loc) {
  // Taint labels propagate through every binary operation. The
  // result inherits the union of both operands' label sets,
  // regardless of whether the value itself folded to a concrete.
  // This is critical for soundness: `"<a>" + location.hash`
  // must produce a string-valued result that still carries the
  // `url` label.
  const labels = D.unionLabels(a, b);

  // Assumption ids propagate from both operands. Previously
  // this only pulled from Opaque — but values of any kind may
  // carry assumption ids (a Disjunct envelope, a Top reached
  // via widening, an imprecise-index-joined OneOf). Reading
  // `assumptionIds` off the operand unconditionally picks up
  // every contributing assumption so the flow's audit trail
  // survives through every concat / arith.
  const aIds = (a && a.assumptionIds) || [];
  const bIds = (b && b.assumptionIds) || [];
  let chainIds = aIds;
  if (bIds.length > 0) {
    if (chainIds.length === 0) {
      chainIds = bIds;
    } else {
      const seen = new Set(aIds);
      chainIds = aIds.slice();
      for (const i of bIds) if (!seen.has(i)) { seen.add(i); chainIds.push(i); }
    }
  }

  // B2: build the SMT formula for the result by combining the
  // operands' formulas. This is the symbolic representation
  // Phase D's Z3 layer queries to refute infeasible flows.
  // The formula is constructed even when the value-level
  // result folds to a concrete: a concrete `"<a>" + tainted`
  // still produces a (str.++ "<a>" |sym|) formula so a
  // downstream branch can ask "is this string equal to
  // a specific literal?"
  const formula = buildBinOpFormula(op, a, b);

  const attach = (v) => formula ? D.withFormula(v, formula) : v;

  // Both concrete → fold directly.
  if (a && a.kind === D.V.CONCRETE && b && b.kind === D.V.CONCRETE) {
    const folded = evalJsBinOp(op, a.value, b.value);
    if (folded !== undefined) {
      if (labels && labels.size > 0) {
        return attach(D.opaque(chainIds, undefined, loc, labels));
      }
      return attach(D.concrete(folded, undefined, loc));
    }
  }
  // Both OneOf → cartesian product.
  if (a && a.kind === D.V.ONE_OF && b && b.kind === D.V.ONE_OF) {
    const results = [];
    for (const va of a.values) {
      for (const vb of b.values) {
        const r = evalJsBinOp(op, va, vb);
        if (r !== undefined) results.push(r);
      }
    }
    if (results.length > 0) {
      if (labels && labels.size > 0) {
        return attach(D.opaque(chainIds, undefined, loc, labels));
      }
      if (results.length === 1) return attach(D.concrete(results[0], undefined, loc));
      return attach(D.oneOf(results, undefined, loc));
    }
  }
  // Concrete × OneOf → broadcast.
  if (a && a.kind === D.V.CONCRETE && b && b.kind === D.V.ONE_OF) {
    const results = [];
    for (const vb of b.values) {
      const r = evalJsBinOp(op, a.value, vb);
      if (r !== undefined) results.push(r);
    }
    if (results.length > 0) {
      if (labels && labels.size > 0) {
        return attach(D.opaque(chainIds, undefined, loc, labels));
      }
      if (results.length === 1) return attach(D.concrete(results[0], undefined, loc));
      return attach(D.oneOf(results, undefined, loc));
    }
  }
  if (b && b.kind === D.V.CONCRETE && a && a.kind === D.V.ONE_OF) {
    const results = [];
    for (const va of a.values) {
      const r = evalJsBinOp(op, va, b.value);
      if (r !== undefined) results.push(r);
    }
    if (results.length > 0) {
      if (labels && labels.size > 0) {
        return attach(D.opaque(chainIds, undefined, loc, labels));
      }
      if (results.length === 1) return attach(D.concrete(results[0], undefined, loc));
      return attach(D.oneOf(results, undefined, loc));
    }
  }
  // Interval arithmetic. Covers the loop-counter case:
  // `i + 1` where `i : Interval(lo, hi)` becomes
  // `Interval(lo+1, hi+1)`, so the refined interval on the
  // next back-edge is a precise shift of the previous one.
  // Without this, the binop fell to Top and the loop
  // counter's lattice value collapsed, triggering
  // imprecise-index downstream even for concrete-bound
  // loops.
  if (a && b && (a.kind === D.V.INTERVAL || a.kind === D.V.CONCRETE) &&
      (b.kind === D.V.INTERVAL || b.kind === D.V.CONCRETE)) {
    const aIsNumericLike = (a.kind === D.V.CONCRETE && typeof a.value === 'number') ||
                           a.kind === D.V.INTERVAL;
    const bIsNumericLike = (b.kind === D.V.CONCRETE && typeof b.value === 'number') ||
                           b.kind === D.V.INTERVAL;
    if (aIsNumericLike && bIsNumericLike) {
      const aLo = a.kind === D.V.INTERVAL ? a.lo : a.value;
      const aHi = a.kind === D.V.INTERVAL ? a.hi : a.value;
      const bLo = b.kind === D.V.INTERVAL ? b.lo : b.value;
      const bHi = b.kind === D.V.INTERVAL ? b.hi : b.value;
      const intervalResult = computeIntervalBinOp(op, aLo, aHi, bLo, bHi);
      if (intervalResult) {
        const resultLo = intervalResult.lo;
        const resultHi = intervalResult.hi;
        if (labels && labels.size > 0) {
          return attach(D.opaque(chainIds, undefined, loc, labels));
        }
        if (resultLo === resultHi && Number.isFinite(resultLo)) {
          return attach(D.concrete(resultLo, undefined, loc));
        }
        return attach(D.interval(resultLo, resultHi, loc));
      }
    }
  }
  // Opaque on either side propagates with merged chain + labels.
  if (a && a.kind === D.V.OPAQUE) {
    return attach(D.opaque(chainIds, null, loc, labels));
  }
  if (b && b.kind === D.V.OPAQUE) {
    return attach(D.opaque(chainIds, null, loc, labels));
  }
  // Operands are of kinds we don't know how to combine for this
  // operator (e.g. Interval + StrPattern). Result is Top with
  // the merged labels.
  return attach(D.top(loc, labels));
}

// computeIntervalBinOp — interval arithmetic. Returns
// { lo, hi } or null if the op isn't interval-compatible.
// Infinity-safe: ∞ ± x = ∞ and ∞ - ∞ is handled as an
// absorbing "unbounded" (returning null so the caller
// falls through to Top — an interval [−∞, +∞] is the
// same as "no information").
function computeIntervalBinOp(op, aLo, aHi, bLo, bHi) {
  if (op === '+') {
    return { lo: aLo + bLo, hi: aHi + bHi };
  }
  if (op === '-') {
    return { lo: aLo - bHi, hi: aHi - bLo };
  }
  if (op === '*') {
    // Multiplication flips sign based on operand signs; we
    // take the min/max of the four corner products. Avoids
    // the need for a separate sign analysis for the common
    // loop case.
    const corners = [aLo * bLo, aLo * bHi, aHi * bLo, aHi * bHi];
    let lo = Infinity, hi = -Infinity;
    for (const c of corners) {
      if (Number.isNaN(c)) return null;
      if (c < lo) lo = c;
      if (c > hi) hi = c;
    }
    return { lo, hi };
  }
  // Comparison ops not modelled here — the caller's
  // existing paths handle concrete/oneOf comparisons; for
  // intervals a comparison against a literal is a Boolean
  // lattice value that collapses to Top unless refinement
  // has already narrowed it.
  return null;
}

// --- Build an SMT formula for a binary op result -------------------------
//
// Given two operand Values and a JS operator, produce the SMT
// formula representing the result. The formula composes the
// operand formulas via the appropriate SMT-LIB primitive:
//
//   '+'  on string operands → str.++
//   '+'  on numeric operands → +
//   '-', '*', '/', '%'        → arith
//   '==', '===', '<', etc.    → cmp
//   logical / bitwise         → not yet (returns null)
//
// Returns null when no operand has a formula or when the op
// doesn't have an SMT translation. Callers handle null by
// leaving the result without a formula (which makes it opaque
// to the SMT layer — consumers fall back to label-based
// reasoning).
function buildBinOpFormula(op, a, b) {
  const fa = formulaOf(a);
  const fb = formulaOf(b);
  if (!fa && !fb) return null;
  // If one side has no formula, we can't translate the op
  // soundly. Return null and let the value-side handling carry
  // labels alone.
  if (!fa || !fb) return null;
  // String concat: + when at least one side is a string
  // formula. mkConcat handles the const-fold internally.
  if (op === '+') {
    const aStr = (fa.value && fa.value.kind === 'str') ||
      (fa.symName && fa.sorts && fa.sorts[fa.symName] === 'String') ||
      fa.stringResult;
    const bStr = (fb.value && fb.value.kind === 'str') ||
      (fb.symName && fb.sorts && fb.sorts[fb.symName] === 'String') ||
      fb.stringResult;
    if (aStr || bStr) return SMT.mkConcat(fa, fb);
    return SMT.mkArith('+', fa, fb);
  }
  if (op === '-' || op === '*' || op === '/' || op === '%') {
    return SMT.mkArith(op, fa, fb);
  }
  if (op === '==' || op === '===' || op === '!=' || op === '!==' ||
      op === '<' || op === '<=' || op === '>' || op === '>=') {
    return SMT.mkCmp(op, fa, fb);
  }
  if (op === '&&') return SMT.mkAnd(fa, fb);
  if (op === '||') return SMT.mkOr(fa, fb);
  // Bitwise / shift / nullish — no SMT translation yet.
  return null;
}

// Evaluate a JavaScript binary op on two concrete primitive
// values. Returns the exact JS result as a primitive, or
// `undefined` if the operation is either not handled or would
// throw a runtime TypeError (e.g. arithmetic across BigInt and
// Number). Never throws itself — all guards are explicit checks.
//
// When this function returns `undefined`, the caller's lattice
// transfer falls through to a more conservative answer. The
// underlying JS exception semantics (TypeError on BigInt mix)
// would be modelled separately when exception flow is
// implemented.
function evalJsBinOp(op, a, b) {
  // Arithmetic and bitwise ops throw if exactly one operand is
  // a BigInt and the other is not.
  const aIsBig = typeof a === 'bigint';
  const bIsBig = typeof b === 'bigint';
  const mixedBigint = aIsBig !== bIsBig;
  const arithLike = op === '+' || op === '-' || op === '*' || op === '/'
    || op === '%' || op === '**' || op === '&' || op === '|' || op === '^'
    || op === '<<' || op === '>>' || op === '>>>';
  if (arithLike && mixedBigint) return undefined;
  // `+` on BigInt + string also throws; `+` on number + string is
  // concatenation which is fine. Only the BigInt-string case is
  // dangerous.
  if (op === '+' && ((aIsBig && typeof b === 'string') || (bIsBig && typeof a === 'string'))) {
    return undefined;
  }
  switch (op) {
    case '+': return a + b;
    case '-': return a - b;
    case '*': return a * b;
    case '/':
      // Integer division by zero on BigInt throws RangeError.
      if (aIsBig && b === 0n) return undefined;
      return a / b;
    case '%':
      if (aIsBig && b === 0n) return undefined;
      return a % b;
    case '**':
      // Negative BigInt exponents throw.
      if (bIsBig && b < 0n) return undefined;
      return a ** b;
    case '==': return a == b;   // eslint-disable-line eqeqeq
    case '!=': return a != b;   // eslint-disable-line eqeqeq
    case '===': return a === b;
    case '!==': return a !== b;
    case '<': return a < b;
    case '<=': return a <= b;
    case '>': return a > b;
    case '>=': return a >= b;
    case '&': return aIsBig ? (a & b) : ((a & b) | 0);
    case '|': return aIsBig ? (a | b) : ((a | b) | 0);
    case '^': return aIsBig ? (a ^ b) : ((a ^ b) | 0);
    case '<<':
      // BigInt shifts can throw on negative shifts too.
      if (aIsBig && b < 0n) return undefined;
      return a << b;
    case '>>':
      if (aIsBig && b < 0n) return undefined;
      return a >> b;
    case '>>>':
      // BigInt doesn't support unsigned right shift — throws.
      if (aIsBig) return undefined;
      return a >>> b;
    case '&&': return a && b;
    case '||': return a || b;
    case '??': return a != null ? a : b;  // eslint-disable-line eqeqeq
    case 'in': return undefined;          // requires heap lookup
    case 'instanceof': return undefined;  // requires type system
    default: return undefined;
  }
}

// --- UnOp ---------------------------------------------------------------

function applyUnOp(ctx, state, instr) {
  const operand = D.getReg(state, instr.operand);
  const loc = instrLoc(ctx, instr);
  if (operand && operand.kind === D.V.CONCRETE) {
    const v = operand.value;
    let r;
    switch (instr.operator) {
      case '-':      r = -v; break;
      case '+':      r = +v; break;
      case '!':      r = !v; break;
      case '~':      r = ~v; break;
      case 'typeof': r = typeof v; break;
      case 'void':   r = undefined; break;
      default: return D.setReg(state, instr.dest, D.top(loc));
    }
    return D.setReg(state, instr.dest, D.concrete(r, undefined, loc));
  }
  if (operand && operand.kind === D.V.OPAQUE) {
    return D.setReg(state, instr.dest, D.opaque(operand.assumptionIds, null, loc));
  }
  return D.setReg(state, instr.dest, D.top(loc));
}

// --- GetGlobal ----------------------------------------------------------
//
// Resolve a bare identifier against the TypeDB. There are three
// outcomes:
//
//   1. Identifier is a known root (e.g. `location`, `document`,
//      `window`). Emit an Opaque value typed to the root's
//      declared type. If the type carries a `selfSource` (like
//      `localStorage` → `storage`), attach the label and raise
//      the corresponding source assumption.
//
//   2. Identifier is not a root but has a global scope entry in
//      the DB (rare; most are handled by their enclosing type).
//      Same as (1).
//
//   3. Identifier is unknown. Raise an `opaque-call` assumption
//      and return a typeless opaque value.
//
// Source detection on the root itself is important: bare
// `localStorage` carries the `storage` label without any
// further property access, matching the legacy engine.

function applyGetGlobal(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const db = ctx.typeDB;
  if (db && db.roots && db.roots[instr.name]) {
    const typeName = db.roots[instr.name];
    // Check if the root type carries a selfSource — reading the
    // bare binding already produces a labeled value (e.g.
    // `localStorage` has selfSource: 'storage').
    const typeDesc = db.types[typeName];
    const selfSource = typeDesc && typeDesc.selfSource;
    if (selfSource) {
      const reason = sourceLabelToReason(selfSource);
      const assumption = ctx.assumptions.raise(
        reason,
        'read from `' + instr.name + '` (TypeDB source: ' + selfSource + ')',
        loc,
        { affects: instr.name }
      );
      // B2: allocate a fresh SMT symbol for this source read so
      // downstream branches and sinks can refer to it. Two
      // reads of the same global (e.g. two bare `localStorage`
      // reads) share the same sym — which is what makes
      // correlation work across multiple read sites. The bare
      // global is the host object itself (Location, Storage,
      // …); when used in a sink context the consumer typically
      // calls toString on it, but the value at the IR level is
      // not a String yet. Default to Int sort here and let
      // sort upgrades occur naturally on the first comparison.
      const sym = allocSourceSym(ctx, selfSource, loc, instr.name);
      const v = D.opaque([assumption.id], typeName, loc, [selfSource]);
      return D.setReg(state, instr.dest, D.withFormula(v, sym));
    }
    // Non-source root (e.g. `document`, `window`): return an
    // opaque value with the TypeDB type but no taint label. The
    // type is enough to let subsequent property reads resolve
    // through the TypeDB and pick up their own source labels.
    return D.setReg(state, instr.dest,
      D.opaque([], typeName, loc));
  }
  // Truly unknown identifier.
  const assumption = ctx.assumptions.raise(
    REASONS.OPAQUE_CALL,
    'global identifier `' + instr.name + '` is not in the TypeDB',
    loc,
    { affects: instr.name }
  );
  return D.setReg(state, instr.dest, D.opaque([assumption.id], null, loc));
}

function applyGetThis(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  // If the engine is currently walking a constructor / method
  // body that was entered with an explicit `this` value (see
  // applyNew / applyCall), return that. Otherwise `this` at
  // the top level resolves to the module-level this binding,
  // which in script mode is the global — we model that as an
  // opaque with a soundness assumption.
  if (ctx._currentThisValue) {
    return D.setReg(state, instr.dest, ctx._currentThisValue);
  }
  const a = ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    'this-binding resolution outside constructor / method context',
    loc
  );
  return D.setReg(state, instr.dest, D.opaque([a.id], null, loc));
}

function applyGetArgs(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const a = ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    'arguments object not yet modeled',
    loc
  );
  return D.setReg(state, instr.dest, D.opaque([a.id], null, loc));
}

// --- GetProp / GetIndex -------------------------------------------------
//
// applyGetProp dispatches per-receiver-variant. When the receiver
// is a Disjunct (e.g. `el = cond ? createElement('a') : createElement('iframe')`)
// each variant has its own typeName and looks up its own
// PropDescriptor. The result is rebuilt as a Disjunct so the
// per-path type information survives the property read — a
// downstream `el.src = ...` write sees both the iframe variant
// (sink) and the anchor variant (no `src` property).

function applyGetProp(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const obj = D.getReg(state, instr.object);
  if (!obj) {
    return D.setReg(state, instr.dest, D.top(loc));
  }
  const result = D.disjunctMap(obj, (variant) =>
    propLookupForVariant(ctx, state, variant, instr, loc));
  return D.setReg(state, instr.dest, result);
}

// Resolve a single (non-disjunct) receiver variant against a
// property name. Returns a Value. Extracted so applyGetProp can
// fan out over Disjuncts via disjunctMap.
function propLookupForVariant(ctx, state, obj, instr, loc) {
  if (obj.kind === D.V.OBJECT) {
    const cell = D.overlayGet(state.heap, obj.objId);
    if (cell && cell.fields[instr.propName]) {
      return cell.fields[instr.propName];
    }
    return D.concrete(undefined, undefined, loc);
  }
  if (obj.kind === D.V.OPAQUE) {
    const db = ctx.typeDB;
    if (db && obj.typeName) {
      const desc = TDB.lookupProp(db, obj.typeName, instr.propName);
      if (desc) {
        const resultType = desc.readType || null;
        const existingLabels = obj.labels || D.EMPTY_LABELS;
        let resultLabels = existingLabels;
        const chainIds = obj.assumptionIds ? obj.assumptionIds.slice() : [];
        let resultFormula = null;
        if (desc.source) {
          const reason = sourceLabelToReason(desc.source);
          const assumption = ctx.assumptions.raise(
            reason,
            'read `' + instr.propName + '` from ' + obj.typeName +
              ' (TypeDB source: ' + desc.source + ')',
            loc,
            {
              affects: instr.propName,
              chain: chainIds.length > 0 ? chainIds : undefined,
            }
          );
          const merged = new Set(existingLabels);
          merged.add(desc.source);
          resultLabels = Object.freeze(merged);
          chainIds.push(assumption.id);
          // B2: allocate an SMT symbol for this source read.
          // The discriminator combines the receiver type and
          // property name so `location.hash` and `location.search`
          // get distinct syms; two reads of `location.hash`
          // anywhere in the program share the same sym (which
          // is what makes path-condition correlation work). The
          // sort is derived from `desc.readType` so a String-typed
          // source produces a String-sorted sym immediately.
          resultFormula = allocSourceSym(ctx, desc.source, loc,
            obj.typeName + '.' + instr.propName,
            readTypeToSort(desc.readType));
        }
        const v = D.opaque(chainIds, resultType, loc, resultLabels);
        return resultFormula ? D.withFormula(v, resultFormula) : v;
      }
    }
    // No TypeDB info → propagate the receiver's opaqueness.
    return D.opaque(obj.assumptionIds || [], null, loc, obj.labels);
  }
  // Property access on a primitive: model autoboxing via the
  // TypeDB's wrapper type when available.
  if (obj.kind === D.V.CONCRETE) {
    const db = ctx.typeDB;
    const wrapperType = primitiveWrapperType(obj.value);
    if (db && wrapperType) {
      const desc = TDB.lookupProp(db, wrapperType, instr.propName);
      if (desc) {
        return D.opaque(obj.assumptionIds || [], desc.readType || null, loc,
          obj.labels);
      }
    }
    // Unknown property on a primitive: standard JS returns
    // undefined (and throws on null/undefined receiver, which we
    // don't model yet).
    return D.concrete(undefined, undefined, loc);
  }
  // OneOf / Interval / StrPattern / Closure / Top: opaque result.
  const a = ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    'property access on ' + obj.kind + ' value not yet modeled',
    loc,
    { affects: instr.propName }
  );
  return D.opaque([a.id], null, loc, obj.labels);
}

// Map a JS primitive value to its TypeDB wrapper type. Returns
// null for null/undefined (no wrapper) or unmodeled types.
function primitiveWrapperType(v) {
  if (v === null || v === undefined) return null;
  switch (typeof v) {
    case 'string':  return 'String';
    case 'number':  return 'Number';
    case 'boolean': return 'Boolean';
    default: return null;
  }
}

// Helper for applyGetIndex: largest integer key present in a
// heap-cell fields map, or null if none. Used by the Interval
// narrowing path to decide whether the interval's upper bound
// escapes the cell and the `undefined`-on-out-of-bounds join
// should be added.
function highestNumericKey(fields) {
  let hi = null;
  for (const k in fields) {
    const n = Number(k);
    if (!Number.isFinite(n) || !Number.isInteger(n)) continue;
    if (hi === null || n > hi) hi = n;
  }
  return hi;
}

function applyGetIndex(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const obj = D.getReg(state, instr.object);
  const key = D.getReg(state, instr.key);

  // Case 1: concrete heap object, concrete scalar key.
  // Exact field lookup.
  if (obj && obj.kind === D.V.OBJECT && key && key.kind === D.V.CONCRETE) {
    const cell = D.overlayGet(state.heap, obj.objId);
    const keyStr = String(key.value);
    if (cell && cell.fields[keyStr]) {
      return D.setReg(state, instr.dest, cell.fields[keyStr]);
    }
    return D.setReg(state, instr.dest, D.concrete(undefined, undefined, loc));
  }

  // Cases 2-4: concrete heap object, NARROWABLE non-concrete
  // key. We use the key's may-be lattice to enumerate only
  // the fields the read can actually pick. When the
  // enumeration covers a finite set of keys, the result is
  // the join of ONLY those fields — no assumption needed,
  // the read is precise with respect to the lattice. We
  // only fall back to "join every field + raise
  // imprecise-index" when the key is truly opaque.
  //
  // Supported narrowing:
  //
  //   * Case 2  key: OneOf [v1, v2, …] (primitive values) →
  //             look up each value as a string key.
  //   * Case 3  key: Interval(lo, hi) → look up each integer
  //             in [lo, hi] clipped to field existence.
  //             Capped by FIELD_ENUM_CAP to avoid walking
  //             enormous intervals.
  //   * Case 4  key: StrPattern (future) — currently falls
  //             through to the opaque fallback.
  //
  // Cases 2 and 3 DO NOT raise any assumption. They are as
  // precise as the lattice allows and produce the exact set
  // of values the read can return.
  if (obj && obj.kind === D.V.OBJECT) {
    const cell = D.overlayGet(state.heap, obj.objId);
    if (cell && cell.fields) {
      const lookup = (keyStr) => {
        const f = cell.fields[keyStr];
        if (f) return f;
        return D.concrete(undefined, undefined, loc);
      };

      // Case 2: OneOf key.
      if (key && key.kind === D.V.ONE_OF && Array.isArray(key.values)) {
        let joined = null;
        for (const kv of key.values) {
          const v = lookup(String(kv));
          joined = joined ? D.join(joined, v) : v;
        }
        if (joined) return D.setReg(state, instr.dest, joined);
      }

      // Case 3: Interval key. We iterate the CELL's existing
      // numeric-named fields, not the interval indices —
      // that way the cost is bounded by heap structure (the
      // number of fields the cell actually holds) rather
      // than by a magic cap on interval width, and an
      // Interval(0, +Infinity) on a 3-element array does
      // the right thing: it picks up fields 0/1/2 and falls
      // through to the imprecise-index fallback only if the
      // interval's bounds genuinely escape the cell's
      // indexable range.
      if (key && key.kind === D.V.INTERVAL &&
          typeof key.lo === 'number' && typeof key.hi === 'number') {
        let joined = null;
        let sawAny = false;
        let missedAnyBound = false;
        for (const k in cell.fields) {
          // Field keys are strings; numeric coerce and
          // check the interval. Non-numeric field names
          // (like 'length' on arrays) are skipped — the
          // interval is an integer range, not a string
          // pattern. If we skip a field whose numeric
          // coerce would have fallen in range we flag it,
          // so the caller can fall through to the
          // imprecise-index path for soundness.
          const n = Number(k);
          if (!Number.isFinite(n) || !Number.isInteger(n)) continue;
          if (n < key.lo || n > key.hi) continue;
          const fv = cell.fields[k];
          if (!fv) continue;
          joined = joined ? D.join(joined, fv) : fv;
          sawAny = true;
        }
        // Interval's upper bound might extend past the
        // highest populated field (e.g. Interval(0, +Infinity)
        // on an array of length 3 — the indices 3, 4, 5, …
        // are legal reads of `undefined`, which we represent
        // as Concrete(undefined)). Union that in when the
        // interval stretches beyond the cell.
        const maxFieldKey = highestNumericKey(cell.fields);
        if (maxFieldKey !== null && key.hi > maxFieldKey) {
          const undef = D.concrete(undefined, undefined, loc);
          joined = joined ? D.join(joined, undef) : undef;
          sawAny = true;
        }
        if (sawAny) return D.setReg(state, instr.dest, joined);
        if (missedAnyBound) { /* fall through */ }
      }

      // Case 5 (fallback): key is Opaque / Top / StrPattern /
      // an unbounded Interval. We cannot narrow the read to
      // a specific subset, so we over-approximate by joining
      // every field the cell currently holds. This is SOUND
      // for taint (any label present on any field surfaces
      // in the result) but IMPRECISE — a points-to analysis
      // or a tighter key lattice would pin the read to
      // fewer fields. We raise `unimplemented` with an
      // `imprecise-index:` details prefix so strict-mode
      // consumers see the class of imprecision, and attach
      // the assumption id to the joined value so the flow's
      // audit trail records it.
      //
      // DOM conversion does NOT consume this path — it
      // rewrites from AST template records, not runtime-
      // join values. Taint over-approximation cannot
      // produce an unsound rewrite.
      let joined = null;
      for (const k in cell.fields) {
        const fv = cell.fields[k];
        if (!fv) continue;
        joined = joined ? D.join(joined, fv) : fv;
      }
      if (joined) {
        const a = ctx.assumptions.raise(
          REASONS.UNIMPLEMENTED,
          'imprecise-index: computed index read with opaque key, joining every field as a sound over-approximation',
          loc
        );
        const withIds = D.withAssumptionIds(joined, [a.id]);
        return D.setReg(state, instr.dest, withIds);
      }
      // Empty heap cell: nothing to return except the
      // per-call assumption-bearing opaque below.
    }
  }

  if (obj && obj.kind === D.V.OPAQUE) {
    // Opaque receiver: preserve its label set so taint that
    // arrived on the receiver side still flows to the
    // read-out value. The old code built a fresh opaque and
    // dropped labels, which lost taint across `obj[k]` reads
    // when the receiver itself was tainted.
    return D.setReg(state, instr.dest,
      D.opaque(obj.assumptionIds, null, loc, obj.labels));
  }

  // Computed index whose target object or key couldn't be
  // narrowed to a concrete value. This is an engineering gap
  // (it would resolve if the may-be lattice narrowed the key
  // to a finite set, or if a points-to analysis pinned the
  // target object) rather than a distinct assumption class.
  const a = ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    'computed index access with unresolved target or key — may-be lattice did not narrow the dispatch',
    loc
  );
  return D.setReg(state, instr.dest, D.opaque([a.id], null, loc));
}

// --- SetProp / SetIndex -------------------------------------------------

function applySetProp(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const obj = D.getReg(state, instr.object);
  const val = D.getReg(state, instr.value);
  // D11.1 completeness gate: any syntactic innerHTML /
  // outerHTML / insertAdjacentHTML write the walker actually
  // executed — regardless of whether the receiver resolved
  // to a DOM type — lands in `ctx.walkedHtmlSites`. The
  // dom-convert consumer uses this to distinguish "walked
  // but plain-object receiver, skip rewriting" from "not
  // walked, probably dead branch, rewrite anyway". Without
  // this record the two cases were indistinguishable from
  // trace.innerHtmlAssignments alone (both are absent).
  if (ctx.walkedHtmlSites &&
      (instr.propName === 'innerHTML' ||
       instr.propName === 'outerHTML')) {
    ctx.walkedHtmlSites.push({
      kind:    instr.propName,
      pos:     loc.pos,
      endPos:  loc.endPos,
      file:    loc.file,
    });
  }
  // Sink classification: iterate over every receiver variant so a
  // Disjunct of element types fires once per variant that has a
  // sink descriptor for this property name. This is the
  // per-path-type element case: if `el` is a Disjunct of anchor
  // and iframe, writing `.src` fires the iframe's navigation sink
  // but not the anchor (which has no `src`).
  for (const variant of D.disjunctVariants(obj)) {
    maybeEmitSinkFlowForWrite(ctx, variant, instr.propName, val, loc);
    maybeRecordInnerHtmlAssignment(ctx, variant, instr.propName, val, loc);
    recordDomMutationForWrite(ctx, variant, instr.propName, val, loc);
    recordStringLiteralSetProp(ctx, variant, instr.propName, val, loc);
  }
  // Heap write: fan out over object-ref variants. We don't know
  // which variant the runtime picks, so we model both being
  // written. (This is sound: the worklist's subsequent reads see
  // the most-recent write on every alias.)
  let newState = state;
  let any = false;
  for (const variant of D.disjunctVariants(obj)) {
    if (variant && variant.kind === D.V.OBJECT) {
      newState = writeHeapField(newState, variant.objId, instr.propName, val);
      any = true;
    } else if (variant && variant.kind === D.V.OPAQUE) {
      ctx.assumptions.raise(
        REASONS.HEAP_ESCAPE,
        'property write on opaque object — mutation not tracked',
        loc,
        { affects: instr.propName, chain: variant.assumptionIds }
      );
    }
  }
  return newState;
}

// --- Sink classification helpers -----------------------------------------
//
// Called by applySetProp and applySetIndex to detect
// tainted-value-reaches-sink patterns. Does nothing if:
//   - The receiver has no TypeDB type (we don't know what it is).
//   - The property isn't a sink on the receiver's type chain.
//   - The value has no taint labels.
// Otherwise emits a TaintFlow via emitTaintFlow.
function maybeEmitSinkFlowForWrite(ctx, obj, propName, val, loc) {
  if (!ctx.typeDB || !obj || !obj.typeName) return;
  if (!val || !val.labels || val.labels.size === 0) return;
  const sinkInfo = TDB.classifySinkByTypeViaDB(ctx.typeDB, obj.typeName, propName);
  if (!sinkInfo) return;
  emitTaintFlow(ctx, sinkInfo, loc, val);
}

// --- Wave 12b: trace-enrichment recorders -------------------------------
//
// Every observation the consumers need flows into a
// dedicated trace field. Consumers read these arrays via the
// query.* functions. Records are generic and consumer-
// agnostic: a single record can serve multiple consumers.

// recordCallSite — push one CallInfo record per call instr.
// Shape (matches docs/API.md §CallInfo):
//
//   {
//     callee: { text, typeName, methodName, calleeName },
//     args: Value[],
//     thisArg: Value | null,
//     site: Location,
//     reachability: 'reachable' | 'unknown',
//     pathFormula: Formula | null,
//   }
//
// `callee.text` is a best-effort display string built from
// the IR's calleeName / methodName hints. `callee.typeName`
// is set when the receiver has a TypeDB type, so consumers
// can filter by receiver type without re-classifying.
function recordCallSite(ctx, instr, callee, thisValue, argValues, loc) {
  if (!ctx.calls) return;
  const text = instr.methodName
    ? (thisValue && thisValue.typeName
        ? thisValue.typeName + '.' + instr.methodName
        : instr.methodName)
    : (instr.calleeName || '<anonymous>');
  ctx.calls.push({
    callee: {
      text,
      typeName: (thisValue && thisValue.typeName) || null,
      methodName: instr.methodName || null,
      calleeName: instr.calleeName || null,
      // Expose the callee's Value so consumers can inspect its
      // labels/assumptionIds without a second lookup.
      value: callee || null,
    },
    args: argValues.slice(),
    thisArg: thisValue || null,
    site: loc,
    reachability: 'reachable',    // if we're in transfer, the instr is reachable
    pathFormula: ctx.currentPath || null,
  });
}

// recordDomMutation — push one DomMutation record for every
// call that mutates a DOM-typed receiver. The TypeDB's type
// chain is the authority: if `thisValue.typeName` is in the
// Element / Node / HTMLCollection / NodeList / CSSStyleDeclaration
// / DOMTokenList / NamedNodeMap chain, the call is a DOM
// mutation observation and goes into trace.domMutations.
//
// Shape (DomMutation):
//
//   {
//     kind: string,           -- method name (e.g. 'setAttribute')
//     category: 'method',
//     targetType: string,     -- receiver's typeName
//     target: Value,          -- receiver value
//     args: Value[],          -- arguments
//     site: Location,
//     pathFormula: Formula | null,
//   }
//
// SetProp observations (property assignments like `el.innerHTML = s`)
// use the parallel `recordDomMutationForWrite` helper called
// from applySetProp.
function recordDomMutation(ctx, instr, thisValue, argValues, loc) {
  if (!ctx.domMutations) return;
  if (!thisValue || !thisValue.typeName) return;
  if (!instr.methodName) return;
  if (!isDomMutationType(ctx, thisValue.typeName)) return;
  ctx.domMutations.push({
    kind: instr.methodName,
    category: 'method',
    targetType: thisValue.typeName,
    target: thisValue,
    args: argValues.slice(),
    site: loc,
    pathFormula: ctx.currentPath || null,
  });
}

// recordDomMutationForWrite — SetProp analogue of
// recordDomMutation. Fired from applySetProp. Skips properties
// already covered by the innerHtmlAssignments channel
// (innerHTML, outerHTML, insertAdjacentHTML) so consumers
// don't have to dedupe.
function recordDomMutationForWrite(ctx, obj, propName, val, loc) {
  if (!ctx.domMutations) return;
  if (!obj || !obj.typeName) return;
  if (!isDomMutationType(ctx, obj.typeName)) return;
  if (propName === 'innerHTML' || propName === 'outerHTML') return;
  ctx.domMutations.push({
    kind: propName,
    category: 'property-set',
    targetType: obj.typeName,
    target: obj,
    args: [val],
    site: loc,
    pathFormula: ctx.currentPath || null,
  });
}

// True iff the given TypeDB type name is in the DOM chain.
// We walk the TypeDB's `extends` links from the given type up
// to the root; any ancestor in the set below qualifies. The
// check is cached per-type on the TypeDB object to avoid
// walking the chain every time.
const DOM_ROOT_TYPES = new Set([
  'Element', 'Node', 'HTMLElement',
  'CSSStyleDeclaration', 'DOMTokenList', 'NamedNodeMap',
  'HTMLCollection', 'NodeList',
  'EventTarget',       // addEventListener / removeEventListener
]);

function isDomMutationType(ctx, typeName) {
  if (!typeName) return false;
  if (!ctx.typeDB || !ctx.typeDB.types) return false;
  if (!ctx._domTypeCache) ctx._domTypeCache = new Map();
  const cached = ctx._domTypeCache.get(typeName);
  if (cached !== undefined) return cached;
  let t = typeName;
  while (t) {
    if (DOM_ROOT_TYPES.has(t)) {
      ctx._domTypeCache.set(typeName, true);
      return true;
    }
    const desc = ctx.typeDB.types[t];
    if (!desc) break;
    t = desc.extends || null;
  }
  ctx._domTypeCache.set(typeName, false);
  return false;
}

// recordStringLiteralArgs — push a LiteralObservation for
// every concrete-string argument of a recorded call. The
// context is built from the callee description so consumers
// can filter to a specific API (e.g. "every concrete string
// passed as the first arg of fetch").
//
// Shape (LiteralObservation):
//
//   {
//     value: string,
//     context: string,          -- e.g. 'fetch/0', 'Element.setAttribute/1'
//     site: Location,
//     sinkKind: string | null,  -- from sink classification, if any
//   }
function recordStringLiteralArgs(ctx, instr, callee, thisValue, argValues, loc) {
  if (!ctx.stringLiterals) return;
  const base = instr.methodName
    ? (thisValue && thisValue.typeName
        ? thisValue.typeName + '.' + instr.methodName
        : instr.methodName)
    : (instr.calleeName || '<anonymous>');
  for (let i = 0; i < argValues.length; i++) {
    const a = argValues[i];
    if (!a || a.kind !== D.V.CONCRETE || typeof a.value !== 'string') continue;
    ctx.stringLiterals.push({
      value: a.value,
      context: base + '/' + i,
      site: loc,
      sinkKind: null,
    });
  }
}

// recordStringLiteralSetProp — SetProp analogue: if `val` is
// a concrete string, record it with context `<type>.<prop>`.
function recordStringLiteralSetProp(ctx, obj, propName, val, loc) {
  if (!ctx.stringLiterals) return;
  if (!val || val.kind !== D.V.CONCRETE || typeof val.value !== 'string') return;
  const typeName = obj && obj.typeName ? obj.typeName : '<anonymous>';
  ctx.stringLiterals.push({
    value: val.value,
    context: typeName + '.' + propName,
    site: loc,
    sinkKind: null,
  });
}

// walkCallbackArgs — interprocedural walk of callback
// arguments to registration APIs (addEventListener, setTimeout,
// setInterval, requestAnimationFrame, queueMicrotask, etc.).
//
// The TypeDB's method descriptor declares `callbackArgs: [N, ...]`
// listing argument indices that receive a function value the
// runtime will invoke later. For each such arg we:
//
//   1. Resolve the descriptor (lookupMethod / roots lookup).
//   2. For each listed index, look up the argument Value.
//   3. If the Value is a Closure pointing at a user function,
//      walk the function body via getAnalyseFunction() with an
//      empty argument context (the callback's own params will
//      be bound to Opaque values because we don't know what
//      the runtime will pass).
//
// Sinks fired inside the walked body land in ctx.taintFlows /
// ctx.calls / ctx.domMutations / ctx.innerHtmlAssignments
// alongside flows from the outer function, so downstream
// consumers (dom-convert, csp-derive, taint-report) pick them
// up uniformly.
//
// Recursion guard: the walk shares ctx._callStack with the
// normal applyCall path, so a callback that registers itself
// (or transitively re-registers) still takes the
// D.callStackContains bail-out.
async function walkCallbackArgs(ctx, state, instr, thisValue, argValues, loc) {
  const db = ctx.typeDB;
  if (!db) return;
  let desc = null;
  if (instr.methodName && thisValue && thisValue.typeName) {
    desc = TDB.lookupMethod(db, thisValue.typeName, instr.methodName);
  } else if (instr.calleeName && db.roots && db.roots[instr.calleeName]) {
    const rootType = db.roots[instr.calleeName];
    const typeDesc = db.types[rootType];
    desc = typeDesc && (typeDesc.call || typeDesc.construct);
  }
  if (!desc || !Array.isArray(desc.callbackArgs) || desc.callbackArgs.length === 0) return;

  // Infer the typeName of the callback's first parameter
  // when the descriptor declares `callbackEventNameArg`.
  // addEventListener('message', h) → eventMap['message'] →
  // 'MessageEvent', so h receives a MessageEvent-typed
  // Opaque whose `.data` read hits the postMessage source
  // classifier. Without this, the handler walks with a
  // bare opaque first-param and every event-data access
  // loses its source label.
  let firstParamType = null;
  if (typeof desc.callbackEventNameArg === 'number' && db.eventMap) {
    const evNameVal = argValues[desc.callbackEventNameArg];
    if (evNameVal && evNameVal.kind === D.V.CONCRETE &&
        typeof evNameVal.value === 'string') {
      const mapped = db.eventMap[evNameVal.value];
      if (mapped && db.types && db.types[mapped]) {
        firstParamType = mapped;
      }
    }
  }

  for (const idx of desc.callbackArgs) {
    if (typeof idx !== 'number') continue;
    const cbValue = argValues[idx];
    if (!cbValue) continue;
    // Resolve a Closure to its user function id.
    let fnId = null;
    if (cbValue.kind === D.V.CLOSURE && cbValue.functionId) {
      fnId = cbValue.functionId;
    }
    // Disjunct: fan out over closure variants.
    if (cbValue.kind === D.V.DISJUNCT && Array.isArray(cbValue.variants)) {
      for (const v of cbValue.variants) {
        if (v && v.kind === D.V.CLOSURE && v.functionId) {
          await walkCallback(ctx, state, v, loc, firstParamType);
        }
      }
      continue;
    }
    if (fnId == null) continue;
    await walkCallback(ctx, state, cbValue, loc, firstParamType);
  }
}

// walkCallback — walk a single closure's body as a synthetic
// call site. Matches the applyCall walking path but with
// empty args (the runtime will supply them later). Captures
// are threaded from the closure's snapshot so variables the
// callback closes over are visible inside.
async function walkCallback(ctx, state, closureValue, loc, firstParamType) {
  const calleeFn = ctx.module.functions.find(f => f.id === closureValue.functionId);
  if (!calleeFn || !calleeFn.cfg) return;

  // Recursion guard per D7 (body + args fingerprint).
  let calleeInit = D.createStateSharingHeap(state);
  // Thread captures.
  const closureCaptures = closureValue.captures || [];
  for (const c of closureCaptures) {
    if (!c || c.innerReg == null) continue;
    let val = null;
    if (c.outerReg != null) {
      const live = D.getReg(state, c.outerReg);
      if (live && live.kind !== D.V.BOTTOM) val = live;
    }
    if (!val && c.value && c.value.kind !== D.V.BOTTOM) val = c.value;
    if (val) calleeInit = D.setReg(calleeInit, c.innerReg, val);
  }
  // Bind each param to an Opaque value. The callback's
  // params receive runtime data we can't predict statically
  // (the event object for addEventListener, no args for
  // setTimeout, etc.) — Opaque is the sound floor. When the
  // caller supplied a `firstParamType` (e.g. MessageEvent
  // derived from the eventMap lookup for
  // addEventListener('message', h)), we type the first
  // parameter so its property reads flow through the
  // TypeDB's source classifier — `msg.data` on a
  // MessageEvent produces a postMessage-tainted value.
  const params = calleeFn.params || [];
  for (let pi = 0; pi < params.length; pi++) {
    const paramReg = params[pi];
    const typeName = (pi === 0 && firstParamType) ? firstParamType : null;
    const a = ctx.assumptions.raise(
      REASONS.UI_INTERACTION,
      'callback argument is supplied by the runtime — walking with an Opaque placeholder' +
        (typeName ? ' typed as ' + typeName : ''),
      loc
    );
    calleeInit = D.setReg(calleeInit, paramReg,
      D.opaque([a.id], typeName, loc));
  }
  // Seed the callback's path with the caller's current path
  // so sinks inside inherit the caller-side reachability.
  const callerPath = ctx.currentPath || null;
  if (callerPath) calleeInit = D.withPath(calleeInit, callerPath);

  const fp = buildArgsFingerprint(calleeFn, calleeInit, closureCaptures, null);
  const frame = { funcId: calleeFn.id, argsFp: fp };
  if (D.callStackContains(state, frame)) return;
  calleeInit = D.pushCallStack(calleeInit, frame);

  const savedPath = ctx.currentPath;
  const savedBlockId = ctx.currentBlockId;
  const savedThis = ctx._currentThisValue;
  try {
    const analyse = getAnalyseFunction();
    await analyse(ctx.module, calleeFn, calleeInit, ctx);
  } finally {
    ctx.currentPath = savedPath;
    ctx.currentBlockId = savedBlockId;
    ctx._currentThisValue = savedThis;
  }
}

// Wave 12 / Phase E: record innerHTML-family assignments so the
// DOM-conversion consumer can iterate them post-walk. Records
// every write to a property the TypeDB classifies as an 'html'
// sink — regardless of whether the value is tainted — because
// the consumer rewrites even concrete assignments into
// createElement/appendChild trees.
//
// Shape (InnerHtmlAssignment):
//   {
//     kind: 'innerHTML' | 'outerHTML' | 'insertAdjacentHTML',
//     targetType: string,          -- receiver's typeName
//     value: Value,                -- the value written
//     location: Location,          -- where the assignment sits
//     labels: string[],            -- taint labels on value
//   }
//
// `kind` is the property name. Consumers that need to
// distinguish innerHTML from outerHTML check this field.
function maybeRecordInnerHtmlAssignment(ctx, obj, propName, val, loc) {
  if (!ctx.innerHtmlAssignments) return;
  if (!ctx.typeDB || !obj || !obj.typeName) return;
  const sinkInfo = TDB.classifySinkByTypeViaDB(ctx.typeDB, obj.typeName, propName);
  if (!sinkInfo || sinkInfo.type !== 'html') return;
  const labels = val && val.labels
    ? Array.from(val.labels).sort()
    : [];
  ctx.innerHtmlAssignments.push({
    kind: propName,
    targetType: obj.typeName,
    value: val,
    location: loc,
    labels,
  });
}

function applySetIndex(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const obj = D.getReg(state, instr.object);
  const key = D.getReg(state, instr.key);
  const val = D.getReg(state, instr.value);
  if (obj && obj.kind === D.V.OBJECT && key && key.kind === D.V.CONCRETE) {
    return writeHeapField(state, obj.objId, String(key.value), val);
  }
  ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    'computed index write with unresolved target or key — may-be lattice did not narrow the dispatch',
    loc
  );
  return state;
}

function applySetGlobal(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    'global binding write not yet modeled: ' + instr.name,
    loc
  );
  return state;
}

function writeHeapField(state, objId, field, value) {
  const cell = D.overlayGet(state.heap, objId);
  const oldFields = (cell && cell.fields) || Object.create(null);
  const newFields = Object.create(null);
  for (const k in oldFields) newFields[k] = oldFields[k];
  newFields[field] = value;
  const newCell = Object.freeze({
    kind: (cell && cell.kind) || 'object',
    fields: Object.freeze(newFields),
    typeName: (cell && cell.typeName) || null,
    origin: (cell && cell.origin) || null,
  });
  if (!state._frozen) {
    state.heap.own.set(objId, newCell);
    return state;
  }
  const newHeap = { own: new Map([[objId, newCell]]), parent: state.heap };
  return Object.freeze({
    regs: state.regs,
    heap: newHeap,
    path: state.path || null,
    effects: state.effects,
    assumptionIds: state.assumptionIds,
    callStack: state.callStack,
    _frozen: true,
  });
}

// --- Alloc / Func / New / Call / Cast -----------------------------------

function applyAlloc(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const objId = nextObjId(ctx);
  const fields = Object.create(null);
  if (instr.fields) {
    for (const [key, reg] of instr.fields) {
      fields[key] = D.getReg(state, reg);
    }
  }
  // Object rest destructuring: copy all own fields from the
  // source that are NOT in the restOmit set.
  if (instr.restSource && instr.kind === 'Object') {
    const src = D.getReg(state, instr.restSource);
    if (src && src.kind === D.V.OBJECT) {
      const srcCell = D.overlayGet(state.heap, src.objId);
      if (srcCell && srcCell.fields) {
        const omit = new Set(instr.restOmit || []);
        for (const k in srcCell.fields) {
          if (omit.has(k)) continue;
          fields[k] = srcCell.fields[k];
        }
      }
    }
  }
  // Array rest destructuring: copy src[restSliceFrom..length]
  // into the new array with indices starting at 0.
  if (instr.restSource && instr.kind === 'Array' && instr.restSliceFrom != null) {
    const src = D.getReg(state, instr.restSource);
    if (src && src.kind === D.V.OBJECT) {
      const srcCell = D.overlayGet(state.heap, src.objId);
      if (srcCell && srcCell.fields) {
        let srcLen = 0;
        const lenVal = srcCell.fields.length;
        if (lenVal && lenVal.kind === D.V.CONCRETE && typeof lenVal.value === 'number') {
          srcLen = lenVal.value;
        }
        let outIdx = 0;
        for (let j = instr.restSliceFrom; j < srcLen; j++) {
          const e = srcCell.fields[String(j)];
          if (e) fields[String(outIdx)] = e;
          outIdx++;
        }
        fields.length = D.concrete(outIdx, 'number', loc);
      }
    }
  }
  // Object spread: copy all fields from each spread source into
  // this cell. Own fields from later spreads override earlier
  // ones; explicit static fields override spreads. Since
  // applyAlloc evaluates fields in source order (they were
  // listed in `instr.fields` first), we overwrite from spreads
  // BEFORE re-applying the static map. That matches JS
  // semantics: `{a: 1, ...obj, b: 2}` lets `obj.a` overwrite
  // the literal a, and explicit `b: 2` overwrite obj.b.
  //
  // Our IR doesn't interleave spread and literal fields — the
  // literal fields are set in instr.fields (which already ran)
  // and all spreads come after. JS semantics for an exact
  // alternating `{a: 1, ...b, c: 2}` would need interleaving;
  // we approximate by: start with empty, apply all spreads in
  // order, then apply all static fields on top.
  if (instr.spreads && instr.kind === 'Object') {
    // Reset fields and re-apply in "spreads first, statics on top" order.
    const staticFields = Object.create(null);
    for (const k in fields) staticFields[k] = fields[k];
    for (const k in fields) delete fields[k];
    for (const srcReg of instr.spreads) {
      const srcVal = D.getReg(state, srcReg);
      if (srcVal && srcVal.kind === D.V.OBJECT) {
        const srcCell = D.overlayGet(state.heap, srcVal.objId);
        if (srcCell && srcCell.fields) {
          for (const k in srcCell.fields) {
            if (k === 'length') continue;  // array metadata
            fields[k] = srcCell.fields[k];
          }
        }
      }
    }
    for (const k in staticFields) fields[k] = staticFields[k];
  }
  // Computed keys: at runtime, evaluate each keyReg. If it's a
  // Concrete string we store under that exact key; otherwise
  // we store under a synthetic `__computed_<n>__` name (precise
  // reads can't hit it, but the field value is still tracked so
  // taint flows through).
  if (instr.computed && instr.kind === 'Object') {
    for (let ci = 0; ci < instr.computed.length; ci++) {
      const pair = instr.computed[ci];
      const keyVal = D.getReg(state, pair.keyReg);
      const valVal = D.getReg(state, pair.valReg);
      let keyName = null;
      if (keyVal && keyVal.kind === D.V.CONCRETE) {
        keyName = String(keyVal.value);
      }
      if (keyName == null) keyName = '__computed_' + ci + '__';
      fields[keyName] = valVal;
    }
  }
  // Array spread: merge integer-keyed fields from each spread
  // source into this Array cell, offset by the position where
  // the spread appears. Since static elements were already
  // written above using their nominal source-order index, we
  // shift later static indices by the spread source's runtime
  // length. For a precise model we'd rewrite indices; for
  // soundness we overwrite any index from the spread source.
  if (instr.spreads && instr.kind === 'Array') {
    let indexOffset = 0;  // tracks how many runtime elements we've added beyond the static count
    for (const sp of instr.spreads) {
      const srcVal = D.getReg(state, sp.reg);
      if (srcVal && srcVal.kind === D.V.OBJECT) {
        const srcCell = D.overlayGet(state.heap, srcVal.objId);
        if (srcCell && srcCell.fields) {
          let sLen = 0;
          const lenVal = srcCell.fields.length;
          if (lenVal && lenVal.kind === D.V.CONCRETE && typeof lenVal.value === 'number') {
            sLen = lenVal.value;
          }
          for (let k = 0; k < sLen; k++) {
            const e = srcCell.fields[String(k)];
            if (e) fields[String(sp.position + indexOffset + k)] = e;
          }
          indexOffset += Math.max(0, sLen - 1);  // -1 because the spread itself occupied one position
        }
      }
    }
    // Update length to reflect the new total.
    const maxIndex = Object.keys(fields)
      .filter(k => /^\d+$/.test(k))
      .reduce((m, k) => Math.max(m, parseInt(k, 10) + 1), 0);
    fields.length = D.concrete(maxIndex, 'number', loc);
  }
  // For class objects (kind='Class'), the typeName is the class
  // name so instances created via `new ClassName(...)` can
  // resolve their method lookups through the TypeDB (when the
  // consumer provides one) and so applyNew can surface the
  // class name on the allocated instance.
  const cellTypeName = instr.kind === 'Class'
    ? (instr.className || null)
    : null;
  const cell = Object.freeze({
    kind: instr.kind || 'object',
    fields: Object.freeze(fields),
    typeName: cellTypeName,
    origin: loc,
  });
  // The ObjectRef's typeName mirrors the cell's typeName (for
  // class objects) or the IR kind (for plain objects/arrays).
  // For plain objects we keep the legacy behaviour of passing
  // instr.kind through.
  const refTypeName = instr.kind === 'Class' ? 'class:' + (instr.className || 'anon')
    : (instr.kind || null);
  if (!state._frozen) {
    state.heap.own.set(objId, cell);
    return D.setReg(state, instr.dest, D.objectRef(objId, refTypeName, loc));
  }
  const newHeap = { own: new Map([[objId, cell]]), parent: state.heap };
  const newState = Object.freeze({
    regs: state.regs,
    heap: newHeap,
    path: state.path || null,
    effects: state.effects,
    assumptionIds: state.assumptionIds,
    callStack: state.callStack,
    _frozen: true,
  });
  return D.setReg(newState, instr.dest, D.objectRef(objId, refTypeName, loc));
}

function applyFunc(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  // Closure captures: snapshot each captured outer register's
  // CURRENT value from the state at Func-instr time. The IR
  // builder places the Func instruction at the source-order
  // declaration point (not at hoist time), so by the time
  // the worklist reaches it all preceding var initializers
  // in the enclosing function have already run — captures
  // see the correct values.
  //
  // The snapshotted values are bundled with the closure so
  // the closure can escape its defining function (e.g. via
  // return) and still be called from a different function
  // whose state lacks the defining function's registers.
  const captureEntries = [];
  if (instr.captures && instr.captures.length > 0) {
    for (const c of instr.captures) {
      const outerVal = D.getReg(state, c.outerReg);
      captureEntries.push({
        innerReg: c.innerReg,
        outerReg: c.outerReg,           // fallback for hoisted-forward-ref
        value: outerVal || null,
      });
    }
  }
  return D.setReg(state, instr.dest,
    D.closure(instr.functionId, captureEntries, loc));
}

// buildArgsFingerprint — stable string summary of a callee's
// input state, per D7. Two calls that hash to the same
// fingerprint share a summary. Components:
//
//   * Each parameter's value fingerprint (in param order).
//   * Each closure-captured value's fingerprint (in capture
//     order). A call into the same body with different
//     captures is a different context and gets its own entry.
//   * `this` fingerprint.
//   * A stable heap-identity tag: D.callStackContains handles
//     recursion, but the cache still needs to know when the
//     heap differs — two calls with the same args but
//     different heap shapes can produce different exit
//     states, so they can't share a summary.
//
// Returns a deterministic string.
function buildArgsFingerprint(calleeFn, calleeInit, closureCaptures, thisValue) {
  const parts = [];
  if (calleeFn.params) {
    parts.push('p=');
    for (const paramReg of calleeFn.params) {
      const v = D.getReg(calleeInit, paramReg);
      parts.push(D.valueFingerprint(v));
      parts.push(',');
    }
  }
  if (closureCaptures && closureCaptures.length > 0) {
    parts.push('|c=');
    for (const c of closureCaptures) {
      if (!c) continue;
      const v = c.innerReg != null ? D.getReg(calleeInit, c.innerReg) : null;
      parts.push(D.valueFingerprint(v));
      parts.push(',');
    }
  }
  if (thisValue) {
    parts.push('|t=');
    parts.push(D.valueFingerprint(thisValue));
  }
  // Heap identity: reuse the caller's heap-overlay identity
  // tag so a function that doesn't touch the heap shares a
  // single cache entry across repeated calls.
  parts.push('|h=');
  parts.push(heapIdentityTag(calleeInit.heap));
  return parts.join('');
}

// Assign a stable, process-unique id to each heap overlay
// object. Two calls with the same overlay REFERENCE get the
// same id; any other overlay gets a fresh id. Because overlays
// are frozen once built, reference-equality implies content-
// equality: a cache hit under this key is always sound.
const _heapIdMap = new WeakMap();
let _nextHeapId = 1;
function heapIdentityTag(heap) {
  if (!heap) return '0';
  // Walk through empty overlays: an overlay with no local
  // writes is observationally equivalent to its parent, so
  // they should share a cache-key identity. Without this, a
  // function called repeatedly would miss the cache even when
  // no heap state has actually changed between calls.
  let o = heap;
  while (o && o.own && o.own.size === 0 && o.parent) o = o.parent;
  if (!o) return '0';
  let id = _heapIdMap.get(o);
  if (id == null) {
    id = _nextHeapId++;
    _heapIdMap.set(o, id);
  }
  return String(id);
}

// True iff `candidate` is an empty overlay chain over `base` —
// i.e. every overlay above `base` has an empty `own` map. This
// means `candidate` adds no new writes to `base` and can be
// replaced by `base` directly without loss of information.
function isEmptyOverlayOver(candidate, base) {
  let o = candidate;
  while (o && o !== base) {
    if (o.own && o.own.size > 0) return false;
    o = o.parent;
  }
  return o === base;
}

async function applyCall(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const callee = D.getReg(state, instr.callee);
  const argValues = instr.args.map(r => D.getReg(state, r));
  const thisValue = instr.thisArg ? D.getReg(state, instr.thisArg) : null;

  // Wave 12b: record every call site on the trace. Consumers
  // (fetch-trace, csp-derive, dom-convert) filter this array
  // via query.calls to find what they care about. The record
  // shape is generic, not consumer-specific.
  recordCallSite(ctx, instr, callee, thisValue, argValues, loc, state);
  // DOM mutation recording: if the call is a method on a
  // DOM-typed receiver, treat it as a DOM mutation observation.
  // This covers setAttribute / appendChild / replaceChildren /
  // insertBefore / removeChild / style.setProperty /
  // classList.add / addEventListener / etc. — every consumer
  // that wants to rewrite or inventory DOM calls reads from
  // trace.domMutations.
  recordDomMutation(ctx, instr, thisValue, argValues, loc);
  // String-literal argument recording: if any argument is a
  // concrete string, record it on trace.stringLiterals with
  // the call's context (callee name + arg index). CSP-derive
  // reads this to find concrete origins for script-src /
  // img-src / connect-src / frame-src; fetch-trace reads it
  // to find hardcoded endpoint URLs.
  recordStringLiteralArgs(ctx, instr, callee, thisValue, argValues, loc);

  // Wave 12c7: interprocedural callback walking. Some APIs
  // take a function argument that the runtime invokes later
  // (addEventListener, setTimeout, setInterval, Promise.then,
  // MutationObserver, etc.). Without walking the callback
  // body, sinks inside it are invisible to the engine — the
  // dom-convert consumer can't rewrite a `document.write`
  // inside an `addEventListener('message', ...)` handler,
  // and csp-derive can't see `fetch()` inside a setTimeout
  // callback.
  //
  // The TypeDB declares which args are callbacks via
  // `callbackArgs: [N, ...]`. We look up the descriptor the
  // same way maybeEmitSinkFlowForCall does, then for each
  // callback index resolve the arg to a Closure Value and
  // walk its body with a synthetic initial state. Sinks fired
  // inside land in ctx.taintFlows / ctx.calls / etc. just
  // like any other walked function.
  await walkCallbackArgs(ctx, state, instr, thisValue, argValues, loc);

  // --- Sink classification for the call site ---
  //
  // When the receiver is a Disjunct (e.g. `(anchor|iframe).method()`),
  // the sink classifier runs once per variant: each variant may
  // have a different method descriptor in the TypeDB, and
  // therefore a different sink profile. For non-disjunct
  // receivers (and for free-function calls where thisValue is
  // null) we run the classifier once with the original value.
  if (thisValue && thisValue.kind === D.V.DISJUNCT) {
    for (const thisVariant of thisValue.variants) {
      maybeEmitSinkFlowForCall(ctx, instr, thisVariant, argValues, loc);
    }
  } else {
    maybeEmitSinkFlowForCall(ctx, instr, thisValue, argValues, loc);
  }

  if (ctx.onCall) {
    // If the consumer's onCall hook throws, the exception
    // propagates — it is a visible consumer bug, not a silent
    // precision issue. Analyses that want fault tolerance
    // should handle errors inside their own hook.
    const result = ctx.onCall(
      callee, argValues, thisValue, state, loc, instr
    );
    if (result) return D.setReg(result.state || state, instr.dest, result.value);
  }

  // --- Phase C1: walk user function calls ---
  //
  // If the callee resolves to a Closure pointing to a user
  // function in this module, walk that function with the
  // caller's argument values bound to its params. The callee's
  // exit state's return value becomes this call's result.
  //
  // Cycle detection: per D7, the callee's initial state
  // carries a `callStack` list of `(funcId, argsFp)` frames.
  // `D.callStackContains(state, frame)` checks whether this
  // exact (body, args) pair is already on the chain — if so
  // we fall through to the recursion fallback below. Different
  // arg fingerprints for the same body proceed (state-level
  // check, not a ctx-level Set).
  //
  // Sinks fired inside the callee already get appended to
  // ctx.taintFlows because the callee shares ctx with the
  // caller. The callee's per-block path conditions are local
  // to its analysis run; the caller's pathCond at the call
  // site is restored by the worklist's prevPathCond stash
  // when this applyCall returns.
  // Resolve the callee to a user function. There are two paths:
  //
  //   1. The callee value is a CLOSURE — the standard case for
  //      `var f = function(){}; f();` and for function declarations
  //      whose name is in scope at the call site.
  //
  //   2. The callee is opaque (typeName=null) but the call's
  //      `calleeName` IR hint matches a top-level function in the
  //      module. This is the "free reference" case: an inner
  //      function references a name defined in the outer scope.
  //      Without closure-capture support (Phase C2) the inner
  //      reference produces a GetGlobal opaque, but the function
  //      IS hoisted into module.functions and we can look it up
  //      by name. This path is a stop-gap until C2 lands; once
  //      captures are tracked, the inner reference produces a
  //      proper Closure and this branch becomes unnecessary.
  let calleeFn = null;
  if (callee && callee.kind === D.V.CLOSURE && callee.functionId) {
    calleeFn = ctx.module.functions.find(f => f.id === callee.functionId);
  } else if (callee && callee.kind === D.V.OPAQUE && instr.calleeName) {
    calleeFn = ctx.module.functions.find(f => f.name === instr.calleeName);
  } else if ((!callee || callee.kind === D.V.BOTTOM) && instr.calleeName) {
    // Hoisted-forward-reference case: `f(); function f(){}` —
    // the call site runs before the Func instruction has
    // executed in the worklist, so state.regs[callee] is
    // undefined. Look up the function by name directly so
    // JS's hoisted-function-visibility semantics are
    // preserved. (Closure captures won't be populated on this
    // path since the Func instr hasn't run yet, but hoisted
    // functions declared in the same enclosing function can
    // still see the enclosing var inits through the usual
    // identifier-to-register path at body-lowering time.)
    calleeFn = ctx.module.functions.find(f => f.name === instr.calleeName);
  }
  if (calleeFn && calleeFn.cfg) {
    // Note: D7 recursion guard is a state-level check using
    // `D.callStackContains(state, frame)` — it runs AFTER the
    // args fingerprint is computed below, so a call with the
    // same (body, argsFp) already on the callStack returns
    // opaque while different argsFps for the same body proceed.
    // Build the callee's initial state. Bind each param
    // register to the corresponding caller-side argValue. We
    // also share the caller's heap so any ObjectRef passed as
    // an argument can be dereferenced by the callee's transfer
    // functions — without this, `function f({a}) { ... }` can't
    // read the destructured field because the ObjectRef's
    // heap cell lives in the caller's state.
    //
    // Spread args: if instr.spreadAt is set (indices of spread
    // positions in instr.args), the corresponding argValues
    // are "spread sources" whose elements are expanded into
    // the positional arg sequence. We expand them against the
    // current heap so the callee sees a flat arg list.
    //
    // Rest params: if calleeFn.restParamIndex is set, the
    // remaining args beyond that index are collected into a
    // fresh Array ObjectRef which is bound to the rest param
    // register. applyCall allocates the array + writes the
    // collected args as integer-keyed fields.
    //
    // Sharing the heap overlay is sound: the callee may mutate
    // cells the caller can see, which is the JS semantics.
    // Precise points-to analysis (Phase C3) would clone the
    // heap into a fresh overlay and reconcile writes back to
    // the caller.
    //
    // Captures: the Closure value's `captures` array stores
    // the values captured at definition time; they need to
    // be bound to the function's capture registers (Phase C2
    // — for now closures capture nothing, so this is a
    // no-op).
    const effectiveArgs = expandSpreadArgs(state, argValues, instr.spreadAt, loc);
    let calleeInit = D.createStateSharingHeap(state);
    // Interprocedural path-sensitivity (Phase D / Wave 11):
    // seed the callee's initial `path` with the caller's
    // current `path`. As the callee branches, every split
    // refines this by conjoining the local branch formula, so
    // any sink fired anywhere inside the callee carries the
    // FULL path from the outermost function entry down to the
    // sink — including all caller-side branches. Without this
    // seeding, the callee analyses under an empty `path` and
    // the Z3 refutation layer cannot use caller-side
    // constraints to prove infeasibility.
    const callerPath = ctx.currentPath || null;
    if (callerPath) {
      calleeInit = D.withPath(calleeInit, callerPath);
    }
    // Closure captures: bind each captured register in the
    // callee's init state. We prefer the caller's CURRENT
    // state over the applyFunc-time snapshot:
    //
    //   * If the caller's state has a value for the capture's
    //     outerReg, use it. This gives correct semantics when
    //     the outer variable was reassigned between closure
    //     creation and the current call (the closure sees the
    //     latest value, matching JS live-environment
    //     semantics).
    //
    //   * Otherwise, fall back to the applyFunc-time snapshot.
    //     This is what ESCAPED closures need: the closure was
    //     returned from an outer function whose state is no
    //     longer available, so the snapshot is the only record
    //     of the captured value.
    //
    // The fixup pass at IR build time ensures outerReg is
    // the register the declaring function bound LAST for the
    // name — so when we check caller state, we check the
    // latest register.
    const closureCaptures = (callee && callee.captures) || [];
    for (const c of closureCaptures) {
      if (!c || c.innerReg == null) continue;
      let val = null;
      // Prefer the live caller-state value if the register is
      // actually bound there (not Bottom). getReg returns a
      // Bottom value for unassigned registers; we detect that
      // and fall back to the applyFunc-time snapshot. This
      // handles both the "closure sees mutation" case (where
      // the caller IS the defining function and the reg is
      // bound to the latest value) and the "escaped closure"
      // case (where the caller is a different function whose
      // state doesn't have the defining function's reg at
      // all — Bottom — so we use the snapshot captured at
      // closure-creation time).
      if (c.outerReg != null) {
        const live = D.getReg(state, c.outerReg);
        if (live && live.kind !== D.V.BOTTOM) val = live;
      }
      if (!val && c.value && c.value.kind !== D.V.BOTTOM) val = c.value;
      if (val) {
        calleeInit = D.setReg(calleeInit, c.innerReg, val);
      }
    }
    const restIdx = calleeFn.restParamIndex != null ? calleeFn.restParamIndex : -1;
    const normalParamCount = restIdx >= 0 ? restIdx : calleeFn.params.length;
    for (let i = 0; i < normalParamCount && i < calleeFn.params.length; i++) {
      const paramReg = calleeFn.params[i];
      const argValue = effectiveArgs[i] || D.concrete(undefined, undefined, loc);
      calleeInit = D.setReg(calleeInit, paramReg, argValue);
    }
    if (restIdx >= 0 && restIdx < calleeFn.params.length) {
      // Collect the remaining args into a fresh Array object.
      const restParamReg = calleeFn.params[restIdx];
      const tailArgs = effectiveArgs.slice(restIdx);
      const restObj = allocRestArray(ctx, tailArgs, loc);
      calleeInit = writeHeapCell(calleeInit, restObj.objId, restObj.cell);
      calleeInit = D.setReg(calleeInit, restParamReg, restObj.ref);
    }

    // --- D7: k-CFA summary cache + (body, args) recursion guard ---
    //
    // Recursion detection: per D7, a call with the same body
    // AND same arg fingerprint already on the callStack returns
    // opaque. Different arg fingerprints for the same body
    // proceed — they represent distinct call contexts. The
    // callStack is threaded through every state (not a ctx-
    // level side channel), so the check is local to the
    // caller's variant and two variants with different
    // callStacks decide independently.
    const argsFingerprint = buildArgsFingerprint(calleeFn, calleeInit, closureCaptures, thisValue);
    const recursionFrame = { funcId: calleeFn.id, argsFp: argsFingerprint };
    if (D.callStackContains(state, recursionFrame)) {
      // Recursion fallback. Raise an unimplemented assumption
      // so the precision floor is auditable and conservatively
      // union the argument labels into the return value.
      const a = ctx.assumptions.raise(
        REASONS.UNIMPLEMENTED,
        'recursive call to `' + (calleeFn.name || calleeFn.id) +
          '` with the same argument fingerprint already on the call stack — return value conservatively inherits all argument labels',
        loc
      );
      let recLabels = D.EMPTY_LABELS;
      const recChain = [a.id];
      for (const arg of argValues) {
        if (arg && arg.labels && arg.labels.size > 0) {
          if (recLabels.size === 0) {
            recLabels = arg.labels;
          } else if (recLabels !== arg.labels) {
            const merged = new Set(recLabels);
            for (const l of arg.labels) merged.add(l);
            recLabels = Object.freeze(merged);
          }
        }
        if (arg && arg.assumptionIds) {
          for (const id of arg.assumptionIds) recChain.push(id);
        }
      }
      return D.setReg(state, instr.dest,
        D.opaque(recChain, null, loc, recLabels));
    }

    // --- C3 (D7): state-correlated function summary cache ---
    //
    // Key shape per D7: `(body range, argument fingerprint,
    // this fingerprint)`. Two calls with the same (body, argsFp,
    // thisFp) share a summary regardless of where they're
    // called from; the entry value is { exitState }. The
    // callerPath seeding is NOT part of the key — the callee
    // analyses the same way structurally regardless of caller
    // context, and per-caller pathFormula propagation is
    // handled by the worklist's Layer 5 cascade running during
    // this walk, not by re-walking per caller.
    //
    // Cache lives on calleeFn (body-local) so repeated calls
    // across analyze() invocations on the same module share
    // summaries without ctx-level bookkeeping.
    // Summary cache: the `accept` set decides whether we use
    // it. A consumer that rejects `summary-reused` gets full
    // context sensitivity — every call walks the callee body
    // fresh regardless of argument fingerprint. Otherwise the
    // cache is consulted; a hit raises SUMMARY_REUSED so the
    // consumer can audit where shortcuts fired.
    const cacheAllowed = ctx.accept == null ||
      ctx.accept.has(REASONS.SUMMARY_REUSED);
    if (!calleeFn._summaryCache) calleeFn._summaryCache = new Map();
    const cacheKey = 'b=' + calleeFn.id + '|a=' + argsFingerprint;
    let calleeResult = cacheAllowed
      ? (calleeFn._summaryCache.get(cacheKey) || null)
      : null;
    let cacheHit = !!calleeResult;
    if (cacheHit) {
      ctx.assumptions.raise(
        REASONS.SUMMARY_REUSED,
        'call to `' + (calleeFn.name || calleeFn.id) + '` replayed from summary cache instead of walking fresh',
        loc
      );
    }

    // Push the current frame onto the callee's callStack so
    // nested recursive calls see it.
    calleeInit = D.pushCallStack(calleeInit, recursionFrame);

    // Save and restore worklist-level ctx fields so the
    // callee's analysis runs in its own scope.
    const savedPath = ctx.currentPath;
    const savedBlockId = ctx.currentBlockId;
    const savedThis = ctx._currentThisValue;
    if (!cacheHit) {
      if (thisValue) ctx._currentThisValue = thisValue;
      try {
        const analyse = getAnalyseFunction();
        calleeResult = await analyse(ctx.module, calleeFn, calleeInit, ctx);
      } finally {
        ctx.currentPath = savedPath;
        ctx.currentBlockId = savedBlockId;
        ctx._currentThisValue = savedThis;
      }
      if (cacheAllowed && calleeResult && calleeResult.exitState) {
        calleeFn._summaryCache.set(cacheKey, {
          exitState: calleeResult.exitState,
        });
      }
    }
    // Adopt the callee's heap writes so method-body side
    // effects on `this` are visible to the caller. We only
    // replace the heap if the callee actually wrote something
    // — if the callee's exit heap is an empty overlay whose
    // parent is the caller's original heap, there are no new
    // writes and we keep the caller's heap reference unchanged
    // (critical for the C3 cache: the next call with the same
    // inputs needs the same heap identity to hit the cache).
    if (calleeResult && calleeResult.exitState) {
      const calleeExitHeap = calleeResult.exitState.heap;
      if (!isEmptyOverlayOver(calleeExitHeap, state.heap)) {
        state = D.withHeap(state, calleeExitHeap);
      }
    }

    // Pull the return value from the callee's exit state.
    // `fn.returns` is the list of registers that flow into
    // explicit `return` statements; their values from the
    // exit state are joined to produce the call's result.
    // If the function has no explicit returns (only the
    // implicit `return undefined`), fn.returns may be empty
    // or contain the synthesized undef register — either way,
    // we fall back to `undefined`.
    let returnValue = null;
    if (calleeFn.returns && calleeFn.returns.length > 0 && calleeResult.exitState) {
      for (const retReg of calleeFn.returns) {
        const v = D.getReg(calleeResult.exitState, retReg);
        if (v) {
          returnValue = returnValue ? D.join(returnValue, v) : v;
        }
      }
    }
    if (!returnValue) {
      returnValue = D.concrete(undefined, undefined, loc);
    }
    return D.setReg(state, instr.dest, returnValue);
  }
  // --- TypeDB return-type resolution (G3) ---
  //
  // Before falling through to a typeless opaque, see if the
  // TypeDB can tell us the return type and source/label
  // semantics of this call. The IR attached `methodName` /
  // `calleeName` hints at lowering time; we use those to find
  // the descriptor and then `resolveReturnType` to compute the
  // return type (handling the dynamic `{ fromArg, map, default }`
  // form for createElement-style APIs).
  //
  // Three flow paths from the receiver and arguments:
  //
  //   1. The descriptor has `source: 'X'` — the return value
  //      itself is a labeled source (e.g. `decodeURIComponent`
  //      doesn't have this but `crypto.randomUUID` could).
  //      Raise the matching assumption and tag the return.
  //
  //   2. The descriptor has `preservesLabelsFromReceiver: true`
  //      — the return inherits all labels from the receiver
  //      (e.g. `String.prototype.slice` preserves taint).
  //
  //   3. The descriptor has `preservesLabelsFromArg: N` — the
  //      return inherits labels from a specific argument
  //      (e.g. `decodeURIComponent(arg0)` preserves arg0's
  //      labels).
  //
  // The default behaviour (no `preserves*` field) is to NOT
  // inherit argument or receiver labels. This is the standard
  // "function call narrows taint" semantics — pure functions
  // like `parseInt` don't propagate labels even though their
  // arg is tainted. The TypeDB's `sanitizer: true` flag (handled
  // in G5) makes this explicit.
  // Fan out TypeDB resolution across receiver variants. For a
  // Disjunct receiver, each variant has its own typeName and
  // may resolve to a different method descriptor (different
  // return type, different source label, different
  // preservesLabelsFrom* flags). The per-variant return values
  // are combined back into a Disjunct so the per-path type
  // information survives the call.
  let tdbResult = null;
  if (thisValue && thisValue.kind === D.V.DISJUNCT) {
    const perVariantResults = [];
    for (const thisVariant of thisValue.variants) {
      const r = resolveCallReturnViaDB(ctx, instr, thisVariant, argValues, loc);
      if (r) perVariantResults.push(r);
    }
    if (perVariantResults.length > 0) {
      tdbResult = perVariantResults.length === 1
        ? perVariantResults[0]
        : D.disjunct(perVariantResults, loc);
    }
  } else {
    tdbResult = resolveCallReturnViaDB(ctx, instr, thisValue, argValues, loc);
  }
  if (tdbResult) {
    return D.setReg(state, instr.dest, tdbResult);
  }
  // Fallback: truly unresolved callee. We don't know what the
  // function does, so the conservative SOUND behavior is to
  // assume any argument's labels could flow to the return
  // value AND any argument's assumption chain could carry
  // forward. A user function that wraps a tainted input and
  // returns it would otherwise silently launder the taint —
  // which is the opposite of sound.
  //
  // This is over-approximation: pure functions (which most
  // wrappers AREN'T) get reported with spurious labels. The
  // fix is interprocedural analysis (Phase C): once we walk
  // the callee's body and compute its actual return-label
  // semantics, the over-approximation is replaced with the
  // true answer.
  //
  // The receiver's labels (this) are also carried over since
  // method calls on a tainted receiver can produce a tainted
  // result through any path the method takes.
  let conservativeLabels = D.EMPTY_LABELS;
  const conservativeChain = [];
  if (thisValue && thisValue.labels && thisValue.labels.size > 0) {
    conservativeLabels = thisValue.labels;
    if (thisValue.assumptionIds) {
      for (const id of thisValue.assumptionIds) conservativeChain.push(id);
    }
  }
  for (const arg of argValues) {
    if (arg && arg.labels && arg.labels.size > 0) {
      if (conservativeLabels.size === 0) {
        conservativeLabels = arg.labels;
      } else if (conservativeLabels !== arg.labels) {
        const merged = new Set(conservativeLabels);
        for (const l of arg.labels) merged.add(l);
        conservativeLabels = Object.freeze(merged);
      }
    }
    if (arg && arg.assumptionIds) {
      for (const id of arg.assumptionIds) conservativeChain.push(id);
    }
  }
  const a = ctx.assumptions.raise(
    REASONS.OPAQUE_CALL,
    'call to unresolved or unanalysed callee — return value conservatively inherits all argument labels',
    loc,
    { chain: conservativeChain.length > 0 ? conservativeChain : undefined }
  );
  conservativeChain.push(a.id);
  return D.setReg(state, instr.dest,
    D.opaque(conservativeChain, null, loc, conservativeLabels));
}

// --- Resolve a call's return value via the TypeDB ------------------------
//
// Returns a Value (the typed return) or null if the callee
// cannot be resolved. The Value is an Opaque tagged with the
// return type name and any propagated labels.
function resolveCallReturnViaDB(ctx, instr, thisValue, argValues, loc) {
  const db = ctx.typeDB;
  if (!db) return null;

  // Resolve the descriptor — same logic as the sink classifier.
  let desc = null;
  if (instr.methodName && thisValue && thisValue.typeName) {
    desc = TDB.lookupMethod(db, thisValue.typeName, instr.methodName);
  } else if (instr.calleeName && db.roots && db.roots[instr.calleeName]) {
    const rootType = db.roots[instr.calleeName];
    const typeDesc = db.types[rootType];
    desc = typeDesc && (typeDesc.call || typeDesc.construct);
  }
  if (!desc) return null;

  // Compute the return type. Concrete-string args feed
  // dynamic `fromArg` mappings so `createElement('iframe')`
  // returns `HTMLIFrameElement` not the default `HTMLElement`.
  const argStrings = argValues.map(v => {
    if (v && v.kind === D.V.CONCRETE && typeof v.value === 'string') return v.value;
    return null;
  });
  const returnType = TDB.resolveReturnType(desc, argStrings);

  // Compute the labels that propagate to the return value.
  // Default: no propagation (function call narrows taint).
  // `preservesLabelsFromReceiver: true` inherits the receiver's
  // labels. `preservesLabelsFromArg: N` inherits arg N's labels.
  // A descriptor `source: 'X'` adds X to the return labels and
  // raises the corresponding assumption.
  let resultLabels = D.EMPTY_LABELS;
  const chainIds = [];
  if (desc.preservesLabelsFromReceiver === true && thisValue && thisValue.labels) {
    if (thisValue.labels.size > 0) resultLabels = thisValue.labels;
    if (thisValue.assumptionIds) {
      for (const id of thisValue.assumptionIds) chainIds.push(id);
    }
  }
  if (typeof desc.preservesLabelsFromArg === 'number') {
    const arg = argValues[desc.preservesLabelsFromArg];
    if (arg && arg.labels && arg.labels.size > 0) {
      if (resultLabels.size === 0) {
        resultLabels = arg.labels;
      } else {
        const merged = new Set(resultLabels);
        for (const l of arg.labels) merged.add(l);
        resultLabels = Object.freeze(merged);
      }
    }
    if (arg && arg.assumptionIds) {
      for (const id of arg.assumptionIds) chainIds.push(id);
    }
  }
  if (desc.source) {
    const reason = sourceLabelToReason(desc.source);
    const callName = instr.methodName || instr.calleeName || '<call>';
    const assumption = ctx.assumptions.raise(
      reason,
      'call result of `' + callName + '` carries source label `' + desc.source + '`',
      loc,
      { chain: chainIds.length > 0 ? chainIds : undefined }
    );
    chainIds.push(assumption.id);
    if (resultLabels.size === 0) {
      resultLabels = Object.freeze(new Set([desc.source]));
    } else {
      const merged = new Set(resultLabels);
      merged.add(desc.source);
      resultLabels = Object.freeze(merged);
    }
  }

  return D.opaque(chainIds, returnType, loc, resultLabels);
}

// --- Sink classification for call sites ----------------------------------
//
// Resolve a call to a TypeDB sink descriptor using the IR's
// `methodName` / `calleeName` hints, then emit a TaintFlow for
// each argument whose sink position carries taint.
//
// Two paths:
//
//   1. `obj.method(args)` — `instr.methodName` is set and
//      `thisValue.typeName` names the receiver type. Look up
//      the method on that type. The method descriptor may
//      declare a call-level `sink` (e.g. `document.write` is
//      an html sink on all args) or per-arg sinks (e.g.
//      `setAttribute(name, value)` is a conditional sink
//      based on the name arg — not yet implemented here).
//
//   2. `fn(args)` — `instr.calleeName` is set and names a
//      global. Resolve through `db.roots[calleeName]` then
//      check `.call.sink` / `.call.args[i].sink` on the
//      resulting type (e.g. `eval(x)` → `GlobalEval.call`).
//
// Taint is checked per argument: an argument carrying labels
// reaching a sink position produces one TaintFlow. A single
// call can emit multiple flows if multiple arguments are
// tainted.
function maybeEmitSinkFlowForCall(ctx, instr, thisValue, argValues, loc) {
  const db = ctx.typeDB;
  if (!db) return;

  // Resolve the method / call descriptor.
  let desc = null;
  let sinkProp = null;
  if (instr.methodName && thisValue && thisValue.typeName) {
    desc = TDB.lookupMethod(db, thisValue.typeName, instr.methodName);
    sinkProp = instr.methodName;
  } else if (instr.calleeName && db.roots && db.roots[instr.calleeName]) {
    const rootType = db.roots[instr.calleeName];
    const typeDesc = db.types[rootType];
    desc = typeDesc && (typeDesc.call || typeDesc.construct);
    sinkProp = instr.calleeName;
  }
  if (!desc) return;

  // Method-level / call-level sink: every argument contributes
  // to the sink. Report once per tainted argument.
  if (desc.sink) {
    const severity = desc.severity || TDB.defaultSinkSeverity(desc.sink);
    if (severity !== 'safe') {
      const sinkInfo = { type: desc.sink, severity, prop: sinkProp };
      for (const arg of argValues) {
        if (arg && arg.labels && arg.labels.size > 0) {
          emitTaintFlow(ctx, sinkInfo, loc, arg);
        }
      }
    }
  }
  // Per-argument sinks: check each descriptor's `args[i].sink`.
  if (desc.args && Array.isArray(desc.args)) {
    for (let i = 0; i < desc.args.length && i < argValues.length; i++) {
      const argDesc = desc.args[i];
      if (!argDesc || !argDesc.sink) continue;
      const severity = argDesc.severity || TDB.defaultSinkSeverity(argDesc.sink);
      if (severity === 'safe') continue;
      const arg = argValues[i];
      if (!arg || !arg.labels || arg.labels.size === 0) continue;
      const sinkInfo = {
        type: argDesc.sink,
        severity,
        prop: sinkProp + '.arg' + i,
      };
      emitTaintFlow(ctx, sinkInfo, loc, arg);
    }
  }
}

async function applyNew(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  let ctorValue = D.getReg(state, instr.ctor);
  const argValues = instr.args.map(r => D.getReg(state, r));

  // Wave 12b: record every `new X(...)` as a call site too.
  // Consumers (fetch-trace, csp-derive) filter trace.calls
  // by callee name — `new WebSocket(...)`, `new Function(...)`,
  // etc. need to appear there alongside plain calls.
  // Synthesize a minimal instr shape so recordCallSite
  // produces a consistent record: the ctor's name goes into
  // `calleeName` (matching the legacy engine's flat-callable
  // view).
  const newInstr = {
    calleeName: instr.calleeName || null,
    methodName: null,
    thisArg: null,
    args: instr.args,
    spreadAt: instr.spreadAt,
  };
  recordCallSite(ctx, newInstr, ctorValue, null, argValues, loc);
  recordStringLiteralArgs(ctx, newInstr, ctorValue, null, argValues, loc);

  // Class objects: when a class is lowered via ClassDeclaration,
  // the class name is bound to a heap-allocated object with a
  // `__ctor__` field pointing at the real constructor closure.
  // If extends is present, the class object also has a
  // `__parent__` field pointing at the parent class object.
  //
  // When the ctor value is a class ObjectRef, we collect the
  // ctor chain by walking __parent__ from root to leaf so the
  // parent's constructor body runs before the child's (matching
  // JS's `super()` semantics: the parent initialises its
  // instance fields first, then the child overrides/adds its
  // own).
  let classTypeName = null;
  let ctorChain = null;      // ordered root-first
  if (ctorValue && ctorValue.kind === D.V.OBJECT) {
    const cell = D.overlayGet(state.heap, ctorValue.objId);
    if (cell && cell.fields && cell.fields.__ctor__) {
      if (ctorValue.typeName && ctorValue.typeName.startsWith('class:')) {
        classTypeName = ctorValue.typeName.slice('class:'.length);
      }
      ctorChain = [];
      // Walk down from the leaf class collecting ctors; we
      // unshift to build a root-first list so applyNew walks
      // parents first.
      let cur = ctorValue;
      const seen = new Set();
      while (cur && cur.kind === D.V.OBJECT && !seen.has(cur.objId)) {
        seen.add(cur.objId);
        const c = D.overlayGet(state.heap, cur.objId);
        if (!c || !c.fields || !c.fields.__ctor__) break;
        ctorChain.unshift(c.fields.__ctor__);
        cur = c.fields.__parent__ || null;
      }
      ctorValue = cell.fields.__ctor__;
    }
  }

  // Allocate a fresh object that will be the `this` inside the
  // constructor body. The object's typeName is either the class
  // name recovered above, or the ctor's own typeName (function
  // name / calleeName hint) so instance property reads and sink
  // classification can use the TypeDB to walk the prototype
  // chain.
  const typeName = classTypeName || ctorTypeName(ctx, ctorValue, instr);
  const objId = nextObjId(ctx);
  const thisRef = D.objectRef(objId, typeName, loc);
  // Initialise an empty heap cell for the new object so
  // constructor-body SetProps land somewhere.
  let newState = initHeapCell(state, objId, typeName);

  // Resolve the ctor chain. For a non-extends class the chain
  // contains just the single ctor closure. For `Child extends
  // Parent extends Grandparent`, the chain is [Grandparent,
  // Parent, Child] (root-first) so their constructor bodies
  // run in inheritance order with `this` bound to the same
  // new object.
  const chainFns = [];
  if (ctorChain) {
    for (const cv of ctorChain) {
      let fn = null;
      if (cv && cv.kind === D.V.CLOSURE && cv.functionId) {
        fn = ctx.module.functions.find(f => f.id === cv.functionId);
      }
      if (fn && fn.cfg) chainFns.push(fn);
    }
  } else {
    // Non-class ctor (regular `new Foo(args)` where Foo is a
    // plain function). Fall back to the single-function path.
    let calleeFn = null;
    if (ctorValue && ctorValue.kind === D.V.CLOSURE && ctorValue.functionId) {
      calleeFn = ctx.module.functions.find(f => f.id === ctorValue.functionId);
    } else if (ctorValue && ctorValue.kind === D.V.OPAQUE && instr.calleeName) {
      calleeFn = ctx.module.functions.find(f => f.name === instr.calleeName);
    }
    if (calleeFn && calleeFn.cfg) chainFns.push(calleeFn);
  }
  // Walk every ctor in the chain, root first. Each ctor sees
  // the same `this` and (for simplicity) the same args — real
  // JS would forward only what the child explicitly passes to
  // super(args), but our Super support is coarse so we pass
  // all args to every ctor. Overrides: a child ctor's SetProp
  // on the same field replaces the parent's value.
  for (const fn of chainFns) {
    // D7 recursion guard at the state-level: skip ctor walks
    // already on this state's callStack with the same argsFp.
    const ctorArgsFp = buildArgsFingerprint(fn, newState, fn.captures || [], thisRef);
    const ctorFrame = { funcId: fn.id, argsFp: ctorArgsFp };
    if (D.callStackContains(newState, ctorFrame)) continue;
    let calleeInit = D.createStateSharingHeap(newState);
    // Closure captures: bind each captured register in the
    // callee's state to the outer register's current value in
    // the caller's state (which is `state` here — the outer
    // function invoking `new`).
    if (fn.captures && fn.captures.length > 0) {
      for (const cap of fn.captures) {
        const outerVal = D.getReg(state, cap.outerReg);
        if (outerVal) {
          calleeInit = D.setReg(calleeInit, cap.innerReg, outerVal);
        }
      }
    }
    for (let i = 0; i < fn.params.length; i++) {
      const paramReg = fn.params[i];
      const argValue = argValues[i] || D.concrete(undefined, undefined, loc);
      calleeInit = D.setReg(calleeInit, paramReg, argValue);
    }
    // Seed the ctor's initial path from the caller's current
    // path so interprocedural refutations apply inside
    // constructors too.
    const ctorCallerPath = ctx.currentPath || null;
    if (ctorCallerPath) calleeInit = D.withPath(calleeInit, ctorCallerPath);
    // Push this ctor's frame onto the callStack so any nested
    // `new` or user call inside the body can see the chain.
    calleeInit = D.pushCallStack(calleeInit, ctorFrame);

    const savedPath = ctx.currentPath;
    const savedBlockId = ctx.currentBlockId;
    const savedThis = ctx._currentThisValue;
    ctx._currentThisValue = thisRef;
    let calleeResult;
    try {
      const analyse = getAnalyseFunction();
      calleeResult = await analyse(ctx.module, fn, calleeInit, ctx);
    } finally {
      ctx.currentPath = savedPath;
      ctx.currentBlockId = savedBlockId;
      ctx._currentThisValue = savedThis;
    }
    // Adopt the callee's heap so the caller sees each ctor's
    // SetProps on `this`. Subsequent ctors in the chain run
    // against this updated state.
    if (calleeResult && calleeResult.exitState) {
      newState = D.withHeap(newState, calleeResult.exitState.heap);
    }
  }
  return D.setReg(newState, instr.dest, thisRef);
}

// expandSpreadArgs — expand SpreadElement positions in a call's
// argument list into positional arguments. `spreadAt` is a
// (possibly undefined) array of indices whose corresponding
// entries in `argValues` should be spread. The spread source
// is read as an array-shaped ObjectRef: we pull out the
// integer-keyed fields up to the length, and any missing ones
// fall through as undefined.
//
// When the spread source isn't a known ObjectRef (it's an
// opaque, a disjunct, or not an array shape), we append a
// single "opaque remainder" value marked with the source's
// labels — sound but imprecise about the arity.
function expandSpreadArgs(state, argValues, spreadAt, loc) {
  if (!spreadAt || spreadAt.length === 0) return argValues;
  const out = [];
  const spreadSet = new Set(spreadAt);
  for (let i = 0; i < argValues.length; i++) {
    if (!spreadSet.has(i)) {
      out.push(argValues[i]);
      continue;
    }
    const src = argValues[i];
    if (src && src.kind === D.V.OBJECT) {
      const cell = D.overlayGet(state.heap, src.objId);
      if (cell && cell.fields) {
        const lengthVal = cell.fields.length;
        let length = 0;
        if (lengthVal && lengthVal.kind === D.V.CONCRETE &&
            typeof lengthVal.value === 'number') {
          length = lengthVal.value;
        } else {
          // Unknown length — enumerate integer-keyed fields.
          for (const k of Object.keys(cell.fields)) {
            if (/^\d+$/.test(k)) {
              const n = parseInt(k, 10) + 1;
              if (n > length) length = n;
            }
          }
        }
        for (let j = 0; j < length; j++) {
          const elem = cell.fields[String(j)];
          out.push(elem || D.concrete(undefined, undefined, loc));
        }
        continue;
      }
    }
    // Unknown spread source — conservatively propagate its
    // labels into the return via a single remainder Opaque.
    // The callee may or may not reference the spread portion;
    // we attach the source's labels so taint flows through.
    const lbls = (src && src.labels) || D.EMPTY_LABELS;
    out.push(D.opaque([], null, loc, lbls));
  }
  return out;
}

// allocRestArray — create a fresh Array-shaped heap cell holding
// `values` as its integer-keyed fields and a Concrete `length`.
// Returns { objId, cell, ref } so the caller can both write the
// cell and bind the ObjectRef to the rest param register.
function allocRestArray(ctx, values, loc) {
  const objId = nextObjId(ctx);
  const fields = Object.create(null);
  for (let i = 0; i < values.length; i++) {
    fields[String(i)] = values[i];
  }
  fields.length = D.concrete(values.length, 'number', loc);
  const cell = Object.freeze({
    kind: 'Array',
    fields: Object.freeze(fields),
    typeName: 'Array',
    origin: loc,
  });
  const ref = D.objectRef(objId, 'Array', loc);
  return { objId, cell, ref };
}

// writeHeapCell — write a complete cell for `objId` into the
// state's heap overlay. Used by applyCall / applyNew to install
// fresh alloc cells during pre-call state setup.
function writeHeapCell(state, objId, cell) {
  if (!state._frozen) {
    state.heap.own.set(objId, cell);
    return state;
  }
  const newHeap = { own: new Map([[objId, cell]]), parent: state.heap };
  return Object.freeze({
    regs: state.regs,
    heap: newHeap,
    path: state.path || null,
    effects: state.effects,
    assumptionIds: state.assumptionIds,
    callStack: state.callStack,
    _frozen: true,
  });
}

// initHeapCell — create an empty heap cell for a freshly
// allocated object. Used by applyNew before walking the
// constructor body so SetProp writes land in the cell.
function initHeapCell(state, objId, typeName) {
  const emptyCell = Object.freeze({
    kind: 'object',
    fields: Object.freeze(Object.create(null)),
    typeName: typeName || null,
    origin: null,
  });
  if (!state._frozen) {
    state.heap.own.set(objId, emptyCell);
    return state;
  }
  const newHeap = { own: new Map([[objId, emptyCell]]), parent: state.heap };
  return Object.freeze({
    regs: state.regs,
    heap: newHeap,
    path: state.path || null,
    effects: state.effects,
    assumptionIds: state.assumptionIds,
    callStack: state.callStack,
    _frozen: true,
  });
}

// Recover a TypeDB type name for a `new Ctor(args)` call. First
// try the IR's `calleeName` hint (bare-identifier ctors like
// `new Foo(...)`). Fall back to the ctor value's typeName.
function ctorTypeName(ctx, ctorValue, instr) {
  if (instr.calleeName) return instr.calleeName;
  if (ctorValue && ctorValue.typeName) return ctorValue.typeName;
  return null;
}

function applyCast(ctx, state, instr) {
  // Cast just re-tags the source register's value with a new type
  // for branch refinement purposes. In the minimal slice it's a
  // no-op; the refiner will fill this in.
  const src = D.getReg(state, instr.source);
  return D.setReg(state, instr.dest, src);
}

function applyOpaqueInstr(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const a = ctx.assumptions.raise(
    instr.reason || REASONS.UNIMPLEMENTED,
    instr.details || 'opaque value introduced by IR builder',
    loc,
    { affects: instr.affects }
  );
  return D.setReg(state, instr.dest, D.opaque([a.id], null, loc));
}

// --- Object id allocator ------------------------------------------------

function nextObjId(ctx) {
  ctx.nextObjId = (ctx.nextObjId || 0) + 1;
  return 'O' + ctx.nextObjId;
}

module.exports = {
  applyInstruction,
  computeBinOp,
  evalJsBinOp,
};
