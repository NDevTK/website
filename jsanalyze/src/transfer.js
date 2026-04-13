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
// block's accumulated path condition via `ctx.currentPathCond`.
// We attach BOTH the block-level pathCond AND the value's own
// formula (built up by computeBinOp / source reads) so a Phase D
// consumer has the full SMT context needed to refute the flow:
//
//   refutable iff
//     (pathCond ∧ valueFormula ∧ <sink-shape-predicate>) is unsat
//
// The `pathConditions` array is the legacy shape (a list of
// human-readable strings) and is left empty for now. The
// machine-readable formulas live on `pathFormula` (current
// block) and `valueFormula` (the value at the sink).
function emitTaintFlow(ctx, sinkInfo, sinkLoc, value) {
  if (!ctx.taintFlows) return;
  if (!value || !value.labels || value.labels.size === 0) return;
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
    pathFormula: ctx.currentPathCond || null,  // SMT formula for the block's reachability
    valueFormula: (value.formula) || null,     // SMT formula for the value at the sink
    assumptionIds: value.assumptionIds ? value.assumptionIds.slice() : [],
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
// Returns the updated State. `ctx` carries the module, assumption
// tracker, and heap-allocation counter.
function applyInstruction(ctx, state, instr) {
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
    case OP.CALL: return applyCall(ctx, state, instr);
    case OP.NEW: return applyNew(ctx, state, instr);
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

  // Opaque assumption ids propagate too — both operands' chains
  // are unioned so the consumer can audit "what assumptions does
  // this binary operation depend on".
  const aIds = (a && a.kind === D.V.OPAQUE) ? a.assumptionIds : [];
  const bIds = (b && b.kind === D.V.OPAQUE) ? b.assumptionIds : [];
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
  // `this` at the top level resolves to the module-level this
  // binding, which in script mode is the global. We don't model
  // the global yet, so this is opaque with an unimplemented mark.
  const a = ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    'this-binding resolution not yet modeled',
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

function applyGetIndex(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const obj = D.getReg(state, instr.object);
  const key = D.getReg(state, instr.key);
  if (obj && obj.kind === D.V.OBJECT && key && key.kind === D.V.CONCRETE) {
    const cell = D.overlayGet(state.heap, obj.objId);
    const keyStr = String(key.value);
    if (cell && cell.fields[keyStr]) {
      return D.setReg(state, instr.dest, cell.fields[keyStr]);
    }
    return D.setReg(state, instr.dest, D.concrete(undefined, undefined, loc));
  }
  if (obj && obj.kind === D.V.OPAQUE) {
    return D.setReg(state, instr.dest, D.opaque(obj.assumptionIds, null, loc));
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
  // Sink classification: iterate over every receiver variant so a
  // Disjunct of element types fires once per variant that has a
  // sink descriptor for this property name. This is the
  // per-path-type element case: if `el` is a Disjunct of anchor
  // and iframe, writing `.src` fires the iframe's navigation sink
  // but not the anchor (which has no `src`).
  for (const variant of D.disjunctVariants(obj)) {
    maybeEmitSinkFlowForWrite(ctx, variant, instr.propName, val, loc);
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
    pathConds: state.pathConds,
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
  const cell = Object.freeze({
    kind: instr.kind || 'object',
    fields: Object.freeze(fields),
    typeName: null,
    origin: loc,
  });
  if (!state._frozen) {
    state.heap.own.set(objId, cell);
    return D.setReg(state, instr.dest, D.objectRef(objId, instr.kind || null, loc));
  }
  const newHeap = { own: new Map([[objId, cell]]), parent: state.heap };
  const newState = Object.freeze({
    regs: state.regs,
    heap: newHeap,
    pathConds: state.pathConds,
    assumptionIds: state.assumptionIds,
    callStack: state.callStack,
    _frozen: true,
  });
  return D.setReg(newState, instr.dest, D.objectRef(objId, instr.kind || null, loc));
}

function applyFunc(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const captureValues = (instr.captures || []).map(r => D.getReg(state, r));
  return D.setReg(state, instr.dest,
    D.closure(instr.functionId, captureValues, loc));
}

function applyCall(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const callee = D.getReg(state, instr.callee);
  const argValues = instr.args.map(r => D.getReg(state, r));
  const thisValue = instr.thisArg ? D.getReg(state, instr.thisArg) : null;

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
  // Cycle detection: we maintain ctx._callStack as a Set of
  // function ids currently being analyzed. Re-entering a
  // function on its own stack = recursion, which we don't
  // model precisely yet — fall through to the conservative
  // fallback with an explicit `unimplemented: recursion`
  // assumption so consumers can see the precision floor.
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
  }
  if (calleeFn && calleeFn.cfg) {
    if (!ctx._callStack) ctx._callStack = new Set();
    if (ctx._callStack.has(calleeFn.id)) {
      // Recursion. Raise an explicit assumption so the
      // imprecision is auditable, and conservatively union the
      // argument labels into the return value — a recursive
      // function might return any of its arguments through any
      // depth of the recursion, so we have to assume it can.
      const a = ctx.assumptions.raise(
        REASONS.UNIMPLEMENTED,
        'recursive call to `' + (calleeFn.name || calleeFn.id) +
          '` not yet modeled — return value conservatively inherits all argument labels',
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
    // Build the callee's initial state. Bind each param
    // register to the corresponding caller-side argValue.
    // Captures: the Closure value's `captures` array stores
    // the values captured at definition time; they need to
    // be bound to the function's capture registers (Phase C2
    // — for now closures capture nothing, so this is a
    // no-op).
    let calleeInit = D.createState();
    for (let i = 0; i < calleeFn.params.length; i++) {
      const paramReg = calleeFn.params[i];
      const argValue = argValues[i] || D.concrete(undefined, undefined, loc);
      calleeInit = D.setReg(calleeInit, paramReg, argValue);
    }

    // Save and restore worklist-level ctx fields so the
    // callee's analysis runs in its own scope without
    // leaking into the caller's. The fields the caller's
    // worklist may have set:
    //   currentPathCond, currentBlockId
    const savedPathCond = ctx.currentPathCond;
    const savedBlockId = ctx.currentBlockId;
    ctx._callStack.add(calleeFn.id);
    let calleeResult;
    try {
      const analyse = getAnalyseFunction();
      calleeResult = analyse(ctx.module, calleeFn, calleeInit, ctx);
    } finally {
      ctx._callStack.delete(calleeFn.id);
      ctx.currentPathCond = savedPathCond;
      ctx.currentBlockId = savedBlockId;
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

function applyNew(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const a = ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    '`new` expression not yet modeled',
    loc
  );
  return D.setReg(state, instr.dest, D.opaque([a.id], null, loc));
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
