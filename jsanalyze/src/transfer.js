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
// The current implementation does NOT yet record path
// conditions or SMT formulas — those land when path-sensitive
// analysis is wired up. The fields are left empty arrays so the
// Trace schema stays stable.
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
    pathConditions: [],  // populated when path-sensitive analysis lands
    pathFormulas: [],    // populated when SMT integration lands
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
  return D.setReg(state, instr.dest, D.concrete(instr.value, undefined, loc));
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

  // Both concrete → fold directly. The folded result inherits
  // the unioned labels even though the value is now a literal —
  // a tainted concat result is still tainted at the value level.
  if (a && a.kind === D.V.CONCRETE && b && b.kind === D.V.CONCRETE) {
    const folded = evalJsBinOp(op, a.value, b.value);
    if (folded !== undefined) {
      // If the labels are non-empty, return an Opaque value
      // tagged with the labels and the folded concrete in the
      // provenance — taint must dominate concreteness for
      // sink classification to work. Otherwise return the
      // straight concrete.
      if (labels && labels.size > 0) {
        return D.opaque(chainIds, undefined, loc, labels);
      }
      return D.concrete(folded, undefined, loc);
    }
  }
  // Both OneOf → compute the full pairwise cartesian product.
  // No size cap. For large OneOfs this produces a large result,
  // which is the precise answer.
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
        return D.opaque(chainIds, undefined, loc, labels);
      }
      if (results.length === 1) return D.concrete(results[0], undefined, loc);
      return D.oneOf(results, undefined, loc);
    }
  }
  // Concrete × OneOf → broadcast across every element.
  if (a && a.kind === D.V.CONCRETE && b && b.kind === D.V.ONE_OF) {
    const results = [];
    for (const vb of b.values) {
      const r = evalJsBinOp(op, a.value, vb);
      if (r !== undefined) results.push(r);
    }
    if (results.length > 0) {
      if (labels && labels.size > 0) {
        return D.opaque(chainIds, undefined, loc, labels);
      }
      if (results.length === 1) return D.concrete(results[0], undefined, loc);
      return D.oneOf(results, undefined, loc);
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
        return D.opaque(chainIds, undefined, loc, labels);
      }
      if (results.length === 1) return D.concrete(results[0], undefined, loc);
      return D.oneOf(results, undefined, loc);
    }
  }
  // Opaque on either side propagates with merged chain + labels.
  if (a && a.kind === D.V.OPAQUE) {
    return D.opaque(chainIds, null, loc, labels);
  }
  if (b && b.kind === D.V.OPAQUE) {
    return D.opaque(chainIds, null, loc, labels);
  }
  // Operands are of kinds we don't know how to combine for this
  // operator (e.g. Interval + StrPattern). Result is Top with
  // the merged labels.
  return D.top(loc, labels);
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
      return D.setReg(state, instr.dest,
        D.opaque([assumption.id], typeName, loc, [selfSource]));
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

function applyGetProp(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const obj = D.getReg(state, instr.object);
  if (!obj) {
    return D.setReg(state, instr.dest, D.top(loc));
  }
  if (obj.kind === D.V.OBJECT) {
    const cell = D.overlayGet(state.heap, obj.objId);
    if (cell && cell.fields[instr.propName]) {
      return D.setReg(state, instr.dest, cell.fields[instr.propName]);
    }
    // Property not set → undefined.
    return D.setReg(state, instr.dest, D.concrete(undefined, undefined, loc));
  }
  if (obj.kind === D.V.OPAQUE) {
    // Receiver has a TypeDB type — resolve the property through
    // the DB to produce a typed result. This is the main path
    // for source detection: `location.hash` arrives here with
    // `obj.typeName === 'Location'` and we look up `hash`
    // against the Location descriptor. A matching PropDescriptor
    // provides the result's type (via `readType`) and, if the
    // descriptor carries a `source`, the taint label + the
    // corresponding assumption reason.
    const db = ctx.typeDB;
    if (db && obj.typeName) {
      const desc = TDB.lookupProp(db, obj.typeName, instr.propName);
      if (desc) {
        const resultType = desc.readType || null;
        // Accumulate existing labels (from the parent chain
        // e.g. `window.location.hash` already has upstream) and
        // add the new source label.
        const existingLabels = obj.labels || D.EMPTY_LABELS;
        let resultLabels = existingLabels;
        const chainIds = obj.assumptionIds ? obj.assumptionIds.slice() : [];
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
        }
        return D.setReg(state, instr.dest,
          D.opaque(chainIds, resultType, loc, resultLabels));
      }
    }
    // No TypeDB info about this property — propagate the
    // receiver's opaqueness without adding new information.
    return D.setReg(state, instr.dest,
      D.opaque(obj.assumptionIds || [], null, loc, obj.labels));
  }
  // Reading a property off a primitive / top value — record an
  // unimplemented assumption (we should be modeling autoboxing but
  // aren't yet).
  const a = ctx.assumptions.raise(
    REASONS.UNIMPLEMENTED,
    'property access on non-object value not yet modeled',
    loc,
    { affects: instr.propName }
  );
  return D.setReg(state, instr.dest, D.opaque([a.id], null, loc));
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
  // Sink classification: before writing, check whether this
  // property on the receiver type is a known sink and whether
  // the value we're writing carries any taint labels. A match
  // emits a TaintFlow record.
  maybeEmitSinkFlowForWrite(ctx, obj, instr.propName, val, loc);
  if (obj && obj.kind === D.V.OBJECT) {
    return writeHeapField(state, obj.objId, instr.propName, val);
  }
  if (obj && obj.kind === D.V.OPAQUE) {
    // Write is lost — we don't know what object is being written.
    // This is a soundness assumption.
    ctx.assumptions.raise(
      REASONS.HEAP_ESCAPE,
      'property write on opaque object — mutation not tracked',
      loc,
      { affects: instr.propName, chain: obj.assumptionIds }
    );
    return state;
  }
  return state;
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
  // Before dispatching to the callee (whether via onCall hook
  // or falling through to opaque), check whether this call is
  // a known sink and whether any argument carries taint. The
  // IR attached two syntactic hints at lowering time:
  //
  //   instr.methodName — for `obj.method(args)` calls
  //   instr.calleeName — for bare-identifier `fn(args)` calls
  //
  // `maybeEmitSinkFlowForCall` uses those hints plus the
  // TypeDB to resolve the sink and emit flows for any
  // tainted arguments.
  maybeEmitSinkFlowForCall(ctx, instr, thisValue, argValues, loc);

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
  const tdbResult = resolveCallReturnViaDB(ctx, instr, thisValue, argValues, loc);
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
