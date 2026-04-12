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
  // Both concrete → fold directly.
  if (a && a.kind === D.V.CONCRETE && b && b.kind === D.V.CONCRETE) {
    try {
      const folded = evalJsBinOp(op, a.value, b.value);
      if (folded !== undefined) {
        return D.concrete(folded, undefined, loc);
      }
    } catch (_) {
      // Fall through to type-level join.
    }
  }
  // Both OneOf → compute pairwise Cartesian product (bounded by small sizes).
  if (a && a.kind === D.V.ONE_OF && b && b.kind === D.V.ONE_OF
      && a.values.length * b.values.length <= 64) {
    const results = [];
    for (const va of a.values) {
      for (const vb of b.values) {
        try {
          const r = evalJsBinOp(op, va, vb);
          if (r !== undefined) results.push(r);
        } catch (_) {}
      }
    }
    if (results.length > 0) {
      if (results.length === 1) return D.concrete(results[0], undefined, loc);
      return D.oneOf(results, undefined, loc);
    }
  }
  // Concrete × OneOf → broadcast.
  if (a && a.kind === D.V.CONCRETE && b && b.kind === D.V.ONE_OF && b.values.length <= 16) {
    const results = [];
    for (const vb of b.values) {
      try {
        const r = evalJsBinOp(op, a.value, vb);
        if (r !== undefined) results.push(r);
      } catch (_) {}
    }
    if (results.length > 0) {
      if (results.length === 1) return D.concrete(results[0], undefined, loc);
      return D.oneOf(results, undefined, loc);
    }
  }
  if (b && b.kind === D.V.CONCRETE && a && a.kind === D.V.ONE_OF && a.values.length <= 16) {
    const results = [];
    for (const va of a.values) {
      try {
        const r = evalJsBinOp(op, va, b.value);
        if (r !== undefined) results.push(r);
      } catch (_) {}
    }
    if (results.length > 0) {
      if (results.length === 1) return D.concrete(results[0], undefined, loc);
      return D.oneOf(results, undefined, loc);
    }
  }
  // Opaque propagates.
  if (a && a.kind === D.V.OPAQUE) return D.opaque(a.assumptionIds, null, loc);
  if (b && b.kind === D.V.OPAQUE) return D.opaque(b.assumptionIds, null, loc);
  // Give up → top. We don't raise an assumption here because the
  // result is a join of the known domains, not a loss of information.
  return D.top(loc);
}

// Evaluate a JavaScript binary op on two concrete primitive values.
// Returns undefined if the op isn't handled or the evaluation would
// throw. Never raises — the caller falls back to top.
function evalJsBinOp(op, a, b) {
  switch (op) {
    case '+': return a + b;
    case '-': return a - b;
    case '*': return a * b;
    case '/': return a / b;
    case '%': return a % b;
    case '**': return a ** b;
    case '==': return a == b;   // eslint-disable-line eqeqeq
    case '!=': return a != b;   // eslint-disable-line eqeqeq
    case '===': return a === b;
    case '!==': return a !== b;
    case '<': return a < b;
    case '<=': return a <= b;
    case '>': return a > b;
    case '>=': return a >= b;
    case '&': return (a & b) | 0;
    case '|': return (a | b) | 0;
    case '^': return (a ^ b) | 0;
    case '<<': return a << b;
    case '>>': return a >> b;
    case '>>>': return a >>> b;
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
// Unresolved identifier read. Treated as opaque with the appropriate
// assumption reason. When a TypeDB is attached later, global reads
// will resolve through the TypeDB roots.

function applyGetGlobal(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const db = ctx.typeDB;
  if (db && db.roots && db.roots[instr.name]) {
    // Resolve via TypeDB: create an opaque value typed to the root's
    // declared type. Values are taint-labeled by subsequent property
    // reads (not yet implemented in this minimal slice).
    return D.setReg(state, instr.dest,
      D.top(loc));  // placeholder; a later pass attaches typeName
  }
  // Truly unknown — this is an opaque read.
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
    return D.setReg(state, instr.dest, D.opaque(obj.assumptionIds, null, loc));
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
  const a = ctx.assumptions.raise(
    REASONS.RUNTIME_TYPE,
    'computed index access with unresolved target or key',
    loc
  );
  return D.setReg(state, instr.dest, D.opaque([a.id], null, loc));
}

// --- SetProp / SetIndex -------------------------------------------------

function applySetProp(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const obj = D.getReg(state, instr.object);
  const val = D.getReg(state, instr.value);
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

function applySetIndex(ctx, state, instr) {
  const loc = instrLoc(ctx, instr);
  const obj = D.getReg(state, instr.object);
  const key = D.getReg(state, instr.key);
  const val = D.getReg(state, instr.value);
  if (obj && obj.kind === D.V.OBJECT && key && key.kind === D.V.CONCRETE) {
    return writeHeapField(state, obj.objId, String(key.value), val);
  }
  ctx.assumptions.raise(
    REASONS.RUNTIME_TYPE,
    'computed index write with unresolved target or key',
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
  // In this minimal slice we don't actually walk the callee's body.
  // The worklist engine does that; this transfer function records
  // that the call happened and returns an opaque result for the
  // callee's return value unless it's a known pure builtin.
  //
  // The correct implementation invokes the worklist recursively
  // with the callee's CFG and propagates the summary back. That's
  // wired up in worklist.js when `onCall` is set; if not set, we
  // return opaque.
  if (ctx.onCall) {
    try {
      const result = ctx.onCall(callee, instr.args.map(r => D.getReg(state, r)),
        instr.thisArg ? D.getReg(state, instr.thisArg) : null,
        state, loc, instr);
      if (result) return D.setReg(result.state || state, instr.dest, result.value);
    } catch (_) {}
  }
  const a = ctx.assumptions.raise(
    REASONS.OPAQUE_CALL,
    'call to unresolved or unanalysed callee',
    loc
  );
  return D.setReg(state, instr.dest, D.opaque([a.id], null, loc));
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
