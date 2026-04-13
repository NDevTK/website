// domain.js — abstract domain: Value lattice, State, lattice operations
//
// Everything in this file is pure data + pure functions. No side effects
// beyond creating new immutable records. Every lattice operation is
// monotone: `join(a, b) ⊒ a` and `join(a, b) ⊒ b`.

'use strict';

// --- Value kinds ---------------------------------------------------------
//
// Closed enumeration. The worklist joins always produce one of these
// kinds; no ad-hoc representations leak into the public API.

const V = Object.freeze({
  BOTTOM:      'bottom',      // ⊥ — no value / unreachable
  CONCRETE:    'concrete',    // single primitive or ObjRef
  ONE_OF:      'oneOf',       // finite set of concretes
  INTERVAL:    'interval',    // numeric [lo, hi]
  STR_PATTERN: 'strPattern',  // string with prefix/suffix/contains refinements
  OBJECT:      'object',      // heap object reference
  CLOSURE:     'closure',     // function closure
  OPAQUE:      'opaque',      // unknown; records an assumption chain
  TOP:         'top',         // ⊤ — any value
});

// --- Value constructors -------------------------------------------------
//
// Every constructed Value is immediately frozen so downstream
// consumers cannot mutate lattice entries. Provenance is a list of
// source Locations where the value acquired its current shape.

// --- Taint labels ------------------------------------------------------
//
// Every value carries an optional frozen `labels` field — a
// read-only Set<string> of taint labels it's accumulated. Labels
// propagate through binary operations, property reads, and call
// results via simple set union; sanitizers clear them. The
// vocabulary is drawn from the TypeDB's `source` fields
// ('url', 'cookie', 'referrer', 'network', 'postMessage', ...)
// plus anything a consumer declares in a custom DB.
//
// Factories accept an optional `labels` argument. When omitted
// the value has no labels. The `withLabels(v, set)` helper
// returns a copy with a new label set attached.
//
// Why a Set<string> instead of an array: taint is unordered,
// and unioning sets is O(|a|+|b|) with no dedup pass.
const EMPTY_LABELS = Object.freeze(new Set());

function freezeLabels(labels) {
  if (!labels) return EMPTY_LABELS;
  if (labels === EMPTY_LABELS) return labels;
  if (labels instanceof Set) {
    if (labels.size === 0) return EMPTY_LABELS;
    // Freeze by wrapping in a new Set (Sets aren't freezable
    // but references can be; we rely on the caller not
    // mutating the returned Set — a convention enforced by
    // `withLabels` being the only mutation API).
    return Object.freeze(new Set(labels));
  }
  if (Array.isArray(labels)) {
    if (labels.length === 0) return EMPTY_LABELS;
    return Object.freeze(new Set(labels));
  }
  return EMPTY_LABELS;
}

function unionLabels(a, b) {
  const la = (a && a.labels) || EMPTY_LABELS;
  const lb = (b && b.labels) || EMPTY_LABELS;
  if (la.size === 0) return lb;
  if (lb.size === 0) return la;
  if (la === lb) return la;
  const out = new Set(la);
  for (const x of lb) out.add(x);
  return Object.freeze(out);
}

// Return a new value with `labels` added to its label set. Used
// by transfer functions when a read or call produces a tainted
// result.
function withLabels(value, labels) {
  if (!value || value.kind === V.BOTTOM) return value;
  const existing = value.labels || EMPTY_LABELS;
  const incoming = labels instanceof Set ? labels : new Set(labels || []);
  if (incoming.size === 0) return value;
  // Union in place is cheaper than rebuilding the set, but the
  // result must stay frozen. Allocate fresh.
  const out = new Set(existing);
  for (const x of incoming) out.add(x);
  const frozen = Object.freeze(out);
  // Clone the value with the new label set. We rebuild via the
  // appropriate factory so the frozen envelope is preserved.
  return cloneWithLabels(value, frozen);
}

// Clone a value's envelope with a new labels field. All factory-
// produced values are frozen; we can't mutate them, so we
// reconstruct via a shallow copy. This is only called from
// `withLabels` which has already computed the union.
function cloneWithLabels(value, labels) {
  const base = Object.assign({}, value);
  base.labels = labels;
  return Object.freeze(base);
}

// --- SMT formula attachment ---------------------------------------------
//
// Every Value can optionally carry a `formula` field — an SMT
// formula record (from src/smt.js) that represents the value
// symbolically. For pure concrete values this is the SMT-LIB
// literal; for opaque source reads it's a fresh symbolic
// variable; for binary-op results it's the symbolic combination
// of operand formulas.
//
// The formula is the bridge to Phase D's Z3 layer: when the
// engine asks "is this branch reachable", it conjoins the path
// condition (built from branch formulas) with the negation of
// the condition under test. Z3 returns sat/unsat/unknown.
//
// `withFormula(v, f)` returns a new frozen Value with the
// formula attached. The Value's lattice kind is preserved.
function withFormula(value, formula) {
  if (!value || value.kind === V.BOTTOM) return value;
  if (!formula) return value;
  const base = Object.assign({}, value);
  base.formula = formula;
  return Object.freeze(base);
}

// Read a Value's formula. Falls back to a const formula for
// concrete primitives so callers don't need to special-case.
// Returns null only when the value has no symbolic representation
// (e.g. opaque without an attached symbol, top, bottom).
function valueFormula(value) {
  if (!value) return null;
  if (value.formula) return value.formula;
  // No formula attached. The caller (smt.js) handles null
  // correctly — formulas built from null operands produce null.
  return null;
}

// --- Branch refinement --------------------------------------------------
//
// Given a value and a constraint of the form `value === literal`
// (or `!==`), return a refined value that's sound on the side
// of the branch where the constraint holds. This is the Layer
// 1-2 piece of branch sensitivity: values whose static lattice
// representation contradicts the test become Bottom, eliminating
// the false-positive flow.
//
// Rules:
//   refineEq(Concrete c, lit) →
//     c === lit ? Concrete(c) : Bottom
//   refineEq(OneOf vs, lit) →
//     lit ∈ vs ? Concrete(lit) : Bottom
//   refineEq(Opaque, lit) → Opaque (cannot refine the lattice;
//     the path-condition formula tracks the constraint instead)
//   refineEq(Top, lit) → Top
//   refineEq(Bottom, _) → Bottom
//
//   refineNeq(Concrete c, lit) →
//     c === lit ? Bottom : Concrete(c)
//   refineNeq(OneOf vs, lit) →
//     OneOf (vs - {lit}) — collapses to Concrete when one element remains,
//     Bottom when zero
//   refineNeq(Opaque, lit) → Opaque (no lattice change)
//   refineNeq(Top, lit) → Top
//
// Refinement preserves labels, formulas, and provenance — only the
// shape narrows.
function refineEq(value, literal) {
  if (!value) return value;
  if (value.kind === V.BOTTOM) return value;
  if (value.kind === V.CONCRETE) {
    return strictEq(value.value, literal) ? value : bottom();
  }
  if (value.kind === V.ONE_OF) {
    for (const v of value.values) {
      if (strictEq(v, literal)) {
        // Build a concrete with the same labels/provenance/formula.
        const c = concrete(literal, value.typeName, value.provenance, value.labels);
        return value.formula ? withFormula(c, value.formula) : c;
      }
    }
    return bottom();
  }
  // Opaque / Top / Object / Closure / Interval / StrPattern: leave alone.
  // The path condition (B3) carries the equality constraint at the
  // formula level for the SMT layer to consume.
  return value;
}

function refineNeq(value, literal) {
  if (!value) return value;
  if (value.kind === V.BOTTOM) return value;
  if (value.kind === V.CONCRETE) {
    return strictEq(value.value, literal) ? bottom() : value;
  }
  if (value.kind === V.ONE_OF) {
    const remaining = [];
    for (const v of value.values) {
      if (!strictEq(v, literal)) remaining.push(v);
    }
    if (remaining.length === 0) return bottom();
    if (remaining.length === 1) {
      const c = concrete(remaining[0], value.typeName, value.provenance, value.labels);
      return value.formula ? withFormula(c, value.formula) : c;
    }
    const o = oneOf(remaining, value.typeName, value.provenance, value.labels);
    return value.formula ? withFormula(o, value.formula) : o;
  }
  return value;
}

// JavaScript strict equality on lattice-extracted primitive
// values. Mirrors `===` semantics including NaN inequality.
function strictEq(a, b) {
  if (a === null && b === null) return true;
  if (a === undefined && b === undefined) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a === 'number') {
    if (Number.isNaN(a) || Number.isNaN(b)) return false;
    return a === b;
  }
  return a === b;
}

function bottom() {
  return Object.freeze({ kind: V.BOTTOM, labels: EMPTY_LABELS });
}

function top(provenance, labels) {
  return Object.freeze({
    kind: V.TOP,
    provenance: freezeProvenance(provenance),
    labels: freezeLabels(labels),
  });
}

function concrete(value, typeName, provenance, labels) {
  return Object.freeze({
    kind: V.CONCRETE,
    value,
    typeName: typeName || inferTypeName(value),
    provenance: freezeProvenance(provenance),
    labels: freezeLabels(labels),
  });
}

function oneOf(values, typeName, provenance, labels) {
  // Normalise: sort + dedupe for canonical form.
  const seen = new Set();
  const clean = [];
  for (const v of values) {
    const k = canonKey(v);
    if (!seen.has(k)) { seen.add(k); clean.push(v); }
  }
  clean.sort((a, b) => {
    const ka = canonKey(a);
    const kb = canonKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  return Object.freeze({
    kind: V.ONE_OF,
    values: Object.freeze(clean),
    typeName: typeName || null,
    provenance: freezeProvenance(provenance),
    labels: freezeLabels(labels),
  });
}

function interval(lo, hi, provenance, labels) {
  if (lo > hi) throw new Error('domain: interval lo > hi');
  return Object.freeze({
    kind: V.INTERVAL,
    lo, hi,
    typeName: 'number',
    provenance: freezeProvenance(provenance),
    labels: freezeLabels(labels),
  });
}

function strPattern(pattern, provenance, labels) {
  return Object.freeze({
    kind: V.STR_PATTERN,
    pattern: Object.freeze({ ...pattern }),
    typeName: 'string',
    provenance: freezeProvenance(provenance),
    labels: freezeLabels(labels),
  });
}

function objectRef(objId, typeName, provenance, labels) {
  return Object.freeze({
    kind: V.OBJECT,
    objId,
    typeName: typeName || null,
    provenance: freezeProvenance(provenance),
    labels: freezeLabels(labels),
  });
}

function closure(functionId, captureValues, provenance, labels) {
  return Object.freeze({
    kind: V.CLOSURE,
    functionId,
    captures: Object.freeze(captureValues.slice()),
    typeName: 'Function',
    provenance: freezeProvenance(provenance),
    labels: freezeLabels(labels),
  });
}

// Opaque values carry a chain of assumption ids explaining why they
// are opaque. Consumers can walk backwards through the chain to find
// the root cause.
function opaque(assumptionIds, typeName, provenance, labels) {
  return Object.freeze({
    kind: V.OPAQUE,
    assumptionIds: Object.freeze(assumptionIds.slice()),
    typeName: typeName || null,
    provenance: freezeProvenance(provenance),
    labels: freezeLabels(labels),
  });
}

// --- Helpers ------------------------------------------------------------

function inferTypeName(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  switch (typeof value) {
    case 'string': return 'string';
    case 'number': return 'number';
    case 'boolean': return 'boolean';
    case 'bigint': return 'bigint';
    case 'object': return 'object';
    case 'function': return 'function';
    default: return 'unknown';
  }
}

function canonKey(v) {
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';
  if (typeof v === 'bigint') return 'b:' + v.toString();
  return typeof v + ':' + String(v);
}

function freezeProvenance(p) {
  if (!p) return Object.freeze([]);
  if (Array.isArray(p)) return Object.freeze(p.slice());
  return Object.freeze([p]);
}

// --- Lattice operations -------------------------------------------------
//
// join(a, b): least upper bound of two values. Commutative, associative,
// idempotent. Always returns a valid Value.
//
// leq(a, b): true iff a ⊑ b (a is no larger than b).

function join(a, b) {
  if (!a || a.kind === V.BOTTOM) return b;
  if (!b || b.kind === V.BOTTOM) return a;
  const mergedLabels = unionLabels(a, b);
  if (a.kind === V.TOP || b.kind === V.TOP) {
    return top(mergeProvenance(a, b), mergedLabels);
  }
  // Opaque propagates: joining opaque with anything yields opaque
  // carrying the union of assumption chains. This preserves the
  // audit trail: a consumer can ask "why did this value become
  // unknown" and trace back through both branches.
  if (a.kind === V.OPAQUE || b.kind === V.OPAQUE) {
    const aIds = a.kind === V.OPAQUE ? a.assumptionIds : [];
    const bIds = b.kind === V.OPAQUE ? b.assumptionIds : [];
    const seen = new Set(aIds);
    const ids = aIds.slice();
    for (const i of bIds) if (!seen.has(i)) { seen.add(i); ids.push(i); }
    const tn = (a.typeName && b.typeName && a.typeName === b.typeName)
      ? a.typeName : null;
    return opaque(ids, tn, mergeProvenance(a, b), mergedLabels);
  }
  // Same kind, same value → return as is (but propagate labels if
  // they differ).
  if (a.kind === V.CONCRETE && b.kind === V.CONCRETE && canonKey(a.value) === canonKey(b.value)) {
    if (mergedLabels === (a.labels || EMPTY_LABELS)) return a;
    return concrete(a.value, a.typeName, mergeProvenance(a, b), mergedLabels);
  }
  // Concrete + concrete with different values → oneOf.
  if (a.kind === V.CONCRETE && b.kind === V.CONCRETE) {
    return oneOf([a.value, b.value], null, mergeProvenance(a, b), mergedLabels);
  }
  // Concrete + oneOf → extended oneOf (if compatible).
  if (a.kind === V.ONE_OF && b.kind === V.CONCRETE) {
    return oneOf(a.values.concat([b.value]), a.typeName, mergeProvenance(a, b), mergedLabels);
  }
  if (a.kind === V.CONCRETE && b.kind === V.ONE_OF) {
    return oneOf(b.values.concat([a.value]), b.typeName, mergeProvenance(a, b), mergedLabels);
  }
  if (a.kind === V.ONE_OF && b.kind === V.ONE_OF) {
    return oneOf(a.values.concat(b.values), null, mergeProvenance(a, b), mergedLabels);
  }
  // Interval merges.
  if (a.kind === V.INTERVAL && b.kind === V.INTERVAL) {
    return interval(Math.min(a.lo, b.lo), Math.max(a.hi, b.hi), mergeProvenance(a, b), mergedLabels);
  }
  if (a.kind === V.CONCRETE && typeof a.value === 'number' && b.kind === V.INTERVAL) {
    return interval(Math.min(a.value, b.lo), Math.max(a.value, b.hi), mergeProvenance(a, b), mergedLabels);
  }
  if (b.kind === V.CONCRETE && typeof b.value === 'number' && a.kind === V.INTERVAL) {
    return interval(Math.min(b.value, a.lo), Math.max(b.value, a.hi), mergeProvenance(a, b), mergedLabels);
  }
  // Object refs — same id means alias, different means the join has to
  // widen to Top (or a "one-of object" if we add that shape later).
  if (a.kind === V.OBJECT && b.kind === V.OBJECT) {
    if (a.objId === b.objId) {
      if (mergedLabels === (a.labels || EMPTY_LABELS)) return a;
      return objectRef(a.objId, a.typeName, mergeProvenance(a, b), mergedLabels);
    }
    return top(mergeProvenance(a, b), mergedLabels);
  }
  // Same closure → same.
  if (a.kind === V.CLOSURE && b.kind === V.CLOSURE && a.functionId === b.functionId) {
    if (mergedLabels === (a.labels || EMPTY_LABELS)) return a;
    return closure(a.functionId, a.captures, mergeProvenance(a, b), mergedLabels);
  }
  // Everything else → Top (conservative). This is where a more
  // sophisticated implementation would introduce a disjunctive
  // shape; for the minimal subset, Top is sound.
  return top(mergeProvenance(a, b), mergedLabels);
}

function leq(a, b) {
  if (!a || a.kind === V.BOTTOM) return true;
  if (!b || b.kind === V.BOTTOM) return a.kind === V.BOTTOM;
  if (b.kind === V.TOP) return true;
  if (a.kind === V.TOP) return false;
  if (a.kind === V.CONCRETE && b.kind === V.CONCRETE) {
    return canonKey(a.value) === canonKey(b.value);
  }
  if (a.kind === V.CONCRETE && b.kind === V.ONE_OF) {
    const key = canonKey(a.value);
    return b.values.some(v => canonKey(v) === key);
  }
  if (a.kind === V.ONE_OF && b.kind === V.ONE_OF) {
    const bkeys = new Set(b.values.map(canonKey));
    return a.values.every(v => bkeys.has(canonKey(v)));
  }
  if (a.kind === V.INTERVAL && b.kind === V.INTERVAL) {
    return a.lo >= b.lo && a.hi <= b.hi;
  }
  if (a.kind === V.CONCRETE && typeof a.value === 'number' && b.kind === V.INTERVAL) {
    return a.value >= b.lo && a.value <= b.hi;
  }
  if (a.kind === V.OBJECT && b.kind === V.OBJECT) {
    return a.objId === b.objId;
  }
  if (a.kind === V.CLOSURE && b.kind === V.CLOSURE) {
    return a.functionId === b.functionId;
  }
  if (a.kind === V.OPAQUE && b.kind === V.OPAQUE) {
    // Opaque ⊑ opaque if b's chain is a superset of a's.
    const bids = new Set(b.assumptionIds);
    return a.assumptionIds.every(i => bids.has(i));
  }
  return false;
}

function equals(a, b) {
  return leq(a, b) && leq(b, a);
}

function mergeProvenance(a, b) {
  const pa = (a && a.provenance) || [];
  const pb = (b && b.provenance) || [];
  if (pa.length === 0) return pb;
  if (pb.length === 0) return pa;
  if (pa === pb) return pa;  // reference equal — common at joins
  // Deduplicate by location pos so repeated joins with the same
  // source don't produce quadratic growth.
  const seen = new Set();
  const out = [];
  for (const p of pa) {
    const k = p.pos + ':' + p.file;
    if (!seen.has(k)) { seen.add(k); out.push(p); }
  }
  for (const p of pb) {
    const k = p.pos + ':' + p.file;
    if (!seen.has(k)) { seen.add(k); out.push(p); }
  }
  return out;
}

// --- Truthiness evaluation ----------------------------------------------
//
// Returns true / false for concretely determined truthiness, or null
// when the value could be either. Used by Layer 2 reachability.

function truthiness(v) {
  if (!v) return null;
  switch (v.kind) {
    case V.BOTTOM: return null;  // unreachable — caller handles
    case V.TOP:    return null;
    case V.OPAQUE: return null;
    case V.CONCRETE: {
      const x = v.value;
      if (x === null || x === undefined) return false;
      if (x === 0 || x === '' || x === false || Number.isNaN(x)) return false;
      return true;
    }
    case V.ONE_OF: {
      let anyTruthy = false, anyFalsy = false;
      for (const x of v.values) {
        const t = truthiness(concrete(x));
        if (t === true) anyTruthy = true;
        if (t === false) anyFalsy = true;
        if (anyTruthy && anyFalsy) return null;
      }
      if (anyTruthy && !anyFalsy) return true;
      if (anyFalsy && !anyTruthy) return false;
      return null;
    }
    case V.INTERVAL:
      if (v.lo > 0 || v.hi < 0) return true;
      if (v.lo === 0 && v.hi === 0) return false;
      return null;
    case V.STR_PATTERN:
      if (v.pattern.exactLength !== undefined) {
        return v.pattern.exactLength > 0;
      }
      return null;
    case V.OBJECT:
    case V.CLOSURE:
      return true;  // objects/closures are always truthy
    default:
      return null;
  }
}

// --- State --------------------------------------------------------------
//
// State represents register values, heap cells, path conditions,
// and assumption ids at a program point. It uses **persistent**
// data structures to avoid O(n) copies on every update:
//
//   regs: a linked chain of overlay Maps. Each state's `regs` is
//         an object { own, parent } where `own` is a Map of this
//         state's local writes, and `parent` points to an older
//         state's regs chain that the writes shadow. Lookups walk
//         the chain; writes append to `own` in-place (mutable
//         path) or create a new overlay (frozen path). Merging at
//         joins flattens into a fresh Map.
//
//   heap: same overlay structure.
//
// This gives O(1) writes and O(k) reads where k is the overlay
// depth. k is bounded by the CFG diameter, not the program size,
// so reads stay fast on typical workloads.
//
// The worklist uses `unfreezeState` at block entry to get a
// mutable overlay over the incoming state. All intra-block writes
// hit the new overlay's `own` Map without touching the parent.
// `freezeState` at block exit just marks the overlay frozen so
// subsequent writes allocate a new layer.

function createEmptyOverlay() {
  return { own: new Map(), parent: null };
}

function overlayGet(overlay, key) {
  let o = overlay;
  while (o) {
    if (o.own.has(key)) return o.own.get(key);
    o = o.parent;
  }
  return undefined;
}

function overlayHas(overlay, key) {
  let o = overlay;
  while (o) {
    if (o.own.has(key)) return true;
    o = o.parent;
  }
  return false;
}

// Iterate every key→value pair in an overlay chain, yielding the
// topmost write for each key (skipping shadowed entries).
function* overlayEntries(overlay) {
  const seen = new Set();
  let o = overlay;
  while (o) {
    for (const [k, v] of o.own) {
      if (seen.has(k)) continue;
      seen.add(k);
      yield [k, v];
    }
    o = o.parent;
  }
}

function overlaySize(overlay) {
  let n = 0;
  // eslint-disable-next-line no-unused-vars
  for (const _ of overlayEntries(overlay)) n++;
  return n;
}

// Collapse an overlay chain into a single flat Map. Used at join
// points so future overlays have a single-layer parent.
function overlayFlatten(overlay) {
  const out = new Map();
  for (const [k, v] of overlayEntries(overlay)) out.set(k, v);
  return out;
}

function createState() {
  return Object.freeze({
    regs: createEmptyOverlay(),
    heap: createEmptyOverlay(),
    pathConds: Object.freeze([]),
    assumptionIds: Object.freeze([]),
    callStack: Object.freeze([]),
    _frozen: true,
  });
}

function setReg(state, register, value) {
  if (!register) return state;
  if (!state._frozen) {
    // Mutable fast path: write to the topmost overlay in place.
    state.regs.own.set(register, value);
    return state;
  }
  // Frozen path: create a new overlay on top of the old one.
  const newRegs = { own: new Map([[register, value]]), parent: state.regs };
  return Object.freeze({
    regs: newRegs,
    heap: state.heap,
    pathConds: state.pathConds,
    assumptionIds: state.assumptionIds,
    callStack: state.callStack,
    _frozen: true,
  });
}

function getReg(state, register) {
  if (!register) return bottom();
  return overlayGet(state.regs, register) || bottom();
}

// Create a mutable working copy of `state`. We allocate an empty
// overlay on top of the frozen state's regs/heap so intra-block
// writes don't disturb the parent. O(1) regardless of state size.
function unfreezeState(state) {
  return {
    regs: { own: new Map(), parent: state.regs },
    heap: { own: new Map(), parent: state.heap },
    pathConds: state.pathConds,
    assumptionIds: state.assumptionIds,
    callStack: state.callStack,
    _frozen: false,
  };
}

function freezeState(state) {
  if (state._frozen) return state;
  // NB: no overlay-depth flattening. A previous version capped the
  // chain at a constant depth "for performance", but the cap was
  // an arbitrary assumption. Chains grow as the worklist adds
  // layers; lookups and joins are O(depth) in the worst case. The
  // cost is documented as a complexity characteristic rather than
  // hidden behind a magic number. Callers that need tighter
  // performance should restructure the analysis, not tune a
  // constant.
  return Object.freeze({
    regs: state.regs,
    heap: state.heap,
    pathConds: state.pathConds,
    assumptionIds: state.assumptionIds,
    callStack: state.callStack,
    _frozen: true,
  });
}

// Find the nearest common ancestor in two overlay chains. Returns
// the shared parent (which may be null) along with the set of
// keys that appear in either chain above that parent.
function overlaysDelta(a, b) {
  // Collect parents of a into a set.
  const aParents = new Set();
  let oa = a;
  while (oa) { aParents.add(oa); oa = oa.parent; }
  // Walk b's parents; the first that's in aParents is the shared base.
  let shared = null;
  let ob = b;
  while (ob) {
    if (aParents.has(ob)) { shared = ob; break; }
    ob = ob.parent;
  }
  // Walk a down to `shared` and collect the union of own keys.
  const keys = new Set();
  let pa = a;
  while (pa && pa !== shared) {
    for (const k of pa.own.keys()) keys.add(k);
    pa = pa.parent;
  }
  let pb = b;
  while (pb && pb !== shared) {
    for (const k of pb.own.keys()) keys.add(k);
    pb = pb.parent;
  }
  return { shared, keys };
}

function joinStates(a, b) {
  if (!a) return b;
  if (!b) return a;
  if (a === b) return a;

  // Fast path: find the nearest common ancestor overlay for regs
  // and heap. Only keys that were written above the shared base
  // need re-joining; everything below is the same in both states.
  const regsDelta = overlaysDelta(a.regs, b.regs);
  const newRegsOwn = new Map();
  for (const name of regsDelta.keys) {
    const va = overlayGet(a.regs, name) || bottom();
    const vb = overlayGet(b.regs, name) || bottom();
    const joined = join(va, vb);
    // If the joined value equals the shared-base value, we don't
    // need to write it (it's inherited). Saves allocations.
    const inherited = regsDelta.shared
      ? (overlayGet(regsDelta.shared, name) || bottom())
      : bottom();
    if (!equals(joined, inherited)) {
      newRegsOwn.set(name, joined);
    }
  }
  const newRegs = newRegsOwn.size > 0
    ? { own: newRegsOwn, parent: regsDelta.shared }
    : (regsDelta.shared || { own: new Map(), parent: null });

  const heapDelta = overlaysDelta(a.heap, b.heap);
  const newHeapOwn = new Map();
  for (const id of heapDelta.keys) {
    const oa = overlayGet(a.heap, id);
    const ob = overlayGet(b.heap, id);
    let joined;
    if (!oa) joined = ob;
    else if (!ob) joined = oa;
    else joined = joinObject(oa, ob);
    newHeapOwn.set(id, joined);
  }
  const newHeap = newHeapOwn.size > 0
    ? { own: newHeapOwn, parent: heapDelta.shared }
    : (heapDelta.shared || { own: new Map(), parent: null });

  const seen = new Set(a.assumptionIds);
  const ids = a.assumptionIds.slice();
  for (const i of b.assumptionIds) if (!seen.has(i)) { seen.add(i); ids.push(i); }
  const pathConds = a.pathConds === b.pathConds
    ? a.pathConds
    : Object.freeze(a.pathConds.concat(b.pathConds));
  return Object.freeze({
    regs: newRegs,
    heap: newHeap,
    pathConds,
    assumptionIds: Object.freeze(ids),
    callStack: a.callStack,
    _frozen: true,
  });
}

function joinObject(a, b) {
  // Object cells keep fields in plain objects for simplicity —
  // field names are known at parse time and the fan-out is
  // typically small.
  const fields = new Set();
  for (const k in a.fields) fields.add(k);
  for (const k in b.fields) fields.add(k);
  const newFields = Object.create(null);
  for (const k of fields) {
    const fa = a.fields[k] || bottom();
    const fb = b.fields[k] || bottom();
    newFields[k] = join(fa, fb);
  }
  return Object.freeze({
    kind: a.kind || b.kind,
    fields: Object.freeze(newFields),
    typeName: (a.typeName && b.typeName && a.typeName === b.typeName) ? a.typeName : null,
    origin: a.origin || b.origin,
  });
}

function stateLeq(a, b) {
  // a ⊑ b iff every register and heap cell in a is ⊑ the
  // corresponding cell in b. Fast path: find the shared base of
  // the two overlays and only compare keys written above it.
  // Everything below the shared base is bit-identical on both
  // sides.
  if (a.regs === b.regs && a.heap === b.heap) return true;
  const regsDelta = overlaysDelta(a.regs, b.regs);
  for (const k of regsDelta.keys) {
    const va = overlayGet(a.regs, k) || bottom();
    const vb = overlayGet(b.regs, k) || bottom();
    if (!leq(va, vb)) return false;
  }
  const heapDelta = overlaysDelta(a.heap, b.heap);
  for (const k of heapDelta.keys) {
    if (!overlayHas(b.heap, k)) return false;
  }
  return true;
}

function stateEquals(a, b) {
  return stateLeq(a, b) && stateLeq(b, a);
}

module.exports = {
  V,
  bottom, top, concrete, oneOf, interval, strPattern, objectRef, closure, opaque,
  join, leq, equals, truthiness,
  withLabels, unionLabels, freezeLabels, EMPTY_LABELS,
  withFormula, valueFormula,
  refineEq, refineNeq,
  createState, setReg, getReg, joinStates, stateLeq, stateEquals,
  unfreezeState, freezeState,
  overlayGet, overlayHas, overlayEntries, overlaySize, overlayFlatten,
  inferTypeName, canonKey,
};
