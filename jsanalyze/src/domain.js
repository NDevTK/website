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
  DISJUNCT:    'disjunct',    // disjunction of incompatible-shape variants
  TOP:         'top',         // ⊤ — any value
});

// --- DISJUNCT (per-path type / shape tracking) --------------------------
//
// A Disjunct value represents the union of several "shape variants"
// that cannot be cleanly merged into a single non-Top abstraction.
// The motivating case: a register that holds an HTMLAnchorElement
// on one path and an HTMLIFrameElement on another. Without
// disjuncts, the join would collapse both to Opaque(typeName=null)
// and downstream `el.href = ...` / `el.src = ...` sink lookups
// would fail because they need a concrete typeName to consult
// the TypeDB.
//
// A Disjunct's variants are themselves regular Values — each carries
// its own kind, typeName, value/values, formula, labels, and
// provenance. The Disjunct is essentially a tagged union; its
// own labels field is the union of all variant labels (so taint
// flows still work without iterating every variant).
//
// Operations on Disjuncts fan out: `applyGetProp` resolves the
// property on each variant and rebuilds a Disjunct of the
// per-variant results. `refineByType` filters variants whose
// type doesn't match. Sink classification iterates every variant
// (different element types may have different sinks under the
// same property name).
//
// Variants are normalized at construction time: nested Disjuncts
// are flattened, duplicate variants (by structural key) are
// deduped, and a single-variant Disjunct collapses back to that
// variant. A Disjunct never contains a Bottom variant — those
// are filtered.
//
// The lattice ordering is "subset of variants": leq(a, b) if every
// variant in a has a corresponding variant in b that's >= it.

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
  // Disjuncts: propagate the labels into every variant so each
  // variant carries its share of the taint and downstream
  // operations on the disjunct see the full label set.
  if (value.kind === V.DISJUNCT) {
    const newVariants = value.variants.map(v => withLabels(v, incoming));
    // Rebuild via factory to refresh the disjunct envelope's
    // label set (factory recomputes it as the union).
    return disjunct(newVariants, value.provenance);
  }
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
//
// For Disjuncts, the formula is attached to every variant so
// each variant has the same SMT representation. (A future
// refinement may keep per-variant formulas — for now the call
// site has no way to distinguish them.)
function withFormula(value, formula) {
  if (!value || value.kind === V.BOTTOM) return value;
  if (!formula) return value;
  if (value.kind === V.DISJUNCT) {
    const newVariants = value.variants.map(v => withFormula(v, formula));
    return disjunct(newVariants, value.provenance);
  }
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
  // Disjunct: refine every variant independently and recombine.
  // A variant that contradicts the equality becomes Bottom and
  // is dropped by the disjunct factory — this is how per-path
  // type refinement works for mixed-type values like
  // `x = cond ? "admin" : 42`.
  if (value.kind === V.DISJUNCT) {
    return disjunctMap(value, (v) => refineEq(v, literal));
  }
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
  if (value.kind === V.DISJUNCT) {
    return disjunctMap(value, (v) => refineNeq(v, literal));
  }
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

// --- typeof / instanceof refinement -------------------------------------
//
// These helpers back Wave 1's B5 extension for runtime type-check
// predicates. They narrow a Value to the subset of shapes that
// are consistent with `typeof v === typeStr` (refineByType) or
// `v instanceof ctorName` (refineInstanceof). Disjunct variants
// are filtered one at a time and the factory collapses or drops
// incompatible variants automatically.
//
// Rules for refineByType(value, typeStr):
//   Concrete:    jsTypeof(value) === typeStr ? keep : Bottom
//   OneOf:       filter values by jsTypeof
//   Opaque:      if typeName is in the db and maps to a
//                JS typeof category that differs from typeStr,
//                Bottom. Otherwise preserve (the formula carries
//                the constraint into the SMT layer).
//   Object:      typeof === 'object' (or 'function' for Closure)
//   Closure:     typeof === 'function'
//   Interval:    typeof === 'number'
//   StrPattern:  typeof === 'string'
//   Disjunct:    map over variants
//   Top/Bottom:  unchanged
function refineByType(value, typeStr) {
  if (!value) return value;
  if (value.kind === V.BOTTOM) return value;
  if (value.kind === V.DISJUNCT) {
    return disjunctMap(value, (v) => refineByType(v, typeStr));
  }
  if (value.kind === V.CONCRETE) {
    return jsTypeof(value.value) === typeStr ? value : bottom();
  }
  if (value.kind === V.ONE_OF) {
    const remaining = [];
    for (const v of value.values) {
      if (jsTypeof(v) === typeStr) remaining.push(v);
    }
    if (remaining.length === 0) return bottom();
    if (remaining.length === 1) {
      const c = concrete(remaining[0], value.typeName, value.provenance, value.labels);
      return value.formula ? withFormula(c, value.formula) : c;
    }
    return oneOf(remaining, value.typeName, value.provenance, value.labels);
  }
  if (value.kind === V.OBJECT)  return typeStr === 'object' ? value : bottom();
  if (value.kind === V.CLOSURE) return typeStr === 'function' ? value : bottom();
  if (value.kind === V.INTERVAL)    return typeStr === 'number' ? value : bottom();
  if (value.kind === V.STR_PATTERN) return typeStr === 'string' ? value : bottom();
  if (value.kind === V.OPAQUE && value.typeName) {
    const expected = typeNameToTypeof(value.typeName);
    if (expected && expected !== typeStr) return bottom();
    return value;
  }
  // Opaque(null), Top: can't decide, preserve.
  return value;
}

function refineNotByType(value, typeStr) {
  if (!value) return value;
  if (value.kind === V.BOTTOM) return value;
  if (value.kind === V.DISJUNCT) {
    return disjunctMap(value, (v) => refineNotByType(v, typeStr));
  }
  if (value.kind === V.CONCRETE) {
    return jsTypeof(value.value) === typeStr ? bottom() : value;
  }
  if (value.kind === V.ONE_OF) {
    const remaining = [];
    for (const v of value.values) {
      if (jsTypeof(v) !== typeStr) remaining.push(v);
    }
    if (remaining.length === 0) return bottom();
    if (remaining.length === 1) {
      const c = concrete(remaining[0], value.typeName, value.provenance, value.labels);
      return value.formula ? withFormula(c, value.formula) : c;
    }
    return oneOf(remaining, value.typeName, value.provenance, value.labels);
  }
  if (value.kind === V.OBJECT)  return typeStr === 'object' ? bottom() : value;
  if (value.kind === V.CLOSURE) return typeStr === 'function' ? bottom() : value;
  if (value.kind === V.INTERVAL)    return typeStr === 'number' ? bottom() : value;
  if (value.kind === V.STR_PATTERN) return typeStr === 'string' ? bottom() : value;
  if (value.kind === V.OPAQUE && value.typeName) {
    const expected = typeNameToTypeof(value.typeName);
    if (expected && expected === typeStr) return bottom();
    return value;
  }
  return value;
}

// jsTypeof — mirror of JS `typeof` on a concrete primitive.
function jsTypeof(v) {
  if (v === null) return 'object';
  if (v === undefined) return 'undefined';
  return typeof v;
}

// typeNameToTypeof — best-effort map from a TypeDB type name to
// the JS typeof category of values of that type. DOM / host types
// all map to 'object'. Primitive wrappers map to their category.
function typeNameToTypeof(typeName) {
  if (!typeName) return null;
  if (typeName === 'string' || typeName === 'String') return 'string';
  if (typeName === 'number' || typeName === 'Number') return 'number';
  if (typeName === 'boolean' || typeName === 'Boolean') return 'boolean';
  if (typeName === 'undefined') return 'undefined';
  if (typeName === 'function' || typeName === 'Function') return 'function';
  if (typeName === 'bigint' || typeName === 'BigInt') return 'bigint';
  if (typeName === 'symbol' || typeName === 'Symbol') return 'symbol';
  if (typeName === 'null') return 'object';
  // Everything else is 'object' (DOM types, host objects, etc.)
  return 'object';
}

// --- instanceof refinement ----------------------------------------------
//
// refineInstanceof(value, ctorName, db) narrows `value` to the
// branch where `value instanceof ctorName` holds. The
// refinement walks the TypeDB `extends` chain (and optionally
// `interfaces`) to decide whether a typeName satisfies
// `instanceof ctorName`.
//
// Primitives never satisfy instanceof (refine → Bottom on the
// positive side; preserve on the negative side). Disjunct
// variants are filtered per-variant, enabling the key use case:
//
//   var el = cond ? createElement('a') : createElement('iframe');
//   if (el instanceof HTMLAnchorElement) {
//       el.href = ...;   // only the anchor variant survives here
//   }
function refineInstanceof(value, ctorName, db) {
  if (!value) return value;
  if (value.kind === V.BOTTOM) return value;
  if (value.kind === V.DISJUNCT) {
    return disjunctMap(value, (v) => refineInstanceof(v, ctorName, db));
  }
  if (value.kind === V.CONCRETE) return bottom();  // primitives fail
  if (value.kind === V.ONE_OF)   return bottom();  // all-primitive collapse
  if (value.kind === V.INTERVAL || value.kind === V.STR_PATTERN) return bottom();
  if (value.kind === V.OBJECT || value.kind === V.OPAQUE || value.kind === V.CLOSURE) {
    if (!value.typeName) return value;     // unknown — preserve
    if (typeChainIncludes(db, value.typeName, ctorName)) return value;
    return bottom();
  }
  return value;
}

function refineNotInstanceof(value, ctorName, db) {
  if (!value) return value;
  if (value.kind === V.BOTTOM) return value;
  if (value.kind === V.DISJUNCT) {
    return disjunctMap(value, (v) => refineNotInstanceof(v, ctorName, db));
  }
  // Primitives never satisfy instanceof, so the negation always
  // holds for them — preserve.
  if (value.kind === V.CONCRETE || value.kind === V.ONE_OF ||
      value.kind === V.INTERVAL || value.kind === V.STR_PATTERN) {
    return value;
  }
  if (value.kind === V.OBJECT || value.kind === V.OPAQUE || value.kind === V.CLOSURE) {
    if (!value.typeName) return value;
    if (typeChainIncludes(db, value.typeName, ctorName)) return bottom();
    return value;
  }
  return value;
}

// True iff typeName transitively extends or implements ctorName
// in the TypeDB. Walks the `extends` chain and the optional
// `interfaces` array.
function typeChainIncludes(db, typeName, ctorName) {
  if (!typeName || !ctorName) return false;
  if (typeName === ctorName) return true;
  if (!db || !db.types) return false;
  const seen = new Set();
  let cur = typeName;
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    if (cur === ctorName) return true;
    const desc = db.types[cur];
    if (!desc) return false;
    if (desc.interfaces) {
      for (const iface of desc.interfaces) {
        if (iface === ctorName) return true;
      }
    }
    cur = desc.extends || null;
  }
  return false;
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

// Disjunct factory. Variants must be Values. The factory:
//   * flattens any nested Disjuncts (a disjunct of disjuncts is a
//     flat disjunct).
//   * filters out Bottom variants (Bottom contributes nothing).
//   * dedupes by `variantKey` (structural key over kind+typeName+
//     value/values/objId/assumptionIds — captures the shape that
//     matters for downstream operations).
//   * collapses single-variant disjuncts back to that variant.
//   * absorbs Top: a disjunct containing Top IS Top.
//
// The result's `labels` is the union of all variant labels — this
// keeps taint-propagation correct without having to walk variants
// at every label union site.
//
// `provenance` is the union of all variant provenance entries.
function disjunct(variants, provenance) {
  // Flatten + filter Bottom.
  const flat = [];
  for (const v of variants) {
    if (!v) continue;
    if (v.kind === V.BOTTOM) continue;
    if (v.kind === V.TOP) {
      // Absorbing element.
      const labelsAcc = new Set();
      for (const w of variants) {
        if (w && w.labels) for (const l of w.labels) labelsAcc.add(l);
      }
      return top(provenance || (v.provenance || []),
        labelsAcc.size > 0 ? Object.freeze(labelsAcc) : EMPTY_LABELS);
    }
    if (v.kind === V.DISJUNCT) {
      for (const inner of v.variants) flat.push(inner);
    } else {
      flat.push(v);
    }
  }
  if (flat.length === 0) return bottom();

  // Dedupe.
  const seen = new Map();
  const unique = [];
  for (const v of flat) {
    const k = variantKey(v);
    if (!seen.has(k)) {
      seen.set(k, true);
      unique.push(v);
    }
  }

  if (unique.length === 1) return unique[0];

  // Compute the union of variant labels for the disjunct envelope.
  let unionLabelsSet = null;
  for (const v of unique) {
    if (v.labels && v.labels.size > 0) {
      if (!unionLabelsSet) unionLabelsSet = new Set(v.labels);
      else for (const l of v.labels) unionLabelsSet.add(l);
    }
  }
  const labelsOut = unionLabelsSet ? Object.freeze(unionLabelsSet) : EMPTY_LABELS;

  // Provenance: union of variant provenance.
  let provOut;
  if (provenance) {
    provOut = freezeProvenance(provenance);
  } else {
    const allProv = [];
    for (const v of unique) {
      if (v.provenance) for (const p of v.provenance) allProv.push(p);
    }
    provOut = Object.freeze(allProv);
  }

  // Sort variants by key for canonical form (helps stateEquals).
  unique.sort((a, b) => {
    const ka = variantKey(a);
    const kb = variantKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  return Object.freeze({
    kind: V.DISJUNCT,
    variants: Object.freeze(unique),
    typeName: null,        // Disjuncts don't have a single typeName
    provenance: provOut,
    labels: labelsOut,
  });
}

// Structural key for a Value variant. Two variants with the same
// key are considered duplicates within a Disjunct. We include the
// minimal fields that affect downstream operations (kind, typeName,
// concrete value, OneOf values, ObjectRef objId, assumption chain).
// Provenance and exact label set are NOT included — variants that
// differ only in where they came from are merged.
function variantKey(v) {
  if (!v) return 'null';
  switch (v.kind) {
    case V.BOTTOM:    return 'B';
    case V.TOP:       return 'T';
    case V.CONCRETE:  return 'C:' + canonKey(v.value) + ':' + (v.typeName || '');
    case V.ONE_OF: {
      const ks = [];
      for (const x of v.values) ks.push(canonKey(x));
      return 'O:[' + ks.join(',') + ']:' + (v.typeName || '');
    }
    case V.INTERVAL:    return 'I:' + v.lo + ',' + v.hi;
    case V.STR_PATTERN: return 'P:' + JSON.stringify(v.pattern);
    case V.OBJECT:      return 'R:' + v.objId + ':' + (v.typeName || '');
    case V.CLOSURE:     return 'F:' + v.functionId;
    case V.OPAQUE:
      // Include the assumption chain because two opaque results
      // from different sources should remain distinct.
      return 'X:' + (v.typeName || '') + ':[' + (v.assumptionIds || []).join(',') + ']';
    case V.DISJUNCT: {
      const ks = [];
      for (const x of v.variants) ks.push(variantKey(x));
      ks.sort();
      return 'D:[' + ks.join('|') + ']';
    }
    default: return '?:' + v.kind;
  }
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

  // --- Disjunct fan-out ---
  //
  // If either side is already a Disjunct, fan the other side out
  // across the variants. The result is the union of variants
  // (possibly merging with existing variants of the same shape).
  if (a.kind === V.DISJUNCT || b.kind === V.DISJUNCT) {
    const aVariants = a.kind === V.DISJUNCT ? a.variants : [a];
    const bVariants = b.kind === V.DISJUNCT ? b.variants : [b];
    return disjunct(aVariants.concat(bVariants), mergeProvenance(a, b));
  }

  // Opaque + Opaque: if same typeName, merge into a single Opaque.
  // If different typeNames AND both are non-null, build a Disjunct
  // — this is the per-path type tracking the user asked for. The
  // motivating case: `el = cond ? createElement('a') : createElement('iframe')`
  // joins HTMLAnchorElement and HTMLIFrameElement opaques, and
  // downstream `el.src = ...` / `el.href = ...` sink lookups need
  // to see BOTH types so the right sink fires.
  if (a.kind === V.OPAQUE && b.kind === V.OPAQUE) {
    const aIds = a.assumptionIds;
    const bIds = b.assumptionIds;
    if (a.typeName && b.typeName && a.typeName !== b.typeName) {
      return disjunct([a, b], mergeProvenance(a, b));
    }
    const seen = new Set(aIds);
    const ids = aIds.slice();
    for (const i of bIds) if (!seen.has(i)) { seen.add(i); ids.push(i); }
    const tn = a.typeName || b.typeName || null;
    return opaque(ids, tn, mergeProvenance(a, b), mergedLabels);
  }
  // Mixed Opaque + non-Opaque: this is also a per-path-type
  // situation if the non-Opaque side has a known shape. Wrap as
  // a Disjunct rather than collapsing the type information.
  if (a.kind === V.OPAQUE || b.kind === V.OPAQUE) {
    return disjunct([a, b], mergeProvenance(a, b));
  }
  // Same kind, same value → return as is (but propagate labels if
  // they differ).
  if (a.kind === V.CONCRETE && b.kind === V.CONCRETE && canonKey(a.value) === canonKey(b.value)) {
    if (mergedLabels === (a.labels || EMPTY_LABELS)) return a;
    return concrete(a.value, a.typeName, mergeProvenance(a, b), mergedLabels);
  }
  // Concrete + concrete with different values → if same JS type,
  // a OneOf is precise; if different JS types, a Disjunct preserves
  // per-path type info (the SMT layer can use the variant whose
  // formula matches the path it's reasoning about).
  if (a.kind === V.CONCRETE && b.kind === V.CONCRETE) {
    if (typeof a.value === typeof b.value) {
      return oneOf([a.value, b.value], a.typeName, mergeProvenance(a, b), mergedLabels);
    }
    return disjunct([a, b], mergeProvenance(a, b));
  }
  // Concrete + oneOf → extended oneOf if same type, else Disjunct.
  if (a.kind === V.ONE_OF && b.kind === V.CONCRETE) {
    if (a.typeName && a.typeName === b.typeName) {
      return oneOf(a.values.concat([b.value]), a.typeName, mergeProvenance(a, b), mergedLabels);
    }
    return disjunct([a, b], mergeProvenance(a, b));
  }
  if (a.kind === V.CONCRETE && b.kind === V.ONE_OF) {
    if (b.typeName && a.typeName === b.typeName) {
      return oneOf(b.values.concat([a.value]), b.typeName, mergeProvenance(a, b), mergedLabels);
    }
    return disjunct([a, b], mergeProvenance(a, b));
  }
  if (a.kind === V.ONE_OF && b.kind === V.ONE_OF) {
    if (a.typeName && a.typeName === b.typeName) {
      return oneOf(a.values.concat(b.values), a.typeName, mergeProvenance(a, b), mergedLabels);
    }
    return disjunct([a, b], mergeProvenance(a, b));
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
  // Object refs — same id means alias, different means we keep
  // both as a Disjunct so per-path heap-cell lookups still work.
  if (a.kind === V.OBJECT && b.kind === V.OBJECT) {
    if (a.objId === b.objId) {
      if (mergedLabels === (a.labels || EMPTY_LABELS)) return a;
      return objectRef(a.objId, a.typeName, mergeProvenance(a, b), mergedLabels);
    }
    return disjunct([a, b], mergeProvenance(a, b));
  }
  // Same closure → same; different closures → Disjunct so call
  // resolution can fan out to both function bodies.
  if (a.kind === V.CLOSURE && b.kind === V.CLOSURE) {
    if (a.functionId === b.functionId) {
      if (mergedLabels === (a.labels || EMPTY_LABELS)) return a;
      return closure(a.functionId, a.captures, mergeProvenance(a, b), mergedLabels);
    }
    return disjunct([a, b], mergeProvenance(a, b));
  }
  // Anything else with mixed shapes (e.g. Concrete + Object,
  // Closure + Concrete, StrPattern + Number) — keep them
  // disjunctively so per-path type-aware operations remain
  // precise. The Disjunct factory will normalize.
  return disjunct([a, b], mergeProvenance(a, b));
}

function leq(a, b) {
  if (!a || a.kind === V.BOTTOM) return true;
  if (!b || b.kind === V.BOTTOM) return a.kind === V.BOTTOM;
  if (b.kind === V.TOP) return true;
  if (a.kind === V.TOP) return false;

  // --- Disjunct handling ---
  // a ⊑ b iff every variant of a has an b-variant ⊒ it.
  if (a.kind === V.DISJUNCT) {
    return a.variants.every(va => leq(va, b));
  }
  // a (non-disjunct) ⊑ b (disjunct) iff some variant of b ⊒ a.
  if (b.kind === V.DISJUNCT) {
    return b.variants.some(vb => leq(a, vb));
  }

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
    // Opaque ⊑ opaque if b's chain is a superset of a's AND the
    // typeNames are compatible (b's is null or matches a's).
    const bids = new Set(b.assumptionIds);
    if (!a.assumptionIds.every(i => bids.has(i))) return false;
    if (b.typeName && a.typeName !== b.typeName) return false;
    return true;
  }
  return false;
}

// Map a function over each variant of a (potentially disjunctive)
// value. The function `fn(variant)` returns a new Value for each
// variant; the results are recombined into a Disjunct. Bottom
// results are dropped. Useful in transfer functions that need to
// fan out per-type operations like property lookups and method
// dispatch.
//
// If `value` is not a Disjunct, the function is called once on
// the value itself.
function disjunctMap(value, fn) {
  if (!value || value.kind === V.BOTTOM) return value;
  if (value.kind !== V.DISJUNCT) return fn(value);
  const out = [];
  for (const v of value.variants) {
    const r = fn(v);
    if (r && r.kind !== V.BOTTOM) out.push(r);
  }
  if (out.length === 0) return bottom();
  if (out.length === 1) return out[0];
  return disjunct(out);
}

// Iterate the variants of a value as an array. For non-disjunct
// values, returns a single-element array. Useful in code that
// needs to enumerate without rebuilding the result (sink emission).
function disjunctVariants(value) {
  if (!value || value.kind === V.BOTTOM) return [];
  if (value.kind === V.DISJUNCT) return value.variants;
  return [value];
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
    case V.DISJUNCT: {
      // The disjunct is truthy iff EVERY variant is truthy, falsy
      // iff every variant is falsy, otherwise unknown. This is
      // sound because each variant represents a different path;
      // the worklist needs unanimous agreement to short-circuit.
      let anyT = false, anyF = false, anyU = false;
      for (const variant of v.variants) {
        const t = truthiness(variant);
        if (t === true) anyT = true;
        else if (t === false) anyF = true;
        else { anyU = true; break; }
      }
      if (anyU) return null;
      if (anyT && !anyF) return true;
      if (anyF && !anyT) return false;
      return null;
    }
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

// createStateSharingHeap — used by inter-procedural call
// lowering (applyCall). Produces a fresh state whose `regs`
// are empty but whose `heap` overlays the caller's, so the
// callee can dereference any ObjectRef / heap cell the caller
// passed as an argument. This is sound for call-site-
// context-insensitive analysis; a more precise treatment
// (Phase C3) would clone-and-reconcile the heap per call
// context.
function createStateSharingHeap(callerState) {
  return Object.freeze({
    regs: createEmptyOverlay(),
    heap: callerState && callerState.heap
      ? { own: new Map(), parent: callerState.heap }
      : createEmptyOverlay(),
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
  disjunct, disjunctMap, disjunctVariants, variantKey,
  join, leq, equals, truthiness,
  withLabels, unionLabels, freezeLabels, EMPTY_LABELS,
  withFormula, valueFormula,
  refineEq, refineNeq, refineByType, refineNotByType,
  refineInstanceof, refineNotInstanceof, typeChainIncludes,
  createState, createStateSharingHeap, setReg, getReg, joinStates, stateLeq, stateEquals,
  unfreezeState, freezeState,
  overlayGet, overlayHas, overlayEntries, overlaySize, overlayFlatten,
  inferTypeName, canonKey,
};
