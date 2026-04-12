// assumptions.js — explicit assumption tracking
//
// Every time the analyser cannot determine a value or a
// reachability answer exactly, it allocates an Assumption
// record. The record lives in the Trace and is exposed via
// `query.assumptions(trace)`.
//
// Reason codes are a stable public contract. Adding a new code
// is a minor version bump; removing or repurposing one is a
// major bump. See docs/ASSUMPTIONS.md for the catalog.

'use strict';

// Every reason code used in the library. The set is closed —
// new codes must be added here and documented in ASSUMPTIONS.md.
const REASONS = Object.freeze({
  NETWORK:         'network',
  USER_INPUT:      'user-input',
  RANDOMNESS:      'randomness',
  TIMING:          'timing',
  UNSOLVABLE_MATH: 'unsolvable-math',
  UNIMPLEMENTED:   'unimplemented',
  DYNAMIC_CODE:    'dynamic-code',
  OPAQUE_CALL:     'opaque-call',
  EXTERNAL_MODULE: 'external-module',
  RUNTIME_TYPE:    'runtime-type',
  HEAP_ESCAPE:     'heap-escape',
});

const VALID_REASONS = new Set(Object.values(REASONS));

// Severity determines what kind of imprecision this assumption
// introduces. Consumers use this to choose whether to trust a
// finding that depends on the assumption.
//
//   'soundness': may cause false negatives (missed findings).
//                Absence of soundness assumptions along a path
//                means every concrete flow through that path is
//                reported.
//   'precision': may cause false positives (over-reported
//                findings). Findings are conservative upper
//                bounds.
const SEVERITIES = Object.freeze({
  SOUNDNESS: 'soundness',
  PRECISION: 'precision',
});

// Maps each reason to its default severity. Individual raises
// can override (e.g. an 'opaque-call' to a pure built-in is
// precision; to a potentially-mutating external function it is
// soundness).
const DEFAULT_SEVERITY = Object.freeze({
  'network':         SEVERITIES.PRECISION,
  'user-input':      SEVERITIES.PRECISION,
  'randomness':      SEVERITIES.PRECISION,
  'timing':          SEVERITIES.PRECISION,
  'unsolvable-math': SEVERITIES.PRECISION,
  'unimplemented':   SEVERITIES.SOUNDNESS,
  'dynamic-code':    SEVERITIES.SOUNDNESS,
  'opaque-call':     SEVERITIES.SOUNDNESS,
  'external-module': SEVERITIES.SOUNDNESS,
  'runtime-type':    SEVERITIES.PRECISION,
  'heap-escape':     SEVERITIES.SOUNDNESS,
});

// AssumptionTracker is the mutable ledger the analyser writes
// to during the walk. It assigns stable ids and builds chain
// relationships when one assumption derives from another.
//
// After the walk completes, the consumer reads the assumptions
// via the frozen list.
class AssumptionTracker {
  constructor() {
    this._nextId = 1;
    this._assumptions = [];
  }

  // Raise a new assumption. Returns the assumption record so
  // the caller can reference it from a chain.
  //
  // Arguments:
  //   reason:   one of REASONS.*
  //   details:  human-readable explanation (non-empty string)
  //   location: { file, line, col, pos, endPos? }
  //   opts:     { affects?, severity?, chain? }
  raise(reason, details, location, opts) {
    if (!VALID_REASONS.has(reason)) {
      throw new Error('AssumptionTracker: unknown reason ' + reason);
    }
    if (typeof details !== 'string' || details.length === 0) {
      throw new Error('AssumptionTracker: details must be a non-empty string');
    }
    if (!location || typeof location !== 'object') {
      throw new Error('AssumptionTracker: location is required');
    }
    const o = opts || {};
    const severity = o.severity || DEFAULT_SEVERITY[reason];
    if (severity !== SEVERITIES.SOUNDNESS && severity !== SEVERITIES.PRECISION) {
      throw new Error('AssumptionTracker: invalid severity ' + severity);
    }
    const record = {
      id: this._nextId++,
      reason,
      details,
      location: Object.freeze({ ...location }),
      affects: o.affects || null,
      severity,
      chain: Array.isArray(o.chain) ? o.chain.slice() : [],
    };
    Object.freeze(record.chain);
    Object.freeze(record);
    this._assumptions.push(record);
    return record;
  }

  // Snapshot: returns a frozen array of all assumptions raised
  // so far, in the order they were raised.
  snapshot() {
    return Object.freeze(this._assumptions.slice());
  }

  // Filter assumptions by reason, severity, file, or custom
  // predicate. Used by query.assumptions().
  filter(predicate) {
    const out = [];
    for (const a of this._assumptions) {
      if (predicate(a)) out.push(a);
    }
    return out;
  }

  // Count by reason — useful for diagnostics.
  stats() {
    const out = Object.create(null);
    for (const a of this._assumptions) {
      out[a.reason] = (out[a.reason] || 0) + 1;
    }
    return out;
  }
}

module.exports = {
  REASONS,
  SEVERITIES,
  DEFAULT_SEVERITY,
  AssumptionTracker,
};
