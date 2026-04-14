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
//
// Codes are grouped into three justification classes (see
// docs/ASSUMPTIONS.md for the reasoning):
//
//   1. Theoretical floor — bytes/behaviour genuinely unknowable:
//      NETWORK, ATTACKER_INPUT, PERSISTENT_STATE, DOM_STATE,
//      UI_INTERACTION, ENVIRONMENTAL, RUNTIME_TIME, PSEUDORANDOM,
//      CRYPTOGRAPHIC_RANDOM, UNSOLVABLE_MATH
//
//   2. Environmental — bytes are outside the analyzer's input
//      and can be narrowed by providing more input / TypeDB:
//      OPAQUE_CALL, EXTERNAL_MODULE, CODE_FROM_DATA
//
//   3. Engineering gaps — could be eliminated by implementing the
//      missing transfer function / analysis pass:
//      UNIMPLEMENTED, HEAP_ESCAPE
const REASONS = Object.freeze({
  // --- Theoretical floor: value unknowable at analysis time ---

  // Bytes arrive from the network at runtime (fetch / XHR /
  // WebSocket / EventSource / BroadcastChannel / sendBeacon).
  NETWORK: 'network',

  // Value is chosen by an attacker and delivered via a vector
  // the attacker controls without requiring user cooperation:
  // `location.*`, `document.referrer`, `window.name` when the
  // opener is untrusted, cross-origin `postMessage`, URL search
  // params, hash fragments.
  //
  // Distinct from UI_INTERACTION: the user is not typing this;
  // the attacker crafted a URL and delivered it. Self-XSS
  // (where the user types the malicious payload themselves) is
  // NOT covered here — that is UI_INTERACTION.
  ATTACKER_INPUT: 'attacker-input',

  // Value was persisted earlier by same-origin code: cookies,
  // localStorage, sessionStorage, IndexedDB, Cache API. The
  // analyzer doesn't know who wrote it or when. Attackers can
  // reach this class only if they already had a prior foothold
  // (to plant the value); for threat modeling it's weaker than
  // ATTACKER_INPUT but the analyzer still can't read the bytes.
  PERSISTENT_STATE: 'persistent-state',

  // Value read from the live DOM tree (`el.innerText`,
  // `el.value` for a field that wasn't populated by analyzed
  // code, `el.dataset.*`, attribute reads). Equivalent to
  // PERSISTENT_STATE for same-origin script writes, but the DOM
  // may also have been populated by attacker-controlled HTML
  // injection earlier. Treated as a separate class so consumers
  // can distinguish "came from storage" from "came from DOM".
  DOM_STATE: 'dom-state',

  // Value came from a UI element AFTER an explicit user
  // interaction: a form field's `.value` inside an `input`/
  // `change` handler, `event.clipboardData` on paste,
  // `event.dataTransfer` on drop, a FileReader result after
  // the user picked a file. This is where the *user* actually
  // typed / dropped / chose something. Usually not an attack
  // surface on its own, except for self-XSS.
  UI_INTERACTION: 'ui-interaction',

  // Value read from the read-only environment: `navigator.*`,
  // `screen.*`, `window.innerWidth`, `document.documentElement
  // .lang`, feature-detection checks. The values are opaque at
  // analysis time but typically not attacker-controlled.
  ENVIRONMENTAL: 'environmental',

  // Deterministic time source: `Date.now()`, `new Date()`,
  // `performance.now()`, `requestAnimationFrame` timestamps,
  // `performance.timing.*`. These return runtime values we
  // cannot predict statically, but they are NOT random — they
  // follow a monotonic clock. Kept separate from pseudorandom/
  // cryptographic-random because the predictability profile is
  // completely different.
  RUNTIME_TIME: 'runtime-time',

  // Pseudorandom source: `Math.random()`. Produces a value
  // drawn from a PRNG that is typically seeded deterministically
  // per context. NOT cryptographically secure. Enough outputs
  // can be used to recover the seed and predict future values.
  PSEUDORANDOM: 'pseudorandom',

  // Cryptographically secure random source:
  // `crypto.getRandomValues`, `crypto.randomUUID`. Genuinely
  // non-deterministic from any predictable seed; the only
  // assumption class where predicting the value would break a
  // cryptographic primitive.
  CRYPTOGRAPHIC_RANDOM: 'cryptographic-random',

  // SMT returned `unknown` on a reachability query, either by
  // timing out or because the formula is in an undecidable
  // theory (non-linear integer arithmetic with quantifiers,
  // Diophantine search, encoded halting problem). Rice's
  // theorem applied directly.
  UNSOLVABLE_MATH: 'unsolvable-math',

  // --- Environmental: bytes outside the analyzer's input ---

  // Call to a function whose body isn't in the input — native
  // built-in not in the TypeDB, an imported function from an
  // external module, a dynamically resolved target.
  OPAQUE_CALL: 'opaque-call',

  // `import` references a module whose source is not in the
  // analyzer's input set.
  EXTERNAL_MODULE: 'external-module',

  // Code whose SOURCE is a runtime value: `eval(s)`,
  // `new Function(s)`, `setTimeout(s, ms)` / `setInterval(s, ms)`
  // with a string first argument, `import(u)` with a
  // non-constant URL, `script.textContent = s`, `script.src = u`.
  // Constant-string eval is walked inline without raising this
  // assumption; this code only fires when the source bytes are
  // themselves determined at runtime.
  CODE_FROM_DATA: 'code-from-data',

  // --- Engineering gaps: could be eliminated by more code ---

  // Construct the engine does not yet model. Every such site is
  // an explicit TODO with a concrete feature gap — the location
  // and construct kind are recorded in `details`. Subsumes the
  // former `timing` (async ordering not modeled) and
  // `runtime-type` (dynamic dispatch not narrowed) codes, since
  // both are specific cases of "this analysis is not yet
  // implemented" rather than distinct categories.
  UNIMPLEMENTED: 'unimplemented',

  // An object reference flowed into an opaque context and its
  // fields can no longer be tracked. Points-to analysis and
  // effect-tracking function summaries would eliminate this.
  HEAP_ESCAPE: 'heap-escape',

  // --- Performance shortcuts: the engine took a precision-
  //     for-time tradeoff the consumer may or may not tolerate ---
  //
  // These reason codes exist so a consumer can declare via
  // `options.accept` whether the engine is allowed to take the
  // shortcut at all. A consumer that rejects a performance
  // reason gets `trace.partial = true` and a
  // `rejectedAssumptions` entry pointing at the site where the
  // engine took the shortcut — and should then reanalyse with
  // a stricter `precision` / `smtTimeoutMs` to suppress it.
  //
  // The engine's default behaviour is to TAKE the shortcut
  // (shortcuts are what make large bundles analyzable) and to
  // raise the assumption so the decision is auditable. A strict
  // consumer can verify soundness by rejecting every
  // performance reason and rerunning.

  // Back-edge widening: at a loop header, a variant arriving on
  // a back edge was pointwise-joined with an existing back-edge
  // variant instead of kept as a separate per-iteration
  // variant. This keeps loop analysis finite but loses per-
  // iteration precision on registers that change inside the
  // body. Rejection forces an exact loop walk.
  LOOP_WIDENING: 'loop-widening',

  // Summary cache reuse: a user-function call hit the D7 k-CFA
  // summary cache and the engine replayed the cached exit
  // state instead of walking the body fresh. Repeated calls
  // with the same (body, args, this) fingerprint share a
  // summary; a consumer that rejects this gets full context
  // sensitivity (every call site walks the body, at the cost
  // of O(calls × body) analysis time).
  SUMMARY_REUSED: 'summary-reused',
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
//
// Rationale per reason:
//
//   Theoretical-floor reasons are PRECISION by default because
//   the analyzer knows the value is opaque and can tag it with
//   an appropriate taint label — the label propagates soundly,
//   only the byte content is unknown.
//
//   Environmental reasons (opaque-call, external-module,
//   code-from-data) are SOUNDNESS because we can't track side
//   effects the opaque code performs on the arguments / shared
//   heap.
//
//   Engineering gaps (unimplemented, heap-escape) are SOUNDNESS
//   because we skipped a construct whose effects we'd otherwise
//   track.
const DEFAULT_SEVERITY = Object.freeze({
  'network':              SEVERITIES.PRECISION,
  'attacker-input':       SEVERITIES.PRECISION,
  'persistent-state':     SEVERITIES.PRECISION,
  'dom-state':            SEVERITIES.PRECISION,
  'ui-interaction':       SEVERITIES.PRECISION,
  'environmental':        SEVERITIES.PRECISION,
  'runtime-time':         SEVERITIES.PRECISION,
  'pseudorandom':         SEVERITIES.PRECISION,
  'cryptographic-random': SEVERITIES.PRECISION,
  'unsolvable-math':      SEVERITIES.PRECISION,
  'opaque-call':          SEVERITIES.SOUNDNESS,
  'external-module':      SEVERITIES.SOUNDNESS,
  'code-from-data':       SEVERITIES.SOUNDNESS,
  'unimplemented':        SEVERITIES.SOUNDNESS,
  'heap-escape':          SEVERITIES.SOUNDNESS,
  // Performance shortcuts: precision by default. A widened
  // loop produces a value that's an OVER-approximation of every
  // iteration's real value, so the resulting findings are
  // conservative upper bounds — may over-report, never miss.
  // Same reasoning for summary reuse (the cached exit state
  // is ⊒ the per-caller-context exit state).
  'loop-widening':        SEVERITIES.PRECISION,
  'summary-reused':       SEVERITIES.PRECISION,
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
    // Cache of previously-raised assumptions keyed by
    // (reason, location.file, location.pos, affects). A repeat
    // raise at the same location returns the cached record so
    // loop bodies that revisit the same source read don't
    // produce a new id on every worklist iteration — which
    // would prevent the lattice from reaching fixpoint because
    // the Opaque values carrying fresh assumption chains would
    // never compare equal.
    //
    // The cache is keyed only by structural position (not by
    // the transfer-function call count), so two distinct AST
    // sites that happen to resolve to the same reason + location
    // (rare — usually impossible because pos differs) would
    // collapse into one. That is the desired behaviour for the
    // soundness floor: one "this read is opaque because X" per
    // source location.
    this._raisedCache = new Map();
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
    // Look up the cache. Use a compact string key.
    const affectsKey = o.affects || '';
    const posKey = (location.pos != null ? location.pos : -1);
    const fileKey = location.file || '';
    const cacheKey = reason + '|' + fileKey + '|' + posKey + '|' + affectsKey;
    const cached = this._raisedCache.get(cacheKey);
    if (cached) return cached;

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
    this._raisedCache.set(cacheKey, record);
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
