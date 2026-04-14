# Assumptions

Every time the analyser cannot determine a value or a
reachability answer exactly, it records an **Assumption** — an
explicit statement that the analysis is over- or
under-approximating at this point, with a reason code, a
location, a severity class, and a chain of upstream assumptions
it derives from.

Consumers access assumptions via `query.assumptions(trace)`. A
finding is trustworthy **iff** the assumptions on the path
source → sink are all classes the consumer is willing to
accept. A consumer that requires provable soundness rejects any
trace containing a `soundness`-class assumption; a consumer
tolerating over-approximation filters to `soundness` only.

## Assumption shape

```ts
type Assumption = {
  id: number;                 // unique within a Trace
  location: Location;         // { file, line, col, pos } where raised
  reason: AssumptionReason;   // machine-readable reason code
  details: string;            // human-readable explanation
  affects: Path | null;       // which abstract value became opaque
  severity: 'soundness' | 'precision';
    // soundness: may cause false negatives (missed findings)
    // precision: may cause false positives (over-reported findings)
  chain: number[];            // ids of upstream assumptions this one derives from
};
```

## Three justification classes

Every reason code falls into exactly one of three classes,
determined by whether the imprecision can ever be eliminated:

1. **Theoretical floor** — bytes or behaviour genuinely
   unknowable at analysis time. Cannot be eliminated by any
   amount of engineering. Examples: network bytes, user input,
   randomness, SMT undecidability.

2. **Environmental** — the information is outside the
   analyzer's current input (a module not bundled, a function
   whose body isn't in the TypeDB). Eliminable by providing
   more input: additional source files, TypeDB entries, or
   explicit annotations.

3. **Engineering gap** — a case the engine could model but
   doesn't yet. Eliminable by implementing the missing transfer
   function or analysis pass.

Every severity follows from these classes:

- Theoretical-floor reasons default to `precision` — the
  analyzer knows *that* the value is opaque and tags it with a
  label; the label propagates soundly, only the byte content is
  unknown.
- Environmental and engineering-gap reasons default to
  `soundness` — skipped code may perform side effects we can't
  track.

Individual raises can override the default when context
demands (e.g. an `opaque-call` to a provably pure built-in is
`precision`, not `soundness`).

## Reason codes

The catalogue below is the complete public set. Adding a new
code is a minor schema-version bump; removing or repurposing one
is a major bump.

---

## Class 1 — Theoretical floor

These are assumptions the analyzer is **forced** to raise
because the value or behaviour is mathematically or physically
unknowable at static-analysis time. No future improvement to
the engine eliminates them.

### `network`

**When raised.** A value is read from a runtime external
source: `fetch()`, `XMLHttpRequest`, `WebSocket`,
`EventSource`, `navigator.sendBeacon`, service worker `message`
events, cross-origin `postMessage` from an arbitrary origin,
`BroadcastChannel`.

**Why it's fundamental.** The bytes come from a remote server
that is not part of the static input. Even if the analyzer
somehow modeled the server, it would need the server's inputs,
which pushes the problem recursively with no bottom.

**Severity.** `precision`. The analyzer tags every derived
value with a `network` label that propagates soundly — the
tool reports every real flow. Over-reporting happens when the
actual response bytes happen to be safe at runtime.

**How to narrow.** Add a TypeDB entry declaring the response's
`readType` (e.g. `fetch('/api/user').readType: 'UserSchema'`)
and a schema type. The content is still unknown, but downstream
analyses can reason about its shape.

### `attacker-input`

**When raised.** A value is read from a source an attacker can
populate without requiring the victim to cooperate:

- `location.*` (href, hash, search, pathname, hostname) — the
  attacker crafts the URL and delivers it as a link.
- `document.referrer` — the attacker controls the source page.
- `window.name` when the document was opened by an untrusted
  context — the attacker (as opener) set the name before
  redirecting.
- Cross-origin `postMessage` from an unverified origin.
- URL-fragment / search-param-driven state.

**Distinction from `ui-interaction`.** The user does not type
this. The attacker crafted the payload and delivered it.
Self-XSS (where the user types a malicious payload themselves)
is classified as `ui-interaction`, not `attacker-input`, because
it requires active user cooperation.

**Why it's fundamental.** The value is chosen by a runtime
entity (the attacker) and arrives via the browser's URL/message
plumbing. The analyzer cannot predict what URL will be sent.

**Severity.** `precision`. Taint label propagates; byte content
unknown.

**How to narrow.** Sanitise (e.g. `encodeURIComponent`,
`DOMPurify.sanitize`) before use. Sanitisers declared in the
TypeDB clear the label on their output.

### `persistent-state`

**When raised.** A value is read from client-side persistent
storage: `document.cookie`, `localStorage`, `sessionStorage`,
`indexedDB`, the Cache API, service-worker stored state.

**Why it's distinct from `attacker-input`.** The user does not
control persistent state; same-origin script does. An attacker
can only influence this class if they had a prior foothold that
let them write to storage (via an earlier XSS, a compromised
same-origin script, a malicious browser extension). The threat
model is weaker than `attacker-input`, but the analyzer still
cannot read the bytes — they were written by code that ran in
a previous session or a prior tab.

**Why it's fundamental.** Storage state is persisted across
browser restarts and tabs. The analyzer sees only the current
source; the value it reads may have been written by a build of
the app long since deleted. There is no static view of what
`localStorage.getItem('token')` returns.

**Severity.** `precision`. Propagates a `persistent-state`
label (or a more specific label if the TypeDB declares a
schema).

**How to narrow.** For first-party keys with a known schema,
declare the schema in the TypeDB so downstream analyses can
treat the read as a typed value. For genuinely unknown keys,
the assumption stays.

### `dom-state`

**When raised.** A value is read from the live DOM tree:
`el.innerText`, `el.value` for a field that the analyzed code
didn't populate, `el.dataset.*`, attribute reads via
`getAttribute`, `el.textContent`, `document.title`.

**Why it's distinct.** DOM state is a mix of three things:
- values the same-origin app wrote earlier (like
  `persistent-state`)
- values a user typed via UI interaction (like
  `ui-interaction`)
- values an attacker injected via earlier HTML injection (like
  `attacker-input` composed with an earlier flow)

The analyzer doesn't know which of the three applies at the
read site without flow-sensitive provenance tracking. Tracking
that precisely is an engineering goal; in the interim the read
raises `dom-state` and the consumer decides how to interpret it.

**Why it's fundamental at read time.** The DOM is a runtime
data structure. A read returns whatever is currently stored
there, not what the analyzer-tracked write path produced.

**Severity.** `precision`.

**How to narrow.** When the analyzed code both writes and reads
the same DOM location within a tracked path, the analyzer can
(when implemented) connect them and eliminate the assumption.
For reads of DOM nodes the analyzed code didn't touch, the
assumption stays.

### `ui-interaction`

**When raised.** A value originated from an explicit user
interaction with a UI element:

- `form.elements[...].value` read inside an `input`, `change`,
  or `submit` handler after the user typed.
- `event.clipboardData` on `paste`.
- `event.dataTransfer` on `drop`.
- `FileReader` result after the user picked a file.
- `el.value` inside a handler whose event was fired by user
  action.

**Distinction from `attacker-input`.** The user actively
supplied this value. In a non-self-XSS threat model, the user
is trusted — so this assumption may be *irrelevant* for
security findings. It still raises an assumption because the
byte content is unknown statically; a consumer can filter
`ui-interaction` out of their severity calculus if their
threat model excludes self-XSS.

**Why it's fundamental.** The analyzer cannot predict what the
user will type, paste, drop, or upload.

**Severity.** `precision`.

**How to narrow.** Validate the input and declare the validator
as a sanitiser in the TypeDB — the label is cleared on
validated output.

### `environmental`

**When raised.** A value is read from the browser's read-only
environment: `navigator.*` (userAgent, language, platform,
hardwareConcurrency), `screen.*`, `window.innerWidth`,
`document.documentElement.lang`, feature-detection checks,
`window.devicePixelRatio`.

**Why it's distinct.** These values are opaque at analysis time
but typically not attacker-controlled in a normal threat model.
An attacker who controls the browser (via an extension) could
influence them, but that's a much stronger attacker than
a typical network adversary.

**Why it's fundamental.** Values are set by the browser / OS
at runtime. The analyzer has no static view of them.

**Severity.** `precision`.

**How to narrow.** Most security consumers treat
`environmental` as low-risk and filter it out. Functional
analyses may pin specific fields via TypeDB (e.g.
`navigator.language` is a BCP-47 string).

### `runtime-time`

**When raised.** A value is read from a deterministic time
source: `Date.now()`, `new Date()`, `performance.now()`,
`performance.timing.*`, `requestAnimationFrame` timestamps.

**Why it's distinct from randomness.** These sources are
**deterministic**, not random. They follow a monotonic clock
whose value depends on wall-clock time. The analyzer cannot
predict the specific number, but the value is not drawn from
any random distribution — it's a reading of the clock at
runtime.

Conflating time with randomness (as the old `randomness`
reason code did) was incorrect: time has completely different
properties for downstream reasoning. A time read can be
compared against a known timestamp, used for rate-limiting, or
treated as a monotonic counter; a random read cannot.

**Why it's fundamental.** Wall-clock time is an environmental
fact decided at runtime. The analyzer has no static view.

**Severity.** `precision`. The value flows as opaque through
downstream arithmetic; equalities against a concrete timestamp
cannot be decided.

**How to narrow.** For relative-time calculations
(`t2 - t1 > DELTA`) the analyzer can sometimes reason about
bounds via interval analysis, even though each absolute
timestamp is opaque. For absolute-time guards, the assumption
stays.

### `pseudorandom`

**When raised.** A value is read from `Math.random()`.

**Why it's distinct from cryptographic random.**
`Math.random()` returns a value from a pseudorandom number
generator. PRNGs are typically seeded once (per context) and
each output is a deterministic function of the seed and the
previous outputs. With enough observations, the seed can
sometimes be recovered and future outputs predicted. For
security-sensitive code this matters: a predictable PRNG is
useless for tokens, nonces, or session ids.

Lumping `Math.random` with `crypto.getRandomValues` (as the
old `randomness` reason code did) was dangerous because it
implied equivalent guarantees. They are not equivalent.

**Why it's fundamental.** The value produced at each call
depends on an internal PRNG state the analyzer cannot
reconstruct statically.

**Severity.** `precision`. The analyzer can bound the value
(`Math.random() ∈ [0, 1)`) via interval analysis but cannot
collapse to a single concrete.

**How to narrow.** Use `crypto.getRandomValues` for
security-sensitive contexts (changes the assumption class to
`cryptographic-random`, which carries stronger semantic
guarantees). For non-security uses, the interval bound is
usually enough.

### `cryptographic-random`

**When raised.** A value is read from
`crypto.getRandomValues()` or `crypto.randomUUID()`.

**Why it's distinct.** Cryptographic random values are
genuinely non-deterministic from any predictable seed. The
web crypto API draws from the OS entropy pool. Predicting
a specific output would constitute a break of the underlying
cryptographic primitive — meaning the assumption is **strictly
unremovable** in a way even stronger than `pseudorandom`.

**Why it's fundamental.** If the analyzer could predict
`crypto.getRandomValues()`, the analyzer would have broken
cryptographic randomness. This is provably hard.

**Severity.** `precision`. Value flows as opaque; the
guarantee propagates that it is unpredictable (useful for
downstream reasoning about token unguessability).

**How to narrow.** Not applicable — this is the strongest
possible random source and no narrowing is meaningful.

### `unsolvable-math`

**When raised.** The SMT solver returned `unknown` on a
reachability query, either because it timed out on a formula
in a decidable theory or because the formula is in an
undecidable theory (non-linear integer arithmetic with
quantifiers, Diophantine search, encoded halting behaviour).

**Why it's fundamental.** This is Rice's theorem applied
directly. Concrete undecidable cases that can be encoded as an
SMT reachability query include:

- `∃ x, y, z ∈ ℤ. p(x, y, z) = 0` for a general polynomial `p`
  — deciding this settles Hilbert's 10th problem, which
  Matiyasevich proved undecidable in 1970.
- A path condition that encodes a Collatz-like recursion —
  deciding settles an open mathematical problem.
- Any formula that embeds an arbitrary Turing machine's
  halting behaviour.

No solver, no matter how advanced, can return a yes/no answer
for these inputs.

**Severity.** `precision`. When SMT returns unknown, the
analyzer treats the branch as reachable (sound over-approximation).

**How to narrow.** Restructure the offending expression into
simpler sub-expressions that SMT can decide. For truly
undecidable fragments, the assumption stays — no amount of
engineering bridges this.

---

## Class 2 — Environmental

These assumptions exist because the information needed to
eliminate them is **outside the analyzer's current input**.
The consumer can eliminate each by providing more input —
additional source files, a richer TypeDB, or explicit
annotations.

### `opaque-call`

**When raised.** A call to a function whose body is not
available at analysis time:

- A native built-in not modeled in the TypeDB.
- An imported function from a module not in the input.
- A target resolved through a dispatch the analyzer couldn't
  narrow to a concrete function binding.

**Why it's not eliminable in isolation.** Without the function
body the analyzer doesn't know:
- Which arguments feed which outputs (input-to-output
  dependence).
- What side effects the call has on arguments or shared heap.

The engine conservatively joins all argument taints onto the
return value. This is sound for scalar returns but does not
cover mutations the function makes to object-typed arguments
or to global/shared state.

**Severity.** `soundness`. Arg-to-return flow is tracked;
arg-to-heap side effects are not. A function `f(obj)` that
mutates `obj.field` to a tainted value escapes detection until
heap-escape / effect-summary analysis is added.

**How to narrow.** Add a TypeDB entry for the function
declaring:
- Argument types and how they flow to the return.
- Write effects (which fields/globals the function mutates).
- Source and sink annotations.

This turns the opaque call into a precise transfer function.
All native browser APIs can be (and in the legacy engine, are)
modeled this way.

### `external-module`

**When raised.** An `import` references a module whose source
is not in the analyzer's input set — a third-party dependency,
a Node built-in, a CDN script, a dynamically loaded chunk
whose URL wasn't bundled.

**Why it's not eliminable in isolation.** The analyzer cannot
walk code it doesn't have. Every export from the module
becomes opaque.

**Severity.** `soundness`. Cross-module taint flow through the
external module is invisible. A helper that internally reads
`location.hash` and returns it would not be detected if the
helper lives in an external module we didn't bundle.

**How to narrow.** Bundle all relevant sources into the input
(first-party modules, vendored dependencies). For modules
whose source is genuinely unavailable (Node native addons,
binary imports), add TypeDB type declarations describing the
module's exports.

### `code-from-data`

**When raised.** Code whose **source is a runtime value** —
i.e. the string to be executed is computed at runtime and
cannot be walked statically:

- `eval(s)` where `s` is not a known constant string.
- `new Function(s)`.
- `setTimeout(s, ms)` / `setInterval(s, ms)` with a string
  first argument (the "string-as-code" form).
- `import(u)` where `u` is not a known constant URL.
- `script.textContent = s` / `script.src = s` with a
  non-constant expression.

**Naming rationale.** The old `dynamic-code` name was
misleading because every JavaScript operation is "dynamic" in
some sense — the term means nothing specific. `code-from-data`
precisely names the condition: the code's source bytes are a
runtime value, not a source-file constant.

**Constant-string eval is NOT this class.** When `eval("...")`
or `setTimeout("...", ms)` has a known constant string, the
engine tokenizes the string and walks it inline without
raising any assumption. The A11-closure pattern applies: the
code is analyzable, just lexically embedded in a string.

**Why it's not eliminable in isolation.** For truly
runtime-computed source, the bytes are determined by
`network` / `attacker-input` / `persistent-state` — whichever
upstream source produced the string. The assumption chains
back to that root cause.

**Severity.** `soundness`. The analyzer cannot walk the
dynamic code body, so any taint flow or side effect the code
produces is invisible.

**Mitigation at the call site.** `eval(tainted)` is also
reported as a `code` sink finding (not just an assumption), so
the dangerous case of running attacker-controlled code is
still flagged visibly — the analyzer just can't follow the
code's internal flow.

**How to narrow.** Replace dynamic `code-from-data` with
static code. If the set of possible source strings is a small
enum, use explicit dispatch instead.

---

## Class 3 — Engineering gaps

These assumptions exist because the engine doesn't yet model
a construct that could in principle be modeled. They are
**deliberately visible**: the alternative (silently treating
unknown constructs as opaque without a record) would be a
hidden assumption. Making them loud lets consumers audit the
floor of trust.

### `unimplemented`

**When raised.** The parser or IR builder encounters an AST
node kind that no current transfer function handles, OR a
specific analysis pass (type narrowing, dispatch resolution,
temporal ordering) is not yet wired up.

Concrete current triggers:
- Unsupported statement kinds: `for`, `while`, `do`, `switch`,
  `try`, `throw`, `break`, `continue`, `with`, `class`,
  `import`, `export`.
- Unsupported expression kinds: destructuring patterns, spread,
  template literals, optional chaining, nullish coalescing
  assignment.
- Computed member access (`obj[key]`) where the may-be lattice
  could not narrow the key to a finite set. This case was
  previously called `runtime-type` but is a specific instance
  of "dispatch not resolved" — an engineering gap, not a
  distinct theoretical class.
- Async ordering / temporal analysis (previously called
  `timing`). Treating the event loop as precise dispatch is a
  feature the engine doesn't yet model; each unmodelled
  interleaving raises this assumption.

**Why it's not a hidden assumption.** Every `unimplemented`
raise carries a `details` string naming the specific construct
or pass (e.g. `"statement kind not yet implemented: for"`) and
a `location` pointing at the source position. Consumers can
`query.assumptions(trace, { reason: ['unimplemented'] })` to
enumerate every feature gap affecting their code.

The alternative — skipping unknown constructs without a record
— would be a silent approximation. The alternative — crashing
— would be a usability disaster. This explicit-marker design
is the honest middle.

**Severity.** `soundness`. Unlike theoretical-floor reasons
(where we *know* the value exists but cannot predict bytes),
`unimplemented` means "code is here whose effects we didn't
model at all." Skipping may hide real flows.

**How to narrow.** Implement the missing transfer function.
Every `unimplemented` assumption is a concrete TODO with a
precise location. There is no theoretical obstacle — just
unwritten code.

### `heap-escape`

**When raised.** An object reference flows into an opaque
context — passed as an argument to an `opaque-call`, stored
in a container whose reads we can't narrow, assigned to a
property on an opaque object, or returned from a function
whose summary we don't have.

Once the reference escapes, subsequent reads of its fields
must return `⊤` because the opaque code may have mutated
them.

**Severity.** `soundness`. If an escaped object is read later
and its fields are used in a sink, the tracked pre-escape
value may not reflect the actual post-mutation state. Taint
flows through field mutations performed by the opaque consumer
are invisible.

**Why it's an engineering gap, not fundamental.** Proper
static analysis handles this with two techniques:
- **Points-to analysis** (Andersen 1994, Steensgaard 1996):
  track which heap cells each reference can point to; narrow
  the escape boundary to a concrete set of objects.
- **Effect-tracking function summaries**: each opaque callee's
  TypeDB entry declares which fields it reads and writes;
  reads on escaped objects join over the union of all declared
  writes plus an `unknown-external-write` label.

Both are standard static-analysis techniques. Neither is yet
implemented in jsanalyze — but they have no theoretical
barrier.

**How to narrow.** Short term: keep mutable objects local to
the analyzed scope; prefer immutable data; annotate external
APIs with `writes` descriptors in the TypeDB. Long term: wait
for the points-to / effect-summary pass.

---

## Class 4 — Performance shortcuts

These reason codes are unique: they mark places where the
engine took a precision-for-time tradeoff that the consumer
can explicitly opt out of. Unlike classes 1-3, rejecting a
performance-shortcut reason via `options.accept` PREVENTS the
engine from taking the shortcut in the first place — the
engine walks exhaustively instead.

### `loop-widening`

**When raised.** A loop header's back-edge variants were
pointwise-joined into a single widened variant instead of
kept as distinct per-iteration variants. This keeps loop
analysis finite (a 1000-iter counter loop would otherwise
spawn 1000 variants and take ~100s); with widening it
converges in milliseconds.

**Severity.** `precision`. The widened variant is an
OVER-approximation of every iteration's actual state, so
findings derived from it are conservative upper bounds — may
over-report, never miss.

**Rejection effect.** The engine does NOT apply the widening.
Back-edge variants stay distinct, loops converge only at the
value-lattice level, analysis time grows linearly in loop
iteration count. The consumer is responsible for accepting
the slowdown (and the risk that unbounded loops may not
terminate).

**How to narrow.** Use smaller loop bounds in test fixtures;
prefer recursive formulations the summary cache can handle;
or accept the widening and audit the raised sites.

### `summary-reused`

**When raised.** A user-function call hit the D7 k-CFA
summary cache and the engine replayed the cached exit state
instead of walking the body fresh. The key is
`(body, argsFingerprint, thisFingerprint)`; repeated calls
with the same fingerprint share a summary.

**Severity.** `precision`. The cached exit state is ⊒ the
per-caller exit state in the lattice order, so reusing it is
sound — any finding that would have fired on a fresh walk
also fires on the cached replay.

**Rejection effect.** The engine does NOT consult the cache
and does NOT populate it. Every call site walks the callee
body fresh, giving full context sensitivity at O(calls × body)
cost. This is equivalent to `precision: 'exact'` scoped to the
summary cache.

**How to narrow.** Keep function arities small so argument
fingerprints are selective; or accept the reuse and audit the
raised sites.

---

## Severity handling

Consumers choose how strictly to interpret each severity class.

### Strict consumer

Rejects any trace containing at least one `soundness`
assumption on any path feeding a reported finding. Use for
security gating, compliance checks, or any setting where
missed findings are unacceptable.

```js
const unsound = query.assumptions(trace, { severity: 'soundness' });
if (unsound.length > 0) throw new Error('analysis not provably sound');
```

### Permissive consumer

Accepts `soundness` assumptions but reports them alongside
findings so the end user knows the guarantee is conditional.
The default mode for most interactive tools.

### Tolerant consumer

Ignores `precision` assumptions and only surfaces
`soundness` ones. Use when the consumer explicitly accepts
over-reporting (e.g. linters that prefer false positives to
false negatives).

---

## Assumption chains

When an opaque value flows into another operation that itself
becomes opaque, the downstream assumption records the upstream
assumption's id in its `chain` field. Walking the chain
backwards recovers the root cause of every `Opaque` value in
the trace.

Example chain:
1. `network` at `fetch('/api/config')` → value flows into a
   variable `cfg`.
2. `code-from-data` at `eval(cfg.script)` → chains back to the
   network assumption.
3. `unimplemented` at a `for` loop inside a function that
   reads `cfg.script` later → chains back to the network
   assumption via a different path.

`query.assumptions(trace, { affectsPath: 'cfg.script' })`
returns all assumptions touching that path. The `chain` field
on each lets consumers traverse the DAG to find root causes.

---

## Catalogue stability

- **Versioned.** Reason codes are part of the stable public
  API. Adding a new code is a minor schema-version bump
  (current: `schemaVersion: '2'`); removing or repurposing
  one is a major bump.
- **Closed set.** `REASONS` in `src/assumptions.js` is
  `Object.freeze`d; attempting to raise an unknown reason
  throws at analysis time. No undeclared reasons can sneak in.
- **No duplicates.** Every approximation maps to exactly one
  reason code. The taxonomy was audited to eliminate
  overlapping classes (e.g. `user-input` was split because
  it conflated attacker-controlled URLs with
  user-typed form values; `randomness` was split because it
  conflated deterministic time with pseudorandom and
  cryptographic random sources; `runtime-type` was folded into
  `unimplemented` because it was a specific case of "dispatch
  not narrowed" rather than a distinct class).
