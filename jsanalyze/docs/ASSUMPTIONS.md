# Assumptions

Every time the analyser cannot determine a value or a reachability
answer exactly, it records an **Assumption** — an explicit
statement that the analysis is over- or under-approximating at this
point, with a reason code and a location.

Consumers access assumptions via `query.assumptions(trace)`. A
result that depends on a particular path is trustworthy iff the
assumptions on that path are all classes the consumer is willing
to accept.

## Assumption shape

```ts
type Assumption = {
  id: number;                 // unique within a Trace
  location: Location;         // { file, line, col } where raised
  reason: AssumptionReason;   // machine-readable reason code
  details: string;            // human-readable explanation
  affects: Path | null;       // which abstract value became opaque
  severity: 'soundness' | 'precision';
    // soundness: may cause false negatives (missed findings)
    // precision: may cause false positives (over-reported findings)
  chain: number[];            // ids of upstream assumptions this derives from
};
```

## Reason codes

### `network`

**When raised.** A value is read from a runtime external source:
`fetch()`, `XMLHttpRequest`, `WebSocket`, `EventSource`,
`navigator.sendBeacon`, service worker `message` events, cross-
origin `postMessage`, `BroadcastChannel`.

**Severity.** Precision. Findings involving network-sourced values
are sound — the tool reports them — but over-report when the runtime
content is actually safe.

**Why not soundness.** The analyser knows a network read happened
and tracks the labeled value through downstream operations. It
can't know the content, so every derived value is tagged `Opaque`
with this assumption.

**How to narrow.** Add a TypeDB entry for the network endpoint that
declares the response's `readType` (e.g. `{ readType: 'Response<User>' }`)
and a `UserSchema` type declaration.

### `user-input`

**When raised.** A value is read from `location.*`, `document.cookie`,
`document.referrer`, `window.name`, `document.forms[*]`,
`event.data`, `event.clipboardData`, `event.dataTransfer`,
`navigator.*`, `localStorage`, `sessionStorage`, `indexedDB`, or
the DOM element's `value` / `textContent` / `innerText` / `files`.

**Severity.** Precision. The analyser treats these values as
attacker-controlled strings of arbitrary content.

**Why not soundness.** The labels carried by user input values
propagate through every operation. The finding reports are sound;
they just may over-include runtime cases where the input happens
to be benign.

**How to narrow.** Apply a sanitiser (declared via TypeDB
`sanitizer`) to the value before use; the assumption is dropped on
the sanitised result.

### `randomness`

**When raised.** A value is read from `Math.random()`,
`crypto.getRandomValues()`, `crypto.randomUUID()`, `Date.now()`,
`performance.now()`, `new Date()`. Also triggered by external time
sources like `requestAnimationFrame` timestamps.

**Severity.** Precision. Randomised values produce different
results at each runtime execution, so the analyser can't pin them
to a single value.

**Why not soundness.** Randomised values participate in value
propagation with full label tracking; they just can't be compared
against a concrete constant.

**How to narrow.** Use an interval or bound annotation in the
TypeDB for sources with known ranges (e.g. `Math.random()` is
`[0, 1)`).

### `timing`

**When raised.** A value or control-flow decision depends on the
order in which async callbacks fire — `setTimeout`, `setInterval`,
`requestAnimationFrame`, `queueMicrotask`, promise resolution
order, event-loop interleaving.

**Severity.** Precision. The analyser computes a fixpoint over
all possible interleavings, so the reported values are sound but
may over-include sequences that never occur in practice.

**Why not soundness.** Every reachable handler is walked at least
once in the callback fixpoint; no callback is silently ignored.

**How to narrow.** Rare. True order-dependent bugs are themselves
order-dependent and usually not worth refining statically.

### `unsolvable-math`

**When raised.** The SMT layer returned `unknown` (timeout, or a
theory the solver can't decide — e.g. non-linear arithmetic with
quantifiers, or a formula that embeds a Diophantine search).

**Severity.** Precision. When SMT can't refute a branch, the
analyser treats it as reachable. Findings on the branch are
sound but may over-report.

**Why not soundness.** SMT is only used at layer 4 of the
reachability cascade. Layers 1–3 (structural, value-set,
path-sensitive propagation) have already refuted what they could.
A layer-4 `unknown` means the remaining case is genuinely in
the hard fragment — sometimes provably undecidable (as with
embedded Collatz or Diophantine search), sometimes just difficult.

**How to narrow.** Break the offending expression into simpler
sub-expressions, or provide a manual annotation that the analyser
can substitute in place of the hard formula.

### `unimplemented`

**When raised.** The engine encounters a JavaScript construct it
doesn't yet model. Every such site is an explicit TODO with a
location.

**Severity.** Soundness. An unimplemented construct becomes
`Opaque` and its effects on the surrounding state are
over-approximated — which can HIDE real flows if the construct
would have propagated a label.

**Why soundness.** Unlike external inputs, the analyser could in
principle track values through an implemented construct but
currently doesn't. Every `unimplemented` assumption is a
concrete feature-gap that weakens the soundness guarantee.

**How to narrow.** Implement the transfer function. Each
`unimplemented` site documents exactly which AST node kind is
missing.

### `dynamic-code`

**When raised.** `eval(s)` where `s` is not a known constant
string; `new Function(s)`; `setTimeout(s, ms)` where `s` is a
string; `import(u)` where `u` is not a known constant string;
`script.textContent = s`.

**Severity.** Soundness. The analyser cannot walk the dynamic
code body, so any taint that the dynamic code would propagate or
consume is invisible.

**Why soundness.** For constant strings, the eval handler
tokenises the string and walks it inline — no assumption raised.
This reason fires only for the non-constant case. The code sink
finding still fires at the call site so the dangerous case is
reported.

**How to narrow.** Replace dynamic code with static code. For
cases where the dynamic code is a bounded enum of constants,
refactor to a dispatch over known branches.

### `opaque-call`

**When raised.** A call to a function whose body is not available
(external module, native built-in not in the TypeDB, dynamically
dispatched target the analyser couldn't resolve).

**Severity.** Soundness in the arguments-to-outputs direction —
the analyser can't know how the function combines its inputs
into its output. In practice it conservatively joins all argument
labels onto the return value.

**Why soundness.** The analyser doesn't know which args feed
which outputs, so it unions all arg taints onto the result. This
is over-approximation for outputs but could HIDE flows that pass
through side effects on the arguments (e.g. `f(obj)` mutating
`obj.field`).

**How to narrow.** Add a TypeDB entry for the function with
explicit argument/return descriptors. Side effects are modelled
via `writes` annotations.

### `external-module`

**When raised.** An `import` references a module that isn't in
the analyzer's input (a third-party dependency, a Node built-in,
a dynamically loaded script).

**Severity.** Soundness. Any values exported by the external
module are opaque.

**Why soundness.** Cross-module taint flow through the external
module is invisible. For example, a helper from a dependency that
internally reads `location.hash` and returns it would not be
detected.

**How to narrow.** Include the module's source in the input, or
add a TypeDB type declaration describing its exports.

### `runtime-type`

**When raised.** A value's type is determined by a runtime
dispatch the analyser can't resolve statically — e.g. reading a
property whose name is computed at runtime (`obj[userInput]`), or
instantiating a class held in a variable
(`new classes[kind]()`), or calling through a dynamic dispatch
table.

**Severity.** Precision. The analyser falls back to the join
over every possible target type.

**Why not soundness.** Each possible target is still walked via
the fixpoint, so no flow is missed — the report just includes
the union.

**How to narrow.** Restrict the dispatch via the may-be lattice
(ensure the computed key can only take known literal values), or
convert to an explicit switch.

### `heap-escape`

**When raised.** An object reference escapes the analysis
boundary — passed to an opaque function, stored in a data
structure read by an opaque source, assigned to an external
property.

**Severity.** Soundness. Once an object escapes, the analyser
can no longer track writes to it, so a later read of a mutated
field may see a stale value.

**Why soundness.** The analyser doesn't know what the external
consumer did with the object, so it over-approximates the object
as "any field may have been written". This is safe for reads
(they see top) but can miss the actual post-mutation state.

**How to narrow.** Keep the object local to the analysed scope.
Avoid passing it to opaque callees.

## Severity handling

Consumers choose how to treat each severity class:

- A **strict** consumer rejects any trace that has at least one
  `soundness` assumption. Use this when findings must be provably
  sound (security gating, compliance checks).

- A **permissive** consumer accepts `soundness` assumptions but
  reports them alongside findings so the user knows the guarantee
  is conditional.

- A **tolerant** consumer ignores `precision` assumptions
  entirely and only surfaces `soundness` ones.

## Assumption chains

When an opaque value flows into another operation that itself
becomes opaque, the downstream assumption records the upstream
assumption's id in its `chain` field. Walking the chain backwards
recovers the root cause of every `Opaque` value in the trace.

## Catalog expansion

This list is the current catalog. New reason codes are added when
a new class of approximation is identified; existing codes are
never repurposed. Every assumption's reason code is part of the
public API's stable contract.
