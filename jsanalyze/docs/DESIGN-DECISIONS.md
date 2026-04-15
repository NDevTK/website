# Design decisions

This document records the architectural decisions made at the
start of the full build-out. Future commits are held to these;
when a decision turns out wrong, the correct response is to
amend this document *and* the implementation in the same
commit, not silently drift.

## Scope

The library must eventually support two real consumers as
primary validation targets:

1. **DOM conversion** — rewrite `innerHTML` / `outerHTML` /
   `document.write` assignments into safe `createElement` /
   `appendChild` trees. Preserves loops, branches, and
   function boundaries.
2. **PoC synthesis** — take a taint flow, invoke Z3 with the
   accumulated path condition + a sink-specific exploitability
   constraint, produce a concrete attacker input that triggers
   the sink.

The library is integrated into `analyzer/index.html` (Monaco
editor + sidebar + findings panel). The legacy engine that
previously lived at `htmldom/jsanalyze.js` has been deleted
and the `analyzer/` UI is now the only entry point.

## Architectural decisions (fixed before implementation)

### D1. TypeDB is pure data with no code

The TypeDB is a plain JavaScript object matching the schema
documented in `docs/TYPEDB.md`. No functions, no classes, no
behaviour. The engine applies the TypeDB through a single set
of lookup helpers (`_lookupProp`, `_lookupMethod`,
`_resolveReturnType`, `_classifySink`). This makes it trivial
to replace the default DB with a custom one for Node APIs,
Web Worker APIs, or a custom runtime.

The default browser TypeDB was ported wholesale from the
original engine's `DEFAULT_TYPE_DB` block (~1500 lines of
declarative data) and now lives at
`jsanalyze/src/default-typedb.js`. It was not rewritten —
the original DB is the source of truth for browser semantics
and has been validated against 1000+ tests.

**Rationale.** Rewriting the TypeDB risks losing accumulated
knowledge about DOM edge cases that took years to surface.
Porting preserves them verbatim.

### D2. IR uses SSA with explicit phi nodes, not a def-use chain

Every register is written exactly once. Merges at control
flow introduce explicit `Phi` instructions at the top of the
merge block. Transfer functions dispatch on instruction kind;
there is no def-use chain API.

**Rationale.** SSA is the simplest form that supports
path-sensitive analysis. Def-use chains duplicate information
already present in the IR. Standard compiler infrastructure.

### D3. Abstract state uses overlay maps without a depth cap

State is `{ own: Map, parent: State | null }`. Writes hit the
top overlay in place (when mutable) or push a new layer (when
frozen). No flattening threshold. Chain depth grows with
program size; reads are O(depth).

**Rationale.** A depth cap is an arbitrary assumption. The
real fix for deep-chain performance is Hash Array Mapped
Tries (HAMT) or similar persistent data structures; adding
them later is a pure perf change that doesn't affect
correctness. Until then, the library is linear on realistic
inputs (confirmed by stress tests up to 50k sequential
statements and 5k-deep call chains).

### D4. Path conditions are SMT-LIB AST fragments, not strings

Every branch pushes an SMT formula (built via
`smt.and/or/not/cmp/str_concat`) onto the state's path
condition stack. Formulas are represented as small records
with `expr` (s-expression string), `sorts` (symbol → sort
declarations needed), and `incompatible` (set iff the formula
can't be translated soundly to SMT-LIB).

The reachability cascade consumes these formulas directly:
Layer 4 (Z3) asks `(check-sat)` on the conjunction.

**Rationale.** The legacy engine stores path conditions as
both SMT ASTs and human-readable strings. The new engine
stores only the SMT AST — the string form can always be
derived from `expr` when needed for display. One source of
truth.

### D5. SMT integration uses Z3 via the vendored `z3-solver` WASM

Z3 is vendored as a real copy (not a symlink) under
`jsanalyze/vendor/z3-solver/`. The directory is a verbatim
copy of the `z3-solver` npm package's build output:
`z3-built.js` + `z3-built.wasm` (the emscripten WASM module
and its loader), `node.js` + `browser.js` (the Node and
browser entry points), and the TypeScript high-level / low-
level wrappers. The tree is checked into git so the engine
has a self-contained copy that doesn't depend on `node_modules`
at any consumer's level.

The SMT layer imports Z3 through a single `_initZ3()` function
in `src/z3.js` that works in both Node (requires the vendored
`node.js` entry via an absolute path rooted at `__dirname`)
and the browser (via the existing `globalThis.__htmldomZ3Init`
hook from `analyzer/jsanalyze-z3-browser.js`, which itself
loads the vendored `z3-built.js` and `browser.esm.js`). Z3 is
REQUIRED — there is no fallback; if the solver can't load,
analysis fails loudly.

The Node path deliberately uses the vendored `node.js` entry
directly (`vendor/z3-solver/node.js`) rather than
`require('z3-solver')`, so the engine's behaviour is
independent of whatever happens to sit in `node_modules` at
the consumer's level. The vendor directory is the sole source
of truth for the Z3 binary.

**Rationale.** A real vendor copy (vs a symlink into the
legacy engine's tree) means `jsanalyze/` is self-contained
and moveable. Z3 is heavy (33 MB WASM) but the engine would
need to ship its own copy for the browser bundle (D12) anyway,
so duplication is inevitable — checking it in once avoids a
build-time copy step and makes `git clone` enough to run the
tests. Requiring Z3 (no optional fallback) means the "proper
interprocedural, path-sensitive, state-correlated" contract
holds in every deployment; consumers never silently downgrade
to a weaker analysis because their install is incomplete.

### D6. Reachability is a 5-layer cascade with no layer skipped

Every branch check goes through all 5 layers in order:
structural (O(1)) → constant fold (O(1)) → value-set
refutation (O(value-set size)) → path-sensitive propagation
(O(refined vars)) → SMT (one Z3 call). A branch is decided at
the earliest layer that can decide it. SMT is only called
when layers 1-4 return unknown.

**Rationale.** SMT calls dominate analysis wall time on
realistic inputs. Cheap layers must run first. The cascade
ordering is fixed in code, not configurable — if a consumer
wants to skip SMT, they add `'smt-skipped'` to
`options.accept` which gates the Layer 5 invocation and
the post-pass refutation on the accept set — the SAME axis
that controls `loop-widening` / `summary-reused`. There is
no parallel `options.precision` knob: a single
`options.accept` set is the source of truth for every
precision / performance / soundness trade-off.

### D7. Interprocedural analysis uses k-CFA context sensitivity via summary cache

Function calls are walked with the callee's CFG and bound
arguments. The result is cached by
`(body range, argument fingerprint, this fingerprint)` so
the same call site with the same abstract input replays the
summary without re-walking. Recursion is guarded by exact
`(body, args)` duplicate detection — a call with the same
body AND same arg fingerprint already on the call stack
returns opaque; different args proceed.

Closures capture their outer environment explicitly at
creation time: the `Func` instruction lists every outer
register the body references, and `instantiateFunction`
binds them into a fresh frame when called.

**Rationale.** Context sensitivity without the blowup of
full path sensitivity. Summary cache makes repeated calls
free. Explicit closure capture avoids global scope chain
walking.

### D8. Taint labels are a separate concept from abstract values

A `Value` carries an optional `labels: Set<Label>` where
`Label` is a string like `url`, `cookie`, `network`,
`persistent-state`. The label propagates through every
operation (concat, binop, prop read, call result) via a
simple union rule. Sinks consume labels; sanitizers clear
them.

**Rationale.** Taint tracking is orthogonal to value
tracking. A value can be simultaneously `Concrete("foo")` and
tainted; the concreteness tells the engine what the string
looks like, the label tells it who controls it.

### D9. TaintFlow records are emitted eagerly at sink sites

When the engine sees a sink operation (e.g.
`SetProp(el, 'innerHTML', value)` where `value` has
`labels: {url}`), it immediately emits a `TaintFlow` record
into the trace. The record contains:
- source: every label with its origin location
- sink: kind, prop, location
- pathConditions: snapshot of the current SMT formula stack
- pathFormulas: the raw SMT ASTs (for the PoC synthesizer)
- assumptionIds: every assumption on the path

**Rationale.** The consumer reads flows from `trace.taintFlows`
without re-walking. The path condition is captured at the
exact moment the flow is seen, which is when the information
is available.

### D10. The HTML literal parser is a library-local module, not a dependency

For DOM conversion, the engine needs to parse HTML literals
(string arguments to `innerHTML = ...`). A dedicated HTML
tokenizer + tree builder lives at `src/html.js`, ~800 lines,
handles the subset needed: open/close tags, attributes,
text, comments, CDATA, void elements, script/style raw
content. It does NOT handle the full HTML5 parsing algorithm
(form elements, foster-parenting, table edge cases) —
consumers that need full HTML5 get it by running the input
through a real parser externally and feeding us the result.

**Rationale.** HTML parsing is the hot path for DOM
conversion. A hand-rolled parser avoids pulling in a
200kb dependency like parse5. Full HTML5 compliance is out
of scope — the DOM conversion is a rewrite, not a renderer.

### D11. Consumers live under `jsanalyze/consumers/`

Each consumer is a standalone file that imports `jsanalyze`
via its public API (`analyze`, `query`). Consumers don't
reach into the engine internals. The directory contains:

- `dom-convert.js` — innerHTML → createElement rewriter
- `poc-synth.js` — SMT-based exploit generator
- `taint-report.js` — human-readable findings
- `fetch-trace.js` — HTTP endpoint discovery
- `csp-derive.js` — CSP policy derivation

Each is 200-500 lines. The first two are primary; the last
three are ports of the legacy consumers, added after the
first two are working.

**Rationale.** Separation of concerns: the engine is generic,
consumers are domain-specific. A new consumer is a new file,
not a patch to the engine.

#### D11.1 What belongs in the engine vs in consumers

This is load-bearing for the "library vs consumer" split —
every piece of logic has a definite home, and drift between
the two is a design bug.

**In the engine (`src/`):**

Anything that computes KNOWLEDGE about the program — its
values, its shapes, its reachability, its interprocedural
effects. Every observation consumers might want is
produced here and lands on the Trace.

Specifically:
  * Parsing JS source → AST → IR → CFG.
  * Abstract interpretation over the value lattice.
  * Taint tracking (source → sink).
  * Interprocedural walking, path sensitivity, state
    correlation (B4), summary caching (C3).
  * Z3 refutation (Layer 5 of the branch cascade + post-pass).
  * HTML literal parsing (via `src/html.js`) when the
    analyzer sees an innerHTML / outerHTML / insertAdjacentHTML
    sink with a non-empty string value. The parser's tree
    AND its flat token stream are both attached to the
    trace's innerHtmlAssignment record.
  * **Structured HTML-template extraction** from JS
    accumulator patterns. When an innerHTML value is built
    by a loop (`var H = '<nav>'; for (...) { H += ...; }
    ...; elem.innerHTML = H;`) or a branch (`if (...) H =
    'a'; else H = 'b';`) or a nested combination, the
    engine recognises the shape at the AST level and
    attaches a structured `HtmlTemplate` to the
    innerHtmlAssignment. The template covers:
      - `kind: 'concrete'` — fully static string (parsed HTML tree)
      - `kind: 'loop'`     — for / while / do-while / for-in /
                             for-of accumulator, including
                             branch-in-loop patterns that
                             collect one accumSite per
                             append inside the body
      - `kind: 'branch'`   — if/else, ternary, else-if chains
                             and nested ternaries (recursive
                             branch templates)
      - `kind: 'switch'`   — switch/case accumulator
      - `kind: 'append'`   — `innerHTML +=` or one-shot
                             fragment build from a concat chain
                             or TemplateLiteral RHS
      - `kind: 'opaque'`   — the engine couldn't recognise
                             a pattern (the consumer decides
                             what to do: leave alone, wrap
                             in a runtime sanitizer, or emit
                             a TODO).
  * Interprocedural callback walking (addEventListener,
    setTimeout, etc.). Sinks inside callbacks appear on the
    trace via callback walking, not via per-consumer AST
    detection.
  * Multi-file project analysis (`options.project`) with
    shared top-level scope so cross-file references
    resolve.

**In consumers (`consumers/`):**

Anything that EMITS output — source rewrites, reports, CSP
directives, exploit PoCs. Consumers read the Trace and
produce their domain-specific result. They never
re-analyze, never run their own AST passes over the input
source, and never reach into engine internals.

Specifically:
  * Format conversion: taintFlow records → human-readable
    report; trace.calls → CSP directive lists.
  * Source-range rewriting: given a trace and the original
    source, apply replacements at the positions the
    engine reported. This is text substitution, not
    analysis.
  * HTML-token-stream mutation: dom-convert reads
    `innerHtmlAssignment.htmlTokens` / `.template` from the
    trace and emits DOM calls. It does NOT re-parse the
    JS source looking for loop patterns — that's what
    `innerHtmlAssignment.template` is for.
  * Consumer-specific filtering: fetch-trace filters
    trace.calls by callee name; csp-derive groups
    trace.calls + trace.stringLiterals + trace.domMutations
    by CSP directive.

**The rule.** If a consumer is parsing JavaScript or
running an AST walker, it's in the wrong place. The engine
parses once, and every observation a consumer needs is
pre-computed on the Trace. Consumers that feel the need
to re-parse are a signal that the Trace shape needs a new
observation field, which is a patch to the engine — not a
workaround in the consumer.

### D12. Browser integration preserves the legacy UI

The target is `analyzer/index.html`. The new engine will be
loadable as:

```html
<script src="jsanalyze/vendor/z3-solver/z3-bootstrap.js"></script>
<script src="jsanalyze/browser-bundle.js"></script>
```

The `browser-bundle.js` is a concatenation of all `src/*.js`
files with a single IIFE wrapper exposing `window.jsanalyze`
= `{ analyze, query, consumers }`. No module system, no
build step — the CommonJS `require()` calls in the source
are replaced at bundle time with references to the other
files by name.

**Rationale.** The legacy UI loads scripts via bare `<script>`
tags. Matching that pattern avoids rewriting the HTML or
adding a bundler. The browser bundle is a simple concatenation
script (~30 lines), not a webpack config.

### D13. No silent exception catches anywhere in the engine

The only try/catch sites are the two analysis boundaries in
`src/index.js`. Every other caught exception is a hidden
assumption and is forbidden. The `test/no-caps.test.js`
regression guard enforces this structurally (greps the source
tree). New code added under this plan must not introduce new
catches.

**Rationale.** Already committed as a principle (commit
`ce90ac7`). Restated here to prevent drift.

### D14. No arbitrary numeric thresholds

No maxIterations, maxOverlayDepth, maxLatticeSize, maxPathDepth,
maxRecursionDepth, maxCartesianProduct, maxStringLength. All
bounds are either structural (given by the input) or decided
structurally (SMT yes/no). Performance characteristics are
documented as complexity classes, not hidden behind tuned
constants.

**Rationale.** Already committed. Same reason as D13.

### D15. Assumption catalog is closed

The 15 reason codes defined in `src/assumptions.js` are the
complete public set. Adding a new code is a minor schema
bump; removing or repurposing one is a major bump. If a new
situation arises that doesn't fit any existing code, the
correct response is to add a new code to the catalog in
`src/assumptions.js` AND document it in `docs/ASSUMPTIONS.md`
in the same commit.

**Rationale.** The catalog is part of the stable public API.
Consumers filter on reason codes; unstable codes break them.

### D16. Tests are additive, not rewritten

Every commit lands tests for every feature it adds. Existing
tests are not rewritten when a feature replaces a stub; the
stub tests are deleted, the new tests are added. The test
count only grows, except where a feature removal explicitly
deletes tests for the removed feature.

**Rationale.** Test churn hides regressions. A feature that
replaces a stub must pass the stub's tests (unchanged) and
add new ones for its new capabilities.

### D19. Worklist is multi-variant (trace partitioning)

Each block in `worklist.analyseFunction` carries a SET of
variants rather than a single joined state. A variant is a
full State (regs + heap + path + effects + assumptionIds +
callStack). Equivalent variants — same `(regs, heap)` — merge
disjunctively (OR their paths, union their assumptionIds and
effects). Distinct variants stay separate through joins so
**cross-register correlation survives merges**.

Without this, a pointwise join at
```
  if (c) { x = 1; y = "a"; } else { x = 2; y = "b"; }
```
loses the `x=1 ⇔ y="a"` correlation: `x` becomes `oneOf{1,2}`,
`y` becomes `oneOf{"a","b"}`, and a later `if (x === 1)` refines
`x` but can't refine `y`. A sink on `y` inside the true branch
then fires with a joined-in `"b"` the true path can never
actually see. Multi-variant keeps `{x=1, y="a"}` and
`{x=2, y="b"}` as separate variants; `if (x === 1)` eliminates
the second variant entirely and the false positive disappears.

Loop handling: back-edge arrivals at a loop header pointwise-
join with any existing back-edge variant for the same
predecessor. Forward edges stay distinct. This collapses per-
iteration variants at loop heads (otherwise a 1000-iter
counter loop spawns 1000 variants) while preserving
pre-loop/post-loop correlation.

Phi resolution: phis are eagerly resolved at enqueue time,
using the specific predecessor variant's state. This is what
makes cross-register correlation survive nested join points —
a variant arriving from predecessor B carries the correlated
values of predecessor B, not a pool over all predecessors.

**Rationale.** Wave 10 / B4. Trace partitioning is the
standard technique for recovering cross-register correlation
in a forward dataflow analysis. The alternative — staying with
pointwise joins and doing per-path reasoning purely at the SMT
layer — makes every sink emission a Z3 call, which is orders
of magnitude slower and depends on Z3 understanding every
abstract value kind (it doesn't). Trace partitioning handles
the correlation at the lattice level and reserves Z3 for the
residual cases where only symbolic reasoning helps.

### D17. Documentation stays in sync with code

Every commit that changes a public API updates the
corresponding doc (`docs/API.md`, `docs/ASSUMPTIONS.md`,
`docs/IR.md`, `docs/ABSTRACT-DOMAIN.md`) in the same commit.
Docs drift is a soundness bug against consumers.

**Rationale.** Consumers read the docs, not the source.

### D20. Conversion is complete, taint is precise

The two primary consumers have DIFFERENT soundness rules.

**DOM conversion** is a source-to-source rewrite whose
output must be safe to run. It therefore MUST handle every
syntactically-present sink, regardless of whether the
engine's reachability analysis walked the block that
contains it. Skipping an unreachable-per-analysis sink
leaves an unpatched security hole the moment the runtime
takes a path the analysis ruled out. Refutation is sound
w.r.t. the model, not the world, so the rewriter commits
to a literal source transformation and doesn't consult
`checkPathSat`.

Mechanically: `consumers/dom-convert.js` enumerates sites
via `src/html-templates.js:findAllAssignments`, which
walks the AST and returns every `innerHTML` / `outerHTML` /
`insertAdjacentHTML` / `document.write` / `document.writeln`
occurrence — including ones inside dead branches, never-
called functions, and nested closures. The template
extractor runs on each site, consulting only source-level
structure. The trace's `innerHtmlAssignments` entries are
merged in where the walker also reached the site, so the
rewriter gets richer lattice-derived templates (taint
labels, accumulator shapes) when available without
depending on them for site discovery.

The one exception is "walked plain-object receiver". The
engine records every syntactic innerHTML / outerHTML
SetProp it executed in `trace.walkedHtmlSites`, DOM or
plain-object. When the AST walker finds a site that's in
`walkedHtmlSites` but NOT in `innerHtmlAssignments`, the
receiver is a non-DOM object and the rewrite is skipped —
converting it would turn a harmless field write into a
broken `createElement` call. Dead-branch sites are absent
from `walkedHtmlSites` entirely and fall through to the
structural rewrite path.

**Taint tracking**, by contrast, is reachability-gated.
The engine's job is to tell the user "this flow is
actually exploitable", and false positives under
infeasible path conditions erode the signal. Flows behind
an SMT-refuted branch are killed at Layer 5 during the
walk (the block isn't enqueued past the refuted edge, so
`applySetProp` never fires at the sink). Flows that survive
walk-time with a non-trivial `pathFormula` go through the
post-pass `z3.refuteTrace`, which conjoins `pathFormula`
with Z3 and drops any flow returning UNSAT (moving them
to `trace.refutedFlows` for audit). A consumer that
accepts `smt-skipped` loses both passes and has to live
with the extra noise.

**The two rules coexist**: taint is precise because
refutation is sound over the analysed model, conversion
is complete because it refuses to trust the refutation
for a source-level transform. One trace feeds both
consumers without either compromising the other.

**Tests**: `dom-convert.test.js` has explicit regression
cases for dead-branch rewriting (`if (1 === 2) { … }`),
uncalled-function rewriting (`function render() { … }`),
nested dead-branch rewriting inside a function body, and
an infeasible-path taint-gate case that confirms the flow
list is empty while conversion continues to run cleanly.

### D18. Every commit ends with `test/run.js` passing

No half-finished commits. If the feature doesn't fit in one
commit, it's split across multiple commits each of which
leaves the tree green.

**Rationale.** Bisection works only on green trees. Breaking
the build for a commit "to be fixed later" is forbidden.

## What's explicitly out of scope

- Full ES2024+ coverage at feature parity with the legacy
  engine — the new engine gets the subset needed for the two
  consumers plus whatever real npm code exercises. Gaps are
  tracked as `unimplemented` assumptions.
- Formal verification of the soundness theorem — the theorem
  is stated in `docs/ABSTRACT-DOMAIN.md` as a design target,
  not as a proven property. Every `unimplemented` /
  `soundness` assumption is a visible gap against it.
- Cross-analysis caching (reusing a trace across edits) — the
  library is a pure function from input to Trace. Incremental
  analysis is a future optimization, not a core feature.
- Security-critical deployment hardening (sandboxing, DoS
  mitigation, memory limits) — the library is designed for
  analysis of known input, not adversarial stress testing.
  A deployment consumer would add these.
