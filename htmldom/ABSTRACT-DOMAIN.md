# Abstract Domain & Soundness

This document formalises the abstract domain `jsanalyze.js` operates over,
the lattice operations it uses to join values at control-flow merges, the
transfer functions it implements per statement kind, and — most importantly
— the explicit assumptions it makes. The goal is to be precise enough that
every approximation in the implementation can be checked against a stated
condition rather than left as folklore.

The framing follows the standard abstract-interpretation pattern of Cousot
& Cousot: an abstract domain `A` with a partial order `⊑`, a join `⊔`, and
a family of transfer functions `⟦stmt⟧ : A → A` that over- or
under-approximate the concrete semantics depending on the soundness
direction we're aiming for. We aim for **soundness with respect to taint
flow**: if a concrete execution propagates a labelled value from a source
to a sink under a satisfiable path condition, the analysis should report
it. Approximations are allowed to over-report (false positives are
imprecise but sound) but should not under-report. Where the implementation
deliberately under-reports — usually for precision in a common case at the
cost of soundness on a rare one — the trade-off is documented in §6.

---

## §1. Concrete semantics

The program under analysis is a JavaScript module (one or more `.js`
source files plus inline `<script>` blocks extracted from HTML). Its
concrete semantics is the standard ECMAScript trace semantics:

- A **state** `σ` is a mapping from lexical names + heap locations to
  runtime values, plus a continuation describing the next syntactic
  position to execute.
- A **trace** `τ = σ₀ → σ₁ → … → σₙ` is a sequence of states reached by
  applying ECMAScript's small-step evaluation rules.
- A **value** at runtime is one of: primitive (number / string / boolean
  / null / undefined / symbol / bigint), object, array, function,
  exotic host object (DOM element, Map, Set, Promise, Proxy, …).

For the taint analysis, every concrete value carries a **provenance set**
`L(v) ⊆ Σ` where `Σ` is a finite set of source labels (`url`, `cookie`,
`referrer`, `network`, `postMessage`, `storage`, `file`, …). The
provenance is propagated by the standard taint rules:

- Constant literals carry the empty set.
- Reading a known taint source (`location.hash`, `document.cookie`,
  `fetch(url)`, …) attaches its label.
- A sanitiser (`encodeURIComponent`, `DOMPurify.sanitize`, `parseInt`,
  …) returns a value with the empty set regardless of input.
- Every other operation propagates the union of its operand
  provenances.

A **finding** is a tuple `(sink, label, σᵢ)` such that at state `σᵢ` the
program writes a value `v` with `label ∈ L(v)` to a sink position
classified by the TypeDB as carrying `sink`.

The analysis is **sound for findings** iff every finding produced by the
concrete trace under a satisfiable path condition is reported. It is
**precise for findings** iff every reported finding corresponds to at
least one satisfiable concrete trace. The implementation aims for
soundness, with the precision/soundness trade-offs in §6 documented
as deviations.

---

## §2. Abstract domain

The abstract state at any program point is a tuple

```
α = ⟨Γ, Λ, M, P, T, S⟩
```

where each component is itself a structured lattice defined below. The
walker tracks `α` implicitly through several intertwined data structures
(`stack`, `_varMayBe`, `pathConstraints`, `taintCondStack`,
`taintFindings`, `_fnSummaryCache`); the formalisation here gives each its
abstract name so the transfer functions in §4 can refer to them
unambiguously.

### §2.1 Abstract values: `Value`

The abstract value lattice `Value` is the disjoint union of nine binding
kinds. Each kind corresponds to a `kind:` discriminator on a JavaScript
object inside `jsanalyze.js` (line numbers in parentheses):

```
Value ::= Chain   (3205)   chainBinding(toks)
        | Object  (3207)   objectBinding(props, __objId)
        | Array   (3208)   arrayBinding(elems, __objId)
        | Function(3209)   functionBinding(params, bodyStart, bodyEnd, isBlock)
        | Element (3221)   elementBinding(origin, typeName, attrs, props,
                                          styles, classList, children,
                                          text, html, attached)
        | TextNode(3252)   {kind:'textNode', text:Chain, attached}
        | Mapped  (6210)   {kind:'mapped', iterExpr, paramName, perElemChain}
        | FactoryRef(7054) {kind:'factoryRef', factoryKey}
        | ⊥                null  -- absent / unanalysable
```

Each kind has its own substructure:

- **Chain** is the most general kind. Its `toks` field is a sequence of
  `Token`s (§2.2) describing how the value was built — concatenations,
  conditionals, calls, references. Optional fields:
  - `typeName : Type` — the static type assigned to the chain by the
    TypeDB walker (§2.5);
  - `innerType : Type` — the parametric inner type (`Promise<T>` carries
    `innerType = T`);
  - `labels : ℘(Σ)` — the cached label set (§2.3); when absent the
    labels are recomputed lazily from `toks` via `collectChainTaint`
    (line 691).

- **Object** is a record with `props : Name → Value` and a stable
  identity `__objId : ℕ` so the may-be lattice (§2.4) can track aliasing.
  Setters and getters live under reserved keys `__setter_<name>` and
  `__getter_<name>`.

- **Array** is `elems : ℕ → Value` plus an `__objId`. Materialised arrays
  preserve element identity for index reads; opaque arrays from unknown
  iterators fall back to a single `Chain` carrying the union of all
  potential elements' labels.

- **Function** is purely syntactic: `(params, bodyStart..bodyEnd,
  isBlock)`. The body is not pre-walked; it is instantiated on each
  call by `instantiateFunction` (line 7353). Functions also carry an
  optional `capturedScope` snapshot for closures.

- **Element** is the virtual-DOM record produced by `document.createElement`,
  `document.getElementById`, `document.querySelector`, etc. The
  `origin` discriminator (`{kind:'create', tag}` or `{kind:'lookup',
  by, value}`) records the provenance and `typeName` is set from the
  TypeDB's `tagMap` for known tags. Sink classification uses
  `typeName` first, then `origin.tag`, then attribute-name fallback.

- **TextNode**, **Mapped**, and **FactoryRef** are specialised value
  kinds for `document.createTextNode`, the result of opaque
  `array.map(fn)`, and the result of `<DOMfactory>.bind(thisArg)`
  respectively. Each is consumed by exactly one downstream operation.

The least element `⊥` is `null` and represents an unanalysable value.
Most transfer functions propagate `⊥` strictly (`⊥ ⊔ x = x`,
`f(⊥) = ⊥`).

### §2.2 Tokens

A `Chain` value is built from a sequence of `Token`s. Tokens are the
"opcodes" of the abstract machine; their granularity is roughly that of
an ECMAScript expression nodelet. Each token type encodes either a
syntactic fragment or a control-flow construct that the chain
flattening preserves through merges.

```
Token ::= Lit    {type:'str',  text}                       -- string literal
        | Other  {type:'other', text, taint?}              -- ident / opaque expr
        | Plus   {type:'plus'}                             -- concat boundary
        | Op     {type:'op',   text}                       -- operator
        | Sep    {type:'sep',  char}                       -- , ; etc.
        | Open   {type:'open', char}                       -- ( [ {
        | Close  {type:'close',char}                       -- ) ] }
        | Tmpl   {type:'tmpl', parts}                      -- `…${expr}…`
        | Regex  {type:'regex',text}                       -- /…/flags
        | Cond   {type:'cond', condExpr, ifTrue, ifFalse,  -- ternary / if-merge
                  loopId?}
        | TryCatch {type:'trycatch', tryBody, catchBody,   -- try / catch merge
                    catchParam}
        | SwitchJoin {type:'switchjoin', discExpr, branches}-- switch merge
        | Iter   {type:'iter', iterExpr, paramName, ...}   -- for-of / map
        | Preserve {type:'preserve', text}                 -- statement snippet
```

Tokens can carry a per-token `taint : ℘(Σ)` field (line 701). The chain
flattener `collectChainTaint` (line 691) walks recursively into `cond`,
`trycatch`, `switchjoin`, and `tmpl` so labels inside any branch are
visible to the union at the chain root.

Plus tokens are concatenation **boundaries**, not operators: a chain
with operands `[A, +, B]` represents `A ⊕ B` for whichever binary
operator the language used (the actual operator text is preserved
inside the concrete trace via the surrounding `Op` tokens; for taint
purposes only the boundary matters).

In addition to user-visible tokens, the walker uses several internal
**work-item tokens** (`range`, `if_merge`, `if_restore`, `try_merge`,
`try_restore`, `switch_capture`, `switch_case`, `switch_merge`,
`_targetPush`, `_targetPop`, `_chain`) on its task stack `_ws`. These
are not values; they are continuation descriptors for the iterative
state machine in `walkRange`. They never appear in a `Chain.toks`
sequence visible to the user.

### §2.3 Label set: `Λ`

`Λ = ℘(Σ)` is the powerset of source labels with the standard subset
order:

```
Λ₁ ⊑_Λ Λ₂ ⇔ Λ₁ ⊆ Λ₂      ⊔_Λ = ∪      ⊥_Λ = ∅
```

The label vocabulary `Σ` is fixed by the TypeDB and currently consists
of:

```
Σ_source = { url, cookie, referrer, window.name, storage, network,
             postMessage, file, dragdrop, clipboard, event,
             form, navigator, ... }
Σ_sink   = { html, code, url, navigation, css, text, origin }
```

Labels are stored either at the binding level (`binding.labels`) or per
token (`tok.taint`). The unified accessor `getBindingLabels` (line 772)
returns the binding-level set when present and falls back to
`collectChainTaint(binding.toks)` otherwise.

### §2.4 May-be lattice: `M`

`M : Name → MayBe` where

```
MayBe = ⟨vals : List Value, keys : ℘(String), complete : Bool,
         fns : List Function, fnIds : Set Id⟩
```

`M[x]` records every binding `x` was assigned across all control-flow
paths in the current scope. `vals` accumulates concrete bindings;
`keys` records observed string-key patterns for indirect-dispatch
lookups; `complete = true` means the lattice has seen every assignment
and the SMT layer may emit a may-be disjunction `(or (= x v₁) (= x v₂)
...)`. The first non-literal assignment forces `complete := false`.

The lattice operation is monotone accumulation: `M[x] ⊔ {v} = M[x]
∪ {v}` with no widening cap (see §6 for the boundedness assumption).

### §2.5 Type lattice: `T`

`T` is the set of named types declared in the active TypeDB plus a
distinguished bottom `⊥_T` (untyped). The order is the inverse of
`extends`-chain ancestry: `t₁ ⊑_T t₂` iff `t₁` extends `t₂`
transitively. `⊔_T` is the most-specific common ancestor computed by
`_typeLUB` (line 735):

```
HTMLIFrameElement ⊔_T HTMLScriptElement = HTMLElement
HTMLAnchorElement ⊔_T HTMLElement       = HTMLElement
Location          ⊔_T Document          = EventTarget
Location          ⊔_T String            = ⊥_T  (no common ancestor)
```

Types are attached to chain bindings via the optional `typeName` field
and propagated through prop / method reads via `_lookupProp` and
`_lookupMethod`, both of which walk the `extends` chain.

### §2.6 Path constraints: `P`

`P` is a stack of SMT-AST formulas with parallel human-readable
strings:

```
P = ⟨pathConstraints : List Formula, taintCondStack : List String⟩
```

Both stacks are pushed and popped in lockstep by `_pushPathConstraint`
/ `_popPathConstraint` (line 8471) at the entry and exit of every
branching construct. The conjunction `⋀ pathConstraints` describes the
**path condition** under which the current statement is reached. At
each finding the snapshot `pathConstraints.slice()` is attached to the
finding so a post-hoc Z3 backend can re-check reachability without
re-walking the program.

### §2.7 Function summary cache: `S`

`S : SummaryKey ⇀ {result : Value}` where

```
SummaryKey = (FunctionBodyRange, ArgFingerprint*, ThisFingerprint)
```

`ArgFingerprint` (line 7320) is a string encoding of a binding's kind,
type, inner type, label set (sorted), known string value, and
identifier text. Object / Array / Function / Element bindings are
fingerprinted by `kind#__objId` so distinct heap identities never
collide.

`S` is populated on the return path of `instantiateFunction` only when
the body walk produced **no findings, no domOps, and no outer-frame
mutations** (the empirical purity test, line 7704). On a cache hit the
walker skips the body entirely and returns the cached value. The cache
is cleared between fixpoint iterations of phase 2 so sibling-mutation
re-walks observe new state.

### §2.8 Findings: `F`

`F` is a multiset of finding records emitted by `recordTaintFinding`
(line 3845):

```
Finding = ⟨type, severity, sink, sources, conditions, formulas, location⟩
```

`sources` is a list of source labels, `conditions` is the snapshot of
`taintCondStack`, `formulas` is the snapshot of `pathConstraints`, and
`location` is the source position. Findings are deduplicated at
emission by `(type, sink, location, |conditions|)`: when two emissions
agree on those four fields the source label sets are unioned into the
existing finding rather than creating a duplicate (line 3855).

---

## §3. Lattice operations

This section defines `⊔` for each component of the abstract state. The
ordering `⊑` is the standard one induced by `⊔` (`x ⊑ y ⇔ x ⊔ y = y`).
The walker uses these joins implicitly at every control-flow merge.

### §3.1 Label join `⊔_Λ`

```
Λ₁ ⊔_Λ Λ₂ = Λ₁ ∪ Λ₂           (set union)
⊥_Λ      = ∅
```

Implemented inline at every site that merges labels (e.g.
`collectChainTaint` line 694, `getBindingLabels` consumers). Pure
union with no widening: the label vocabulary is finite, so the lattice
has finite height `|Σ|` and ascending chains terminate trivially.

### §3.2 Type join `⊔_T`

```
t ⊔_T t                = t
t₁ ⊔_T t₂              = least t such that t₁ ⊑_T t and t₂ ⊑_T t
                         (most-specific common ancestor in extends chain)
t  ⊔_T ⊥_T             = t
```

Implemented by `_typeLUB` (line 735). The lattice is the inverted
extends-DAG of the active TypeDB; height is bounded by the longest
extends chain (currently ≤ 4: e.g.
`HTMLAnchorElement → HTMLElement → Element → Node → EventTarget`).

When `t₁` and `t₂` have no common ancestor, `_typeLUB` returns `null`
which the walker treats as "untyped, fall back to the structural sink
classifier". This is a sound over-approximation: an untyped chain
participates in every potential sink rather than the type-restricted
subset.

### §3.3 Value join `⊔_Value`

The value join is the **structural** merge that produces a single
abstract value summarising both branches of a control-flow split. It
is implemented in three flavours depending on the construct:

#### §3.3.1 Conditional join (`if` / ternary)

For `if (c) { x = a } else { x = b }`, the post-merge value of `x` is
constructed by `if_merge` (task line 8336):

```
join_cond(c, a, b) = Cond { condExpr := stringify(c)
                          , ifTrue   := tokens(a)
                          , ifFalse  := tokens(b) }
```

The result is a single `Chain` whose `toks` array contains exactly
one `Cond` token. Both arms are preserved verbatim so:

```
labels(join_cond(c, a, b)) = labels(a) ⊔_Λ labels(b)        (sound for taint)
type  (join_cond(c, a, b)) = type(a) ⊔_T type(b)            (sound for types)
```

The `condExpr` is retained for the SMT layer: when the joined value is
later involved in a sink condition, Z3 can refute one arm if its
branch condition (or its negation) contradicts the surrounding path
constraints.

#### §3.3.2 Try-catch join

For `try { … } catch (e) { … }`, the body and the handler are joined
into a single `TryCatch` token:

```
join_try(t, c, e) = TryCatch { tryBody    := tokens(t)
                             , catchBody  := tokens(c)
                             , catchParam := e }
```

The catch parameter `e` is bound to a chain whose labels are the union
of every potentially-thrown expression's labels in `t`. (This is a
coarse approximation: we do not track which throw site reached which
catch site. See §6.)

#### §3.3.3 Switch join

For `switch (d) { case k₁: …; case k₂: …; default: … }`, every case
that contributes a value to the same name produces a `SwitchJoin`:

```
join_switch(d, [(k₁, v₁), (k₂, v₂), …]) =
    SwitchJoin { discExpr := stringify(d)
               , branches := [{ label := k₁, caseExpr := stringify(d == k₁)
                              , chain   := tokens(v₁) },
                              { label := k₂, ... },
                              ...] }
```

Per-case path formulas are conjoined with the surrounding path
condition during the `switch_merge` task (line 8746) so the SMT layer
can refute unreachable cases independently.

### §3.4 May-be join `⊔_M`

`M` is updated by monotone accumulation. For each name `x` and each
new assignment `x := v`:

```
M[x] ⊔_M {v} = ⟨ vals     := M[x].vals ++ [v]
               , keys     := M[x].keys ∪ key-pattern(v)
               , complete := M[x].complete ∧ is-literal(v)
               , fns      := M[x].fns    ++ functions-of(v)
               , fnIds    := M[x].fnIds  ∪ fnId-of(v)⟩
```

`is-literal(v)` is true when `v` is a constant string or number. Once
any non-literal binding lands, `complete` flips to false and the SMT
layer stops emitting may-be disjunctions for `x`.

The lattice has **no widening operator**. Termination relies on the
walker's symbolic structure (every loop body is walked at most a
fixed number of fixpoint iterations) rather than on `M` reaching a
fixed point per-variable. This is documented as Assumption A4 in §6.

### §3.5 Path-constraint join

The path constraint stack `P` is not joined; it is **restored** at
control-flow merges. Both branches of an `if` see the same outer
path condition; on entry to the `then` branch the walker pushes
`pathFormula(c)` and on entry to the `else` branch it pushes
`smtNot(pathFormula(c))`. After the merge both pushes are popped, so
the post-merge path condition is exactly the pre-branch condition.

```
push P with formula(c)        — entering then branch
walk then-body
pop                           — leaving then branch
push P with smtNot(formula(c))— entering else branch
walk else-body
pop                           — leaving else branch
                              — outer P unchanged
```

This is the standard path-sensitive treatment from path-sensitive
abstract interpretation literature: the path condition is a context
that scopes findings, not a value that propagates through assignments.
Findings emitted inside a branch carry a snapshot of the full
`pathConstraints` stack at the moment of emission, so post-hoc
verification can re-check reachability under arbitrary additional
constraints.

### §3.6 Function-summary join (`S`)

`S` is content-addressed: there is no join across summary entries.
Each `(body, args, this)` fingerprint maps to exactly one cached
result. On a cache miss the body is walked fresh; on a hit the cached
result is returned verbatim. The cache is invalidated wholesale at
the start of each phase-2 fixpoint iteration so sibling-mutation
effects propagate.

The cache populates only when the walk satisfies the empirical purity
predicate

```
pure(walk) ⇔ (Δfindings = 0) ∧ (ΔdomOps = 0) ∧ (Δ_outerMutCount = 0)
```

Impure walks bypass the store entirely. This predicate is sound only
under Assumption A1 in §6 (the three observed channels are the only
side effects the walker can produce).

---

## §4. Transfer functions

The transfer function `⟦stmt⟧ : A → A` updates the abstract state for
each ECMAScript construct. The implementation lives in `walkRange`
(line 8557) as a single iterative state machine driven by a work
stack `_ws` of `range`, `if_*`, `try_*`, `switch_*` tasks. The
descriptions below give the input/output behaviour at the abstract
level; the exact dispatch lives in the line-numbered handlers cited.

Notation: `α = ⟨Γ, Λ, M, P, T, S, F⟩` is the abstract state. `Γ` is the
lexical environment (`stack` in the implementation), mapping in-scope
names to `Value`s.

### §4.1 Variable declaration and assignment

```
⟦var x = e⟧ α = α[Γ ↦ Γ[x ↦ ⟦e⟧_expr α], M ↦ M ⊔_M {x ↦ ⟦e⟧_expr α}]
⟦x = e⟧   α = same, with closest enclosing binding for x
⟦x += e⟧  α = ⟦x = x + e⟧ α   (concat boundary preserved as Plus token)
```

Both forms route through `assignName` (line 4226). Writing across a
function boundary increments `_outerMutCount` so the function-summary
purity predicate (§3.6) sees the side effect.

### §4.2 Path assignment

```
⟦obj.p = e⟧            α = α[Γ ↦ Γ', Λ ↦ Λ', F ↦ F']
  where  obj' = ⟦obj⟧_lhs α
         v    = ⟦e⟧_expr α
         Γ'   = update obj'.props[p] := v
         F'   = F ∪ classify_sink(obj', p, v, P)

⟦obj.p₁.p₂.…pₙ = e⟧    α = walk obj.p₁..pₙ₋₁ to leaf container,
                            then assign pₙ; sink-classify the leaf
```

The leaf classifier consults the TypeDB type of `obj'` first
(`_classifyBindingSink`, line 3871), then the tag (for element
bindings), then the attribute-name fallback (`attrSinks`). The
classifier emits a `Finding` whenever:

1. The leaf prop is a sink in the TypeDB **and**
2. `getBindingLabels(v) ≠ ∅` (the value carries at least one source
   label) **and**
3. The current path constraint is satisfiable (`smtCheckBoth` line
   1905, called via `recordTaintFinding` indirectly through the
   `formulas` snapshot).

For `el.style.<prop>` writes (line 11083) the classifier fires a
`css` sink at `medium` severity even though the receiver is reached
via a typed-chain global root (`document.body.style.X`); see §6.13.

### §4.3 Conditional `if`

```
⟦if (c) S₁ else S₂⟧ α =
  let φ      = ⟦c⟧_smt α
      α₁     = walk S₁ in α with P pushed by φ
      α₂     = walk S₂ in α with P pushed by ¬φ
      Γ'     = mergeBindings(Γ_α₁, Γ_α₂)   -- joins each name via §3.3.1
      M'     = M_α₁ ⊔_M M_α₂
      F'     = F_α₁ ⊎ F_α₂                  -- multiset union, dedup at emit
  in α[Γ ↦ Γ', M ↦ M', F ↦ F']
```

Implemented across `if_restore` (task line 8324) and `if_merge` (task
line 8337). Names assigned in only one branch are joined against
their pre-branch value via `Cond { condExpr ↦ φ }`.

SMT refutation: when φ is statically false (`smtCheckBoth` shows the
formula is unsatisfiable in the current outer constraints), the
walker can skip walking `S₁` entirely (and symmetrically for `¬φ`).
This is what makes the `if (x === 99)` SMT-refutation tests work.

### §4.4 Loops `while` / `for` / `do…while` / `for-of` / `for-in`

```
⟦for-of (x of e) S⟧ α =
  let xs   = ⟦e⟧_expr α                            -- iterable
      αᵢ   = walk S in α with x bound to xs.elems[i]
                                                   for i in 0..|xs|-1
      α∞   = walk S once with x bound to a fresh
              opaque chain typed by iteratesType(e) -- catch-all
  in join αᵢ ⊔ α∞
```

Implemented in the `loopStack` machinery (line 8825). Materialised
iterables are unrolled element-by-element so per-element bindings
flow through `S`'s sinks; opaque iterables fall back to a single walk
with the loop var bound to a typed chain whose labels are the union
of all known elements'.

After the loop the modified variables are captured as `loopVar`
records (line 8616) and replaced with opaque post-loop synthetics
(`deriveExprRef(name, b.toks)`). Per-iteration refinements are not
preserved into the post-loop scope (Assumption A4).

There is **no widening operator**. Termination is guaranteed because
each loop body is walked at most a fixed number of times — Phase 1
walks once eagerly, Phase 2 walks each callback up to N times until
no new findings appear, and the function summary cache short-circuits
recursive calls via `_callStack`.

### §4.5 Try / catch / finally

```
⟦try B catch (e) C finally F⟧ α =
  push fresh Θ onto _tryThrowAccStack
  let α_B = walk B (every `throw e` reached during the walk
            unions getBindingLabels(e) into Θ; nested try-catches
            push their own deeper Θ' so handled throws don't
            escape; function calls inside B also push to Θ via
            instantiateFunction's body walk going through the
            same throw handler)
  pop Θ from _tryThrowAccStack
  bind catch parameter e to chainBinding([exprRef(e) with taint=Θ])
  let α_C = walk C in α[Γ[e ↦ Θ-tagged]]
      Γ'  = join_try(Γ_B, Γ_C, e)
      α_F = walk F in α[Γ ↦ Γ']
  in α_F
```

Implemented across the try handler (line 9810+), `try_restore`
(line 9078+), `try_merge` (line 9141+), and the walker `throw`
handler (line 9143+).

The thrown-set `Θ` is computed by the **walker-driven throw
accumulator** `_tryThrowAccStack`: every reachable `throw e`
unions `getBindingLabels(e)` into the top-of-stack accumulator.
Critically, function calls inside B share the same accumulator
because instantiateFunction's body walk dispatches through the
same `throw` handler in `walkRange`. Nested try-catch inside a
called function pushes its own Θ' onto the stack, captures its
own handled throws, and pops on exit — so only **escaping**
throws reach the outer accumulator. This is the academic
**effect-system** semantics: each function's effective `thrown :
Λ` set is the labels of throws it does not catch internally.

The legacy syntactic `_scanThrowsIn` static scan is still
present but no longer feeds the catch parameter; the walker
accumulator is now the sole source of truth (the static scan
ignored nested try-catch and missed method/dispatch/built-in
throws).

### §4.6 Switch

```
⟦switch (d) { case k₁: S₁ … case kₙ: Sₙ default: S_d }⟧ α =
  for each case kᵢ:
    let φᵢ  = ⟦d == kᵢ⟧_smt α  ∧  ¬φ₁ ∧ … ∧ ¬φᵢ₋₁  -- fall-through aware
        αᵢ  = walk Sᵢ in α with P pushed by φᵢ
  Γ' for each modified name x:
    join_switch(d, [(k₁, αᵢ.Γ[x]) for each case])
```

Implemented across `switch_capture`, `switch_case`, `switch_merge`
(task lines 8504, 8512, 8569). The default case is treated as `¬⋁ φᵢ`
when present.

### §4.7 Return

```
⟦return e⟧ α  inside a function frame =
  capture (position, snapshot(P)) into _returnCapture.entries
  -- the rest of the return statement is processed by the
  -- statement walker as usual so call watchers / sink handlers
  -- inside the return expression still fire
```

Implemented as a **two-source reduction** in `instantiateFunction`:

1. The walker's `return` handler (in `walkRange`, after the
   `break`/`continue` handler) snapshots the path-condition stack
   (function-relative slice) and the return statement's source
   position into `_returnCapture.entries`. **The handler does not
   consume the return expression** — the walker continues processing
   the rest of the line so embedded calls like `return fetch(...)`
   still fire the statement-level call watchers.
2. After `walkRange`, `instantiateFunction` runs a syntactic
   post-walk scan of the body to enumerate every top-level `return`
   token and read each return value via `readValue`. This is the
   source of truth for which return *bindings* exist
   (path-INsensitive: the scan finds every syntactic return,
   including ones a concrete walk would skip).
3. The reduction matches each syntactic return against the walker
   captures by source position. When both agree, the syntactic
   binding is annotated with the captured path condition. Returns
   the walker did **not** reach (because a surrounding `if` was
   concretely refuted by the walker, e.g. `if (n <= 0) return 0;`
   when n is a known non-zero literal) get no captured condition
   and the cond fold defaults their `condExpr` to `"true"`.

The reduction itself follows the §4.7.1 fold below, with one
documented precision shortcut for the no-taint case (assumption A3).

#### §4.7.1 Multi-return reduction (implemented)

```
⟦return e⟧ α at body position p inside function f, with current
            function-relative taintCondStack slice φ_p =
                taintCondStack[entryTCSize..] :
  _returnCapture.entries ⊔= {(p, φ_p, snapshot(P))}

After walkRange completes, instantiateFunction reduces the
syntactically-scanned return bindings (r₀, r₁, …, rₙ) by matching
each against _returnCapture.entries by position to produce
(r₀@C₀, r₁@C₁, …, rₙ@Cₙ) where Cᵢ is "true" when the walker did
not reach return i. Then:

  case n of
    0 → ⊥                                     -- void function
    1 → r₀                                    -- single return
    ≥2 ∧ all chains ∧ ∃ tainted →             -- cond fold
        fold-right
          (λ (rᵢ, Cᵢ) acc.
             [Cond { condExpr := Cᵢ
                   , ifTrue   := tokens(rᵢ)
                   , ifFalse  := acc }])
          tokens(rₙ)        -- last return is the leaf
          (init returns)    -- r₀..rₙ₋₁ wrap from outside in
    ≥2 ∧ all chains ∧ no taint → r₀          -- A3 shortcut
    ≥2 ∧ mixed kinds → first non-chain binding
```

Properties:

- **Sound for taint** by §3.3.1: `collectChainTaint` recurses into
  the cond tokens and unions every reachable branch's labels.
- **Structurally precise**: each `Cond.condExpr` carries the
  control-dependence condition computed by
  `_enclosingConditionsAt` (a static AST scan that walks every
  enclosing `if`/`else`/`while` block lexically containing the
  return statement) — falling back to the walker-captured
  taintCondStack slice when the static scan finds nothing.
- **Call-site SMT refutation (implemented)**: after the cond
  chain is built, the reduction substitutes the call site's
  concretely-bound argument values into each `cond.condExpr`
  via `_simplifyCondToksAtCallSite` and asks `smtCheckCondition`
  whether the substituted formula is concretely true, false, or
  unknown. Refuted branches collapse to the surviving arm in
  place; unknown conds are kept verbatim with both arms
  recursively simplified. This eliminates the would-be false
  positive on
  ```
  function f(a) { if (a > 5) return "safe"; return location.hash; }
  document.body.innerHTML = f(10);
  ```
  by refuting the second branch (10 > 5 is true → ifTrue arm
  survives, ifFalse arm dropped → result is `"safe"` with no
  taint). The substitution is regex-based with word boundaries;
  numeric and known-string arguments substitute as the literal
  text, opaque arg bindings are skipped (and the cond is
  preserved with both arms intact).
- **No-taint shortcut (A3)**: when no return carries taint labels,
  the cond fold would lose the recursion-arithmetic precision
  shortcut. The reduction instead takes only the first return so
  patterns like `function f(n){if(n<=0)return 0; return f(n-1)+1;}`
  can be SMT-refuted at concrete call sites
  (`if (f(3) === 99) sink(...)` is correctly classified
  unreachable because `f(3)` reduces to `0`, not to a cond chain
  containing an opaque recursive call).

### §4.8 Function call

```
⟦f(e₁, …, eₙ)⟧_expr α =
  let v_f      = ⟦f⟧_expr α
      args     = [⟦eᵢ⟧_expr α | i ∈ 1..n]
      thisArg  = receiver of f if dotted, else null
  in case v_f of
       Function fb         → instantiateFunction(fb, args, thisArg)
       FactoryRef k        → DOM_FACTORIES[k](args, ...)
       Object {kind:object, props:{...}} & DOM/built-in → applyMethod
       Chain (typed)       → resolve via TypeDB method descriptor
       Chain (opaque)      → opaque-call propagation:
                               result = exprRef(call-text) with labels =
                                        ⊔ᵢ getBindingLabels(args[i])
       ⊥                   → ⊥
```

`instantiateFunction` (line 7353) is the inter-procedural workhorse.
It pushes a new lexical frame, binds `params[i] := args[i]` (with
support for default values, rest params, and destructured patterns),
walks the body via `walkRange`, then constructs the return value via
the §4.7 transfer function. Recursion is detected via `_callStack`:
on a self-call, `instantiateFunction` returns `null` and the caller
falls back to the opaque-call propagation rule above.

### §4.9 New expression

```
⟦new C(e₁, …, eₙ)⟧_expr α =
  case ⟦C⟧_expr α of
    Object {_isClass: true} → instantiate-class(C, args)
    Chain {typeName: 'GlobalXxxCtor'} → look up construct descriptor
                                          in TypeDB, return typed instance
    'Map' / 'Set' / 'WeakMap' / 'WeakSet' → empty Object _mapLike-tagged
    'Proxy'                 → return target argument unchanged
                              (transparent pass-through, A6)
    'Promise' / 'Date' / …  → typed instance from TypeDB
    other                   → opaque chain with arg-taint propagation
```

Class instantiation (line 6412) creates an `Object` with the class's
prop map shallow-copied from the constructor descriptor, then runs
the `constructor` method with the new instance bound as `this`.

### §4.10 Throw

```
⟦throw e⟧ α =
  if _tryThrowAccStack non-empty:
    read ⟦e⟧_expr α via readValue
    union getBindingLabels(result) into top-of-stack accumulator
  advance past the throw expression
  (implicit: the rest of the enclosing scope is dead)
```

The walker-driven accumulator is path-sensitive: only throws
actually reached during the walk are unioned into the top
accumulator. The enclosing try (§4.5) or async function body
(§4.8) supplies that top accumulator. Function calls inside
either context share the same accumulator because
`instantiateFunction` walks through the same handler — so
unhandled throws across arbitrary call depth surface to the
outer frame.

---

## §5. Soundness statement

We state soundness for taint findings: every concrete trace that
propagates a labelled value to a sink is reported, modulo the
explicit assumptions enumerated in §6.

**Soundness theorem (informal).** For any concrete trace `τ = σ₀ →
σ₁ → … → σₙ` of the program, if there exist indices `i ≤ j` and a
value `v` such that:

1. `σᵢ` produces `v` at a syntactic position whose TypeDB descriptor
   carries `source: ℓ` (so `ℓ ∈ L(v)`),
2. `σⱼ` writes a value `w` derived from `v` (i.e. `ℓ ∈ L(w)`) into a
   syntactic position whose descriptor carries `sink: κ`,
3. the path `σᵢ → σⱼ` is realised by some satisfiable assignment of
   the free variables in the surrounding control conditions,

then **provided assumptions A1–A14 in §6 hold**, the analysis emits a
finding `(κ, ℓ, location(σⱼ))`.

The "modulo assumptions" caveat is essential: each assumption in §6
identifies a class of concrete traces the analysis may miss or
over-report. Soundness is preserved exactly when all assumptions
hold; deviation from any single assumption may yield false negatives
(for `UNSAFE` assumptions) or false positives (for `SAFE`
assumptions).

We do not claim **completeness**: a reported finding may correspond
to no satisfiable concrete trace because the SMT layer was unable to
refute a path it conservatively retained. False positives are
expected and acceptable; false negatives are bugs.

The current implementation is **not formally verified against this
statement**. The assumptions in §6 are the result of an audit of the
walker (line-numbered references are to the current commit). Future
work should reduce the assumption count by replacing each `UNSAFE`
item with a principled lattice operation, ideally with a small
correctness proof against the standard-library semantics it
approximates.

---

## §6. Explicit assumptions

Each assumption below identifies a single approximation in the
walker, gives its line number, classifies it as **SAFE** (over-
approximation, may yield false positives) or **UNSAFE** (under-
approximation, may yield false negatives), and states the precise
condition under which the analysis remains sound.

### A1. Function-summary purity is observed via three counters

**Lines:** 7345–7352 (`_puresig`).
**Class:** SAFE.
**Statement.** A function call is cached as pure iff the body walk
produced no findings, no `domOps`, and no outer-frame mutations.
**Condition.** Sound iff every observable side effect of a function
body is captured by at least one of `taintFindings`, `domOps`, or
`_outerMutCount`. Side effects that escape these channels — global
object writes via reflective `Reflect.set` on a non-tracked target,
mutations to a binding stored in `_varMayBe` only, writes through a
captured-but-not-outer reference — are not observed and a stale
cached result may be returned on the next call with matching
fingerprint.

### A2. Recursion returns opaque

**Lines:** 7362 (`_callStack` recursion guard).
**Class:** SAFE (over-approximates: returns an opaque chain that may
mention the call site verbatim and propagates argument taint).
**Statement.** When `instantiateFunction` is invoked with a body
range already on `_callStack`, it returns `null` and the caller
substitutes `chainBinding([exprRef(callText)])` with arg-taint.
**Condition.** Sound for taint flow: every argument's labels reach
the call result. **Imprecise** for value-level reasoning: any
recursive call's actual return value (e.g. a Fibonacci number) is
unknown to the SMT layer, so refutation that depends on the result
fails. The recursion test
`function f(n){if(n<=0)return 0; return f(n-1)+1;}` only refutes
`f(3) === 99` because the **first** return is concretely 0 — not
because the analysis reasoned about the recursion.

### A3. Multi-return reduction with call-site SMT refutation

**Lines:** 7551–7720 (instantiateFunction reduction); 7178–7340
(`_enclosingConditionsAt`, `_evalCondAtCallSite`,
`_simplifyCondToksAtCallSite`); 9105–9127 (walker `return`
capture handler).
**Class:** SAFE in the tainted case (over-approximates after
SMT refutation: all surviving branches contribute labels via
`collectChainTaint`); UNSAFE in the no-taint case
(first-return shortcut for recursive-arithmetic SMT refutation).
**Statement.** The walker installs a `_returnCapture` slot at the
start of each `instantiateFunction` body walk; every `return`
keyword encountered records `(position, taintCondStack slice,
pathConstraints slice)` into the slot — without consuming the
return expression, so embedded calls (`return fetch(...)`) still
fire the statement-level call watchers. After `walkRange`, a
syntactic post-walk scan enumerates every top-level return
binding. The reduction then produces:

| # returns | Any tainted? | Result                                       |
|-----------|--------------|----------------------------------------------|
| 0         | n/a          | `⊥` (void function)                          |
| 1         | n/a          | the single return                            |
| ≥ 2       | yes          | call-site-specialised `Cond` chain (§4.7.1)  |
| ≥ 2       | no           | **first return only** (recursion shortcut)   |

The any-tainted case fold is now **call-site specialised**:

1. Each cond's `condExpr` is the conjunction of static enclosing
   conditions computed by `_enclosingConditionsAt` (a reverse AST
   scan from `bodyStart` that walks `if`/`else`/`while` blocks
   to determine which lexical control predicates dominate each
   return position). The walker capture's taintCondStack is used
   as a fallback when the static scan returns nothing (e.g. for
   returns inside `for`/`switch` constructs the static scanner
   doesn't yet model).
2. After the fold, `_simplifyCondToksAtCallSite` walks the cond
   chain. Each cond's `condExpr` is substituted via
   `_evalCondAtCallSite`: every concretely-bound argument's
   literal text is regex-substituted (word-boundary) for its
   parameter name, the result is tokenised, and
   `smtCheckCondition` is asked whether the substituted formula
   is satisfiable / unsatisfiable.
3. Concretely-true conds collapse to their `ifTrue` arm,
   concretely-false conds collapse to their `ifFalse` arm, and
   unknown conds keep both arms (recursively simplified).

This eliminates the would-be false positive on
```
function f(a) { if (a > 5) return "safe"; return location.hash; }
document.body.innerHTML = f(10);
```
because the cond `(a > 5)` substitutes to `(10 > 5)` and SMT
evaluates it to true, so the second return drops out and the
caller sees only `"safe"`.

The no-taint case still falls back to the first return so SMT
refutation on numeric-only recursive arithmetic (`function f(n)
{if(n<=0)return 0; return f(n-1)+1;}` followed by
`if (f(3) === 99) sink(...)`) continues to terminate. Replacing
this shortcut with a sound principled join requires either (a)
recursive specialisation of function summaries (partial
evaluation that bottoms out the recursion at concrete base cases),
or (b) the SMT layer to symbolically reduce opaque recursive
calls. Both remain open work items.

**Condition.** Sound for taint flow whenever the syntactic
post-walk scan finds every return statement (it does; the scan
walks `[bodyStart, bodyEnd)` skipping nested `{}` blocks) AND
`_enclosingConditionsAt` correctly identifies the dominating
control predicates (it handles `if`/`else`/`while`; `for` and
`switch case` are approximated by the walker capture fallback).
UNSAFE in the specific case where the no-taint shortcut hides a
sink-relevant return value, and in the case where a refuted
branch was only refuted spuriously (an SMT layer false negative).

### A4. Loop variables collapse to opaque post-loop

**Lines:** 8825–8880.
**Class:** SAFE (over-approximates: post-loop reads see an opaque
chain carrying the union of every iteration's labels).
**Statement.** On loop exit, every variable assigned inside the body
is replaced with `chainBinding([deriveExprRef(name, b.toks)])`. Per-
iteration refinements (e.g. "after iteration 5, x is `'foo'`") are
lost.
**Condition.** Sound for taint: labels propagate via the synthetic
chain. **Imprecise** for SMT refutation: the post-loop value is
opaque so any sink condition involving it cannot be refuted.

### A5. May-be lattice has no widening cap

**Lines:** 3526–3638 (`_varMayBe`, `_trackMayBeAssign`).
**Class:** SAFE (lattice grows monotonically; the only consequence
of unbounded growth is memory pressure, not unsoundness).
**Statement.** The `vals` list of a may-be entry accumulates without
limit. The `complete` flag flips to `false` at the first non-literal
assignment, after which the SMT layer stops emitting may-be
disjunctions for the variable.
**Condition.** Sound iff total memory consumption stays within
process limits over the entire walk. Practical worst case: a
variable assigned every literal string in a 50,000-line bundle.
Currently no input has triggered the failure mode, but a malicious
input could.

### A6. `new Proxy(target, handler)` is transparent

**Lines:** 6537–6543.
**Class:** UNSAFE when `handler` defines non-trivial traps.
**Statement.** The `handler` argument is ignored entirely; the
result of `new Proxy(t, h)` is `t` itself.
**Condition.** Sound iff `handler.get`, `handler.set`,
`handler.deleteProperty`, `handler.has`, `handler.apply`, and
`handler.construct` are either undefined, identity-projecting, or
side-effect-free. Custom traps that transform reads (e.g. tainting
every property access) or block writes are silently ignored.

### A7. Class `extends` is copy-at-definition

**Lines:** 10125–10128.
**Class:** SAFE for static method tables; UNSAFE for late-binding.
**Statement.** Parent methods are copied into the child class's prop
map at the moment of class definition. Subsequent assignments to a
parent class's prototype after the child is defined do not propagate
to instances of the child.
**Condition.** Sound iff no code mutates a parent class's prototype
after a subclass has been defined. Standard ES6 class hierarchies
satisfy this; legacy prototype-extension patterns may not.

### A8. Optional chaining drops the null-check

**Lines:** 5396–5442 (resolved path), 7103–7119 (opaque path).
**Class:** SAFE for taint; UNSAFE for nullability reasoning.
**Statement.** `a?.b` is treated as `a.b` for purposes of property
access and call dispatch. The `?.` operator does not introduce a
control-flow split for the null branch.
**Condition.** Sound for taint: if `a.b` is tainted, the analysis
reports it whether or not `a` was actually non-null at runtime. Any
analysis that depends on knowing `a !== null` (e.g. dead-code
elimination after `if (a == null) return`) is lossy.

### A9. Async / await are treated as synchronous (with promise rejection flow)

**Lines:** 5120 (`async` skip), 6472 (`await` unwrap), 7905–7935
(instantiateFunction rejection-label accumulator), 6262–6272
(`.catch` handler reading `rejectionLabels`), 10706–10720 (async
function declaration stamping).
**Class:** SAFE for data-flow, PARTIAL for temporal.
**Statement.** Async functions are parsed with an `isAsync` flag.
`async function f() {…}`, `async function(…)` expressions, and
`async (…) => …` arrows all set the flag on the resulting
`functionBinding`. `await e` still resolves synchronously to `e`'s
`innerType` if `e` is a `Promise<T>`, else to `e` directly. The
event loop, microtask ordering, and suspension semantics are
invisible — the walker executes async bodies straight-line.

**Promise rejection flow (A9 sub-gap closure).** Unhandled throws
inside an async function body become the rejection labels of its
returned Promise:

1. `instantiateFunction` pushes a fresh `Set<label>` onto
   `_tryThrowAccStack` before walking the body iff `fn.isAsync`
   is true.
2. The walker's `throw` handler (shared with G6 exception flow)
   unions throw-expression labels into the top accumulator; an
   inner try-catch pushes its own deeper entry so handled
   throws don't escape.
3. After the body walk, the accumulator is popped. If non-empty,
   the labels are attached to the return token array as
   `_rejectionLabels` (and the result is typed as `Promise` if
   not already).
4. The caller's `chainBinding` wrapper copies `_rejectionLabels`
   onto the chain as `chain.rejectionLabels`.
5. The `.catch(cb)` handler in `applyMethod` reads
   `bind.rejectionLabels` and binds `cb`'s first parameter to
   an opaque chain tagged with those labels.
6. The `.then(cb)` handler propagates `rejectionLabels` through
   the returned chain so `.then(x => …).catch(e => …)` still
   consumes the upstream rejection.

**Condition.** Sound for data-flow through async functions: every
unhandled throw inside an async body reaches a `.catch` downstream
with its labels. Sound for temporal properties ONLY when those
properties don't depend on the order microtasks resolve —
anything stateful (e.g. "this initialiser must run before that
sink") is still too coarse.

### A10. Constructor-function `new` ✓ implemented

**Lines:** 6783–6817 (constructor-function walking),
6579–6770 (existing class / Proxy / Map-Set paths).
**Class:** SAFE.
**Statement.** When `new C(args)` is evaluated and `C` resolves
to a plain function binding (not a class, not Proxy, not a
built-in `_mapLike`), the walker now:

  1. Creates a fresh empty Object binding as the instance.
  2. Reads the constructor arguments via `readCallArgBindings`.
  3. Calls `instantiateFunction(C, args, instance)` — the
     constructor body walks with `this` bound to the fresh
     instance, so `this.prop = arg` writes populate the
     instance object (and feed `_varMayBe` for subsequent
     indirect-dispatch lookups).
  4. If the constructor returns a non-chain binding (object /
     array / function), ECMAScript semantics say `new` yields
     that return value rather than the freshly constructed
     `this`. Otherwise yield the instance.

Closes the pre-class constructor-function pattern
`function Foo(x) { this.x = x; }` and the factory pattern
`function Factory(x) { return { prop: x }; }`. Taint flows
through argument-to-instance writes and through method calls
on the resulting instance.

**Condition.** Sound for any constructor whose body is a plain
JavaScript function (the walker supports all the same constructs
as ordinary function bodies). Unknown `new C(args)` where `C`
does not resolve to a function binding still falls through to
the opaque-expression handler further down, which propagates
arg-taint but loses side effects — tracked as a narrower
sub-gap (genuinely unknown / dynamically-imported constructors).

### A11. `eval` and `with` are unmodelled

**Lines:** no dedicated handler.
**Class:** UNSAFE in the strict sense.
**Statement.** The walker does not interpret `eval(s)` even when `s`
is a known constant string, and `with (obj) { … }` is treated as a
plain block scope.
**Condition.** Sound iff the program does not use `eval` for control
flow or `with` for scope manipulation. In the security setting we
report `eval(tainted)` itself as a critical sink (`code` finding) so
the dangerous case is not missed even though the body of the eval'd
string is not analysed.

### A12. `Function.prototype.bind` partial application ✓ implemented

**Lines:** 5739–5768 (applyMethod `.bind` handler),
7918–7930 (instantiateFunction entry-point prepend).
**Class:** SAFE.
**Statement.** `f.bind(thisArg, ...preBound)` now clones the
function binding and stores `_boundArgs := preBound` and
`_boundThis := thisArg` on the clone (the original is untouched
so other references to `f` aren't disturbed). When the clone is
later called, `instantiateFunction` prepends `_boundArgs` to
the caller's argument list and uses `_boundThis` in place of
the caller's `thisBinding` if none was supplied. Rebinding via
a second `.bind(…)` concatenates the new pre-bound args onto
the existing `_boundArgs` but does NOT rebind `this` — matching
the ECMAScript spec where a bound function's `this` is fixed at
the outermost `.bind`.
**Condition.** Sound iff every `.bind` result flows through
`instantiateFunction` at its call site (which includes direct
calls, `.call`/`.apply` reflective dispatch, `.then`/`.catch`
callbacks, forEach callbacks, and factoryRef aliases). Chain
tokens that contain bound functions without ever hitting a call
site can't be refined further, but no taint flow is lost.

### A13. Parser failures silently fall back to opaque

**Lines:** 5684, 5920, 7362, many others (`return null` exits).
**Class:** UNSAFE.
**Statement.** When a sub-parser (e.g. `readArrowBody`,
`readFunctionExpr`, `peekArrow`) cannot make sense of the token
stream, it returns `null` and the caller falls back to opaque-call
propagation.
**Condition.** Sound iff every parser failure is a syntactic shape
the analysis genuinely cannot reason about. In practice many `return
null` exits are precision shortcuts where a more thorough parser
would extract structure. Each one is a potential lost flow.

### A14. `el.style.<prop>` CSS sinks fire only on element-extending receivers

**Lines:** 11083–11144.
**Class:** SAFE.
**Statement.** A `style.<prop>` write is classified as a CSS sink
only when the receiver is a tracked element binding **or** a
typed-chain path that resolves through the TypeDB to a type whose
`extends` chain reaches `HTMLElement` or `Element`. Receivers whose
type is unknown produce no finding.
**Condition.** Sound iff every CSS-injection-relevant code path
flows through a typed receiver. `var anyObj = { style: {} };
anyObj.style.cssText = tainted;` would not fire (correctly: it's not
a real element), but a typed wrapper around an element that hides
its underlying HTMLElement type from the analysis would also not
fire (incorrectly: the wrapper does eventually reach the DOM).

---

## §7. Known gaps (planned future work)

The following ECMAScript features are not modelled at all. Each is a
candidate for a dedicated transfer function in §4.

### G1. Generators (`function*` / `yield`) ✓ implemented

`functionBinding` carries an `isGenerator` flag set at parse time
when the walker sees `function*` (as a separate `*` op token
after `function`) in either a function declaration or a function
expression. `instantiateFunction` for a generator body pushes a
fresh entry onto `_yieldCaptureStack` before walking; the walker's
`yield` handler reads the yielded expression via `readValue` and
appends its binding to the top-of-stack accumulator. After the
body walk the accumulator is popped and its contents become the
elements of an `Array` binding — the generator's return value.

The approximation is **eager materialisation**: we model
`gen()` as if all yields had already happened, collapsing the
iterator protocol into a concrete array. `for (var v of gen())`
then iterates via the existing array-iteration path, destructure
patterns work via the G3-sub-gap code, and `[...gen()]` works
via a new spread-of-call extension in `_stepReadArrayLit`.

Sound for taint: every yielded label reaches the consumer. May
over-report when yields are path-dependent (we collect every
reachable yield, not just ones reachable under a particular
condition). Precise enough for real-world patterns; a truly lazy
iterator abstraction would require treating `gen()` as a
suspendable continuation with per-next() state.

Not yet modeled: `yield*` delegation to another iterable (treated
as a regular `yield` of the delegated expression for now);
generator `.next()` / `.throw()` / `.return()` method calls —
direct iteration via `for-of` and `spread` cover the common
cases.

### G2. Async iterators (`for await (… of stream)`)

The current `for-of` handler does not understand `await`. A
`for await (var chunk of fetch('/api'))` therefore drops the
`network` label.

**Sketch of fix.** Lift the for-of handler to recognise `for await`
and treat the iterable as `AsyncIterable<T>` with `T` extracted from
the iterable's `innerType`.

### G3. `Map.entries()` / `Map.values()` / `Set.values()` iteration ✓ implemented

`applyMethod` now materialises the `_mapLike` Object's stored
entries into a concrete Array binding when the method is
`.entries()`, `.values()`, or `.keys()`, and walks the callback
per entry for `.forEach()`. Known-string-keyed entries come from
`bind.props`; tainted / opaque keys and values are preserved on
`bind._opaqueEntries` (a list pushed at `.set` / `.add` time when
`chainAsKnownString` couldn't resolve the key) and included in
both iteration and forEach walks.

The statement-level walker also routes `m.forEach(cb)`,
`m.entries()`, `m.values()`, `m.keys()` through `applyMethod` so
bare-statement calls fire the same iteration handlers as
expression-position ones.

The for-of loop handler was extended along two axes:

  1. Loop variables bind to structured elements (array / object
     / element) when iterating an array of such elements — so
     `for (var pair of m.entries()) pair[1]` resolves `pair[1]`
     correctly.
  2. **Destructure-in-for-of** is now supported: when the loop
     variable is a destructure pattern like `var [k, v]` or
     `var {prop}`, `readDestructurePattern` parses the pattern,
     `applyPatternBindings` maps each known element through it,
     and each leaf name is bound in the loop frame to an opaque
     chain carrying the union of labels from its matching slot
     across every known element. Position sensitivity holds:
     `for (var [k, v] of [[tainted, "v"]])` flags reads of `k`
     but not `v`.

### G4. `Symbol.iterator` protocol on plain objects

A user-defined iterator (`{ [Symbol.iterator]: function*() { … } }`)
is not recognised. `for (var v of customIter)` walks an opaque
chain.

### G5. Parametric `Array<T>` for opaque arrays

Materialised arrays preserve element identity, but an array returned
from an opaque API like `JSON.parse(s)` is a single chain with no
element type. There is no `innerType` analogue for `Array<T>` the
way `Promise<T>` has `innerType: T`.

**Sketch of fix.** Add an `elementType` field to opaque chains
typed `Array` and propagate it through `.forEach(e => …)`,
`.map(e => …)`, etc. so the callback's first param is bound to a
chain typed by `elementType`.

### G6. Real interprocedural exception flow ✓ implemented

The walker-driven throw accumulator `_tryThrowAccStack` (§4.5)
captures every `throw e` reached during a try body walk —
directly OR through arbitrarily-deep function calls — and
respects nested try-catch boundaries so handled throws don't
escape. `try { f(); } catch (e) { sink(e.message); }` now flows
labels from inside `f`'s body (and any function `f` calls
transitively) to the caller's catch parameter. This is the
academic effect-system semantics; each function's effective
`thrown : Λ` set is the labels of throws it does not catch
internally.

Promise rejection flow (previously a sub-gap of A9) is now
**implemented** as an extension of this same walker-driven
accumulator: `instantiateFunction` pushes a fresh entry onto
`_tryThrowAccStack` when entering an `async` function body, so
unhandled throws surface as `chain.rejectionLabels` on the
returned Promise. The `.catch(cb)` handler reads these labels
and binds them to the callback's first parameter. See A9 in §6.

### G7. Path-sensitive function summaries

Currently summaries are keyed by argument fingerprint but produce a
single result that conflates all return paths. The §4.7.1 target
moves toward path-sensitive returns at the **call site** but not yet
at the **summary** level — caching a function with different
incoming path conditions still produces the same cached result.

**Sketch of fix.** Extend `SummaryKey` with the relevant slice of
the caller's path constraints. This is k-CFA-style context
sensitivity restricted to the constraints actually consulted by the
body.

### G8. Heap shape / points-to analysis

The `_varMayBe` lattice is the closest thing to a points-to
abstraction but is name-keyed, not heap-keyed. Aliasing through
containers (`refs.push(o); refs[i].x = …`) is approximated only for
literal indices.

**Sketch of fix.** Add an Andersen-style points-to graph with one
node per `__objId` and edges for prop reads / writes. Field
sensitivity (`o.f` distinct from `o.g`) gives Steensgaard-level
precision; flow sensitivity gives Andersen-level.

### G9. Widening operator on `_varMayBe`

To make A5 a true precision/cost trade-off rather than an
unbounded-growth risk, replace the unbounded `vals` list with a
bounded abstraction that widens after `k` accumulated values to
`⊤_Λ` (all possible labels) and `⊤_T` (all possible types).

---

## §8. References

The framing and operators in this document are standard
abstract-interpretation material. Specific influences:

- **Cousot & Cousot (1977), "Abstract Interpretation: A Unified
  Lattice Model for Static Analysis of Programs by Construction or
  Approximation of Fixpoints."** Source for the `⟦stmt⟧ : A → A`
  transfer-function framing in §4 and the soundness theorem in §5.

- **Cousot & Cousot (1992), "Abstract Interpretation Frameworks."**
  Source for the widening (∇) and narrowing (Δ) operators referenced
  by the absence-of-widening discussion in §4.4 and assumption A5.

- **TAJS — Type Analysis for JavaScript (Jensen, Møller, Thiemann
  2009).** The lattice over JavaScript values in §2.1 is loosely
  modeled on TAJS's abstract value lattice. TAJS distinguishes
  primitive abstractions (e.g. `STR_UINT`, `STR_PREFIX`) more finely
  than we do; we collapse all string-like values to the chain
  abstraction with token-level provenance.

- **Andersen (1994), "Program Analysis and Specialization for the C
  Programming Language."** Inspiration for the (planned) points-to
  abstraction in G8. Andersen's subset-based formulation maps
  cleanly onto the proposed `_varMayBe` replacement.

- **Steensgaard (1996), "Points-to Analysis in Almost Linear
  Time."** The faster, less precise alternative to Andersen also
  considered for G8.

- **Bodin et al. (2014), "A Trusted Mechanised JavaScript
  Specification."** Relevant if we ever want to verify the §5
  soundness theorem mechanically against an executable
  specification of ECMAScript.

- **Vanegue & Heelan (2012), "SMT Solvers for Software Security."**
  Background for the SMT-refutation use of Z3 in §3.5 and §4.3.

- **The Z3 SMT-LIB v2 standard.** Direct dependency: every formula
  pushed onto `pathConstraints` is an SMT-LIB AST consumed by the
  vendored Z3 build.

---

## Appendix: Where to look in the source

| Concept                          | Lines              |
|----------------------------------|--------------------|
| Binding constructors             | 3205–3258          |
| Token type definitions           | 3261–3289 + uses   |
| `collectChainTaint`              | 691–721            |
| `_typeLUB`                       | 735–755            |
| `getBindingLabels`               | 772–777            |
| `_varMayBe` may-be lattice       | 3501–3638          |
| `pathConstraints` push/pop       | 8471–8478          |
| `walkRange` state machine        | 8557–9500          |
| `instantiateFunction`            | 7353–7720          |
| Function summary cache           | 7178, 7320–7352, 7704 |
| `recordTaintFinding` + dedup     | 3845–3895          |
| TypeDB                           | 12418–13190        |
| `attrSinks`                      | 13141–13152        |
| `tagMap`                         | 13116–13135        |
| `eventMap`                       | 13155–13180        |
| Multi-return merge (heuristic)   | 7619–7654          |
| `if_merge` task                  | 8324–8430          |
| `try_merge` task                 | 8421–8470          |
| `switch_merge` task              | 8504–8569          |

