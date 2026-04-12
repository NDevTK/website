# jsanalyze

A whole-program static analysis library for JavaScript, designed from
first principles for **precision on real code**, **explicit tracking
of every approximation**, and **iterative analysis that never blows
the call stack**.

This is a from-scratch rewrite of the engine that previously lived in
`htmldom/jsanalyze.js`. The old engine ships and still powers the
four consumers in `htmldom/` (htmldom-convert, fetch-trace,
taint-report, csp-derive). The new engine is intended to eventually
replace it — both are kept side by side during the transition.

## Design principles

1. **No hardcoded third-party library knowledge.** Every source,
   sink, sanitiser, and type is declared in the TypeDB. The engine
   treats Lodash, React, jQuery, and `location.hash` the same way:
   look up the declarative descriptor and apply it.

2. **Iterative engine, never recursive.** The worklist fixpoint is
   a `while` loop over a queue of basic blocks. No transfer function
   recurses into itself or into another analysis pass. Deeply nested
   code, large call graphs, and arbitrary expressions never blow the
   JavaScript call stack.

3. **Proper AST parser.** Source is parsed via
   [acorn](https://github.com/acornjs/acorn) (vendored under
   `vendor/`). Every construct in the ECMAScript spec is a node
   kind the analyser can pattern-match on. There is no ad-hoc
   tokenizer and no brace-matching heuristic.

4. **SSA intermediate representation.** The AST is lowered to a
   typed SSA form with a control-flow graph of basic blocks. Every
   analysis pass operates on the IR, not the AST — so scope, phi
   merges, and control dependence are explicit rather than inferred.

5. **Full path sensitivity.** Branches split the abstract state
   into disjoint sub-states, each refined by the branch condition.
   Sub-states are only re-joined at post-dominators. Correlations
   between branch guards are preserved.

6. **Every approximation is recorded as an explicit Assumption.**
   When the analyser gives up — because the value came from the
   network, because SMT timed out, because a feature isn't
   implemented yet — it emits an `Assumption` record with a reason
   code and a location. Consumers query `trace.assumptions` to
   understand exactly where and why the analysis is imprecise.

7. **Sound over-approximation as the universal fallback.** When a
   branch's reachability is genuinely unknown, the analyser treats
   it as reachable. When a value's content is genuinely unknown, it
   becomes `Opaque` with a cited assumption. Findings are never
   silently dropped.

8. **Cascaded reachability checks.** Cheap analyses first (dead
   control flow, constant propagation, value-set refutation, type
   narrowing), SMT only when they can't decide. Z3 is the last
   resort, not the default.

## Layout

```
jsanalyze/
├── src/
│   ├── parse.js         acorn wrapper
│   ├── ir.js            SSA IR types + AST→IR builder
│   ├── domain.js        abstract domain (Value, State, lattice ops)
│   ├── transfer.js      transfer functions per IR instruction
│   ├── worklist.js      iterative fixpoint engine
│   ├── reach.js         reachability cascade
│   ├── assumptions.js   Assumption record + reason codes
│   ├── query.js         public query.* namespace over a Trace
│   ├── typedb.js        default TypeDB (pure data)
│   └── index.js         analyze() entry point
├── vendor/
│   └── acorn.js         vendored parser
├── test/
│   └── *.test.js        tests
├── docs/
│   ├── API.md           public API reference
│   ├── IR.md            IR instruction set
│   ├── ABSTRACT-DOMAIN.md  formal abstract domain + transfer functions
│   └── ASSUMPTIONS.md   catalog of assumption reason codes
└── README.md
```

## Usage

```js
const { analyze, query } = require('./jsanalyze');

const trace = await analyze({
  'app.js': 'var x = location.hash; document.getElementById("o").innerHTML = x;',
}, { taint: true });

// Query the results.
for (const flow of query.taintFlows(trace)) {
  console.log(flow.sink.prop, '←', flow.sources);
}

// Inspect what the analyser had to assume.
for (const a of query.assumptions(trace)) {
  console.log(a.reason, ':', a.details, '@', a.location.file, a.location.line);
}
```

## Status

Under active development. See `docs/ABSTRACT-DOMAIN.md` for the
formal design and `test/` for the current coverage. The engine is
being built from the ground up on a minimal JS subset and expanded
by construction; every supported construct has an explicit
transfer function and regression tests.

**What works today:** the foundation — parser, IR builder, domain
types, worklist shell, assumption API, public query surface. A
minimal end-to-end vertical slice (literals, variables, assignment,
binary operations) is tested.

**What doesn't yet:** most of ECMAScript. This is by design — the
rewrite explicitly refuses to inherit the old engine's ad-hoc
coverage. Every feature is added with a formal transfer function,
a soundness statement, and tests.
