# Public API

This document defines the **stable public interface** that
consumers depend on. Internal types, IR nodes, worklist state,
and solver details are NOT public — consumers may only reference
types defined here.

## Entry point

### `analyze(input, options?) → Promise<Trace>`

Parses the input, lowers it to IR, runs the worklist fixpoint,
and returns a `Trace` object. The analysis is fully deterministic
given a fixed input, TypeDB, and precision setting.

**Parameters.**

- `input: string | { [filename: string]: string }`
  - Bare string: analysed as a single top-level script file named
    `<input>.js`.
  - Object: analysed as a multi-file project. Keys are filenames,
    values are source strings. File dependency order is inferred
    from imports; files with no imports are walked first.

- `options?: AnalyzeOptions`

### `AnalyzeOptions`

```ts
type AnalyzeOptions = {
  // Custom TypeDB. Overrides the default. See `docs/TYPEDB.md`.
  typeDB?: TypeDB;

  // Soft cap per SMT call in milliseconds. Exceeded calls
  // return 'unknown' and raise an `unsolvable-math` assumption.
  // Default: 5000. Plumbed through to z3.checkPathSat on every
  // Layer 5 invocation and to the post-pass refutation.
  smtTimeoutMs?: number;

  // PRESCRIPTIVE assumption-acceptance set. Declares which
  // assumption reason codes the consumer tolerates.
  // `accept` is the SINGLE axis for every precision /
  // performance / soundness trade-off — there's no parallel
  // `precision: 'fast' | 'precise' | 'exact'` option.
  //
  // Omitting the option gives the default accept set, which
  // includes every reason code EXCEPT `'smt-skipped'`:
  // that default corresponds to what legacy engines called
  // "precise mode" — engine runs Z3, takes loop-widening
  // and summary-reuse shortcuts, and accepts every
  // theoretical-floor reason.
  //
  // Passing an explicit `accept: [...]` gives fine-grained
  // strict mode. Any assumption raised with a reason NOT in
  // the set is copied into `trace.rejectedAssumptions` and
  // sets `trace.partial = true`. Rejection is prescriptive
  // for performance shortcuts (the engine does NOT take
  // them) and advisory for theoretical-floor reasons (the
  // engine can't conjure bytes it doesn't have).
  //
  // Common recipes:
  //
  //   * Fast mode: add 'smt-skipped' to the accept set so
  //     the engine skips Z3 at branch decisions and the
  //     post-pass refutation. Consumer gets faster analysis
  //     at the cost of keeping infeasible taint flows.
  //
  //   * Exact mode: remove 'summary-reused' from the accept
  //     set so every call site walks the callee body
  //     fresh. O(calls × body) cost; full context
  //     sensitivity.
  //
  //   * Strict mode: remove 'opaque-call' /
  //     'external-module' / 'unimplemented' / 'heap-escape'
  //     so the engine flags every imprecise spot as a
  //     rejected assumption on the trace.
  //
  // Class 4 (performance shortcuts) default membership:
  //
  //     loop-widening         IN  (engine widens by default)
  //     summary-reused        IN  (engine caches by default)
  //     smt-skipped           OUT (engine runs Z3 by default)
  //
  // Defaults favor precision over speed. Consumers that
  // want speed opt in to 'smt-skipped'; consumers that want
  // maximum precision opt out of 'loop-widening' /
  // 'summary-reused'.
  accept?: AssumptionReason[];

  // Enable taint tracking. When false, the analyser skips
  // source/sink classification but still produces the call
  // graph, string literals, and value sets. Default: true.
  taint?: boolean;

  // Streaming watchers. Invoked during the walk rather than
  // after. Use for long-running analyses where incremental
  // feedback matters.
  //
  //   onCall       — fired for every user-function call walked
  //                  interprocedurally. The callback receives
  //                  (callee, argValues, thisValue, state, loc,
  //                  instr). May return an override { value,
  //                  state } to short-circuit the walk.
  //   onFinding    — fired with each TaintFlow as it is emitted.
  //   onAssumption — fired with each Assumption as it is raised.
  watchers?: {
    onCall?: (callee, argValues, thisValue, state, loc, instr) =>
      void | { value: Value, state?: State };
    onFinding?: (flow: TaintFlow) => void;
    onAssumption?: (a: Assumption) => void;
  };
};
```

## Trace

The `Trace` is pure data, JSON-serialisable, and versioned. Every
field is a stable contract.

```ts
type Trace = {
  schemaVersion: '2';
  files: { [filename: string]: string };

  // Every call site observed during the walk. Arguments are
  // resolved to their abstract `Value`.
  calls: CallInfo[];

  // Taint flows from sources to sinks, with accumulated path
  // conditions. Flows whose path condition Z3 proved UNSAT at
  // branch-decision time (Layer 5) are never emitted and do
  // not appear here. Flows refuted by the post-pass are moved
  // to `refutedFlows`.
  taintFlows: TaintFlow[];

  // Flows that the Z3 post-pass refutation moved out of
  // `taintFlows`. Present only when the post-pass found at
  // least one refutable flow (when the consumer has
  // accepted 'smt-skipped' Z3 never runs and this field is
  // never populated). Consumers that want to audit which
  // flows were dropped inspect this list; consumers that
  // only want surviving flows ignore it.
  refutedFlows?: TaintFlow[];

  // Assumptions that were raised during the walk AND whose
  // reason code was NOT in `options.accept`. Empty when the
  // consumer didn't pass an accept set or when every raised
  // assumption's reason was in it. Presence sets
  // `partial = true`.
  rejectedAssumptions: Assumption[];

  // Wave 12b: DOM mutations — method calls and property
  // writes on DOM-typed receivers. Consumers that rewrite or
  // inventory DOM code read from here.
  domMutations: DomMutation[];

  // Assignments to innerHTML / outerHTML / document.write.
  innerHtmlAssignments: InnerHtmlAssignment[];

  // String literals observed in specific contexts (e.g. assigned
  // to script.src, passed to fetch).
  stringLiterals: LiteralObservation[];

  // Value sets per top-level binding name.
  mayBe: { [name: string]: ValueSet };

  // Final top-level bindings — what each top-level name is
  // bound to at the end of analysis.
  bindings: { [name: string]: Value };

  // Call graph from observed calls.
  callGraph: {
    nodes: CallGraphNode[];
    edges: CallGraphEdge[];
  };

  // Reachability map: for every block in the program, the
  // analyser's verdict.
  reachability: Map<Location, 'reachable' | 'unreachable' | 'unknown'>;

  // Every assumption raised during analysis.
  assumptions: Assumption[];

  // Partial-walk notices (analysis errors, timeouts, parser
  // recovery points).
  warnings: Warning[];

  // True iff the analyser hit a hard error that cut a walk
  // short. A partial trace still contains everything the
  // analyser learned before the cut.
  partial: boolean;
};
```

## Value

The abstract value shape consumers see. This is a **projection**
of the internal `Value` type, flattened and serialised for query
consumption. Internal refinements like `Interval` or `StrPattern`
are surfaced through dedicated helper queries.

```ts
type Value =
  | { kind: 'concrete';  value: Primitive;           typeName?: string; provenance: Source[]; }
  | { kind: 'oneOf';     values: Primitive[];        typeName?: string; provenance: Source[]; }
  | { kind: 'interval';  lo: number; hi: number;     typeName?: string; provenance: Source[]; }
  | { kind: 'strPattern'; pattern: StringPattern;    typeName?: string; provenance: Source[]; }
  | { kind: 'object';    props: Record<string, Value>; typeName?: string; provenance: Source[]; }
  | { kind: 'array';     elems: Value[];              typeName?: string; provenance: Source[]; }
  | { kind: 'closure';   name?: string; params: number; bodyRef: FunctionRef; provenance: Source[]; }
  | { kind: 'opaque';    assumptionIds: number[];     typeName?: string; provenance: Source[]; };

type Primitive = string | number | boolean | bigint | null;

type StringPattern = {
  prefix?: string;
  suffix?: string;
  contains?: string[];
  exactLength?: number;
};

// Wave 12 — innerHTML / outerHTML / insertAdjacentHTML
// assignment observation. Every write to a property the
// TypeDB classifies as an 'html' sink is recorded here,
// regardless of whether the value is tainted.
//
// When the assigned value is a concrete string, the trace
// EAGERLY parses it via the vendored HTML parser
// (src/html.js) and attaches:
//   * `concrete`     — the raw string source
//   * `parsedHtml`   — the parsed HTML fragment tree
//   * `htmlTokens`   — the flat token stream for source-
//                      preserving rewrites (dom-convert
//                      mutates these in place and calls
//                      html.serializeTokens to re-emit)
//
// Non-concrete values (loop-built strings, tainted opaque,
// OneOf unions) get `parsedHtml = null` / `htmlTokens = null`
// / `concrete = null`. Consumers detect this and fall back
// to runtime-guarded rewrites (wrapping the tainted value in
// a `__safeNav`-style filter).
type InnerHtmlAssignment = {
  kind: 'innerHTML' | 'outerHTML' | 'insertAdjacentHTML';
  targetType: string;                // receiver's TypeDB typeName
  value: Value;                      // the assigned Value
  location: Location;
  labels: string[];                  // taint labels on value
  concrete: string | null;           // raw string when concrete
  parsedHtml: HtmlNode | null;       // parsed fragment when concrete
  htmlTokens: HtmlToken[] | null;    // flat token stream when concrete
};

type HtmlNode =
  | { type: 'fragment'; children: HtmlNode[]; loc: { start, end } }
  | { type: 'element'; tag: string; tagRaw: string;
      attrs: Record<string, string>;
      attrList: HtmlAttr[];          // ordered, with original casing
      children: HtmlNode[]; loc }
  | { type: 'text'; value: string; loc }
  | { type: 'comment'; value: string; loc }
  | { type: 'doctype'; value: string; loc };

type HtmlAttr = {
  name: string;                      // lowercase
  nameRaw: string;                   // original casing
  value: string;                     // entity-decoded
  quoted: '"' | "'" | null;          // original quoting style
};

// Wave 12b — DOM mutation observation. Every method call
// whose receiver has a DOM-chain typeName, and every property
// write on a DOM-chain receiver (except innerHTML/outerHTML/
// insertAdjacentHTML, which have their own innerHtmlAssignments
// channel), appears as one DomMutation record.
//
// Consumers filter by `kind` to find specific API use:
// `'setAttribute'`, `'appendChild'`, `'addEventListener'`,
// `'style.setProperty'`, `'classList.add'`, etc. The
// `target` field is the receiver Value, so consumers can
// check its `typeName` to narrow to (say) HTMLIFrameElement.
type DomMutation = {
  kind: string;            // method name or property name
  category: 'method' | 'property-set';
  targetType: string;      // receiver's TypeDB typeName
  target: Value;           // receiver Value
  args: Value[];           // method args or [value] for property-set
  site: Location;
  pathFormula: Formula | null;   // path condition at the mutation site
};

type Formula = {
  expr: string;            // SMT-LIB v2 expression
  isBool?: boolean;
  incompatible?: boolean;
  // ... see src/smt.js for the full shape
};
```

Every `Value` carries `provenance` — the list of source locations
where it got its current shape.

## Assumption

```ts
type Assumption = {
  id: number;
  location: Location;
  reason: AssumptionReason;
  details: string;
  affects: Path | null;
  severity: 'soundness' | 'precision';
  chain: number[];  // upstream assumption ids
};

type AssumptionReason =
  // Theoretical floor: unknowable at analysis time
  | 'network'
  | 'attacker-input'
  | 'persistent-state'
  | 'dom-state'
  | 'ui-interaction'
  | 'environmental'
  | 'runtime-time'
  | 'pseudorandom'
  | 'cryptographic-random'
  | 'unsolvable-math'
  // Environmental: can be narrowed with more input
  | 'opaque-call'
  | 'external-module'
  | 'code-from-data'
  // Engineering gaps: can be eliminated by more code
  | 'unimplemented'
  | 'heap-escape';

type Location = {
  file: string;
  line: number;  // 1-based
  col: number;   // 1-based
  pos: number;   // byte offset into the file
  endPos?: number;
};

type Path = string; // dotted path like "user.name" or "results[0].url"
```

See `docs/ASSUMPTIONS.md` for the catalogue of reason codes.

## Query namespace

All query functions are **pure functions over a Trace**. They
never re-walk the source and are safe to call multiple times.

### `query.calls(trace, filter?) → CallInfo[]`

Every call site matching the filter.

```ts
type CallInfo = {
  callee: { text: string; resolved?: FunctionRef };
  args: Value[];
  thisArg?: Value;
  site: Location;
  reachability: 'reachable' | 'unreachable' | 'unknown';
  pathConditions: string[];
};

type CallsFilter = {
  targets?: string[];                     // callee name prefixes
  reached?: boolean;                      // only reachable calls
  argType?: { index: number; type: string };  // arg type filter
  site?: (loc: Location) => boolean;     // arbitrary site filter
};
```

### `query.taintFlows(trace, filter?) → TaintFlow[]`

Every observed taint flow.

```ts
type TaintFlow = {
  id: number;
  source: { label: string; location: Location };
  sink:   { kind: string; prop: string; location: Location };
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  pathConditions: string[];
  pathFormulas: unknown[];
  assumptionIds: number[];  // assumptions on this flow's path
};

type TaintFlowsFilter = {
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  source?: string;
  sinkKind?: string;
};
```

### `query.innerHtmlAssignments(trace) → InnerHtmlAssignment[]`

Every `el.innerHTML = …`, `el.outerHTML = …`, `document.write(…)`
site, resolved to a `Value`.

### `query.stringLiterals(trace, filter?) → LiteralObservation[]`

String literals observed in specific contexts — e.g. assigned to
`script.src`, passed as the first arg of `fetch`.

### `query.valueSetOf(trace, path) → Value`

The set of values a named binding or path takes across the
program.

### `query.callGraph(trace) → { nodes, edges }`

Call graph computed from observed calls.

### `query.assumptions(trace, filter?) → Assumption[]`

Every assumption raised during analysis, optionally filtered.

```ts
type AssumptionsFilter = {
  reason?: AssumptionReason[];
  severity?: 'soundness' | 'precision';
  file?: string;
  affectsPath?: Path;
};
```

### `query.reachability(trace, location) → 'reachable' | 'unreachable' | 'unknown'`

The analyser's verdict on a specific source location.

### `query.pathTo(trace, finding) → Path`

The ordered list of IR instructions from source to sink for a
given taint flow, with each step's abstract state.

## TypeDB

The TypeDB is pure data that drives source, sink, sanitiser, and
type resolution. See `docs/TYPEDB.md` for the full schema. It is
consumer-replaceable via `options.typeDB`.

```ts
type TypeDB = {
  types: { [typeName: string]: TypeDescriptor };
  roots: { [globalName: string]: string };   // global → typeName
  tagMap?: { [lowercaseTag: string]: string };
  eventMap?: { [eventName: string]: string };
};
```

## Stability

- **Versioned.** `Trace.schemaVersion === '2'`. The current
  version is `'2'`; the legacy engine was `'1'`. Consumers check
  the version and migrate on major bumps.

- **Additive changes allowed.** Adding new fields to `Trace`,
  new query functions, or new `AssumptionReason` variants is a
  minor version bump and doesn't break consumers.

- **Breaking changes forbidden without a version bump.**
  Changing an existing field's semantics, removing a query, or
  repurposing an assumption reason code requires a major bump.

- **Internal types are not public.** Anything not in this
  document is an implementation detail that may change without
  notice.
