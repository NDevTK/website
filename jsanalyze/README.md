# jsanalyze

A whole-program static analysis library for JavaScript, designed from
first principles for **precision on real code**, **explicit tracking
of every approximation**, and **iterative analysis that never blows
the call stack**.

This is a from-scratch rewrite of the engine that previously lived under
`htmldom/`. The browser UI now lives under `analyzer/`
(`analyzer/index.html`) and loads the new engine via the browser
bundle at `jsanalyze/browser-bundle.js`. The legacy engine and its
legacy consumers have been removed from the tree.

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
   kind the analyser can pattern-match on. No ad-hoc tokenizer, no
   brace-matching heuristic.

4. **SSA intermediate representation.** The AST is lowered to a
   typed SSA form with a control-flow graph of basic blocks. Every
   analysis pass operates on the IR, not the AST — scope, phi
   merges, and control dependence are explicit rather than inferred.

5. **Full path sensitivity with state correlation.** Branches split
   the abstract state into disjoint sub-states, each refined by the
   branch condition. Sub-states are only re-joined at post-
   dominators. Correlations between branch guards are preserved
   via B4 multi-variant worklist state.

6. **Z3-backed reachability and witness generation.** The reachability
   cascade's Layer 5 and the post-pass refutation both call Z3
   (`src/z3.js`) on the accumulated path formulas. The
   `taint-report` consumer reuses the same solver via `getModel`
   to extract concrete attacker inputs from reachable flows
   (sink-specific exploit shapes live there, not in the engine).
   Z3 is required — there is no "disable SMT" fallback.

7. **Every approximation is recorded as an explicit Assumption.**
   When the analyser gives up — because the value came from the
   network, because SMT timed out, because a feature isn't
   implemented yet — it emits an `Assumption` record with a reason
   code and a location. Consumers query `trace.assumptions` to
   understand exactly where and why the analysis is imprecise.

8. **Sound over-approximation as the universal fallback.** When a
   branch's reachability is genuinely unknown, the analyser treats
   it as reachable. When a value's content is genuinely unknown, it
   becomes `Opaque` with a cited assumption. Findings are never
   silently dropped.

9. **Single precision axis: `options.accept`.** There is no
   `precision: 'fast' | 'precise' | 'exact'` knob. Every trade-off
   between performance, precision, and soundness is expressed as
   the set of assumption reason codes the consumer tolerates. Fast
   mode adds `'smt-skipped'`; exact mode removes `'summary-reused'`;
   strict mode removes the environmental reasons. See
   `docs/API.md`.

## Layout

```
jsanalyze/
├── src/
│   ├── parse.js          acorn wrapper (vendored)
│   ├── ir.js             SSA IR types + AST→IR builder (multi-file
│   │                     project support via buildProjectModule)
│   ├── domain.js         abstract domain (Value, State, lattice ops)
│   ├── transfer.js       transfer functions per IR instruction
│   ├── worklist.js       iterative fixpoint engine (B4 multi-variant)
│   ├── reach.js          reachability cascade (layers 1-5)
│   ├── assumptions.js    Assumption record + reason codes + DEFAULT_ACCEPT
│   ├── query.js          public query.* namespace over a Trace
│   ├── typedb.js         TypeDB schema + lookup helpers
│   ├── default-typedb.js default browser TypeDB (Location, Storage,
│   │                     Element, Node, HTMLCollection, …)
│   ├── smt.js            SMT-LIB formula construction
│   ├── z3.js             Z3 solver wrapper (checkPathSat, getModel,
│   │                     refuteTrace)
│   ├── html.js           HTML literal parser + serialiser
│   ├── html-templates.js JS accumulator-pattern extractor
│   │                     (concrete / append / branch / switch /
│   │                     loop / block-loop templates)
│   └── index.js          analyze() entry point
├── consumers/
│   ├── dom-convert.js    innerHTML / outerHTML / document.write /
│   │                     insertAdjacentHTML → createElement trees.
│   │                     Preserves loops, branches, function
│   │                     boundaries. Ships convertProject for
│   │                     per-HTML-file multi-file rewrites.
│   ├── taint-report.js   Human-readable taint flow report AND
│   │                     Z3-backed PoC synthesis. Takes a trace
│   │                     + sink-specific exploit constraint,
│   │                     attaches a concrete attacker-input
│   │                     witness to every surviving flow via
│   │                     `synthesisePocs`.
│   ├── fetch-trace.js    HTTP endpoint discovery from trace.calls.
│   └── csp-derive.js     CSP directive derivation from
│                         trace.stringLiterals + trace.domMutations.
├── vendor/
│   ├── acorn.js          vendored parser
│   └── z3-solver/        vendored Z3 WASM (single canonical copy)
├── scripts/
│   └── build-bundle.js   builds jsanalyze/browser-bundle.js
├── browser-bundle.js     single-file bundle loaded by analyzer/index.html
├── test/
│   └── *.test.js         635 tests across engine + consumers
├── docs/
│   ├── API.md            public API reference
│   ├── DESIGN-DECISIONS.md  architectural decisions + library/
│   │                        consumer boundary (D11.1)
│   ├── IR.md             IR instruction set
│   ├── ABSTRACT-DOMAIN.md formal abstract domain + transfer functions
│   └── ASSUMPTIONS.md    catalogue of assumption reason codes
└── README.md
```

## Usage

### Single-file analysis

```js
const { analyze, query } = require('./jsanalyze');

const trace = await analyze(
  'var x = location.hash; document.getElementById("o").innerHTML = x;',
);

for (const flow of query.taintFlows(trace)) {
  console.log(flow.sink.kind, flow.sink.prop, '←',
    flow.source.map(s => s.label).join(','));
}
```

### Multi-file project

```js
const trace = await analyze(
  {
    'store.js': 'var items = []; function addItem(t) { items.push(t); }',
    'app.js':
      'var html = ""; for (var i = 0; i < items.length; i++) {' +
      ' html += "<li>" + items[i] + "</li>"; } ' +
      'document.getElementById("out").innerHTML = html;',
  },
  { project: ['store.js', 'app.js'] },   // ordered script-srcs
);
```

Project mode builds one IR module whose top-level scope is the
concatenation of each file's statements in order, so `app.js` sees
`items` declared in `store.js`. This matches how the browser
evaluates multiple `<script src="…">` tags into one global scope.

### DOM conversion consumer

```js
const { convertProject } = require('./jsanalyze/consumers/dom-convert.js');

const files = {
  'index.html': '<html><body><div id="o"></div>' +
                '<script src="app.js"></script></body></html>',
  'app.js':     'document.getElementById("o").innerHTML = ' +
                '"<p>" + location.hash + "</p>";',
};
const out = await convertProject(files);
// out['app.js'] rewrites innerHTML = "…" into createElement / appendChild
// calls that preserve runtime semantics.
```

Each HTML page in the project is analysed with its own set of
script-src JS files as siblings sharing the top-level scope. Pages
are independent: `a.html` and `b.html` are processed as separate
analyses even when they share some scripts.

### Taint report + PoC synthesis consumer

```js
const tr = require('./jsanalyze/consumers/taint-report.js');

const report = await tr.analyze(
  'var h = location.hash.slice(1); document.body.innerHTML = h;');

for (const flow of report.flows) {
  if (flow.poc && flow.poc.verdict === 'synthesised') {
    console.log('[' + flow.sink.kind + '] payload:', flow.poc.payload);
    console.log('  attempt:', flow.poc.attempt);
    console.log('  bindings:', flow.poc.bindings);
    // Example:
    //   [html] payload: <script>alert(1)</script>
    //     attempt: script-tag
    //     bindings: { url: '<script>alert(1)</script>' }
  }
}
```

`tr.analyze` walks the program (via the engine), then for every
surviving taint flow conjoins the flow's `pathFormula` with a
sink-specific exploit constraint on the `valueFormula` and asks
Z3 for a satisfying model.

**Multiple exploit attempts per sink.** Each sink kind has an
ordered list of candidate payloads — for `html` the list is
`<script>`, `<img onerror>`, `<svg onload>`, attribute-breakout,
style-breakout. The synthesiser tries each in order and returns
the first that Z3 reports SAT, naming the winning shape in
`poc.attempt`. Direct attacker-controlled flows with no
intermediate constraints return the primary payload without a
solver round-trip.

**Per-source bindings.** `poc.bindings` is a map from source
label (e.g. `'url'`, `'postMessage'`, `'persistent-state'`) to
the string Z3 chose for that source. Multi-source flows get one
binding per source so delivery consumers can format reproducers
(URL fragments, postMessage calls, storage writes) per source.

**Symbolic operations.** String methods registered with an
`smtOp` in the TypeDB (`slice`, `substring`, `substr`, `charAt`,
`concat`, `replace`, `replaceAll`, `indexOf`, `includes`,
`startsWith`, `endsWith`, `length`) propagate SMT formulas
through the lattice, so `location.hash.slice(1)` and
`'pre:' + location.hash.replace('a', 'b')` remain solvable.
Unmodelled ops (`trim`, `split`, `toLowerCase`, …) raise an
`unsolvable-math` assumption at the call site so the precision
drop is visible in strict mode.

**Direct API.** `tr.synthesisePocs(trace, options)` attaches
PoCs to a pre-built trace without re-analysing.

## Browser integration

`scripts/build-bundle.js` concatenates every file under `src/` and
`consumers/` into a single self-contained IIFE at
`jsanalyze/browser-bundle.js` (`globalThis.Jsanalyze`). The bundle
is loaded by `analyzer/index.html` via `analyzer/monaco-init.js` and
`analyzer/jsanalyze-bridge.js`; the Z3 WASM is loaded separately via
`analyzer/jsanalyze-z3-browser.js`.

Rebuild after library / consumer changes:

```
node jsanalyze/scripts/build-bundle.js
```

## Status

Run `node jsanalyze/test/run.js` to see the current pass count
(updated every commit).

**Working consumers:**

- `dom-convert.js`  — concrete, append, branch (incl. else-if
  chains + nested ternaries), switch, loop (for / while /
  do-while / for-in / for-of), block-loop (loop inside branch),
  nested loops, branch-in-loop, template literal RHS,
  `innerHTML +=` append, `outerHTML = …` via
  `parentNode.replaceChild`, `insertAdjacentHTML` with
  position-aware insertion, `document.write` /
  `document.writeln`, negative cases (plain-object receivers,
  var named `innerHTML`, innerHTML in comments / strings).
- `taint-report.js` — human-readable findings AND Z3
  `getModel`-based PoC synthesis for html / navigation / url /
  code sinks.
- `fetch-trace.js`  — HTTP endpoint discovery.
- `csp-derive.js`   — CSP directive derivation.

**Engine features:** SSA IR, interprocedural worklist fixpoint,
B4 per-path state correlation, C3 k-CFA summary cache,
classes / closures / destructuring / arrow functions / template
literals / switch / try/catch, callbacks via
`addEventListener` / `setTimeout` / `setInterval`, Z3 Layer 5
branch refutation, Z3 post-pass refutation, multi-file projects.

See `docs/DESIGN-DECISIONS.md` for the full architectural
rationale.
