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

## Whole-program fixpoint

Every JavaScript program is a set of entry points — module top, plus
every callback the runtime invokes asynchronously (DOM events, timers,
Promise settlements, MutationObserver callbacks, BroadcastChannel
messages). A single-pass analysis that walks each entry once can't see
cross-entry state machines: if handler A's write to a module global
is needed for handler B's sink to fire, walking B first means seeing
the global unwritten.

The engine runs an abstract-interpretation fixpoint over all entry
points. Registration (via a TypeDB `callbackArgs` descriptor) records
the callback; the fixpoint driver re-walks every registered callback
against the accumulated persisted state until nothing new is learnt.
Widening kicks in after 4 iterations to guarantee termination; the
bound is 8 iterations.

Channels the loop covers:

| Channel | Mechanism |
|---------|-----------|
| `addEventListener` / `onclick=` / `setTimeout-with-fn` / `setInterval` / `requestAnimationFrame` / `MutationObserver` / `BroadcastChannel` / service worker `message` | TypeDB `callbackArgs` declares which arg is the callback. Registration records; fixpoint walks. |
| `Promise.then` / `.catch` / `.finally` | Same. |
| Module-level globals written by any function | Writes flow through the shared heap during the callback walk; fixpoint joins them into persisted state. |
| Closure-captured shared state | Captures snapshot at registration; writes into captured objects propagate via the heap. |
| Class instance state | Method invocations share `this` via the heap. |
| Exported functions called from outside | Registered when the module exports them. |

Not covered by the loop (needs additional engine work):

- **DOM as a state channel.** The DOM is modelled as opaque with a
  `dom-state` label; writes via `el.dataset.x = …` followed by reads
  elsewhere are invisible. Fix would model the DOM as a concrete heap
  cell in the TypeDB.

- **Symbolic heap values.** When handler A writes `g.flag = true`
  under condition `a.data === 'flip'`, the lattice currently joins
  `g.flag ∈ {false, true}`; the causal link to `a.data` is lost, so
  a PoC for handler B's sink doesn't include the prerequisite `'flip'`
  message. Fix would store heap values symbolically (the flag's SMT
  formula references `a.data`), making B's path condition carry the
  precondition through.

Both are meaningful improvements; neither is a soundness bug (the
current behaviour over-approximates, producing PoCs that may under-
specify the prerequisite inputs).

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
  'var h = location.hash.slice(1); document.body.innerHTML = h;',
  { contextUrl: 'https://victim.example/page.html' });

for (const flow of report.flows) {
  if (flow.poc && flow.poc.verdict === 'synthesised') {
    console.log(flow.poc.reproducer);
    // (function () {
    //   // Auto-generated PoC from jsanalyze.
    //   // Flow: url -> innerHTML (<input>.js:1)
    //   // Attempt: img-onerror
    //   // Navigate the victim to the exploit URL:
    //   window.open("https://victim.example/page.html#<img src=x onerror=alert(1)>");
    // })();
  }
}
```

`tr.analyze` walks the program (via the engine), then for every
surviving taint flow conjoins the flow's `pathFormula` with an
exploit constraint on the `valueFormula` and asks Z3 for a
satisfying model. **All exploit shapes live in the TypeDB as
pure data** (`typeDB.exploits[...]`): the consumer holds zero
hardcoded payload strings. Each sink's TypeDB descriptor
declares an `exploit` code that indexes into the exploits
table; the table's `attempts` list is tried in order, first
SAT wins.

**PoC field.** Each `flow.poc` carries:

```ts
{
  verdict:    'synthesised' | 'trivial' | 'infeasible' | 'unsolvable';
  payload:    string | null;       // value arriving at the sink
  attempt:    string | null;       // name of the exploit shape that matched
  bindings:   { [label]: string }; // what the attacker supplies per source
  reproducer: string | null;       // runnable JavaScript program
  note:       string | null;
}
```

`reproducer` is a self-contained JavaScript program. Paste into
a browser console and it opens the victim page at
`options.contextUrl` (default `https://example.com/`) with the
URL parts, storage, cookies, postMessages, and other deliveries
sequenced so the flow fires end-to-end. Multi-source flows get
one reproducer that wires every source through its declared
delivery mechanism.

**Source delivery.** Each TypeDB source descriptor declares a
`delivery` code — `'location-fragment'`, `'postMessage:data'`,
`'localStorage'`, `'cookie'`, `'referrer'`, `'network-response'`,
`'file-drop'`, `'clipboard-paste'`, `'history-state'`,
`'window-name'`. The consumer's default `deliveryEmitters` map
each to a JS emitter; users can override with
`options.deliveryEmitters` for custom targets (testing
harnesses, sandbox deployments, bug bounty PoC format).

**Per-invocation sources.** Event data (`MessageEvent.data`,
`DragEvent.dataTransfer`, etc.) carries `sourceScope: 'call'` in
the TypeDB. Two `message` handlers each reading `event.data`
get INDEPENDENT SMT symbols — so Z3 can solve for distinct
payloads per handler. Stable sources (`location.*`,
`localStorage`) keep the default `'page'` scope so two reads
correlate through one symbol.

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
PoCs (including `reproducer`) to a pre-built trace without
re-analysing.

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
