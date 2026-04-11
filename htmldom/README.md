# jsanalyze — whole-program static analysis library for browser JavaScript

`jsanalyze` is a reusable JavaScript static analysis library. Its
engine is a symbolic interpreter that walks a multi-file JS bundle,
folds constants across functions and branches, tracks taint with
Z3-backed path-constraint reasoning, and produces a versioned,
queryable `Trace` of everything it learned. Consumers read the
trace through a small query API and project it into domain-specific
views.

The library ships with four reference consumers. **DOM conversion
(`htmldom-convert.js`) is one of them** — the original use case
that drove the walker's development — but the engine is deliberately
decoupled from any single output format.

| Consumer | What it does |
|---|---|
| `htmldom-convert.js` | Rewrites `innerHTML` / `outerHTML` / `document.write` assignments into safe `createElement` / `appendChild` DOM code, preserving loops and branches. |
| `fetch-trace.js` | Discovers every HTTP endpoint a bundle reaches — `fetch` / `XMLHttpRequest` / `WebSocket` / `Worker` / dynamic `import` — with resolved URLs, methods, headers, bodies, and per-argument allowed-value sets. Includes APIs that are defined but never called. |
| `taint-report.js` | Path-sensitive taint reporter that flows known sources (`location.hash`, `document.cookie`, `event.data`, …) through the program and reports reachable sinks (`innerHTML`, `eval`, `document.write`, …). Uses Z3 to refute unreachable flows. |
| `csp-derive.js` | Derives a minimal Content-Security-Policy from observed `script-src` / `connect-src` / `worker-src` / `frame-src` / `img-src` targets plus flags on `eval` / `new Function` / tainted `innerHTML`. |

New consumers are written in ~200–500 LOC against the published
query API. None of them reach into the walker's internals.

## Quick start

### Node

```js
const { analyze, query } = require('./htmldom/jsanalyze-query.js');

const trace = await analyze({
  'api.js': 'function loadUser(id) { return fetch("/api/users/" + id); }',
  'app.js': 'loadUser(42);',
});

for (const call of query.calls(trace, { targets: ['fetch'] })) {
  console.log(call.site.file + ':' + call.site.line, query.asConcrete(call.args[0]));
  // api.js:1  /api/users/42
}
```

### Browser

`index.html` loads the files in dependency order via `monaco-init.js`:

1. `jsanalyze-schemas.js` — public `Value` factories
2. `jsanalyze-z3-browser.js` — Z3 bootstrap (registers
   `globalThis.__htmldomZ3Init` lazily)
3. `jsanalyze.js` — the engine
4. `jsanalyze-query.js` — `analyze()` + query primitives
5. `htmldom-convert.js` / `fetch-trace.js` / `taint-report.js` /
   `csp-derive.js` — consumers

Everything runs client-side with no build step and no third-party
CDN dependency. Z3 is vendored under `htmldom/vendor/z3-solver/`.

## Public API

### `analyze(input, options)` → `Promise<Trace>`

Runs the engine over a single source string or a `{filename → source}`
map and returns a Trace. A Trace is pure data, JSON-serializable,
and versioned via `schemaVersion`.

```js
const trace = await analyze(files, {
  taint: true,           // enable taint flow tracking + Z3 reachability
  watchers: { ... },     // optional streaming hooks
});
```

### `query.*` — pure functions over a Trace

All queries take a `Trace` and return typed results. They never
re-walk the source, so you can run any number of queries on a single
trace cheaply.

| Primitive | Returns |
|---|---|
| `query.calls(trace, { targets, reached?, reachability? })` | Every call site matching the target filter, with resolved arguments, caller, and reachability. |
| `query.property(value, path)` | Navigate into a nested `Value` via dotted path (`'headers.Content-Type'`). |
| `query.enumerate(value)` | Every concrete primitive a `Value` can take, or `null` if unenumerable. |
| `query.asConcrete(value)` | The single concrete primitive if the `Value` is `kind: 'concrete'`, else `null`. |
| `query.innerHtmlAssignments(trace)` | Every `innerHTML` / `outerHTML` / `document.write` site. |
| `query.taintFlows(trace, { severity?, source?, sinkProp? })` | Taint flows with source + sink + path conditions. |
| `query.stringLiterals(trace, { context })` | String literals in a given context (e.g. assigned to `script.src`). |
| `query.valueSetOf(trace, name)` | Every concrete literal a variable takes across the program. |
| `query.callGraph(trace)` | `{ nodes, edges }` built from observed calls. |

### `Value` — the versioned tagged union consumers see

Defined in `jsanalyze-schemas.js`. Every binding the walker knows
about converts to one of these shapes via the `bindingToValue`
boundary function:

```ts
type Value =
  | { kind: 'concrete',  value: string|number|boolean|null,          provenance: Source[] }
  | { kind: 'oneOf',     values: ConcreteValue[], source: OneOfSource, provenance: Source[] }
  | { kind: 'template',  parts: TemplatePart[],                       provenance: Source[] }
  | { kind: 'object',    props: Record<string, Value>,                provenance: Source[] }
  | { kind: 'array',     elems: Value[],                              provenance: Source[] }
  | { kind: 'function',  name?, params, bodyRef,                      provenance: Source[] }
  | { kind: 'unknown',   reason: UnknownReason, taint?: string[],     provenance: Source[] };
```

Every `Value` carries **provenance** — the source locations where
it got its current shape. `unknown` carries an explicit `reason`
(`unresolved-identifier` / `runtime-random` / `user-input` /
`unknown-call-return` / `loop-poisoned` / `recursion-cap` /
`opaque-external`) so consumers can distinguish "external library"
from "user input" from "walker gave up".

See `jsanalyze-schemas.js` for the full list and the helper
functions (`asConcrete`, `enumerate`, `mergeBranches`, `stringify`).

## Library layout

| File | Role |
|---|---|
| `jsanalyze.js`                | Engine: tokenizer, walker, SMT path reasoner, taint propagation, virtual DOM, binding seam |
| `jsanalyze-schemas.js`        | Public `Value` factories + versioned schema + validation |
| `jsanalyze-query.js`          | `analyze()` entry point + `query.*` primitives over a Trace |
| `jsanalyze-z3-browser.js`     | Browser bootstrap for Z3 (registers `globalThis.__htmldomZ3Init` lazily) |
| `vendor/z3-solver/`           | Vendored z3-solver (WASM + ESM-bundled browser.js). Self-hosted; no CDN dependency. |
| `htmldom-convert.js`          | Consumer: innerHTML/outerHTML → DOM API rewriter |
| `fetch-trace.js`              | Consumer: HTTP endpoint discovery |
| `taint-report.js`             | Consumer: taint flow reporter |
| `csp-derive.js`                | Consumer: CSP derivation |
| `htmldom.test.js`             | Shared test harness |
| `index.html`                  | Browser UI (Monaco editor + sidebar + findings panel) |
| `monaco-init.js`              | UI bootstrap (loads the scripts in dependency order) |

**Consumer dependency rule:** consumers depend on
`jsanalyze-query.js` + `jsanalyze-schemas.js` only. They never
reach into the engine's internals. The engine's public surface
is the `analyze()` + `query.*` + `Value` trio documented above.

## The type system

The walker is **type-first**: every binding carries a `typeName`
resolved against a declarative **TypeDB**, and sink / source /
sanitizer / navigation classification is driven entirely by that
type — not by hardcoded name lists. This is what makes it a
reusable engine: a consumer that wants to analyse a different
runtime (Node APIs, WebWorker APIs, a custom host) swaps in its
own TypeDB and the same walker produces the same shape of trace.

### The TypeDB (`DEFAULT_TYPE_DB`)

The TypeDB is pure data — no code — and lives at the bottom of
`jsanalyze.js`. It has three top-level fields:

```js
{
  types: {                          // the type graph
    Window: {
      extends: 'EventTarget',
      props: {
        location:   { readType: 'Location' },
        document:   { readType: 'Document' },
        name:       { source: 'window.name', readType: 'String' },
        // ...
      },
      methods: {
        open: { args: [{ sink: 'navigation', severity: 'medium' }] },
        // ...
      },
    },
    Location: {
      selfSource: 'url',            // reading a bare Location yields `url`
      props: {
        href:  { source: 'url', readType: 'String', sink: 'navigation' },
        hash:  { source: 'url', readType: 'String' },
        // ...
      },
      methods: {
        assign:  { args: [{ sink: 'navigation' }] },
        replace: { args: [{ sink: 'navigation' }] },
      },
    },
    GlobalEval: {
      call: { args: [{ sink: 'code', severity: 'high' }] },
    },
    GlobalFetch: {
      call: { source: 'network', returnType: 'Promise' },
    },
    HTMLIFrameElement: {
      extends: 'HTMLElement',
      props: { src: { sink: 'url' }, srcdoc: { sink: 'html' } },
    },
    // ...65 types total
  },

  roots: {                          // unshadowed globals → type
    window:         'Window',
    document:       'Document',
    location:       'Location',
    localStorage:   'Storage',
    eval:           'GlobalEval',
    fetch:          'GlobalFetch',
    XMLHttpRequest: 'GlobalXMLHttpRequestCtor',
    FileReader:     'GlobalFileReaderCtor',
    // ...
  },

  tagMap: {                         // createElement(tag) → concrete type
    iframe: 'HTMLIFrameElement',
    script: 'HTMLScriptElement',
    a:      'HTMLAnchorElement',
    input:  'HTMLInputElement',
    // ...
  },

  eventMap: {                       // addEventListener(name) → Event subtype
    message:    'MessageEvent',
    hashchange: 'HashChangeEvent',
    drop:       'DragEvent',
    paste:      'ClipboardEvent',
    // ...
  },

  attrSinks: {                      // setAttribute(name, v) sinks
    onclick: 'code', onload: 'code', /* ... */
    style:   'css',
  },
}
```

Every type descriptor field is optional. Fields the walker
recognises:

| Field | Meaning |
|---|---|
| `extends: 'T'` | Inherit props/methods from type `T`. |
| `props: { [name]: PropDescriptor }` | Readable / writable properties. |
| `methods: { [name]: MethodDescriptor }` | Callable methods. |
| `call: MethodDescriptor` | The type's value is a callable (e.g. `eval`). |
| `construct: MethodDescriptor` | The type's value is a constructor (e.g. `FileReader`). |
| `selfSource: 'label'` | A bare reference to this type carries this label (used for `Location`, `Storage`). |

A **PropDescriptor** carries:

| Field | Meaning |
|---|---|
| `source: 'label'` | Reading this property attaches `'label'` to the result. |
| `sink: 'kind'` | Writing this property is a sink of kind `html` / `url` / `code` / `navigation` / `css` / `text` / `safe`. |
| `severity: 'critical' \| 'high' \| 'medium' \| 'safe'` | Overrides the default severity for this sink kind. |
| `readType: 'T'` | Property reads produce a value of type `T`. |

A **MethodDescriptor** carries:

| Field | Meaning |
|---|---|
| `args: [ArgDescriptor, …]` | Per-positional-arg sink labels. |
| `returnType: 'T'` | Static return type for `_resolveExprTypeViaDB`. |
| `source: 'label'` | Calling the method yields the label on its result. |
| `sink: 'kind'` | The call itself is a sink (e.g. `document.write`). |
| `sanitizer: true` | The call neutralises taint on its return value (e.g. `encodeURIComponent`, `DOMPurify.sanitize`). |
| `preservesLabelsFromReceiver: true` | Result carries the receiver's labels (e.g. `String.slice`). |

An **ArgDescriptor** carries `sink`, `severity`, `sinkIfArgEquals`
(for `setAttribute` — look up the sink based on the value of
another arg), and accepts all the same fields as PropDescriptor.

### Flow-sensitive type tracking on bindings

Every variable binding the walker produces carries an optional
`typeName` inferred at assignment time. The walker's
`_withInferredType(binding)` runs on:

- Single opaque-ref chains (`var loc = window.location` →
  walks `window.location` through the TypeDB → Location).
- Bare-call roots and constructors (`var resp = fetch('/x')` →
  Promise; `var fr = new FileReader()` → FileReader).
- String concatenation chains (`var url = base + '/' + path` →
  String when every operand is string-producing).
- Template literals (`` `pre${x}post` `` → String).
- Ternary expressions with same-type arms (simple lattice join).
- Element bindings from `createElement` / `getElementById`
  (tagged at factory-creation time via `db.tagMap`).
- Event-handler parameters typed via `db.eventMap`
  (`addEventListener('message', e => …)` → `e` is `MessageEvent`).

Once typed, **every subsequent property read on the binding**
resolves through `_lookupProp` / `_lookupMethod` on its
`typeName`. This is what makes aliasing work:

```js
var loc = window.location;   // loc.typeName = 'Location'
x.innerHTML = loc.hash;      // resolves Location.hash → source='url'

var f = eval;                // f.typeName = 'GlobalEval'
f(userInput);                // code sink via GlobalEval.call.args[0].sink

var fr = new FileReader();   // fr.typeName = 'FileReader'
x.innerHTML = fr.result;     // FileReader.result → source='file'

var el = document.createElement('iframe');  // el.typeName = 'HTMLIFrameElement'
el.src = userInput;                         // url sink on HTMLIFrameElement.src
```

**Shadowing is handled via flow-sensitive scope lookup**, not a
file-wide declared-names set. `typedScope(name)` consults the
current binding via `resolve()`: when the name is in scope and
carries a `typeName`, that type wins; when it's in scope with no
type (a plain user var), the walker treats it as shadowed and
refuses to fall back to `db.roots`. Function parameters,
closures, and block-scoped locals all participate automatically.

### How taint tracing uses the type system

Taint tracing is one **consumer** of the type system. Source and
sink detection are thin wrappers over the TypeDB walkers:

| Engine helper | Purpose |
|---|---|
| `getTaintSource(expr, scope)` | Returns the source label for an expression (walks via `_walkPathInDB`). |
| `getBindingLabels(binding)` | Returns the taint labels a binding's value carries. |
| `classifySink(prop, elementTag)` | Returns sink info for a property write. |
| `_classifySinkByTypeViaDB(db, typeName, prop)` | Type-first sink classifier for typed bindings. |
| `_classifyCallSinkViaDB(db, callExpr, scope)` | Returns sink info for a call expression. |
| `_isSanitizerCallViaDB(db, callExpr, scope)` | Returns `true` if the call neutralises taint. |
| `_isNavSinkViaDB(db, expr, scope)` | Returns `true` if the expression addresses a navigation sink. |

At each sink site, the walker:

1. Computes `getBindingLabels(valueBinding)` — a `Set<label>` of
   the value's taint labels.
2. Classifies the sink via the receiver binding's `typeName`
   (falling back to element-tag lookup when untyped).
3. Emits a finding linking the source labels to the sink kind +
   severity, with the path constraints active at that program
   point (for Z3 reachability refutation).

**No hardcoded name lists, regex heuristics, or flat tables**.
Every security decision traces back to a TypeDB descriptor.

### Swapping in a custom TypeDB

Consumers can pass `options.typeDB` to `analyze(...)` to
override the default. The shape is identical to `DEFAULT_TYPE_DB`
— add, remove, or replace types, roots, tagMap entries, and
event-map entries to match the runtime you're analysing.

```js
const customDB = require('./my-typedb.js');
const trace = await analyze(files, {
  taint: true,
  typeDB: customDB,          // your declarative types + roots
});
```

This is how a consumer for Node built-ins (`fs`, `child_process`,
`http`) or for a custom framework's surface would be written:
describe the API in data, reuse the walker unchanged.

## What the walker can fold

The engine is a symbolic interpreter — it runs the JS code at
analysis time, inlining functions, tracking object state across
assignments, and folding constants wherever possible. This section
documents what it understands.

## Supported JS subset

### Variables & scoping

- `var` / `let` / `const` with full scope tracking (block, function, arrow).
- Reassignment, shadowing, and a mutation pre-pass that flags
  cross-function-mutated variables as runtime-reference.
- `var` hoists to function scope; `let`/`const` are block-scoped.

### Literals & types

- String literals (`'...'`, `"..."`), template literals (`` `...${expr}...` ``).
- Number literals with full numeric type tracking (`jsType: 'number'`).
- `true`, `false` (jsType `'boolean'`), `null` (jsType `'null'`),
  `undefined` (jsType `'undefined'`), `Infinity`, `NaN`.
- Regex literals (`/pattern/flags`) preserved for method evaluation.

### Expressions

- String / template literal concatenation including `+` chains,
  `+=` builders, and `${expr}` interpolation.
- Object/array literals with member access (`obj.a.b`, `arr[0]`,
  `obj['key']`). Spread `[...arr, x]` / `{...obj, k: v}`.
- Destructuring: `var { a } = obj`, `var { a: b, ...rest } = obj`,
  `var [x, y = 'default'] = arr`, `var [a, ...r] = arr`.
- Arithmetic / bitwise / comparison / logical / ternary / unary
  expressions with operator precedence.
- `++`/`--` on known numeric bindings.
- Optional chaining `?.` and nullish coalescing `??`.
- Comma operator `(a, b, c)` returns last value.
- `in` / `instanceof` as symbolic relational operators.
- String equality/comparison (`===`, `!==`, `<`, `>`, etc.) folds
  on known strings and numbers.

### Type-aware + operator

- `1 + 2` = `3` (numeric addition).
- `'1' + '2'` = `'12'` (string concatenation).
- `'a' + 1` = `'a1'` (mixed → concatenation).
- `true + 1` = `2` (boolean coerces to number).

### Builtins (shadow-aware)

All builtins check `isShadowed()` — if the user redefined `Math`,
`parseInt`, etc., the builtin path is skipped and the user's binding
is used instead.

- `Math.floor/ceil/round/trunc/abs/sqrt/…`, `Math.PI`/`E`/…
- `parseInt(str)`, `parseFloat(str)`, `Number(str)`, `Boolean(val)`,
  `isNaN(val)`, `isFinite(val)`.
- `String(val)`, `String.fromCharCode(n, ...)`, `String.fromCodePoint(n, ...)`.
- `Object.keys/values/entries`, `Object.assign`, `Object.fromEntries`.
- `JSON.stringify` / `JSON.parse` round-trip through known bindings.
- `Array.isArray`, `Array.of`, `Array.from(iter, mapFn?)`.

### String methods

- `.toUpperCase/.toLowerCase/.trim/.trimStart/.trimEnd`
- `.repeat(n)`, `.slice/.substring/.substr`, `.charAt`, `.at(n)`
- `.indexOf/.lastIndexOf`, `.includes/.startsWith/.endsWith`
- `.padStart/.padEnd`, `.split(sep)`, `.toString`
- `.replace(str|regex, str)`, `.replaceAll(str|regex, str)`
- `.match(regex)`, `.search(regex)` — with literal regex
- `.charCodeAt(n)`, `.codePointAt(n)`

### Number methods

- `.toFixed(n)`, `.toString(radix)`, `.toPrecision(n)`, `.toExponential(n)`

### Array methods

- `.join(sep)`, `.slice`, `.indexOf`, `.includes`, `.reverse`, `.at(n)`
- `.map(fn)`, `.filter(fn)`, `.forEach(fn)`, `.reduce(fn, init)`
- `.find(fn)`, `.findIndex(fn)`, `.some(fn)`, `.every(fn)`, `.flatMap(fn)`
- `.concat(arr, ...)`, `.flat(depth?)`, `.fill(val, start?, end?)`
- `.sort()`, `.splice(start, del, ...items)`
- Mutation at statement level: `.push`, `.pop`, `.shift`, `.unshift`,
  `.splice`, `.fill`, `.sort`, `.reverse`

### Regex methods

- `regex.test(str)` on literal regex receivers.
- String methods accept regex args: `.replace`, `.match`, `.search`, `.split`.

### Functions

- Arrow or `function` declaration with parameter binding and
  return-expression inline. Default parameter values.
- Spread in calls: `f(...args)` splices known arrays into arg list.
- `instantiateFunctionBinding` preserves typed returns (array/object)
  so `var [x,y] = f()` and `f().prop` work.

### Control flow

- `if`/`else` with concrete condition evaluation — walks only
  the matching branch. Supports else-if chains.
- `switch` with concrete discriminant walks matching case.
- `try`/`catch`/`finally` — walks each block.
- `for`/`while` loop simulation: evaluates condition, walks body,
  repeats until condition becomes false or opaque. Handles `i++`,
  `i--`, `i+=N`, `i-=N` steps and any deterministic termination.
- `for-of`/`for-in` with known iterables: full body re-evaluation
  per element via `walkRange()`, including destructuring patterns.
- `do...while` loop support.

### Assignments & mutations

- `obj.x = v`, `obj.a.b = v`, `arr[i] = v`, `obj['k'] = v`.
- Compound: `+=` (numeric fold or string concat), `-=`, `*=`, `/=`,
  `%=`, `**=`, `|=`, `&=`, `^=`, `<<=`, `>>=`, `>>>=`.
- Logical/nullish: `||=`, `&&=`, `??=`.

### Module & keyword handling

- `import` statements skipped.
- `export` stripped from declarations, or entire statement skipped.
- `with` statement body skipped (scope unpredictable).
- `debugger` statement skipped.
- `class` declarations parsed into classBindings with constructor +
  methods. Class bodies still walked for innerHTML assignments.

### Classes

- `class Name { constructor(x) { this.x = x; } method() {} }`
  parsed into `classBinding` with constructor and named methods.
- `new ClassName(args)` creates instance: runs constructor with
  `this` bound to fresh object, attaches methods.
- `this.prop` resolves via scope frame `thisBinding`.
- Instance methods invoked with `this` bound to receiver.
- Methods can call other methods on `this`.
- `extends SuperClass`: inherited methods, `super()` in
  constructors, `super.method()` calls.
- Class expressions: `var C = class { ... }`.

### Getters

- `{ get x() { return val; } }` — getter invoked on property
  access, including with `this` binding for computed getters.
- Getter result cached as the property value at parse time.

### typeof folding

- `typeof 'hi'` → `'string'`, `typeof 5` → `'number'`,
  `typeof true` → `'boolean'`, `typeof null` → `'object'`,
  `typeof undefined` → `'undefined'`, `typeof []` → `'object'`,
  `typeof function(){}` → `'function'`.
- `typeof (3>2)` → `'boolean'` (comparison results are typed).

### Captured as opaque references

- Calls to unknown functions, bracket access with non-literal key.
- Any expression the parser can't fold.
- `eval()`, `Symbol()`, `Proxy`, `Reflect` — always opaque.

## Testing

```
node htmldom/htmldom.test.js
```

The harness loads `jsanalyze.js` and every consumer with minimal
DOM stubs and runs inline assertions. 899+ tests covering:

- **Engine**: tokenizer, scope walker, virtual DOM extraction,
  SMT-refuted taint reachability, cross-file inter-procedural flow
- **Schemas**: `Value` factory shapes, validation, helpers
- **Query primitives**: `analyze`, `query.calls`, `query.property`,
  `query.enumerate`, `query.taintFlows`, `query.callGraph`, JSON
  round-trip, query purity
- **Consumers**: `htmldom-convert` (111 behavioral-equivalence
  cases — converted output runs identically in JSDOM), `fetch-trace`
  (API discovery across realistic bundles), `taint-report` (grouping
  + rendering), `csp-derive` (origin extraction + unsafe-eval detection),
  plus an integration case that runs all three consumers on one walk
- **Vendor presence**: the browser Z3 bootstrap + its vendored
  WASM files exist and are non-trivial

## Vendoring Z3

z3-solver ships separate Node and browser builds and the browser
build has a non-trivial loading protocol (`global.initZ3` shim,
classic-script WASM loader, ESM high-level module). To avoid
shipping a CDN dependency for a security tool, `jsanalyze` vendors
the z3-solver `build/` directory under `htmldom/vendor/z3-solver/`
and ships a pre-bundled ESM wrapper alongside the original files.

The vendor layout:

```
htmldom/vendor/z3-solver/
  z3-built.js          ← WASM loader (classic UMD script; 338 KB)
  z3-built.wasm        ← the actual Z3 WASM binary (33 MB)
  browser.js           ← original CommonJS high-level wrapper
  browser.esm.js       ← esbuild-bundled ESM form of browser.js (297 KB)
  node.js              ← Node entry (unused in the browser)
  high-level/          ← original CommonJS sources (kept for reference)
  low-level/           ← original CommonJS sources
```

`htmldom/jsanalyze-z3-browser.js` orchestrates the browser-side
loading on first use:

1. Aliases `window.global = window` so z3-solver's browser build
   can read `global.initZ3` without a `ReferenceError`.
2. Injects `vendor/z3-solver/z3-built.js` as a classic `<script>`,
   awaiting `onload`. The UMD top-level `var initZ3 = (...)();`
   becomes a `window.initZ3` property.
3. Dynamic-imports `vendor/z3-solver/browser.esm.js`. Its
   `default` export is the z3-solver browser module with `init`.
4. Registers `globalThis.__htmldomZ3Init` as a lazy wrapper that
   runs steps 1–3 on first call, then calls `mod.init()`.

### Cross-origin isolation (`SharedArrayBuffer`)

z3-solver's WASM build was compiled with pthread support.
Emscripten pthreads use `SharedArrayBuffer`, which browsers only
expose to **cross-origin isolated** pages — pages served with
these HTTP headers:

```
Cross-Origin-Opener-Policy:   same-origin
Cross-Origin-Embedder-Policy: credentialless
```

Static file servers like `python -m http.server` don't send
those headers, so the page isn't cross-origin isolated by
default and any call into Z3 crashes with
`pthread_create: environment does not support SharedArrayBuffer`.

To fix this without requiring server configuration, `index.html`
ships two tiny files:

- **`coi-serviceworker.js`** — a service worker that intercepts
  the navigation request and re-emits it with COOP + COEP
  headers.
- **`coi-register.js`** — a classic script that registers the
  SW on first load and reloads once so the page enters SW
  control. A session-storage flag prevents reload loops in
  browsers that don't yet support `credentialless` COEP
  (notably Safari).

`coi-register.js` is loaded as the first `<script>` in
`index.html` so COI is active before Monaco or jsanalyze
start loading.

`jsanalyze.js`'s `_initZ3` picks up `globalThis.__htmldomZ3Init`
on its first branch and uses it directly — it does no DOM,
dynamic-import, or CDN work itself. Node continues to use
`require('z3-solver')` against the installed npm package.

### Re-bundling `browser.esm.js` on z3-solver upgrade

```
npx esbuild htmldom/vendor/z3-solver/browser.js \
  --bundle --format=esm --platform=browser \
  --outfile=htmldom/vendor/z3-solver/browser.esm.js
```

Run this after upgrading `z3-solver` in `package.json` and
re-copying `node_modules/z3-solver/build/` to
`htmldom/vendor/z3-solver/`. The `htmldom.test.js` vendor-presence
section will fail on Node if either file is missing.
