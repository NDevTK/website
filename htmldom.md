# htmldom — JS → DOM-API converter

Converts `innerHTML`/`outerHTML` assignments in JavaScript to safe
`createElement`/`appendChild` DOM code. Statically resolves as much
of the input as possible; runtime-only values flow through as named
references.

## Public API

Loaded as a plain `<script>` in `htmldom.html`. Three extraction
functions are exposed inside the IIFE (accessible via the UI's
`Convert` button):

### `extractHTML(input)` → `{ html, autoSubs, target, assignProp, assignOp, loops?, loopVars? }`

Extracts the FIRST `X.innerHTML`/`X.outerHTML` assignment from
`input`. Returns raw-HTML input unchanged. Fields:

- `html` — the materialized HTML string, with `__HDX#__` placeholders
  for unresolved sub-expressions and `__HDLOOP#S__`/`__HDLOOP#E__`
  markers around for/while loop bodies.
- `autoSubs` — `[[placeholder, source-expression], ...]` mapping
  each placeholder to the original JS expression it represents.
- `target`, `assignProp`, `assignOp` — the LHS target (e.g.
  `document.body`), `'innerHTML'` or `'outerHTML'`, and `'='` or `'+='`.
- `loops` — loop metadata when markers are present.
- `loopVars` — per-loop-built-variable metadata (see below).

### `extractAllHTML(input)` → `[extractHTML-result, ...]`

Returns one result per `.innerHTML`/`.outerHTML` site in source order,
scope-aware: each result's `loopVars` only contains entries in scope
at that assignment site.

### `extractAllDOM(input)` → `{ elements, ops, roots, html }`

Tracks virtual DOM state built via `document.createElement`,
`getElementById`, `querySelector`, `createTextNode` plus subsequent
`el.prop = ...`, `el.setAttribute(...)`, `el.appendChild(...)`, etc.
Useful for scripts that build DOM through the API (no `innerHTML`).

## Supported JS subset

Statically resolved:

- `var` / `let` / `const` declarations with scope tracking
  (block, function, arrow).
- Reassignment order, shadowing, and a mutation pre-pass that
  flags cross-function-mutated variables as runtime-reference.
- String / template literal concatenation including `+` chains and
  `+=` builders; template literal `${expr}` interpolation.
- Object/array literals with member access (`obj.a.b`, `arr[0]`,
  `obj['key']`). Spread `[...arr, x]` / `{...obj, k: v}`.
- Destructuring: `var { a } = obj`, `var { a: b } = obj`, `var [x, y] = arr`.
- Arithmetic / bitwise / comparison / logical / ternary / unary
  expressions with operator precedence: `**` > `*`/`/`/`%` >
  `-`/`+` > shifts > comparison > equality > `&` > `^` > `|` >
  `&&` > `||`/`??` > ternary.
- `++`/`--` on known numeric bindings.
- Optional chaining `?.` and nullish coalescing `??`.
- Known builtins: `Math.floor/ceil/round/trunc/abs/sqrt/…`,
  `Math.PI`/`E`/…, `parseInt`, `parseFloat`, `Number`, `String`,
  `Boolean`, `isNaN`, `isFinite`.
- String methods on known strings: `.toUpperCase/.toLowerCase/.trim`,
  `.repeat(n)`, `.slice/.substring/.substr`, `.charAt`, `.indexOf/
  .lastIndexOf`, `.includes/.startsWith/.endsWith`, `.padStart/
  .padEnd`, `.split`, `.toString`.
- Array methods: `.join(sep)`, `.slice`, `.indexOf`, `.includes`,
  `.reverse`.
- Function calls (arrow or `function` declaration) with parameter
  binding and a return-expression inline. Default parameter values.
- `for`/`while` loop body extraction with loop-counter shadowing.

Captured as opaque source references:

- Calls to unknown functions (`Math.random()`, `performance.now()`,
  `fetch(...)`, array `.map(fn)`).
- Bracket access with a non-literal key.
- Any expression the parser can't fold.

## Output format: loop markers

When the resolved HTML contains a `for`/`while`-built segment, the
main `html` field wraps it with marker strings:

```
__HDLOOP0S__<a href="...">item</a> __HDLOOP0E__
```

The `loops` array carries each marker's `{ id, kind, headerSrc }`.
The `convert()` step splits the HTML at these markers and emits a
matching `for (header) { ... }` block around the DOM code for that
segment.

## Testing

A Node.js test harness lives in `tests/htmldom.test.js`:

```
node tests/htmldom.test.js
```

The harness loads `htmldom.js` with minimal DOM stubs, exposes the
three extract functions, and runs inline assertions.
