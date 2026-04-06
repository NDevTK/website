# htmldom — JS → DOM-API converter

Converts `innerHTML`/`outerHTML` assignments in JavaScript to safe
`createElement`/`appendChild` DOM code. Statically resolves as much
of the input as possible; runtime-only values flow through as named
references.

## Public API

Loaded as a plain `<script>` in `index.html`. Three extraction
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
- `loopVars` — per-loop-built-variable metadata.

### `extractAllHTML(input)` → `[extractHTML-result, ...]`

Returns one result per `.innerHTML`/`.outerHTML` site in source order.

### `extractAllDOM(input)` → `{ elements, ops, roots, html }`

Tracks virtual DOM state built via `document.createElement`,
`getElementById`, `querySelector`, `createTextNode` plus subsequent
`el.prop = ...`, `el.setAttribute(...)`, `el.appendChild(...)`, etc.

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

A Node.js test harness lives in `htmldom.test.js`:

```
node htmldom/htmldom.test.js
```

The harness loads `htmldom.js` with minimal DOM stubs, exposes the
three extract functions, and runs inline assertions. 370+ tests.
