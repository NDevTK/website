// jsanalyze-schemas.js
//
// Public type factories and validation for the jsanalyze library's
// versioned schema. This file is the single source of truth for the
// shapes that consumers (htmldom-convert, fetch-trace, taint-report,
// csp-derive, …) see when they inspect a Trace.
//
// Design goals:
//   - Every public value knows where it came from (provenance).
//   - Tagged unions over inheritance so consumers pattern-match on kind.
//   - Explicit "unknown" with a reason — consumers can tell
//     "external library" apart from "runtime random" apart from
//     "walker gave up at recursion cap".
//   - Loadable in both Node (CommonJS) and the browser (IIFE sets
//     globalThis.JsAnalyzeSchemas). No build step.
//   - Pure factories — no walker internals, no external dependencies.
//     The walker (in jsanalyze.js) converts
//     its internal binding shape to these types via a boundary
//     function (`bindingToValue`) so the walker is free to refactor
//     its internals without breaking consumers.
//
// Schema versioning:
//   SCHEMA_VERSION follows SemVer on the structural shape. Breaking
//   changes bump the major version; consumers pin a major at analyze()
//   call time. Additive changes (new fields, new `unknown` reasons,
//   new kinds behind feature flags) bump the minor. Factories never
//   silently change shape across versions.
//

(function () {
  'use strict';

  // === Version ===
  // Bump major for breaking changes. Bump minor for additive changes.
  const SCHEMA_VERSION = '1.0';
  const SCHEMA_MAJOR = '1';

  // === UnknownReason enum ===
  // When the walker can't resolve a value to concrete/oneOf/template,
  // it records WHY so consumers can react appropriately. A fetch
  // tracer treats 'opaque-external' differently from 'user-input'
  // from 'runtime-random'. The taint reporter cares about
  // 'user-input'. The DOM converter treats 'unresolved-identifier'
  // as "fall through to opaque reference".
  const UNKNOWN_REASONS = Object.freeze({
    // The identifier wasn't declared in any reachable scope.
    // Example: `fetch(externalLib.url)` — externalLib is imported.
    UNRESOLVED_IDENTIFIER: 'unresolved-identifier',

    // The value comes from a non-deterministic runtime source.
    // Example: `Math.random()`, `crypto.randomUUID()`, `Date.now()`.
    RUNTIME_RANDOM: 'runtime-random',

    // The value comes from a known taint source (user input).
    // Example: `location.hash`, `window.name`, `document.cookie`,
    // `event.data` inside an addEventListener callback.
    USER_INPUT: 'user-input',

    // A function call returned something the walker couldn't
    // inline — the function body was too large, recursive, or
    // depends on external state.
    UNKNOWN_CALL_RETURN: 'unknown-call-return',

    // A loop body assignment poisoned the may-be lattice because
    // the assigned value couldn't be enumerated as a finite set.
    // Example: `for (…) state = someComputed(i)`.
    LOOP_POISONED: 'loop-poisoned',

    // The walker hit its recursion cap walking a function chain.
    // Consumers may want to report this as a warning.
    RECURSION_CAP: 'recursion-cap',

    // The value is the result of an external API call — fetch,
    // IndexedDB, storage, Worker message. By definition opaque
    // at analyze time.
    OPAQUE_EXTERNAL: 'opaque-external',
  });

  const UNKNOWN_REASON_SET = new Set(Object.values(UNKNOWN_REASONS));

  // === Source (provenance) ===
  // Every value carries a list of Sources — the places where it
  // gained its current shape. A concrete string literal has one
  // source (its declaration). A merged cond value has at least two
  // (one per branch). A value propagated through N assignments has
  // up to N+1 sources.
  //
  // `kind` enumerates how the value was produced at that location:
  //   'assignment'     — `x = ...`
  //   'declaration'    — `var x = ...`
  //   'parameter'      — bound at a function call site
  //   'return'         — result of a `return` statement
  //   'inline-literal' — a literal appearing directly in source
  //   'branch-merge'   — the merge point of if/else/switch/try/catch
  const SOURCE_KINDS = Object.freeze({
    ASSIGNMENT: 'assignment',
    DECLARATION: 'declaration',
    PARAMETER: 'parameter',
    RETURN: 'return',
    INLINE_LITERAL: 'inline-literal',
    BRANCH_MERGE: 'branch-merge',
  });

  const SOURCE_KIND_SET = new Set(Object.values(SOURCE_KINDS));

  function mkSource(file, line, col, kind, snippet) {
    return {
      file: file != null ? String(file) : '<anonymous>',
      line: (line | 0) || 1,
      col: (col | 0) || 0,
      kind: kind || SOURCE_KINDS.INLINE_LITERAL,
      snippet: snippet != null ? String(snippet) : undefined,
    };
  }

  // === Value factories ===
  //
  // A `Value` is a tagged union describing what the walker knows
  // about some quantity at a given program point. Consumers pattern
  // match on `kind` and read the appropriate payload. Every Value
  // carries `provenance: Source[]`.

  // Fully concrete: the walker folded this to a single JS primitive.
  function valueConcrete(value, provenance) {
    return {
      kind: 'concrete',
      value: value,
      provenance: provenance || [],
    };
  }

  // One of a finite, enumerable set. Used when a variable can take
  // a known-finite set of values (switch, if/else, .includes guard,
  // enum object, inter-procedural call-site enumeration).
  //
  // `values` is an array of ConcreteValue — i.e. plain JS primitives
  // (strings / numbers / booleans / null), not nested Value objects.
  // If you need a set of Values (e.g. one of several templates),
  // use `kind: 'template'` with a hole whose Value is itself oneOf.
  //
  // `source` describes how the enumeration was derived so the UI can
  // explain it: "from the switch cases", "from the ALLOWED array", etc.
  const ONE_OF_SOURCES = Object.freeze({
    ENUM: 'enum',                     // from an object literal / enum-style const
    BRANCH: 'branch',                 // if/else or switch or try/catch branches merged
    LATTICE: 'lattice',               // every distinct literal assigned anywhere
    PATH_CONSTRAINT: 'path-constraint', // extracted from an if(x === "a" || x === "b") guard
    INCLUDES_GUARD: 'includes-guard', // extracted from an arr.includes(x) guard
    PARAMETER_CALLSITES: 'parameter-callsites', // every concrete arg ever passed
  });

  function valueOneOf(values, source, provenance) {
    return {
      kind: 'oneOf',
      values: values.slice(),
      source: source || ONE_OF_SOURCES.BRANCH,
      provenance: provenance || [],
    };
  }

  // A string template with literal segments and symbolic holes.
  // Each hole carries its own Value so template-of-template is
  // representable (e.g. "/api/" + (cond ? "get" : "set") + "/" + id
  // is a template with one literal, one oneOf hole, one literal,
  // one unknown hole).
  function valueTemplate(parts, provenance) {
    return {
      kind: 'template',
      parts: parts.slice(),
      provenance: provenance || [],
    };
  }

  function partLiteral(value) {
    return { kind: 'literal', value: String(value) };
  }

  function partHole(value, symbolName) {
    return {
      kind: 'hole',
      value: value,
      symbolName: symbolName != null ? String(symbolName) : null,
    };
  }

  // Nested record — object literals, RequestInit, headers, etc.
  // `props` is `{ key: Value }`. Keys are plain strings.
  function valueObject(props, provenance) {
    const copy = Object.create(null);
    for (const k in props) copy[k] = props[k];
    return {
      kind: 'object',
      props: copy,
      provenance: provenance || [],
    };
  }

  // Array literal with per-element Values.
  function valueArray(elems, provenance) {
    return {
      kind: 'array',
      elems: elems.slice(),
      provenance: provenance || [],
    };
  }

  // Function reference. `bodyRef` is an opaque locator the walker
  // uses to re-enter the body; consumers should treat it as a handle,
  // not inspect it. `params` is an array of parameter names.
  function valueFunction(name, params, bodyRef, provenance) {
    return {
      kind: 'function',
      name: name || null,
      params: params.slice(),
      bodyRef: bodyRef || null,
      provenance: provenance || [],
    };
  }

  // The walker couldn't resolve this to a concrete/enumerable shape.
  // Always carries a reason so consumers can distinguish
  // "external library we didn't load" from "user input".
  function valueUnknown(reason, taint, provenance) {
    if (!UNKNOWN_REASON_SET.has(reason)) {
      throw new Error('jsanalyze-schemas: invalid unknown reason: ' + reason);
    }
    return {
      kind: 'unknown',
      reason: reason,
      taint: taint && taint.length ? taint.slice() : null,
      provenance: provenance || [],
    };
  }

  // Attach a TypeDB type name to a Value. Consumers of the
  // trace can read `value.typeName` to see the resolved type
  // of the underlying binding (e.g. 'Location', 'FileReader',
  // 'HTMLIFrameElement'). Null when the walker couldn't infer
  // a type.
  //
  // Returns the same Value (mutated in place) for fluent use.
  function valueWithType(value, typeName) {
    if (value && typeName) value.typeName = typeName;
    return value;
  }

  // === Validation ===
  //
  // validateValue returns null if the value conforms to the schema,
  // or a string describing the first non-conformance. Used by
  // conformance tests and by debug builds of the walker. Not a hot
  // path — correctness over speed.
  function validateValue(v) {
    if (v == null || typeof v !== 'object') return 'value is not an object';
    if (typeof v.kind !== 'string') return 'missing kind';
    if (!Array.isArray(v.provenance)) return 'missing provenance array';
    for (let i = 0; i < v.provenance.length; i++) {
      const pErr = validateSource(v.provenance[i]);
      if (pErr) return 'provenance[' + i + ']: ' + pErr;
    }
    switch (v.kind) {
      case 'concrete':
        if (!('value' in v)) return 'concrete: missing value field';
        return null;
      case 'oneOf':
        if (!Array.isArray(v.values)) return 'oneOf: values is not an array';
        if (!v.source) return 'oneOf: missing source';
        return null;
      case 'template':
        if (!Array.isArray(v.parts)) return 'template: parts is not an array';
        for (let i = 0; i < v.parts.length; i++) {
          const part = v.parts[i];
          if (!part || typeof part !== 'object') return 'template.parts[' + i + ']: not an object';
          if (part.kind === 'literal') {
            if (typeof part.value !== 'string') return 'template.parts[' + i + '] literal: value is not a string';
          } else if (part.kind === 'hole') {
            const holeErr = validateValue(part.value);
            if (holeErr) return 'template.parts[' + i + '] hole.value: ' + holeErr;
          } else {
            return 'template.parts[' + i + ']: invalid kind ' + part.kind;
          }
        }
        return null;
      case 'object':
        if (!v.props || typeof v.props !== 'object') return 'object: missing props';
        for (const k in v.props) {
          const propErr = validateValue(v.props[k]);
          if (propErr) return 'object.props.' + k + ': ' + propErr;
        }
        return null;
      case 'array':
        if (!Array.isArray(v.elems)) return 'array: elems is not an array';
        for (let i = 0; i < v.elems.length; i++) {
          const elemErr = validateValue(v.elems[i]);
          if (elemErr) return 'array.elems[' + i + ']: ' + elemErr;
        }
        return null;
      case 'function':
        if (!Array.isArray(v.params)) return 'function: params is not an array';
        return null;
      case 'unknown':
        if (!UNKNOWN_REASON_SET.has(v.reason)) return 'unknown: invalid reason ' + v.reason;
        if (v.taint != null && !Array.isArray(v.taint)) return 'unknown: taint must be null or an array';
        return null;
      default:
        return 'invalid kind: ' + v.kind;
    }
  }

  function validateSource(s) {
    if (s == null || typeof s !== 'object') return 'not an object';
    if (typeof s.file !== 'string') return 'file is not a string';
    if (typeof s.line !== 'number') return 'line is not a number';
    if (typeof s.col !== 'number') return 'col is not a number';
    if (!SOURCE_KIND_SET.has(s.kind)) return 'invalid kind ' + s.kind;
    return null;
  }

  // === Utility helpers that consumers will want ===
  //
  // These are pure operations on Values that don't need walker
  // access. They belong on the schema module because they're
  // part of the contract — consumers can rely on them.

  // Returns the single concrete JS value if `v` is `kind: 'concrete'`,
  // otherwise null. Does not attempt to materialize templates or oneOf.
  function asConcrete(v) {
    if (v && v.kind === 'concrete') return v.value;
    return null;
  }

  // Enumerates every possible concrete value `v` could take, if
  // fully enumerable. Returns an array, or null if any branch is
  // a template/unknown.
  function enumerate(v) {
    if (!v) return null;
    if (v.kind === 'concrete') return [v.value];
    if (v.kind === 'oneOf') return v.values.slice();
    if (v.kind === 'template') {
      // Distribute across holes: each hole must be fully enumerable.
      const parts = v.parts;
      let accs = [''];
      for (let i = 0; i < parts.length; i++) {
        const p = parts[i];
        if (p.kind === 'literal') {
          accs = accs.map(a => a + p.value);
        } else {
          const holeVals = enumerate(p.value);
          if (!holeVals) return null;
          const next = [];
          for (const a of accs) for (const h of holeVals) next.push(a + h);
          accs = next;
        }
      }
      return accs;
    }
    return null;
  }

  // Merges N values at a branch join point. If all branches are
  // concrete with distinct values, returns oneOf. If one, returns
  // the concrete. If any can't enumerate, returns a template or
  // unknown as appropriate. Returns the merged Value.
  function mergeBranches(values, source, provenance) {
    source = source || ONE_OF_SOURCES.BRANCH;
    if (!values || values.length === 0) return valueUnknown(UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER, null, provenance);
    if (values.length === 1) return values[0];

    // Collect all concrete enumerations
    const allSets = values.map(enumerate);
    if (allSets.every(s => s !== null)) {
      const merged = [];
      const seen = new Set();
      for (const s of allSets) {
        for (const v of s) {
          const k = typeof v + ':' + String(v);
          if (!seen.has(k)) { seen.add(k); merged.push(v); }
        }
      }
      if (merged.length === 1) return valueConcrete(merged[0], provenance || []);
      return valueOneOf(merged, source, provenance || []);
    }

    // Can't enumerate — fall back to unknown. A future version
    // could model "one of these Values" as a new kind, but for
    // now consumers get a reasoned unknown.
    const taints = [];
    for (const v of values) {
      if (v && v.kind === 'unknown' && v.taint) for (const t of v.taint) taints.push(t);
    }
    return valueUnknown(
      taints.length ? UNKNOWN_REASONS.USER_INPUT : UNKNOWN_REASONS.UNKNOWN_CALL_RETURN,
      taints.length ? Array.from(new Set(taints)) : null,
      provenance || []
    );
  }

  // Pretty-print a Value as a human-readable template string.
  // Concrete → the value. oneOf → "(a|b|c)". template → joined
  // parts with ${…} for holes. unknown → "<unknown:reason>".
  // Used by debug tests and default renderers. Not the canonical
  // serialization — that's JSON.stringify.
  function stringify(v) {
    if (!v) return '<null>';
    switch (v.kind) {
      case 'concrete': return typeof v.value === 'string' ? JSON.stringify(v.value) : String(v.value);
      case 'oneOf': return '(' + v.values.map(x => typeof x === 'string' ? JSON.stringify(x) : String(x)).join('|') + ')';
      case 'template': {
        let s = '';
        for (const p of v.parts) {
          if (p.kind === 'literal') s += p.value;
          else s += '${' + (p.symbolName || stringify(p.value)) + '}';
        }
        return s;
      }
      case 'object': {
        const entries = Object.keys(v.props).map(k => JSON.stringify(k) + ':' + stringify(v.props[k]));
        return '{' + entries.join(',') + '}';
      }
      case 'array': return '[' + v.elems.map(stringify).join(',') + ']';
      case 'function': return 'function(' + v.params.join(',') + ')';
      case 'unknown': return '<unknown:' + v.reason + (v.taint ? ':taint=' + v.taint.join(',') : '') + '>';
      default: return '<invalid:' + v.kind + '>';
    }
  }

  // === Export ===
  const api = Object.freeze({
    SCHEMA_VERSION,
    SCHEMA_MAJOR,
    UNKNOWN_REASONS,
    SOURCE_KINDS,
    ONE_OF_SOURCES,

    mkSource,

    value: Object.freeze({
      concrete: valueConcrete,
      oneOf: valueOneOf,
      template: valueTemplate,
      object: valueObject,
      array: valueArray,
      function: valueFunction,
      unknown: valueUnknown,
      withType: valueWithType,
    }),

    part: Object.freeze({
      literal: partLiteral,
      hole: partHole,
    }),

    validate: Object.freeze({
      value: validateValue,
      source: validateSource,
    }),

    helpers: Object.freeze({
      asConcrete,
      enumerate,
      mergeBranches,
      stringify,
    }),
  });

  // CommonJS export (Node tests / consumers that use require).
  if (typeof module !== 'undefined' && module && module.exports) {
    module.exports = api;
  }
  // Browser global (index.html loads this as a <script> tag).
  if (typeof globalThis !== 'undefined') {
    globalThis.JsAnalyzeSchemas = api;
  }
})();
