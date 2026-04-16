// typedb.js — TypeDB lookup helpers.
//
// The TypeDB (see `src/default-typedb.js` for the default
// browser DB) is pure data. This module provides the generic
// lookup logic the engine's transfer functions use to query
// it: property lookup with inheritance, method lookup, return
// type resolution, sink classification, source walking,
// sanitizer detection, least upper bound, and dotted-path
// expression resolution.
//
// Every helper here is pure. No module-level state. No silent
// catches. Every function that reads the DB accepts the DB as
// an explicit first argument so the same helpers work on the
// default DB, a consumer-supplied custom DB, or a test fixture.
//
// Helpers (public — used by transfer functions + consumers):
//
//   lookupProp(db, typeName, propName)
//     Walk the extends chain looking for a PropDescriptor.
//     Returns the descriptor or null.
//
//   lookupMethod(db, typeName, methodName)
//     Walk the extends chain looking for a MethodDescriptor.
//     Returns the descriptor or null.
//
//   resolveReturnType(methodDesc, argStrings)
//     Resolve a method's return type, handling the static
//     `returnType: 'X'` form and the dynamic
//     `returnType: { fromArg: N, map: {...}, default: 'X' }`
//     form used for createElement-style APIs.
//
//   defaultSinkSeverity(sinkKind)
//     Return the default severity label ('safe' | 'medium' |
//     'high' | 'critical') for a sink kind. Descriptors may
//     override this via an explicit `severity` field.
//
//   sinkInfoFromPropDescriptor(desc, propName, elementTag)
//     Shape a PropDescriptor's sink metadata into a
//     `{ type, severity, prop, elementTag? }` record. Returns
//     null for non-sink or 'safe'-severity descriptors.
//
//   classifySinkByTypeViaDB(db, typeName, propName)
//     Type-first sink classification: given a concrete receiver
//     type, look up the prop and return sink info if any.
//
//   classifySinkViaDB(db, propName, elementTag)
//     Tag-based sink classification: resolve a tag to its
//     element subtype via `db.tagMap`, then delegate.
//
//   classifyAttrSinkViaDB(db, attrName)
//     Attribute-name sink classification via `db.attrSinks`.
//
//   classifyCallSinkViaDB(db, callExpr, scope)
//     Call-site sink classification by walking a dotted
//     expression through the TypeDB. Used for eval /
//     document.write / location.assign / etc.
//
//   propIsEverASink(db, propName)
//     Precheck: does any type in the DB have `propName` as a
//     sink? Used to skip full classification on property
//     writes whose name couldn't possibly be a sink.
//
//   walkPathInDB(db, expr, scope)
//     Walk a dotted expression through the DB and return the
//     source label (if any) produced by the deepest resolvable
//     segment. Used by `getTaintSource` / `getTaintSourceCall`.
//
//   resolveExprTypeViaDB(db, expr, scope)
//     Walk a dotted expression and return the terminal type
//     name — the type the expression's VALUE has at runtime.
//
//   resolveInnerTypeViaDB(db, expr, scope)
//     Like `resolveExprTypeViaDB` but returns the parametric
//     inner type (the `T` in `Promise<T>`).
//
//   isNavSinkViaDB(db, expr, scope)
//     Answer "does writing to / calling this expression
//     trigger page navigation?"
//
//   isSanitizerCallViaDB(db, callExpr, scope)
//     Answer "is this call a known sanitizer?" Sanitizers
//     declared with `sanitizer: true` clear taint on the return.
//
//   typeLUB(db, a, b)
//     Least upper bound of two type names in the `extends`
//     lattice — the most specific common ancestor, or null if
//     none exists.
//
// All functions take the `db` as an explicit argument so the
// engine can support custom TypeDBs passed via
// `analyze(input, { typeDB: myDB })`.
//
// The `scope` parameter (optional on every helper that takes
// one) is a function `name => { typeName?, shadowed? } | null`.
// It lets callers provide flow-sensitive type tracking: if the
// root name resolves to a typed local binding, the walk starts
// from that type; if it resolves to an untyped local binding
// the walk aborts (the user shadowed the global).

'use strict';

// --- Inheritance-aware property lookup ------------------------------------
//
// Walk the type's `extends` chain from most-specific to base,
// stopping at the first type that declares `propName`. Returns
// the PropDescriptor or null.
function lookupProp(db, typeName, propName) {
  let t = typeName;
  while (t) {
    const desc = db.types[t];
    if (!desc) return null;
    if (desc.props && Object.prototype.hasOwnProperty.call(desc.props, propName)) {
      return desc.props[propName];
    }
    t = desc.extends || null;
  }
  return null;
}

// --- Inheritance-aware method lookup --------------------------------------
//
// Same as `lookupProp` but for methods. Methods declared on a
// parent type are visible on subtypes.
function lookupMethod(db, typeName, methodName) {
  let t = typeName;
  while (t) {
    const desc = db.types[t];
    if (!desc) return null;
    if (desc.methods && Object.prototype.hasOwnProperty.call(desc.methods, methodName)) {
      return desc.methods[methodName];
    }
    t = desc.extends || null;
  }
  return null;
}

// --- Method return type resolution ----------------------------------------
//
// Methods declare their return type in one of two forms:
//
//   1. Static: `returnType: 'Element'` — every call returns
//      the same type regardless of arguments.
//   2. Dynamic: `returnType: { fromArg: N, map: {...},
//      default: 'Element' }` — the return type depends on the
//      string value of argument N. Used for
//      `document.createElement('iframe')` returning
//      `HTMLIFrameElement`, etc. `argStrings[N]` is the
//      concretely-known string passed at the call site; if
//      absent or unmapped, the `default` is used.
function resolveReturnType(methodDesc, argStrings) {
  const rt = methodDesc && methodDesc.returnType;
  if (!rt) return null;
  if (typeof rt === 'string') return rt;
  if (typeof rt === 'object' && typeof rt.fromArg === 'number') {
    const key = argStrings[rt.fromArg];
    if (key != null && rt.map && Object.prototype.hasOwnProperty.call(rt.map, key)) {
      return rt.map[key];
    }
    return rt.default || null;
  }
  return null;
}

// --- Default severity per sink kind ---------------------------------------
//
// Every sink kind has a default severity. Individual descriptors
// may override via an explicit `severity` field. 'safe'-severity
// descriptors are treated as non-sinks by consumers.
function defaultSinkSeverity(sinkKind) {
  switch (sinkKind) {
    case 'code':       return 'critical';
    case 'safe':       return 'safe';
    case 'text':       return 'safe';
    case 'navigation': return 'high';
    case 'html':       return 'high';
    case 'url':        return 'high';
    case 'css':        return 'medium';
    default:           return 'high';
  }
}

// --- Shape a PropDescriptor into a SinkInfo record ------------------------
//
// Returns `{ type, severity, prop, elementTag? }` or null. The
// elementTag is included only when the caller had tag-level
// context (e.g. a type-based lookup doesn't carry a tag).
function sinkInfoFromPropDescriptor(desc, propName, elementTag) {
  if (!desc || !desc.sink) return null;
  const severity = desc.severity || defaultSinkSeverity(desc.sink);
  if (severity === 'safe') return null;
  const out = { type: desc.sink, severity, prop: propName };
  if (elementTag) out.elementTag = elementTag;
  // `exploit` links this sink to a named entry in
  // `db.exploits[...]` — the exploit attempts library for
  // PoC synthesis. Carry it through so the consumer doesn't
  // need to re-lookup the descriptor.
  if (desc.exploit) out.exploit = desc.exploit;
  return out;
}

// --- Type-first sink classification ---------------------------------------
//
// Given a concrete receiver typeName, look up the property on
// that type (walking the inheritance chain) and shape the
// result into a SinkInfo. This is the PRIMARY classifier — it
// should be called whenever the walker has a real typeName for
// the receiver. No tag fallback, no scanning.
function classifySinkByTypeViaDB(db, typeName, propName) {
  if (!db || !typeName || !propName) return null;
  const desc = lookupProp(db, typeName, propName);
  return sinkInfoFromPropDescriptor(desc, propName, null);
}

// --- Tag-based sink classification ----------------------------------------
//
// Used when the caller only has an element tag (e.g. a
// virtual-DOM element binding tagged via createElement). The
// tag is resolved to a concrete type via `db.tagMap`, then the
// classification proceeds as above. Falls back to the
// `HTMLElement` base chain when the tag is unknown or null —
// covers innerHTML, outerHTML, and other properties that apply
// to every element regardless of specific subtype.
function classifySinkViaDB(db, propName, elementTag) {
  if (!db || !propName) return null;
  let typeName = elementTag && db.tagMap && db.tagMap[elementTag.toLowerCase()];
  if (!typeName) typeName = 'HTMLElement';
  const desc = lookupProp(db, typeName, propName);
  return sinkInfoFromPropDescriptor(desc, propName, elementTag);
}

// --- Attribute-name sink classification -----------------------------------
//
// `setAttribute(attr, v)` sinks are driven by `db.attrSinks`,
// a flat `{attrName: sinkKind}` map. The map is shared with
// `Element.methods.setAttribute.args[0].sinkIfArgEquals.values`
// so attribute classification has exactly one source of truth.
function classifyAttrSinkViaDB(db, attrName) {
  if (!db || !attrName || !db.attrSinks) return null;
  const sinkKind = db.attrSinks[attrName.toLowerCase()];
  if (!sinkKind) return null;
  const severity = defaultSinkSeverity(sinkKind);
  if (severity === 'safe') return null;
  return { type: sinkKind, severity, prop: attrName };
}

// --- Dotted-expression splitter (respects balanced brackets) --------------
//
// Splits a dotted expression on `.` boundaries while respecting
// balanced parens / brackets / braces and quoted strings. A naive
// `expr.split('.')` on something like
//   document.querySelectorAll(".x").forEach
// produces garbage because it splits inside the quoted `.x`
// selector.
//
// Only `.` characters at bracket depth 0 and outside quotes are
// treated as separators.
function splitDottedExpr(expr) {
  const parts = [];
  let cur = '';
  let depth = 0;
  let quote = null;
  for (let i = 0; i < expr.length; i++) {
    const c = expr.charAt(i);
    if (quote) {
      cur += c;
      if (c === '\\') { cur += expr.charAt(++i) || ''; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; cur += c; continue; }
    if (c === ')' || c === ']' || c === '}') { depth--; cur += c; continue; }
    if (c === '.' && depth === 0) {
      parts.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  return parts;
}

// --- Walk a dotted expression and return the source label ----------------
//
// This is the core source-detection walker. Takes a dotted
// expression text and walks it segment-by-segment through the
// TypeDB, returning the source label (if any) produced by the
// deepest resolvable segment.
//
// Semantics:
//
//   1. The root segment is resolved via `scope(rootName)` first
//      (so a local binding's flow-sensitive typeName wins), then
//      via `db.roots[rootName]` (the global binding). If neither
//      provides a type, the walk returns null.
//   2. Before advancing, the current type's `selfSource` (if
//      present) becomes the accumulated source. This models
//      "reading a bare binding of this type yields this label"
//      — e.g. `localStorage` without further access still
//      carries the `storage` label.
//   3. Each non-root segment is looked up as a property first,
//      then as a method. A descriptor with `source: 'X'`
//      updates the accumulated label. A descriptor with
//      `readType: 'T'` / `returnType: 'T'` advances the
//      current type to T; non-static return types end the walk
//      early.
//   4. If a segment can't be resolved on the current type, the
//      walk stops and returns whatever source was accumulated
//      so far. This gives prefix-match semantics: e.g.
//      `location.hash.slice(1)` returns `url` from the
//      `location.hash` step because `slice(1)` isn't itself a
//      source but the prefix was.
//   5. After the final segment, the terminal type's
//      `.call.source` / `.construct.source` is honoured if no
//      earlier segment produced a source. Models bare-name
//      callables like `decodeURIComponent` that carry source
//      labels on their invocation.
//
// The `scope` parameter, when provided, is a function
// `name => { typeName?, shadowed? } | null` consulted ONLY for
// the root segment. Returning `{shadowed: true}` aborts the
// walk (the user has a local binding shadowing the global).
function walkPathInDB(db, expr, scope) {
  if (!db || !expr) return null;
  const parts = splitDottedExpr(expr);
  if (parts.length === 0) return null;
  let rootName = parts[0];
  const parenIdx0 = rootName.indexOf('(');
  if (parenIdx0 >= 0) rootName = rootName.slice(0, parenIdx0);
  let typeName = null;
  if (scope) {
    const rootHit = scope(rootName);
    if (rootHit) {
      if (rootHit.typeName) typeName = rootHit.typeName;
      else if (rootHit.shadowed) return null;
    }
  }
  if (!typeName) typeName = db.roots[rootName];
  if (!typeName) return null;
  let currentSource = null;
  let typeDesc = db.types[typeName];
  if (typeDesc && typeDesc.selfSource) currentSource = typeDesc.selfSource;
  for (let i = 1; i < parts.length; i++) {
    let seg = parts[i];
    const parenIdx = seg.indexOf('(');
    const isCall = parenIdx >= 0;
    if (isCall) seg = seg.slice(0, parenIdx);
    const propDesc = lookupProp(db, typeName, seg);
    const methodDesc = propDesc ? null : lookupMethod(db, typeName, seg);
    if (!propDesc && !methodDesc) return currentSource;
    const desc = propDesc || methodDesc;
    if (desc.source) currentSource = desc.source;
    let nextType = null;
    if (methodDesc) {
      if (typeof methodDesc.returnType === 'string') nextType = methodDesc.returnType;
    } else {
      nextType = propDesc.readType || null;
    }
    if (!nextType) return currentSource;
    typeName = nextType;
    // Honour the new type's selfSource after advancing, but
    // only when we haven't already picked up a stronger label
    // along the way. Covers `window.location` advancing to
    // `Location` which has `selfSource: 'url'`.
    if (!currentSource) {
      const newDesc = db.types[typeName];
      if (newDesc && newDesc.selfSource) currentSource = newDesc.selfSource;
    }
  }
  // After all segments consumed, honour the terminal type's
  // `.call.source` / `.construct.source`. Models callable
  // singletons like `decodeURIComponent()` (call-style) and
  // `new XMLHttpRequest()` (construct-style) whose bare name
  // carries a source label.
  if (!currentSource) {
    const finalDesc = db.types[typeName];
    if (finalDesc) {
      if (finalDesc.call && finalDesc.call.source) currentSource = finalDesc.call.source;
      else if (finalDesc.construct && finalDesc.construct.source) currentSource = finalDesc.construct.source;
    }
  }
  return currentSource;
}

// --- Call-site sink classification ----------------------------------------
//
// Look up a sink for a global or dotted callable. Returns the
// same `{type, severity, prop}` shape the prop-write classifier
// returns, or null for non-sink calls.
//
// Implementation: walks the callExpr through the TypeDB like
// `walkPathInDB` does for sources, but looks at MethodDescriptor
// `.sink` labels (and first-arg `.sink` labels) at each segment.
// The deepest segment that carries a sink label wins; an
// explicit `severity` field on the descriptor overrides the
// sink-kind default.
//
// If the walk consumes every segment without finding a method-
// level sink, the terminal type's `.call.sink` /
// `.construct.sink` / `.call.args[0].sink` is honoured as a
// fallback. This catches bare-name callables like `eval`,
// `setTimeout`, and `new Function(...)`.
function classifyCallSinkViaDB(db, callExpr, scope) {
  if (!db || !callExpr) return null;
  const parts = splitDottedExpr(callExpr);
  const rootName = parts[0];
  let typeName = null;
  if (scope) {
    const rootHit = scope(rootName);
    if (rootHit) {
      if (rootHit.typeName) typeName = rootHit.typeName;
      else if (rootHit.shadowed) return null;
    }
  }
  if (!typeName) typeName = db.roots[rootName];
  if (!typeName) return null;
  let currentSink = null;
  let currentSeverity = null;
  let typeDesc = db.types[typeName];
  const adopt = (sinkKind, explicitSev) => {
    currentSink = sinkKind;
    currentSeverity = explicitSev || defaultSinkSeverity(sinkKind);
  };
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i];
    const methodDesc = lookupMethod(db, typeName, seg);
    if (!methodDesc) break;
    if (methodDesc.sink) adopt(methodDesc.sink, methodDesc.severity);
    // Also honour a per-arg sink on the first arg for this
    // method — captures e.g. Location.assign which puts the
    // sink on arg0.
    if (!currentSink && methodDesc.args && methodDesc.args.length > 0 && methodDesc.args[0].sink) {
      adopt(methodDesc.args[0].sink, methodDesc.args[0].severity);
    }
    if (typeof methodDesc.returnType === 'string') {
      typeName = methodDesc.returnType;
      typeDesc = db.types[typeName];
    } else {
      break;
    }
  }
  // Fall back to the terminal type's .call / .construct
  // descriptor — catches eval, setTimeout, new Function, etc.
  if (!currentSink && typeDesc) {
    const callDesc = typeDesc.call || typeDesc.construct;
    if (callDesc) {
      if (callDesc.sink) adopt(callDesc.sink, callDesc.severity);
      else if (callDesc.args && callDesc.args.length > 0 && callDesc.args[0].sink) {
        adopt(callDesc.args[0].sink, callDesc.args[0].severity);
      }
    }
  }
  if (!currentSink || currentSeverity === 'safe') return null;
  return {
    type: currentSink,
    severity: currentSeverity,
    prop: (splitDottedExpr(callExpr).pop() || '').replace(/\(.*$/, ''),
  };
}

// --- Navigation sink detection --------------------------------------------
//
// Answer "does writing to or calling this expression trigger
// page navigation?" — i.e. does it need javascript:-protocol
// filtering?
//
// An expression qualifies if ANY of:
//   - The terminal type is `Location` itself (direct
//     `location = url` or `window.location = url` assignment).
//   - The terminal prop's container is a Location-like type
//     and the prop has `sink: 'navigation'` (covers
//     `location.href = url`, `location.hash = url`).
//   - The terminal method has `sink: 'navigation'` or its
//     first arg carries `sink: 'navigation'` (covers
//     `location.assign(url)`, `window.open(url)`).
function isNavSinkViaDB(db, expr, scope) {
  if (!db || !expr) return false;
  const parts = splitDottedExpr(expr);
  const rootName = parts[0];
  let typeName = null;
  if (scope) {
    const rootHit = scope(rootName);
    if (rootHit) {
      if (rootHit.typeName) typeName = rootHit.typeName;
      else if (rootHit.shadowed) return false;
    }
  }
  if (!typeName) typeName = db.roots[rootName];
  if (!typeName) return false;
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i];
    const pd = lookupProp(db, typeName, seg);
    const md = pd ? null : lookupMethod(db, typeName, seg);
    if (!pd && !md) return false;
    const isLast = (i === parts.length - 1);
    if (pd) {
      typeName = pd.readType || null;
      if (isLast) {
        if (pd.sink === 'navigation') return true;
        return typeName === 'Location';
      }
      if (!typeName) return false;
    } else {
      if (md.sink === 'navigation') return true;
      if (md.args && md.args.length > 0 && md.args[0].sink === 'navigation') return true;
      return false;
    }
  }
  // Bare root resolved directly to Location (e.g. `location`).
  return typeName === 'Location';
}

// --- Sanitizer detection --------------------------------------------------
//
// Answer "is this call a known sanitizer?" Sanitizers are
// declared in the TypeDB via `sanitizer: true` on `.call` or
// method descriptors. Their return values clear any accumulated
// taint labels.
//
// Covers bare-name sanitizers via `.call.sanitizer` (e.g.
// `encodeURIComponent`, `parseInt`) and dotted method calls
// via per-method descriptors (e.g. `DOMPurify.sanitize`).
function isSanitizerCallViaDB(db, callExpr, scope) {
  if (!db || !callExpr) return false;
  const parts = splitDottedExpr(callExpr);
  const rootName = parts[0];
  let typeName = null;
  if (scope) {
    const rootHit = scope(rootName);
    if (rootHit) {
      if (rootHit.typeName) typeName = rootHit.typeName;
      else if (rootHit.shadowed) return false;
    }
  }
  if (!typeName) typeName = db.roots[rootName];
  if (!typeName) return false;
  const typeDesc = db.types[typeName];
  if (parts.length > 1) {
    // Dotted method call: walk per-segment and check sanitizer
    // flag on the terminal method descriptor.
    let cur = typeName;
    for (let i = 1; i < parts.length; i++) {
      const md = lookupMethod(db, cur, parts[i]);
      if (!md) return false;
      if (i === parts.length - 1) return md.sanitizer === true;
      if (typeof md.returnType !== 'string') return false;
      cur = md.returnType;
    }
    return false;
  }
  // Bare call: check .call / .construct sanitizer flag.
  if (typeDesc) {
    const cd = typeDesc.call || typeDesc.construct;
    if (cd && cd.sanitizer === true) return true;
  }
  return false;
}

// --- Expression → type resolution -----------------------------------------
//
// Walk a dotted expression text through the TypeDB and return
// the terminal type name — the type that the expression's
// VALUE has at runtime, assuming the browser spec is followed
// and the root isn't shadowed by a local binding.
//
// This is the type-tracking counterpart to `walkPathInDB`:
// where that accumulates source labels along the walk, this
// one returns the final type for storage on value bindings.
//
// A leading `new ` is stripped so `new FileReader()` resolves
// the same way as `FileReader()` — both go through the type's
// `.construct` / `.call` descriptor.
//
// An expression whose tail can't be resolved on the current
// type yields null (unknown type); the caller treats the
// binding as untyped.
function resolveExprTypeViaDB(db, expr, scope) {
  if (!db || !expr) return null;
  if (/^new\s+/.test(expr)) expr = expr.replace(/^new\s+/, '');
  const parts = splitDottedExpr(expr);
  if (parts.length === 0) return null;
  let typeName = null;
  for (let i = 0; i < parts.length; i++) {
    let seg = parts[i];
    const parenIdx = seg.indexOf('(');
    const isCall = parenIdx >= 0;
    if (isCall) seg = seg.slice(0, parenIdx);
    if (i === 0) {
      if (scope) {
        const rootHit = scope(seg);
        if (rootHit) {
          if (rootHit.typeName) typeName = rootHit.typeName;
          else if (rootHit.shadowed) return null;
        }
      }
      if (!typeName) typeName = db.roots[seg];
      if (!typeName) return null;
      if (isCall) {
        const rootDesc = db.types[typeName];
        const cd = rootDesc ? (rootDesc.call || rootDesc.construct) : null;
        if (!cd || typeof cd.returnType !== 'string') return null;
        typeName = cd.returnType;
      }
      continue;
    }
    if (isCall) {
      const methodDesc = lookupMethod(db, typeName, seg);
      if (!methodDesc || typeof methodDesc.returnType !== 'string') return null;
      typeName = methodDesc.returnType;
    } else {
      const propDesc = lookupProp(db, typeName, seg);
      if (!propDesc || !propDesc.readType) return null;
      typeName = propDesc.readType;
    }
  }
  return typeName;
}

// --- Parametric inner type resolution -------------------------------------
//
// Walks the same path as `resolveExprTypeViaDB` but reads
// `innerType` from the terminal descriptor instead of the
// outer `returnType` / `readType`. Returns the inner type
// string or null if the expression's result isn't parametric.
//
// Used for container types like `Promise<T>`, `Array<T>`,
// `Set<T>`. Lets the engine propagate element types through
// `.then(v => ...)` callbacks and iterator protocols.
function resolveInnerTypeViaDB(db, expr, scope) {
  if (!db || !expr) return null;
  if (/^new\s+/.test(expr)) expr = expr.replace(/^new\s+/, '');
  const parts = splitDottedExpr(expr);
  if (parts.length === 0) return null;
  let typeName = null;
  let innerType = null;
  for (let i = 0; i < parts.length; i++) {
    let seg = parts[i];
    const parenIdx = seg.indexOf('(');
    const isCall = parenIdx >= 0;
    if (isCall) seg = seg.slice(0, parenIdx);
    if (i === 0) {
      if (scope) {
        const rootHit = scope(seg);
        if (rootHit) {
          if (rootHit.typeName) typeName = rootHit.typeName;
          else if (rootHit.shadowed) return null;
        }
      }
      if (!typeName) typeName = db.roots[seg];
      if (!typeName) return null;
      if (isCall) {
        const rootDesc = db.types[typeName];
        const cd = rootDesc ? (rootDesc.call || rootDesc.construct) : null;
        if (!cd) return null;
        if (cd.innerType) innerType = cd.innerType;
        if (typeof cd.returnType !== 'string') return null;
        typeName = cd.returnType;
      }
      continue;
    }
    if (isCall) {
      const methodDesc = lookupMethod(db, typeName, seg);
      if (!methodDesc) return null;
      innerType = methodDesc.innerType || null;  // reset per segment
      if (typeof methodDesc.returnType !== 'string') return null;
      typeName = methodDesc.returnType;
    } else {
      const propDesc = lookupProp(db, typeName, seg);
      if (!propDesc || !propDesc.readType) return null;
      innerType = null;  // property reads don't carry innerType
      typeName = propDesc.readType;
    }
  }
  return innerType;
}

// --- Least upper bound in the extends lattice ----------------------------
//
// Returns the most specific type that is an ancestor of both
// `a` and `b`, or null when no common ancestor exists. Used to
// join values from different control-flow branches whose types
// are related but distinct.
//
// Examples:
//   HTMLIFrameElement ⊔ HTMLScriptElement = HTMLElement
//   HTMLAnchorElement ⊔ HTMLElement       = HTMLElement
//   Location          ⊔ Document          = EventTarget
//   Location          ⊔ String            = null
function typeLUB(db, a, b) {
  if (!db || !a || !b) return null;
  if (a === b) return a;
  // Walk `a`'s extends chain collecting ancestors (inclusive
  // of `a` itself).
  const ancestors = Object.create(null);
  let cur = a;
  while (cur) {
    ancestors[cur] = true;
    const td = db.types[cur];
    cur = (td && td.extends) || null;
  }
  // Walk `b`'s extends chain; first hit wins (the most
  // specific common ancestor).
  cur = b;
  while (cur) {
    if (ancestors[cur]) return cur;
    const td2 = db.types[cur];
    cur = (td2 && td2.extends) || null;
  }
  return null;
}

// --- Precheck: is this prop name a sink on any type? ----------------------
//
// Before entering the full classification path for a property
// write, the engine can ask "could `propName` possibly be a
// sink on any type in the DB?" A negative answer lets the
// caller skip the classifier entirely. 'safe'-severity
// descriptors count as "yes" here because the caller may still
// want to look them up with tag-level precision.
function propIsEverASink(db, propName) {
  if (!db || !propName) return false;
  for (const tn in db.types) {
    const td = db.types[tn];
    if (td.props && td.props[propName] && td.props[propName].sink) return true;
  }
  return false;
}

module.exports = {
  lookupProp,
  lookupMethod,
  resolveReturnType,
  defaultSinkSeverity,
  sinkInfoFromPropDescriptor,
  classifySinkByTypeViaDB,
  classifySinkViaDB,
  classifyAttrSinkViaDB,
  propIsEverASink,
  splitDottedExpr,
  walkPathInDB,
  classifyCallSinkViaDB,
  isNavSinkViaDB,
  isSanitizerCallViaDB,
  resolveExprTypeViaDB,
  resolveInnerTypeViaDB,
  typeLUB,
};
