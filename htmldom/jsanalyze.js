// jsanalyze.js — whole-program symbolic JS interpreter
//
// The engine file of the jsanalyze static-analysis library.
// Loads in both Node (CommonJS) and the browser (IIFE, no build
// step). Consumers never reach into internals — they go through
// the public `api` object exposed at the end of the IIFE, and
// (for typed value inspection) through the `bindingToValue`
// boundary function which converts walker bindings to the
// versioned shapes defined in jsanalyze-schemas.js.
//
// What lives in this file:
//   - JS + HTML tokenizers
//   - Scope-stack walker (buildScopeState)
//   - SMT-backed path reasoner (Z3 via z3-solver)
//   - May-be value lattice that feeds SMT disjunctions
//   - Promise / async / closure / class / Map dispatch tracking
//   - Callback fixpoint across event handlers, .then, setTimeout
//   - Virtual DOM extraction (extractAllDOM)
//   - Taint propagation (traceTaint, traceTaintInJs)
//   - bindingToValue — the walker → public-Value boundary
//
// Consumers (each in its own file, each a thin layer over the
// library's public query primitives):
//   jsanalyze-query.js    — analyze() entry + query.calls / query.taintFlows
//                            / query.valueSetOf / query.innerHtmlAssignments
//                            / query.stringLiterals / query.callGraph
//   fetch-trace.js        — HTTP API discovery (fetch/XHR/Worker/WS endpoints)
//   taint-report.js       — human-friendly taint reporter with grouping
//   csp-derive.js         — Content-Security-Policy derivation from observed calls
//   htmldom-convert.js    — innerHTML/outerHTML → createElement/appendChild rewriter
//
// The directory is still named htmldom/ because that's the
// Git-tracked feature area; jsanalyze is the library inside it.
// The front-end UI lives at htmldom/index.html and wires the
// walker + converter through monaco-init.js.
(async function () {
  'use strict';

  // IDL properties that reflect HTML attributes on common elements.
  const IDL_PROPS = new Set([
    'id', 'title', 'lang', 'dir', 'hidden', 'draggable', 'translate',
    'src', 'href', 'alt', 'name', 'type', 'placeholder',
    'width', 'height', 'rel', 'target', 'download', 'ping', 'hreflang',
    'loading', 'fetchPriority', 'srcdoc', 'srcset', 'sizes', 'allow',
    'integrity', 'min', 'max', 'step', 'pattern', 'autocomplete',
    'cols', 'rows', 'wrap', 'action', 'method', 'enctype',
    'content', 'media', 'as', 'coords', 'shape', 'useMap', 'isMap',
    'span', 'headers', 'scope', 'colSpan', 'rowSpan',
    'label', 'className'
  ]);

  // HTML attribute name -> IDL property name mapping.
  const ATTR_TO_PROP = {
    'class': 'className',
    'for': 'htmlFor',
    'tabindex': 'tabIndex',
    'readonly': 'readOnly',
    'maxlength': 'maxLength',
    'minlength': 'minLength',
    'novalidate': 'noValidate',
    'allowfullscreen': 'allowFullscreen',
    'crossorigin': 'crossOrigin',
    'referrerpolicy': 'referrerPolicy',
    'http-equiv': 'httpEquiv',
    'accept-charset': 'acceptCharset',
    'datetime': 'dateTime',
    'formaction': 'formAction',
    'formenctype': 'formEnctype',
    'formmethod': 'formMethod',
    'formnovalidate': 'formNoValidate',
    'formtarget': 'formTarget',
    'usemap': 'useMap',
    'ismap': 'isMap',
    'colspan': 'colSpan',
    'rowspan': 'rowSpan',
    'fetchpriority': 'fetchPriority',
    'contenteditable': 'contentEditable',
    'inputmode': 'inputMode',
    'enterkeyhint': 'enterKeyHint',
    'spellcheck': 'spellcheck'
  };

  // Boolean HTML attributes — empty value means true, absence means false.
  // Note: `checked` and `selected` are intentionally omitted so they go
  // through setAttribute, preserving defaultChecked/defaultSelected semantics.
  const BOOLEAN_ATTRS = new Set([
    'disabled', 'readonly', 'required', 'multiple',
    'autofocus', 'novalidate', 'allowfullscreen', 'async', 'defer',
    'hidden', 'ismap', 'loop', 'muted', 'open', 'reversed', 'autoplay',
    'controls', 'default', 'formnovalidate', 'nomodule', 'playsinline',
    'itemscope', 'inert'
  ]);

  // HTML void elements that have no closing tag.
  const VOID_ELEMENTS = new Set([
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
    'link', 'meta', 'param', 'source', 'track', 'wbr'
  ]);

  // Attributes that should always go through setAttribute (non-reflected, legacy, or namespaced).
  const FORCE_ATTR = new Set([
    'credentialless', 'sandbox', 'frameborder', 'marginwidth', 'marginheight',
    'scrolling', 'allowpaymentrequest', 'allowtransparency',
    'role', 'is', 'slot', 'part', 'exportparts',
    'itemtype', 'itemprop', 'itemid', 'itemref'
  ]);

  // Namespaces.
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const MATHML_NS = 'http://www.w3.org/1998/Math/MathML';
  const XLINK_NS = 'http://www.w3.org/1999/xlink';
  const XML_NS = 'http://www.w3.org/XML/1998/namespace';
  const XMLNS_NS = 'http://www.w3.org/2000/xmlns/';

  const SVG_TAGS = new Set([
    'svg', 'g', 'defs', 'symbol', 'use', 'path', 'rect', 'circle', 'ellipse',
    'line', 'polyline', 'polygon', 'text', 'tspan', 'textpath', 'image',
    'pattern', 'mask', 'clippath', 'lineargradient', 'radialgradient', 'stop',
    'filter', 'feblend', 'fecolormatrix', 'fecomposite', 'feconvolvematrix',
    'fediffuselighting', 'fedisplacementmap', 'fedropshadow', 'feflood',
    'fefunca', 'fefuncb', 'fefuncg', 'fefuncr', 'fegaussianblur',
    'feimage', 'femerge', 'femergenode', 'femorphology', 'feoffset',
    'fepointlight', 'fespecularlighting', 'fespotlight', 'fetile',
    'feturbulence', 'foreignobject', 'marker', 'metadata',
    'desc', 'view', 'switch', 'animate', 'animatemotion', 'animatetransform',
    'set', 'mpath',
  ]);

  function $(id) { return document.getElementById(id); }

  // -----------------------------------------------------------------------
  // Taint Analysis Infrastructure
  // -----------------------------------------------------------------------

  // ---------------------------------------------------------------
  // TypeDB — the declarative database that drives every source/sink
  // decision the walker makes. Pure data, no behaviour; the engine
  // applies the entries below uniformly through a single set of
  // lookup helpers (lookupProp / lookupMethod / resolveReturnType)
  // and has no hardcoded name literals of its own.
  //
  // Shape:
  //
  //   TypeDB = {
  //     types:    { [typeName]: TypeDescriptor },
  //     roots:    { [globalName]: typeName },   // unshadowed globals
  //     tagMap:   { [lowercaseTag]: typeName }, // createElement → subtype
  //     eventMap: { [eventName]: typeName },    // handler first-param type
  //   }
  //
  //   TypeDescriptor = {
  //     extends?: typeName,                  // inheritance chain
  //     props?:   { [name]: PropDescriptor },
  //     methods?: { [name]: MethodDescriptor },
  //     call?:    MethodDescriptor,          // callable singletons (eval/fetch)
  //     construct?: MethodDescriptor,        // `new T(...)` semantics
  //   }
  //
  //   PropDescriptor = {
  //     source?:   string,                   // read → binding gets this label
  //     sink?:     string,                   // write → finding with this kind
  //     readType?: typeName,                 // type of the value read
  //     writeType?: typeName,                // type refinement on write
  //   }
  //
  //   MethodDescriptor = {
  //     args?:        ArgDescriptor[],       // per-position arg metadata
  //     returnType?:  typeName |             // static return type
  //                   { fromArg: number,     // dynamic: pick by arg string
  //                     map: { [argValue]: typeName },
  //                     default?: typeName },
  //     source?:                    string,  // return value gets this label
  //     sink?:                      string,  // call-site sink kind
  //     preservesLabelsFromArg?:    number,  // e.g. decodeURIComponent(arg0)
  //     preservesLabelsFromReceiver?: boolean, // e.g. String.slice preserves
  //   }
  //
  //   ArgDescriptor = {
  //     sink?: string,                       // passing a labeled value → finding
  //     sinkIfArgEquals?: {                  // e.g. setAttribute('onX', …) is code
  //       arg: number,
  //       values: { [argValue]: string },
  //     },
  //   }
  //
  // The preset DEFAULT_TYPE_DB at the bottom of this file holds the
  // browser type descriptors. Consumers can replace or extend it by
  // passing their own DB as options.taintConfig.typeDB.
  function _lookupProp(db, typeName, propName) {
    var t = typeName;
    while (t) {
      var desc = db.types[t];
      if (!desc) return null;
      if (desc.props && Object.prototype.hasOwnProperty.call(desc.props, propName)) {
        return desc.props[propName];
      }
      t = desc.extends || null;
    }
    return null;
  }
  function _lookupMethod(db, typeName, methodName) {
    var t = typeName;
    while (t) {
      var desc = db.types[t];
      if (!desc) return null;
      if (desc.methods && Object.prototype.hasOwnProperty.call(desc.methods, methodName)) {
        return desc.methods[methodName];
      }
      t = desc.extends || null;
    }
    return null;
  }
  // Resolve a method's return type given call-site information.
  // Handles the static `returnType: 'X'` form and the dynamic
  // `returnType: { fromArg: N, map: {...}, default: 'X' }` form
  // used for createElement-style APIs.
  function _resolveReturnType(methodDesc, argStrings) {
    var rt = methodDesc && methodDesc.returnType;
    if (!rt) return null;
    if (typeof rt === 'string') return rt;
    if (typeof rt === 'object' && typeof rt.fromArg === 'number') {
      var key = argStrings[rt.fromArg];
      if (key != null && rt.map && Object.prototype.hasOwnProperty.call(rt.map, key)) {
        return rt.map[key];
      }
      return rt.default || null;
    }
    return null;
  }

  // Default severity for a sink kind. Sink descriptors may carry
  // their own `severity` field which overrides this default.
  function _defaultSinkSeverity(sinkKind) {
    if (sinkKind === 'code')       return 'critical';
    if (sinkKind === 'safe')       return 'safe';
    if (sinkKind === 'text')       return 'safe';
    if (sinkKind === 'navigation') return 'high';
    if (sinkKind === 'html')       return 'high';
    if (sinkKind === 'url')        return 'high';
    if (sinkKind === 'css')        return 'medium';
    return 'high';
  }

  // Shape a PropDescriptor's sink metadata into the {type,
  // severity, prop, elementTag} object the legacy classifySink
  // API returns. `desc.severity` overrides the sink-kind default;
  // 'safe' sinks collapse to null so the caller treats them as
  // non-sinks.
  function _sinkInfoFromPropDescriptor(desc, propName, elementTag) {
    if (!desc || !desc.sink) return null;
    var severity = desc.severity || _defaultSinkSeverity(desc.sink);
    if (severity === 'safe') return null;
    var out = { type: desc.sink, severity: severity, prop: propName };
    if (elementTag) out.elementTag = elementTag;
    return out;
  }

  // Classify a property-write sink via the TypeDB, replacing the
  // legacy `classifySink(propName, elementTag)` that consulted
  // TAINT_SINKS + ELEMENT_SINK_TYPES.
  //
  // Semantics:
  //
  //   - When `elementTag` is a known tag, resolve it to its
  //     concrete TypeDescriptor via `db.tagMap`, walk the
  //     inheritance chain with `_lookupProp`, and return the
  //     resulting PropDescriptor's sink info if any.
  //   - When `elementTag` is unknown, check the base
  //     HTMLElement chain first (covers innerHTML, outerHTML,
  //     and anything else that applies to every element). If
  //     that doesn't match, scan every subtype in the DB for the
  //     same propName — if ANY subtype has it as a sink, report
  //     it with elementTag='unknown'. This preserves the legacy
  //     behaviour where an element-dependent sink on an
  //     unresolved tag was reported conservatively.
  // Type-first variant: given a concrete receiver typeName,
  // look up the prop on that type and return the sink info.
  // No scanning, no fallback — when the walker has a real type
  // for the receiver this answer is definitive.
  function _classifySinkByTypeViaDB(db, typeName, propName) {
    if (!db || !typeName || !propName) return null;
    var desc = _lookupProp(db, typeName, propName);
    return _sinkInfoFromPropDescriptor(desc, propName, null);
  }

  // Legacy variant that takes an element tag string. Used by
  // callers that only know the tag (e.g. element bindings
  // tagged via getElementTag). Internally it resolves the tag
  // to a concrete type via `db.tagMap` and delegates to
  // `_classifySinkByTypeViaDB`. When the tag is unknown (or
  // null), falls through to the base `HTMLElement` chain —
  // there's no subtype scan; the type system already has the
  // answer via the flow-sensitive binding typeName.
  function _classifySinkViaDB(db, propName, elementTag) {
    if (!db || !propName) return null;
    var typeName = elementTag && db.tagMap && db.tagMap[elementTag.toLowerCase()];
    if (!typeName) typeName = 'HTMLElement';
    var desc = _lookupProp(db, typeName, propName);
    return _sinkInfoFromPropDescriptor(desc, propName, elementTag);
  }

  // Classify a `setAttribute(attr, v)`-style attribute-name sink
  // via `db.attrSinks`. Returns the same shape as
  // `_classifySinkViaDB` — `{type, severity, prop}` — or null.
  function _classifyAttrSinkViaDB(db, attrName) {
    if (!db || !attrName || !db.attrSinks) return null;
    var sinkKind = db.attrSinks[attrName.toLowerCase()];
    if (!sinkKind) return null;
    var severity = _defaultSinkSeverity(sinkKind);
    if (severity === 'safe') return null;
    return { type: sinkKind, severity: severity, prop: attrName };
  }

  // Answer "is `propName` a sink on ANY type in the DB?". This
  // is the precheck used before entering the sink-classification
  // branch for property writes on non-tracked bindings — it
  // avoids walking every property write through the full
  // classifier when the name can't possibly resolve to a sink.
  // `safe`-severity sinks count as "yes" here so the caller can
  // still look them up via `_classifySinkViaDB` with a known tag.
  function _propIsEverASink(db, propName) {
    if (!db || !propName) return false;
    for (var tn in db.types) {
      var td = db.types[tn];
      if (td.props && td.props[propName] && td.props[propName].sink) return true;
    }
    return false;
  }

  // Walk a dotted expression text through the TypeDB and return
  // the terminal type name — the type that the expression's
  // VALUE has at runtime, assuming the browser spec is followed
  // and the root isn't shadowed by a user variable.
  //
  // This is the type-tracking counterpart to `_walkPathInDB`:
  // where that one accumulates source LABELS along the walk,
  // this one returns the final TYPE for storage on bindings.
  // An expression whose tail can't be resolved on the current
  // type yields null (unknown type); the caller treats the
  // binding as untyped. `scope`, when provided, overrides the
  // root segment the same way `_walkPathInDB` does.
  function _resolveExprTypeViaDB(db, expr, scope) {
    if (!db || !expr) return null;
    // Strip a leading `new ` so `new FileReader()` resolves the
    // same way as `FileReader()` — both go through the type's
    // .construct / .call descriptor.
    if (/^new\s+/.test(expr)) expr = expr.replace(/^new\s+/, '');
    var parts = expr.split('.');
    if (parts.length === 0) return null;
    var typeName = null;
    for (var i = 0; i < parts.length; i++) {
      var seg = parts[i];
      var parenIdx = seg.indexOf('(');
      var isCall = parenIdx >= 0;
      if (isCall) seg = seg.slice(0, parenIdx);
      if (i === 0) {
        // Root segment: resolve via scope first, then db.roots.
        if (scope) {
          var rootHit = scope(seg);
          if (rootHit) {
            if (rootHit.typeName) typeName = rootHit.typeName;
            else if (rootHit.shadowed) return null;
          }
        }
        if (!typeName) typeName = db.roots[seg];
        if (!typeName) return null;
        // Bare-call root (e.g. `fetch(x)`, `new FileReader()`):
        // advance through the type's .call / .construct return
        // type when static. Non-static returnTypes yield null —
        // we don't try to parse args here.
        if (isCall) {
          var rootDesc = db.types[typeName];
          var cd = rootDesc ? (rootDesc.call || rootDesc.construct) : null;
          if (!cd || typeof cd.returnType !== 'string') return null;
          typeName = cd.returnType;
        }
        continue;
      }
      // Non-root segment: method (if isCall) or prop (otherwise).
      if (isCall) {
        var methodDesc = _lookupMethod(db, typeName, seg);
        if (!methodDesc || typeof methodDesc.returnType !== 'string') return null;
        typeName = methodDesc.returnType;
      } else {
        var propDesc = _lookupProp(db, typeName, seg);
        if (!propDesc || !propDesc.readType) return null;
        typeName = propDesc.readType;
      }
    }
    return typeName;
  }

  // Answer "does this expression address a navigation sink?" —
  // i.e. does assigning to it OR calling it trigger page
  // navigation (and thus need javascript:-protocol filtering)?
  //
  // Implemented by walking the dotted expression through the
  // TypeDB. An expression qualifies if ANY of:
  //   - The terminal type is `Location` (direct `location = url`
  //     assignment to a Location binding).
  //   - The terminal prop's container type is `Location` and the
  //     prop itself has `sink: 'navigation'` (covers
  //     `location.href = url`).
  //   - The terminal method has `sink: 'navigation'` or its
  //     first arg carries `sink: 'navigation'` (covers
  //     `location.assign(url)`, `location.replace(url)`,
  //     `window.open(url)`, `navigation.navigate(url)`).
  //
  // The `scope` parameter (when provided) makes the check
  // flow-sensitive: if the root name resolves to a typed local
  // binding, the walk starts from that type; if it resolves to
  // an untyped local binding the walk aborts (user shadowed).
  function _isNavSinkViaDB(db, expr, scope) {
    if (!db || !expr) return false;
    var parts = expr.split('.');
    var rootName = parts[0];
    var typeName = null;
    if (scope) {
      var rootHit = scope(rootName);
      if (rootHit) {
        if (rootHit.typeName) typeName = rootHit.typeName;
        else if (rootHit.shadowed) return false;
      }
    }
    if (!typeName) typeName = db.roots[rootName];
    if (!typeName) return false;
    for (var i = 1; i < parts.length; i++) {
      var seg = parts[i];
      var pd = _lookupProp(db, typeName, seg);
      var md = pd ? null : _lookupMethod(db, typeName, seg);
      if (!pd && !md) return false;
      var prevType = typeName;
      var isLast = (i === parts.length - 1);
      if (pd) {
        typeName = pd.readType || null;
        if (isLast) {
          // `container.prop = url` where container is Location
          // and prop is a navigation sink (the `.href` case).
          if (pd.sink === 'navigation') return true;
          // Advanced through a chain whose tail is a Location
          // reference (the `window.location = url`, `document.
          // location = url` intermediate case).
          return typeName === 'Location';
        }
        if (!typeName) return false;
      } else {
        // Method segment: check per-method + per-arg navigation
        // sink labels. Method sinks terminate the walk.
        if (md.sink === 'navigation') return true;
        if (md.args && md.args.length > 0 && md.args[0].sink === 'navigation') return true;
        return false;
      }
    }
    // Bare root resolved directly to Location (e.g. `location`).
    return typeName === 'Location';
  }

  // Answer "is `callExpr` a known sanitizer?" by walking the
  // expression through the TypeDB. A descriptor carries
  // `sanitizer: true` if calling it neutralises taint on its
  // return value. Covers bare globals (`parseInt`,
  // `encodeURIComponent`) via `.call.sanitizer` AND dotted
  // method calls (`DOMPurify.sanitize`) via per-method
  // descriptors.
  function _isSanitizerCallViaDB(db, callExpr, scope) {
    if (!db || !callExpr) return false;
    var parts = callExpr.split('.');
    var rootName = parts[0];
    var typeName = null;
    if (scope) {
      var rootHit = scope(rootName);
      if (rootHit) {
        if (rootHit.typeName) typeName = rootHit.typeName;
        else if (rootHit.shadowed) return false;
      }
    }
    if (!typeName) typeName = db.roots[rootName];
    if (!typeName) return false;
    var typeDesc = db.types[typeName];
    // Dotted method call: walk per-segment.
    if (parts.length > 1) {
      var cur = typeName;
      for (var i = 1; i < parts.length; i++) {
        var md = _lookupMethod(db, cur, parts[i]);
        if (!md) return false;
        if (i === parts.length - 1) return md.sanitizer === true;
        if (typeof md.returnType !== 'string') return false;
        cur = md.returnType;
      }
      return false;
    }
    // Bare call: check .call / .construct descriptor.
    if (typeDesc) {
      var cd = typeDesc.call || typeDesc.construct;
      if (cd && cd.sanitizer === true) return true;
    }
    return false;
  }

  // Collect every `source` label reachable from an Event subtype
  // via its props/methods (and transitively via readType /
  // returnType refs, and via the `extends` chain). Used to
  // compute the flat taint-label set an addEventListener handler
  // should attach to its event-parameter binding.
  //
  // Example: MessageEvent → {data: postMessage, origin:
  // postMessage} → {'postMessage'}.
  //
  // Example: DragEvent → {dataTransfer: DataTransfer} →
  // DataTransfer.{files: file, getData(): dragdrop} →
  // {'file', 'dragdrop'}.
  function _collectEventSourceLabels(db, typeName, seen) {
    var labels = new Set();
    if (!db || !typeName) return labels;
    seen = seen || new Set();
    if (seen.has(typeName)) return labels;
    seen.add(typeName);
    var cur = typeName;
    while (cur) {
      var td = db.types[cur];
      if (!td) break;
      if (td.props) {
        for (var p in td.props) {
          var pd = td.props[p];
          if (pd.source) labels.add(pd.source);
          if (pd.readType) {
            var sub = _collectEventSourceLabels(db, pd.readType, seen);
            sub.forEach(function (l) { labels.add(l); });
          }
        }
      }
      if (td.methods) {
        for (var m in td.methods) {
          var md = td.methods[m];
          if (md.source) labels.add(md.source);
          if (typeof md.returnType === 'string') {
            var sub2 = _collectEventSourceLabels(db, md.returnType, seen);
            sub2.forEach(function (l) { labels.add(l); });
          }
        }
      }
      cur = td.extends || null;
    }
    return labels;
  }

  // Look up a call-site sink for a global/dotted callable, e.g.
  // `eval` / `document.write` / `location.assign`. Returns the
  // same `{type, severity, prop}` shape callers expect.
  //
  // Implemented by walking the callExpr through the TypeDB.
  // The deepest segment that carries a `sink` label in its
  // method descriptor wins, or the final type's `.call.sink` /
  // `.construct.sink` if one is defined (for bare global
  // callables like `eval`). Preserves the legacy
  // TAINT_CALL_SINKS behaviour without a flat lookup table.
  function _classifyCallSinkViaDB(db, callExpr, scope) {
    if (!db || !callExpr) return null;
    var parts = callExpr.split('.');
    var rootName = parts[0];
    var typeName = null;
    if (scope) {
      var rootHit = scope(rootName);
      if (rootHit) {
        if (rootHit.typeName) typeName = rootHit.typeName;
        else if (rootHit.shadowed) return null;
      }
    }
    if (!typeName) typeName = db.roots[rootName];
    if (!typeName) return null;
    var currentSink = null;
    var currentSeverity = null;
    var typeDesc = db.types[typeName];
    // Walk per-segment method descriptors, preferring the
    // deepest sink encountered. A descriptor's explicit
    // `severity` overrides the sink-kind default.
    var _adopt = function(sinkKind, explicitSev) {
      currentSink = sinkKind;
      currentSeverity = explicitSev || _defaultSinkSeverity(sinkKind);
    };
    for (var i = 1; i < parts.length; i++) {
      var seg = parts[i];
      var methodDesc = _lookupMethod(db, typeName, seg);
      if (!methodDesc) break;
      if (methodDesc.sink) _adopt(methodDesc.sink, methodDesc.severity);
      // Also honour a per-arg sink on the first arg for this
      // method — captures e.g. Location.assign which puts the
      // sink on arg0.
      if (!currentSink && methodDesc.args && methodDesc.args.length > 0 && methodDesc.args[0].sink) {
        _adopt(methodDesc.args[0].sink, methodDesc.args[0].severity);
      }
      if (typeof methodDesc.returnType === 'string') {
        typeName = methodDesc.returnType;
        typeDesc = db.types[typeName];
      } else {
        break;
      }
    }
    // If the walk consumed every segment without finding a
    // method-level sink, fall back to the current type's
    // `.call.sink` / `.construct.sink` / `.call.args[0].sink`.
    // This catches bare-name callables like eval, setTimeout,
    // and `new Function(...)`.
    if (!currentSink && typeDesc) {
      var callDesc = typeDesc.call || typeDesc.construct;
      if (callDesc) {
        if (callDesc.sink) _adopt(callDesc.sink, callDesc.severity);
        else if (callDesc.args && callDesc.args.length > 0 && callDesc.args[0].sink) {
          _adopt(callDesc.args[0].sink, callDesc.args[0].severity);
        }
      }
    }
    if (!currentSink || currentSeverity === 'safe') return null;
    return {
      type: currentSink,
      severity: currentSeverity,
      prop: callExpr.split('.').pop(),
    };
  }

  // Legacy TAINT_SOURCES / TAINT_SOURCE_CALLS tables were removed
  // in phase 2 of the type-db refactor. Source detection is now
  // driven entirely by `_walkPathInDB` walking expression texts
  // against the DEFAULT_TYPE_DB at the bottom of this file. See
  // `getTaintSource` / `getTaintSourceCall` for the API the rest
  // of the walker still calls.
  // Legacy EVENT_TAINT_SOURCES table was removed in phase 4 of
  // the type-db refactor. Event-handler parameter taint is now
  // resolved via `DEFAULT_TYPE_DB.eventMap[eventName]` → Event
  // subtype → `_collectEventSourceLabels` which walks the
  // subtype's props/methods (and transitive readType/returnType
  // refs) for `source` fields. See the addEventListener branch
  // in statement walking for the consumer.

  // Legacy flat-table sink classification was removed in phase 3
  // of the type-db refactor. Property, element-specific, call, and
  // attribute-name sinks are now driven entirely by DEFAULT_TYPE_DB
  // via `_classifySinkViaDB`, `_classifyCallSinkViaDB`, and
  // `_classifyAttrSinkViaDB`. See `classifySink` / `checkSinkCall`
  // / `checkSinkSetAttribute` for the thin API the rest of the
  // walker still calls.

  // Legacy TAINT_SANITIZERS set was removed in phase 5 of the
  // type-db refactor. Sanitizers are now declared in the TypeDB
  // via `sanitizer: true` on `.call` / method descriptors, and
  // looked up by `_isSanitizerCallViaDB`. See `isSanitizer`.

  // Collect taint from a chain token array. Returns a Set of source labels
  // or null if no taint. Recurses into structured tokens (cond, trycatch,
  // switch, tmpl) so taint inside branches is never missed.
  function collectChainTaint(toks) {
    if (!toks) return null;
    var result = null;
    var merge = function(set) {
      if (!set) return;
      if (!result) result = new Set();
      for (var label of set) result.add(label);
    };
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t.taint) merge(t.taint);
      if (t.type === 'cond') {
        merge(collectChainTaint(t.ifTrue));
        merge(collectChainTaint(t.ifFalse));
      } else if (t.type === 'trycatch') {
        merge(collectChainTaint(t.tryBody));
        merge(collectChainTaint(t.catchBody));
      } else if ((t.type === 'switch' || t.type === 'switchjoin') && t.branches) {
        for (var bi = 0; bi < t.branches.length; bi++) {
          merge(collectChainTaint(t.branches[bi].chain));
        }
      } else if (t.type === 'tmpl' && t.parts) {
        for (var pi = 0; pi < t.parts.length; pi++) {
          if (t.parts[pi].kind === 'expr' && t.parts[pi].toks) {
            merge(collectChainTaint(t.parts[pi].toks));
          }
        }
      }
    }
    return result;
  }

  // Create an exprRef that inherits taint from any number of source token
  // arrays. Every place that creates a derived opaque expression from
  // existing bindings should use this instead of bare exprRef().
  function deriveExprRef(text) {
    var ref = exprRef(text);
    for (var i = 1; i < arguments.length; i++) {
      var t = collectChainTaint(arguments[i]);
      if (t) {
        if (!ref.taint) ref.taint = new Set();
        for (var l of t) ref.taint.add(l);
      }
    }
    return ref;
  }

  // Walk a dotted expression text through the TypeDB and return
  // the source label (if any) produced by the final — or last
  // resolvable — segment along the path.
  //
  // This is the type-based replacement for the legacy flat-table
  // `getTaintSource(expr)`: instead of string-matching `expr`
  // against a pre-enumerated list of source paths, it resolves
  // the root name to a type via `db.roots`, walks each subsequent
  // segment via `_lookupProp` / `_lookupMethod` chaining through
  // the `readType` / `returnType` advancement, and returns the
  // source label at the deepest segment that had one. Segments
  // that end with `(` are treated as method calls; their return
  // type (when static) continues the walk.
  //
  // Prefix-match semantics: if a segment can't be resolved on the
  // current type, the walk stops and returns whatever source
  // label was accumulated earlier. That matches the legacy
  // behaviour where `location.hash.slice(1)` produced the `url`
  // label from `location.hash` even though `slice(1)` isn't itself
  // enumerated as a taint source.
  //
  // A type descriptor may also carry a `selfSource` field,
  // meaning "reading a binding of this type directly yields this
  // label" — this preserves the legacy behaviour where bare
  // `localStorage` / `sessionStorage` carried the `storage`
  // label without any further property access.
  // `scope`, when provided, is a resolver `(name) => { typeName?,
  // shadowed? }` consulted for the ROOT segment. It gives callers
  // flow-sensitive type tracking: if the root name resolves to a
  // typed local binding, walking starts from that type instead of
  // `db.roots`. If it resolves to an untyped local binding
  // (`shadowed: true`) the walk aborts entirely — the user has
  // shadowed any global of the same name with a user variable.
  function _walkPathInDB(db, expr, scope) {
    if (!db || !expr) return null;
    var parts = expr.split('.');
    if (parts.length === 0) return null;
    var rootName = parts[0];
    var parenIdx0 = rootName.indexOf('(');
    if (parenIdx0 >= 0) rootName = rootName.slice(0, parenIdx0);
    var typeName = null;
    if (scope) {
      var rootHit = scope(rootName);
      if (rootHit) {
        if (rootHit.typeName) typeName = rootHit.typeName;
        else if (rootHit.shadowed) return null;
      }
    }
    if (!typeName) typeName = db.roots[rootName];
    if (!typeName) return null;
    var currentSource = null;
    var typeDesc = db.types[typeName];
    if (typeDesc && typeDesc.selfSource) currentSource = typeDesc.selfSource;
    for (var i = 1; i < parts.length; i++) {
      var seg = parts[i];
      var parenIdx = seg.indexOf('(');
      var isCall = parenIdx >= 0;
      if (isCall) seg = seg.slice(0, parenIdx);
      var propDesc = _lookupProp(db, typeName, seg);
      var methodDesc = propDesc ? null : _lookupMethod(db, typeName, seg);
      if (!propDesc && !methodDesc) return currentSource;
      var desc = propDesc || methodDesc;
      if (desc.source) currentSource = desc.source;
      var nextType = null;
      if (methodDesc) {
        if (typeof methodDesc.returnType === 'string') nextType = methodDesc.returnType;
      } else {
        nextType = propDesc.readType || null;
      }
      if (!nextType) return currentSource;
      typeName = nextType;
      // After advancing to a new type along the walk, honour the
      // new type's `selfSource` if we haven't already picked up a
      // stronger per-segment source along the way. This catches
      // the case where a prop read advances to a type whose
      // own-identity carries a label (e.g. `window.location`
      // advances to `Location` which has `selfSource: 'url'`).
      if (!currentSource) {
        var newDesc = db.types[typeName];
        if (newDesc && newDesc.selfSource) currentSource = newDesc.selfSource;
      }
    }
    // After consuming all path segments, honour the current
    // type's `.call.source` / `.construct.source` if one is
    // defined — this models global callable singletons like
    // `decodeURIComponent()` (call-style) and `new
    // XMLHttpRequest()` (construct-style) whose bare-name
    // reference is its own call-site source.
    if (!currentSource) {
      var finalDesc = db.types[typeName];
      if (finalDesc) {
        if (finalDesc.call && finalDesc.call.source) currentSource = finalDesc.call.source;
        else if (finalDesc.construct && finalDesc.construct.source) currentSource = finalDesc.construct.source;
      }
    }
    return currentSource;
  }

  // Check if an expression text matches a known taint source. Returns label or null.
  //
  // Implemented by walking the dotted expression through the
  // TypeDB via `_walkPathInDB`: each segment advances the current
  // type via `_lookupProp` / `_lookupMethod` chaining, and the
  // deepest segment that carries a `source` label (or the deepest
  // type whose `selfSource` applies) determines the returned
  // label. Unresolvable tail segments fall back to whatever source
  // was accumulated earlier, which preserves the legacy prefix-
  // match behaviour for patterns like `location.hash.slice(1)`
  // where the final `slice(1)` doesn't itself resolve on the
  // TypeDB but `location.hash` does.
  function getTaintSource(expr, scope) {
    return _walkPathInDB(DEFAULT_TYPE_DB, expr, scope);
  }

  // Check if an expression is a known call-based taint source.
  //
  // Implemented via the same TypeDB path walker `getTaintSource`
  // uses: the callee's dotted name is walked through the TypeDB,
  // and both per-segment `source` labels AND the final type's
  // `.call.source` / `.construct.source` are considered. That
  // covers bare global callables like `decodeURIComponent`,
  // `fetch`, `atob`, and dotted call sources like `localStorage.
  // getItem` and `location.toString`.
  function getTaintSourceCall(callExpr, scope) {
    return _walkPathInDB(DEFAULT_TYPE_DB, callExpr, scope);
  }

  // Classify a property sink given the element type. Returns
  // sink info or null. Thin wrapper over `_classifySinkViaDB`
  // that walks the preset TypeDB.
  function classifySink(propName, elementTag) {
    return _classifySinkViaDB(DEFAULT_TYPE_DB, propName, elementTag);
  }

  // Check if a function name is a known sanitizer. Thin wrapper
  // over `_isSanitizerCallViaDB` which walks the call expression
  // through DEFAULT_TYPE_DB looking for descriptors that carry
  // `sanitizer: true`. The `scope` parameter is an optional
  // flow-sensitive resolver consulted for the root segment.
  function isSanitizer(name, scope) {
    return _isSanitizerCallViaDB(DEFAULT_TYPE_DB, name, scope);
  }

  // Extract the element tag from a binding's origin (for element type tracking).
  function getElementTag(binding) {
    if (!binding) return null;
    if (binding.kind === 'element' && binding.origin) {
      if (binding.origin.kind === 'create') return binding.origin.tag;
    }
    return null;
  }

  // -----------------------------------------------------------------------
  // Navigation Sink Infrastructure
  // -----------------------------------------------------------------------


  // Legacy NAV_SINKS / FRAME_NAV_PROPS / LOCATION_NAV_PROPS /
  // NAV_SINK_EXPRS flat tables were removed in phase 6 of the
  // type-db refactor. Navigation-sink assignment detection is
  // now driven by `_isNavSinkAssignViaDB` which walks the
  // expression through DEFAULT_TYPE_DB and checks whether the
  // terminal type is `Location` OR whether the terminal
  // property descriptor carries `sink: 'navigation'` on a
  // Location container. Navigation-sink method calls (eval /
  // location.assign / window.open / navigation.navigate) are
  // picked up by the general `_classifyCallSinkViaDB` path.

  // Check if an expression addresses a navigation sink (either
  // as an assignment target OR as a callable). Thin wrapper
  // over `_isNavSinkViaDB`. The `scope` parameter is an optional
  // flow-sensitive resolver consulted for the root segment.
  function isNavSink(expr, scope) {
    return _isNavSinkViaDB(DEFAULT_TYPE_DB, expr, scope);
  }

  // Protocol filter code for safe navigation: validates URL is http(s).
  var NAV_SAFE_FILTER = 'function __safeNav(url){try{var u=new URL(url,location.href);if(u.protocol===\"https:\"||u.protocol===\"http:\")return url}catch(e){}return undefined}';
  var NAV_SAFE_FILTER_USED = false;

  // -----------------------------------------------------------------------
  // SMT Constraint Solver
  // -----------------------------------------------------------------------
  //
  // Determines satisfiability of conditions at compile time using
  // constraint formulas, theory solvers, and path constraint propagation.
  //
  // Architecture:
  //   1. Formula AST — typed expression tree (Sym, Const, Not, And, Or, Cmp)
  //   2. Theory solvers — evaluate formulas over specific domains:
  //      - Boolean theory: AND, OR, NOT simplification
  //      - Linear arithmetic: integer/float comparisons and bounds
  //      - Equality theory: =, !=, ===, !== with unification
  //   3. Satisfiability checker — determines if a formula has a model
  //      (assignment of symbolic variables that makes it true)
  //   4. Condition parser — builds formulas from raw JS condition tokens
  //   5. Integration — scope walker queries the solver for branch reachability
  //
  // A symbolic variable represents a value the attacker controls:
  //   - Taint sources (location.search, postMessage data)
  //   - Event handler invocation counts (handler fires N times)
  //   - Any value derived from the above through operations

  // --- Formula representation ---
  // Each formula is a small object carrying its SMT-LIB s-expression
  // alongside the metadata Z3 needs to type-check it:
  //
  //   { expr:    string  -- SMT-LIB s-expression
  //     sorts:   { name → 'Int'|'String' }  -- declarations needed
  //     isBool:  bool    -- true if expr is already a Bool s-expression
  //     value:   { kind: 'bool'|'int'|'str', val } | undefined
  //                       -- present for fully-concrete formulas, used
  //                          for compile-time const folding
  //     symName: string  -- when this object is a single sym, its name
  //                          (used by smtCmp/smtStrProp to upgrade sort)
  //   }
  //
  // The builders below construct these objects directly. There is no
  // intermediate AST: smtSat just emits `(declare-const ...)` from
  // `sorts` and `(assert <expr>)` and feeds it to Z3.

  function _quoteSmtName(s) { return '|' + s.replace(/\|/g, '_') + '|'; }
  function _quoteSmtString(s) { return '"' + s.replace(/"/g, '""') + '"'; }
  // True when `o`'s SMT expression denotes a String-sorted value:
  // a string literal, a sym previously declared as String, or a
  // composite result flagged `stringResult: true` by smtArith /
  // smtStrProp. Used by smtCmp to upgrade a compared sym's declared
  // sort when the other side is a String expression without an
  // inspectable `.value`.
  function _isStringSide(o) {
    if (!o) return false;
    if (o.value && o.value.kind === 'str') return true;
    if (o.symName && o.sorts && o.sorts[o.symName] === 'String') return true;
    if (o.stringResult) return true;
    return false;
  }

  function _mergeSorts(a, b) {
    var out = {};
    var conflict = false;
    if (a) for (var k in a) out[k] = a[k];
    if (b) for (var k2 in b) {
      if (out[k2] && out[k2] !== b[k2]) conflict = true;
      out[k2] = (out[k2] === 'String' || b[k2] === 'String') ? 'String' : (out[k2] || b[k2]);
    }
    if (conflict) Object.defineProperty(out, '__conflict', { value: true });
    return out;
  }
  // Coerce a value-typed expression to its boolean form (truthy check).
  function _toBool(o) {
    if (!o) return 'true';
    if (o.isBool) return o.expr;
    if (o.value) {
      if (o.value.kind === 'bool') return o.value.val ? 'true' : 'false';
      if (o.value.kind === 'int')  return o.value.val !== 0  ? 'true' : 'false';
      if (o.value.kind === 'str') {
        // JS semantics: "false" / "null" / "undefined" / "NaN" are
        // the string forms of JS-falsy primitives and should resolve
        // to SMT false for boolean-context checks. Non-empty strings
        // are otherwise truthy.
        var sv = o.value.val;
        if (sv === '' || sv === 'false' || sv === 'null' || sv === 'undefined' || sv === 'NaN' || sv === '0') return 'false';
        return 'true';
      }
    }
    if (o.symName) {
      var sort = o.sorts[o.symName] || 'Int';
      if (sort === 'String') {
        // Unknown string sym — check it's not any of the JS-falsy
        // primitive string forms. When combined with a may-be
        // disjunction pinning the sym to a specific value (e.g.
        // "false"), Z3 can refute the bool-context test correctly.
        return '(and (not (= ' + o.expr + ' ""))' +
               ' (not (= ' + o.expr + ' "false"))' +
               ' (not (= ' + o.expr + ' "null"))' +
               ' (not (= ' + o.expr + ' "undefined"))' +
               ' (not (= ' + o.expr + ' "NaN"))' +
               ' (not (= ' + o.expr + ' "0")))';
      }
      return '(not (= ' + o.expr + ' 0))';
    }
    return '(not (= ' + o.expr + ' 0))';
  }

  // Symbol identity tracking. Each symbolic variable name has a stable
  // numeric id used by code that needs to compare symbols structurally.
  var _nextSymId = 0;
  var _symNameMap = Object.create(null);
  function _symIdFor(name) {
    if (name in _symNameMap) return _symNameMap[name];
    var id = _nextSymId++;
    _symNameMap[name] = id;
    return id;
  }

  function smtSym(name) {
    var id = _symIdFor(name);
    var sorts = Object.create(null);
    sorts[name] = 'Int';
    return { expr: _quoteSmtName(name), sorts: sorts, isBool: false, symName: name, symId: id };
  }
  function smtConst(value) {
    if (typeof value === 'boolean') {
      return { expr: value ? 'true' : 'false', sorts: {}, isBool: true, value: { kind: 'bool', val: value } };
    }
    if (typeof value === 'number') {
      var n = value < 0 ? '(- ' + (-value) + ')' : String(value);
      return { expr: n, sorts: {}, isBool: false, value: { kind: 'int', val: value } };
    }
    if (typeof value === 'string') {
      return { expr: _quoteSmtString(value), sorts: {}, isBool: false, value: { kind: 'str', val: value }, stringResult: true };
    }
    return { expr: 'true', sorts: {}, isBool: true, value: { kind: 'bool', val: true } };
  }
  function smtNot(o) {
    if (!o) return null;
    if (o.value && o.value.kind === 'bool') return smtConst(!o.value.val);
    var r = { expr: '(not ' + _toBool(o) + ')', sorts: o.sorts, isBool: true };
    if (o.incompatible) r.incompatible = true;
    return r;
  }
  function smtAnd(a, b) {
    if (!a) return b;
    if (!b) return a;
    if (a.value && a.value.kind === 'bool') return a.value.val ? b : a;
    if (b.value && b.value.kind === 'bool') return b.value.val ? a : b;
    var sorts = _mergeSorts(a.sorts, b.sorts);
    var r = { expr: '(and ' + _toBool(a) + ' ' + _toBool(b) + ')',
              sorts: sorts, isBool: true };
    if (a.incompatible || b.incompatible || sorts.__conflict) r.incompatible = true;
    return r;
  }
  function smtOr(a, b) {
    if (!a) return b;
    if (!b) return a;
    if (a.value && a.value.kind === 'bool') return a.value.val ? a : b;
    if (b.value && b.value.kind === 'bool') return b.value.val ? b : a;
    var sorts = _mergeSorts(a.sorts, b.sorts);
    var r = { expr: '(or ' + _toBool(a) + ' ' + _toBool(b) + ')',
              sorts: sorts, isBool: true };
    if (a.incompatible || b.incompatible || sorts.__conflict) r.incompatible = true;
    return r;
  }
  function smtCmp(op, l, r) {
    if (!l || !r) return null;
    // Compile-time fold for fully-concrete operands. We intentionally
    // do NOT gate this on `l.value.kind === r.value.kind`, because
    // JavaScript's comparison operators are defined for mixed types
    // via well-known coercion rules, and leaving cross-kind compares
    // to flow into the SMT emitter produces sort-mismatched formulas
    // like `(= false "svg")` which Z3 rejects as a parse error.
    //
    // Strict equality (===/!==) requires the kinds to match too, so
    // we short-circuit cross-kind ===/!== to false/true respectively
    // BEFORE letting JS evaluate — `false === "svg"` happens to
    // evaluate to false in JS anyway, but this form is explicit and
    // safe under any future value shape.
    if (l.value && r.value) {
      var lv = l.value.val, rv = r.value.val, ok;
      var sameKind = l.value.kind === r.value.kind;
      switch (op) {
        case '<':  ok = lv < rv; break;
        case '>':  ok = lv > rv; break;
        case '<=': ok = lv <= rv; break;
        case '>=': ok = lv >= rv; break;
        case '==': ok = lv == rv; break;
        case '===': ok = sameKind && lv === rv; break;
        case '!=': ok = lv != rv; break;
        case '!==': ok = !sameKind || lv !== rv; break;
        default: ok = true;
      }
      return smtConst(ok);
    }
    // Sort upgrade: a sym compared with a String-sorted expression
    // becomes String. "String-sorted" covers three cases:
    //   (1) a string literal          -> o.value.kind === 'str'
    //   (2) a sym already declared    -> o.sorts[o.symName] === 'String'
    //   (3) a composite str-theory    -> str.++ / str.substr / str.at
    //       result, detected by the `stringResult` tag set by smtArith
    //       (and the String-literal / String-sym cases also set it).
    // Without case (3), equating `|_expr|` (Int) against a `(str.++ …)`
    // expression left `_expr` declared as Int while the assertion
    // needed it as String — Z3 rejected the formula with a "sorts Int
    // and String are incompatible" parse error.
    var sorts = _mergeSorts(l.sorts, r.sorts);
    var lIsString = _isStringSide(l);
    var rIsString = _isStringSide(r);
    if (l.symName && rIsString) sorts[l.symName] = 'String';
    if (r.symName && lIsString) sorts[r.symName] = 'String';
    var smtOp;
    if (op === '<')  smtOp = '<';
    else if (op === '>')  smtOp = '>';
    else if (op === '<=') smtOp = '<=';
    else if (op === '>=') smtOp = '>=';
    else if (op === '==' || op === '===') smtOp = '=';
    else if (op === '!=' || op === '!==') {
      var rne = { expr: '(not (= ' + l.expr + ' ' + r.expr + '))',
                  sorts: sorts, isBool: true };
      if (l.incompatible || r.incompatible || sorts.__conflict) rne.incompatible = true;
      return rne;
    } else return null;
    var re = { expr: '(' + smtOp + ' ' + l.expr + ' ' + r.expr + ')',
               sorts: sorts, isBool: true };
    if (l.incompatible || r.incompatible || sorts.__conflict) re.incompatible = true;
    return re;
  }
  function smtArith(op, l, r, r2) {
    if (!l || !r) return null;
    // String theory: x.length, x.indexOf(literal), x.charAt(n),
    // x.substring(start,end), x.substr(start,len), x.slice(start,end)
    if (op === 'length' && l.symName) {
      var sortsL = _mergeSorts(l.sorts, null);
      sortsL[l.symName] = 'String';
      return { expr: '(str.len ' + l.expr + ')', sorts: sortsL, isBool: false };
    }
    if (op === 'indexOf' && l.symName) {
      // The needle can be a literal string (r.value) OR another sym
      // (r.symName) — both are valid second args to str.indexof.
      if ((r.value && r.value.kind === 'str') || r.symName) {
        var sortsI = _mergeSorts(l.sorts, null);
        sortsI[l.symName] = 'String';
        if (r.symName) sortsI[r.symName] = 'String';
        return { expr: '(str.indexof ' + l.expr + ' ' + r.expr + ' 0)',
                 sorts: sortsI, isBool: false };
      }
    }
    if (op === 'charAt' && l.symName && r.value && r.value.kind === 'int') {
      var sortsC = _mergeSorts(l.sorts, null);
      sortsC[l.symName] = 'String';
      return { expr: '(str.at ' + l.expr + ' ' + r.expr + ')', sorts: sortsC, isBool: false, stringResult: true };
    }
    if ((op === 'substring' || op === 'substr' || op === 'slice') &&
        l.symName && r.value && r.value.kind === 'int' && r2 && r2.value && r2.value.kind === 'int') {
      var sortsS = _mergeSorts(l.sorts, null);
      sortsS[l.symName] = 'String';
      // JS substring(start, end) and slice(start, end) take a half-open
      // range; SMT-LIB str.substr takes (start, length).
      // substr(start, length) already matches SMT semantics.
      var startV = r.value.val, secondV = r2.value.val;
      var lenV = (op === 'substr') ? secondV : (secondV - startV);
      if (lenV < 0) lenV = 0;
      return { expr: '(str.substr ' + l.expr + ' ' + startV + ' ' + lenV + ')',
               sorts: sortsS, isBool: false, stringResult: true };
    }
    // String concatenation: + with at least one String operand. JS
    // overloads + for both numeric add and string concat; we detect
    // the string variant whenever one side is a string literal (the
    // common pattern \`"prefix" + x\` / \`x + ".html"\`) and translate
    // to (str.++ a b), declaring any sym operand as String.
    if (op === '+') {
      var lIsStr = !!(l.value && l.value.kind === 'str') || (l.symName && l.sorts[l.symName] === 'String');
      var rIsStr = !!(r.value && r.value.kind === 'str') || (r.symName && r.sorts[r.symName] === 'String');
      if (lIsStr || rIsStr) {
        // Const fold.
        if (l.value && l.value.kind === 'str' && r.value && r.value.kind === 'str') {
          return smtConst(l.value.val + r.value.val);
        }
        var sortsCat = _mergeSorts(l.sorts, r.sorts);
        if (l.symName) sortsCat[l.symName] = 'String';
        if (r.symName) sortsCat[r.symName] = 'String';
        var ccIncompat = false;
        if (l.incompatible || r.incompatible || sortsCat.__conflict) ccIncompat = true;
        var rcc = { expr: '(str.++ ' + l.expr + ' ' + r.expr + ')',
                    sorts: sortsCat, isBool: false, stringResult: true };
        if (ccIncompat) rcc.incompatible = true;
        return rcc;
      }
    }
    // Numeric arithmetic.
    if (op === '+' || op === '-' || op === '*' || op === '/' || op === '%') {
      // Const fold.
      if (l.value && l.value.kind === 'int' && r.value && r.value.kind === 'int') {
        switch (op) {
          case '+': return smtConst(l.value.val + r.value.val);
          case '-': return smtConst(l.value.val - r.value.val);
          case '*': return smtConst(l.value.val * r.value.val);
          case '/': if (r.value.val !== 0) return smtConst(l.value.val / r.value.val); break;
          case '%': if (r.value.val !== 0) return smtConst(l.value.val % r.value.val); break;
        }
      }
      // Sort check: numeric arith requires Int operands. If either side
      // has a sym already declared as String (from a prior cmp/strProp),
      // the formula is untranslatable.
      var arithIncompat = false;
      if (l.symName && l.sorts[l.symName] === 'String') arithIncompat = true;
      if (r.symName && r.sorts[r.symName] === 'String') arithIncompat = true;
      if (l.incompatible || r.incompatible) arithIncompat = true;
      var smtOp = op === '/' ? 'div' : op === '%' ? 'mod' : op;
      var sortsA = _mergeSorts(l.sorts, r.sorts);
      if (sortsA.__conflict) arithIncompat = true;
      var ra = { expr: '(' + smtOp + ' ' + l.expr + ' ' + r.expr + ')',
                 sorts: sortsA, isBool: false };
      if (arithIncompat) ra.incompatible = true;
      return ra;
    }
    return null;
  }
  // String predicates: startsWith / endsWith / includes. `symObj` is a
  // smtSym() result; `value` is the literal substring.
  // smtStrProp builds startsWith / endsWith / includes constraints.
  // The needle (`value`) can be either a literal string OR another sym
  // formula object — both spell to the same Z3 string-theory primitives,
  // and both syms get declared as String.
  function smtStrProp(symObj, prop, value) {
    if (!symObj || !symObj.symName) return null;
    var sorts = _mergeSorts(symObj.sorts, null);
    sorts[symObj.symName] = 'String';
    var v;
    if (typeof value === 'string') {
      v = _quoteSmtString(value);
    } else if (value && value.symName) {
      v = value.expr;
      sorts = _mergeSorts(sorts, value.sorts);
      sorts[value.symName] = 'String';
    } else {
      return null;
    }
    if (prop === 'startsWith') return { expr: '(str.prefixof ' + v + ' ' + symObj.expr + ')', sorts: sorts, isBool: true };
    if (prop === 'endsWith')   return { expr: '(str.suffixof ' + v + ' ' + symObj.expr + ')', sorts: sorts, isBool: true };
    if (prop === 'includes')   return { expr: '(str.contains ' + symObj.expr + ' ' + v + ')', sorts: sorts, isBool: true };
    return null;
  }

  function smtHasSym(o) {
    if (!o || !o.sorts) return false;
    for (var k in o.sorts) return true;
    return false;
  }

  // --- Z3 initialisation (mandatory; no fallback) ---
  // smtSat awaits this once; afterwards Z3 is a cached shared Context.
  //
  // Three loading paths, tried in order:
  //
  //   1. `globalThis.__htmldomZ3Init` — a pre-registered init
  //      function. This is the normal browser path: the page
  //      loads `jsanalyze-z3-browser.js` before `jsanalyze.js`,
  //      and that bootstrap file registers a lazy loader that
  //      knows how to pull z3-built.js + browser.esm.js from the
  //      vendored `htmldom/vendor/z3-solver/` directory. Using
  //      this hook keeps jsanalyze.js browser-agnostic — no DOM
  //      APIs, no dynamic imports, no CSP assumptions.
  //
  //   2. Node's `require('z3-solver')` — the test harness and
  //      any CommonJS consumer that runs under Node. Detection
  //      is strict: `window === undefined && module.exports &&
  //      require === function`. Monaco's AMD loader defines
  //      `require` but not `window === undefined`, so this
  //      branch doesn't match under Monaco.
  //
  //   3. Error — neither path was set up. Emit a clear message
  //      so the consumer knows to load jsanalyze-z3-browser.js
  //      first (browser) or install z3-solver (Node).
  var _z3 = null;
  var _z3Promise = null;
  function _initZ3() {
    if (_z3Promise) return _z3Promise;
    _z3Promise = (async function () {
      var initFn = null;
      if (typeof globalThis !== 'undefined' && typeof globalThis.__htmldomZ3Init === 'function') {
        initFn = globalThis.__htmldomZ3Init;
      } else if (typeof window === 'undefined' && typeof module === 'object' && module && module.exports && typeof require === 'function') {
        var mod = require('z3-solver');
        initFn = mod.init;
      } else {
        throw new Error(
          'jsanalyze: Z3 is not available. In the browser, load ' +
          'htmldom/jsanalyze-z3-browser.js before jsanalyze.js. ' +
          'In Node, ensure z3-solver is installed.'
        );
      }
      var api = await initFn();
      var ctx = api.Context('htmldom');
      _z3 = { api: api, Context: ctx, Solver: ctx.Solver };
      return _z3;
    })();
    return _z3Promise;
  }

  // --- Main satisfiability checker (Z3) ---
  // Every formula goes through Z3. There is no fallback solver.
  // The formula is already in SMT-LIB form (built by the smt* helpers
  // above); smtSat just emits the necessary `(declare-const ...)` lines
  // from `formula.sorts`, asserts `formula` (coerced to Bool), and asks
  // Z3 to check satisfiability.
  // Per-walk may-be lattice. buildScopeState sets these to its own
  // _varMayBe map and _mayBeKey resolver for the duration of phase 1 +
  // phase 2 walks; smtSat reads them when emitting extra
  // (or (= sym v1) (= sym v2) ...) constraints for variables whose
  // value space is fully enumerated. _currentMayBeKey normalises
  // textual paths to identity-keyed canonical form so aliases of the
  // same object look up the same lattice slot.
  var _currentVarMayBe = null;
  var _currentMayBeKey = null;

  // --- Memoization + solver reuse + persistent declarations ---
  //
  // Each walker pass issues many smtSat calls with overlapping or
  // identical formulas. Without help, each call would repeat the
  // full Z3 round-trip: declare every symbol, re-parse the formula,
  // run the solver. The walker is dominated by SMT wall time on any
  // non-trivial file, so we layer three defenses on top of every
  // call:
  //
  //   1. `_smtCache` — a Map keyed by the exact SMT-LIB source
  //      string. Every smtSat call checks the cache before touching
  //      Z3. The cache is UNBOUNDED — entries are never evicted —
  //      because the analyser must never skip a query or pay for a
  //      re-run of a query it has already answered. On real programs
  //      the distinct-formula count is small relative to total call
  //      count, so the cache stays a moderate size even for large
  //      files.
  //
  //   2. `_sharedSolver` — one Solver per Z3 context, isolated via
  //      push()/pop() between calls instead of `new z3.Solver()`.
  //      Stops Solver-level state from accumulating and avoids both
  //      the per-call allocation of fresh solver objects AND the
  //      cost of re-declaring every symbol on every call.
  //
  //   3. `_declaredSorts` — a Map of `<symName> -> <sortName>`
  //      remembering which symbols have already been declared on
  //      `_sharedSolver`. Z3's `(declare-const)` is permanent at the
  //      solver level: once a symbol is declared we can keep using
  //      it until the solver is destroyed. By emitting declarations
  //      ONCE per symbol (instead of once per call), every smtSat
  //      call past the first only has to feed Z3 the may-be lattice
  //      extras + the actual assertion — the heavy lifting of
  //      symbol-table setup is amortised across the whole walk. On
  //      htmldom-convert.js this turns ~700 redeclarations of the
  //      same handful of symbols into ~10 one-time declarations.
  var _smtCache = new Map();
  var _sharedSolver = null;
  var _declaredSorts = new Map();

  async function smtSat(formula) {
    if (!formula) return true;
    // Compile-time fold for fully-concrete results.
    if (formula.value && formula.value.kind === 'bool') return formula.value.val;
    // Untranslatable formulas (sort conflicts the Z3 type system can't
    // represent — e.g. a sym used as both Int and String) are
    // conservatively reported as satisfiable: we don't know enough to
    // refute the branch.
    if (formula.incompatible) return true;

    // Walk the formula's sort table to figure out which symbols need
    // to be declared on the solver, and which ones need a may-be
    // disjunction emitted into the formula's local push() frame.
    //
    // `pendingDecls`  — declarations to emit ONCE on the persistent
    //                   solver (outside any push frame). Empty most
    //                   of the time, since most syms have already
    //                   been declared by an earlier smtSat call.
    // `extras`        — may-be lattice constraints, emitted INSIDE
    //                   the push frame so they don't leak into
    //                   subsequent calls (the lattice can grow
    //                   monotonically over the walk so today's
    //                   emitted may-be might be tomorrow's stale).
    var pendingDecls = '';
    var extras = '';
    for (var name in formula.sorts) {
      if (name === '__conflict') continue;
      var sort = formula.sorts[name] || 'Int';
      var alreadyDeclared = _declaredSorts.get(name);
      if (alreadyDeclared !== sort) {
        // Either undeclared, or previously declared at a different
        // sort (rare but possible — the walker can upgrade an Int
        // sym to String mid-walk when it learns about a new use).
        // The solver doesn't let us "redeclare" so we'd have to
        // reset the entire solver state if the sort actually
        // changed. To keep things simple AND correct we fall back
        // to the legacy reset+fromString path on sort change. New
        // declarations otherwise just append.
        if (alreadyDeclared && alreadyDeclared !== sort) {
          return await _smtSatFullReset(formula);
        }
        pendingDecls += '(declare-const ' + _quoteSmtName(name) + ' ' + sort + ')\n';
      }
      // Emit a may-be disjunction if the variable's value space is
      // fully enumerated (every assignment was a literal we could
      // encode). The disjunction tells Z3 the sym CAN ONLY equal one
      // of these specific values, which lets it refute paths
      // requiring any other value — even when the values were set
      // in a different callback / branch / loop iteration.
      if (_currentVarMayBe) {
        // Resolve the lookup key to its identity-canonical form so
        // aliases of the same object hit the same slot.
        var lookupKey = _currentMayBeKey ? _currentMayBeKey(name) : name;
        var slot = _currentVarMayBe[lookupKey];
        // Emit a may-be disjunction (or `(= sym v)` for single-value
        // slots) whenever the lattice has at least one concrete value.
        // Single-value slots still pin the sym to a specific literal,
        // which lets refutations fire when the current binding is an
        // opaque post-loop / post-if synthetic value but the lattice
        // still records the single literal actually held.
        if (slot && slot.complete && slot.vals && slot.vals.length >= 1) {
          // Only emit when the recorded sort matches the formula sort
          // (mixing Int and String literals on the same symbol would
          // produce a sort-mismatched disjunction).
          var sortOk = true;
          for (var _vi = 0; _vi < slot.vals.length; _vi++) {
            if (slot.vals[_vi].sort !== sort) { sortOk = false; break; }
          }
          if (sortOk) {
            if (slot.vals.length === 1) {
              extras += '(assert (= ' + _quoteSmtName(name) + ' ' + slot.vals[0].lit + '))\n';
            } else {
              var lits = [];
              for (var _vj = 0; _vj < slot.vals.length; _vj++) {
                lits.push('(= ' + _quoteSmtName(name) + ' ' + slot.vals[_vj].lit + ')');
              }
              extras += '(assert (or ' + lits.join(' ') + '))\n';
            }
          }
        }
      }
    }
    var assertText = '(assert ' + _toBool(formula) + ')\n';
    // The cache key combines the may-be extras and the assertion;
    // pendingDecls is a function of which syms have been declared
    // already, which is determined by the order of prior smtSat
    // calls — not by the formula's semantics — so we exclude it
    // from the cache key. Two formulas with identical extras +
    // assertText have the same satisfiability regardless of which
    // declarations the solver had pre-loaded.
    var cacheKey = extras + assertText;

    // Layer 1: memoization cache (unbounded).
    if (_smtCache.has(cacheKey)) return _smtCache.get(cacheKey);

    var z3 = await _initZ3();

    // Layer 2: reuse one Solver across calls. The solver is created
    // once per Z3 context and persists for the rest of the analysis.
    if (!_sharedSolver) _sharedSolver = new z3.Solver();

    // Layer 3: emit any new declarations ONCE on the persistent
    // solver so they survive every push/pop. Declarations are
    // permanent at the solver level — Z3's symbol table can be
    // appended to but never restored — which is exactly what we
    // want here.
    if (pendingDecls) {
      _sharedSolver.fromString(pendingDecls);
      for (var pname in formula.sorts) {
        if (pname === '__conflict') continue;
        var psort = formula.sorts[pname] || 'Int';
        if (_declaredSorts.get(pname) !== psort) _declaredSorts.set(pname, psort);
      }
    }

    // Push an isolation frame so the may-be extras and the formula
    // assertion don't leak into the next smtSat call. After check(),
    // pop() restores the solver to its pre-call state.
    _sharedSolver.push();
    if (extras) _sharedSolver.fromString(extras);
    _sharedSolver.fromString(assertText);
    var result = await _sharedSolver.check();
    _sharedSolver.pop();

    var answer = result !== 'unsat';
    _smtCache.set(cacheKey, answer);
    return answer;
  }

  // Slow-path fallback for the rare case where a symbol's sort
  // changed mid-walk (e.g. an Int sym got upgraded to String after
  // the walker discovered a string-context use). The solver-level
  // declaration is permanent in Z3, so when a sort actually changes
  // we have to discard the entire solver state and start fresh.
  // The formula's may-be extras + assertion are then added inside a
  // push/pop frame so they don't leak into the NEXT smtSat call —
  // exactly the same isolation regime smtSat itself uses on the
  // hot path. Without the push/pop here, the test suite would see
  // the previous reset's formula remain permanently asserted and
  // every subsequent call would silently incorporate it into its
  // satisfiability check.
  //
  // The fresh solver is left as `_sharedSolver` so subsequent calls
  // can keep amortising declarations against it.
  async function _smtSatFullReset(formula) {
    var z3 = await _initZ3();
    _sharedSolver = new z3.Solver();
    _declaredSorts.clear();
    var decls = '';
    var extras = '';
    for (var name in formula.sorts) {
      if (name === '__conflict') continue;
      var sort = formula.sorts[name] || 'Int';
      decls += '(declare-const ' + _quoteSmtName(name) + ' ' + sort + ')\n';
      _declaredSorts.set(name, sort);
      if (_currentVarMayBe) {
        var lookupKey = _currentMayBeKey ? _currentMayBeKey(name) : name;
        var slot = _currentVarMayBe[lookupKey];
        if (slot && slot.complete && slot.vals && slot.vals.length >= 1) {
          var sortOk = true;
          for (var _vi = 0; _vi < slot.vals.length; _vi++) {
            if (slot.vals[_vi].sort !== sort) { sortOk = false; break; }
          }
          if (sortOk) {
            if (slot.vals.length === 1) {
              extras += '(assert (= ' + _quoteSmtName(name) + ' ' + slot.vals[0].lit + '))\n';
            } else {
              var lits = [];
              for (var _vj = 0; _vj < slot.vals.length; _vj++) {
                lits.push('(= ' + _quoteSmtName(name) + ' ' + slot.vals[_vj].lit + ')');
              }
              extras += '(assert (or ' + lits.join(' ') + '))\n';
            }
          }
        }
      }
    }
    // Declarations live at level 0 (permanent on the new solver).
    if (decls) _sharedSolver.fromString(decls);
    // Push an isolation frame for the may-be extras and the formula
    // assertion — same pattern as smtSat's hot path.
    _sharedSolver.push();
    var assertText = '(assert ' + _toBool(formula) + ')\n';
    if (extras) _sharedSolver.fromString(extras);
    _sharedSolver.fromString(assertText);
    var result = await _sharedSolver.check();
    _sharedSolver.pop();
    var answer = result !== 'unsat';
    _smtCache.set(extras + assertText, answer);
    return answer;
  }
  // --- Condition parser: raw JS tokens → SMT formula ---
  // Operator precedence: || < && < comparisons < atoms
  var _cmpOps = { '<':1, '>':1, '<=':1, '>=':1, '==':1, '!=':1, '===':1, '!==':1 };

  async function smtParseExpr(toks, start, end, resolveFunc, resolvePathFunc) {
    if (start >= end) return null;
    // Find lowest-precedence binary operator at depth 0.
    // Precedence (low→high): || < && < comparisons < +/- < */% < atoms
    var d = 0, lastOr = -1, lastAnd = -1, lastCmp = -1, lastCmpOp = null;
    var lastAdd = -1, lastAddOp = null, lastMul = -1, lastMulOp = null;
    for (var i = start; i < end; i++) {
      if (toks[i].type === 'open') d++;
      if (toks[i].type === 'close') d--;
      if (d !== 0) continue;
      var tt = toks[i].text;
      if (toks[i].type === 'op' && tt === '||') lastOr = i;
      else if (toks[i].type === 'op' && tt === '&&') lastAnd = i;
      else if (toks[i].type === 'op' && _cmpOps[tt]) { lastCmp = i; lastCmpOp = tt; }
      else if ((toks[i].type === 'op' && (tt === '-')) || (toks[i].type === 'plus')) { lastAdd = i; lastAddOp = tt === '-' ? '-' : '+'; }
      else if (toks[i].type === 'op' && (tt === '*' || tt === '/' || tt === '%')) { lastMul = i; lastMulOp = tt; }
    }
    if (lastOr >= 0) return smtOr(await smtParseExpr(toks, start, lastOr, resolveFunc, resolvePathFunc), await smtParseExpr(toks, lastOr + 1, end, resolveFunc, resolvePathFunc));
    if (lastAnd >= 0) return smtAnd(await smtParseExpr(toks, start, lastAnd, resolveFunc, resolvePathFunc), await smtParseExpr(toks, lastAnd + 1, end, resolveFunc, resolvePathFunc));
    if (lastCmp >= 0) {
      var cl = await smtParseExpr(toks, start, lastCmp, resolveFunc, resolvePathFunc);
      var cr = await smtParseExpr(toks, lastCmp + 1, end, resolveFunc, resolvePathFunc);
      return (cl && cr) ? smtCmp(lastCmpOp, cl, cr) : null;
    }
    if (lastAdd >= 0) {
      var al = await smtParseExpr(toks, start, lastAdd, resolveFunc, resolvePathFunc);
      var ar = await smtParseExpr(toks, lastAdd + 1, end, resolveFunc, resolvePathFunc);
      if (al && ar) return smtArith(lastAddOp, al, ar);
    }
    if (lastMul >= 0) {
      var ml = await smtParseExpr(toks, start, lastMul, resolveFunc, resolvePathFunc);
      var mr = await smtParseExpr(toks, lastMul + 1, end, resolveFunc, resolvePathFunc);
      if (ml && mr) return smtArith(lastMulOp, ml, mr);
    }
    return await smtParseAtom(toks, start, end, resolveFunc, resolvePathFunc);
  }

  async function smtParseAtom(toks, start, end, resolveFunc, resolvePathFunc) {
    if (start >= end) return null;
    // NOT prefix.
    if (toks[start].type === 'op' && toks[start].text === '!') {
      var inner = await smtParseAtom(toks, start + 1, end, resolveFunc, resolvePathFunc);
      return inner ? smtNot(inner) : null;
    }
    // Parenthesized.
    if (toks[start].type === 'open' && toks[start].char === '(') {
      var d2 = 1, j2 = start + 1;
      while (j2 < end && d2 > 0) { if (toks[j2].type === 'open') d2++; if (toks[j2].type === 'close') d2--; j2++; }
      return await smtParseExpr(toks, start + 1, j2 - 1, resolveFunc, resolvePathFunc);
    }
    // Single token.
    if (end === start + 1) {
      var t = toks[start];
      // String literal.
      if (t.type === 'str') return smtConst(t.text);
      if (t.type === 'other') {
        // JS constants.
        if (t.text === 'true') return smtConst(true);
        if (t.text === 'false') return smtConst(false);
        if (t.text === 'null' || t.text === 'undefined') return smtConst(false);
        if (/^\d+(\.\d+)?$/.test(t.text)) return smtConst(Number(t.text));
        // Identifier: check if symbolic (tainted / event-modified).
        var root = t.text.split('.')[0];
        if (IDENT_RE.test(root)) {
          var rb = await resolveFunc(root);
          if (rb) {
            // Check root binding for taint (recursive into arrays/objects).
            var _hasTaint = function(b) {
              if (!b) return false;
              if (b.kind === 'chain') return !!collectChainTaint(b.toks);
              if (b.kind === 'array') { for (var e = 0; e < b.elems.length; e++) if (_hasTaint(b.elems[e])) return true; }
              if (b.kind === 'object') { for (var k in b.props) if (_hasTaint(b.props[k])) return true; }
              return false;
            };
            if (_hasTaint(rb)) {
              // Resolve aliases: if the binding is a single opaque ref to
              // another expression, use that expression as the symbolic name.
              // This unifies x and y when y = x.
              var _symName = t.text;
              if (rb.kind === 'chain' && rb.toks.length === 1 && rb.toks[0].type === 'other') {
                _symName = rb.toks[0].text;
              }
              if (_symName.endsWith('.length') || t.text.endsWith('.length')) return smtArith('length', smtSym(_symName.replace(/\.length$/, '')), smtConst(0));
              return smtSym(_symName);
            }
          }
          // Resolve full path to concrete value.
          var fb = await resolvePathFunc(t.text);
          if (fb && fb.kind === 'chain' && fb.toks.length === 1 && fb.toks[0].type === 'str') {
            // Before folding to a single concrete value, check the
            // may-be lattice. If the variable has been assigned more
            // than one distinct literal across the analyzed program
            // (e.g. set in two different callbacks), DON'T fold to
            // the current value — return a sym so smtSat emits the
            // (or (= sym v1) (= sym v2) …) disjunction over the full
            // value space. Without this, the SMT layer would only
            // see whichever value happened to be most-recently
            // assigned in source order, missing branches that depend
            // on other values in the may-be set.
            var _mbKey = _currentMayBeKey ? _currentMayBeKey(t.text) : t.text;
            var _mbSlot = _currentVarMayBe ? _currentVarMayBe[_mbKey] : null;
            if (_mbSlot && _mbSlot.complete && _mbSlot.vals && _mbSlot.vals.length > 1) {
              // Use the canonical identity-keyed name as the symbol so
              // smtSat looks up the same slot when emitting the
              // disjunction extras. Tag with the lattice's declared
              // sort so smtSat emits the disjunction (String lattice
              // + Int-defaulted sym would otherwise silently drop
              // the disjunction).
              var _mbSym = smtSym(_mbKey);
              var _mbSortVal = _mbSlot.vals[0].sort;
              var _mbAllSame = true;
              for (var _mvi = 1; _mvi < _mbSlot.vals.length; _mvi++) {
                if (_mbSlot.vals[_mvi].sort !== _mbSortVal) { _mbAllSame = false; break; }
              }
              if (_mbAllSame) _mbSym.sorts[_mbKey] = _mbSortVal;
              return _mbSym;
            }
            var fv = fb.toks[0].text;
            if (fv === 'true') return smtConst(true);
            if (fv === 'false' || fv === 'null' || fv === 'undefined' || fv === '') return smtConst(false);
            var nv = Number(fv);
            if (!Number.isNaN(nv)) return smtConst(nv);
            return smtConst(fv);
          }
          // Binding is a multi-token chain (e.g. a cond / trycatch /
          // switchjoin merge) or a non-chain — not a concrete fold
          // target. Consult the may-be lattice and use its stored
          // sort for the resulting sym so disjunctions fire. This is
          // what makes `var s = "init"; if (c) s="a"; else s="b";`
          // followed by `if (s==="ready") ...` refute: after the
          // merge, fb is a cond chain, so the fold path above skips
          // it, but the lattice still contains "init"/"a"/"b".
          var _mbKey2 = _currentMayBeKey ? _currentMayBeKey(t.text) : t.text;
          var _mbSlot2 = _currentVarMayBe ? _currentVarMayBe[_mbKey2] : null;
          if (_mbSlot2 && _mbSlot2.complete && _mbSlot2.vals && _mbSlot2.vals.length > 0) {
            var _mbSym2 = smtSym(_mbKey2);
            var _mbSortVal2 = _mbSlot2.vals[0].sort;
            var _mbAllSame2 = true;
            for (var _mvi2 = 1; _mvi2 < _mbSlot2.vals.length; _mvi2++) {
              if (_mbSlot2.vals[_mvi2].sort !== _mbSortVal2) { _mbAllSame2 = false; break; }
            }
            if (_mbAllSame2) _mbSym2.sorts[_mbKey2] = _mbSortVal2;
            return _mbSym2;
          }
        }
        return smtSym(t.text);
      }
    }
    // Multi-token: detect method calls like x.startsWith("str"), x.indexOf("str").
    // Pattern: IDENT_PATH ( ARG )
    if (end >= start + 3 && toks[start].type === 'other' && toks[start + 1].type === 'open' && toks[start + 1].char === '(') {
      var _mPath = toks[start].text;
      var _mDot = _mPath.lastIndexOf('.');
      if (_mDot > 0) {
        var _mBase = _mPath.slice(0, _mDot);
        var _mMethod = _mPath.slice(_mDot + 1);
        // Resolve the base to check if it's symbolic.
        var _mRoot = _mBase.split('.')[0];
        var _mRb = await resolveFunc(_mRoot);
        var _mIsSym = false;
        if (_mRb) {
          var _ht = function(b) { if (!b) return false; if (b.kind==='chain') return !!collectChainTaint(b.toks); if (b.kind==='array') { for (var e=0;e<b.elems.length;e++) if (_ht(b.elems[e])) return true; } if (b.kind==='object') { for (var k in b.props) if (_ht(b.props[k])) return true; } return false; };
          _mIsSym = _ht(_mRb);
        }
        if (_mIsSym) {
          // Resolve aliases for consistent symbolic ID.
          var _mResolvedBase = _mBase;
          if (_mRb && _mRb.kind === 'chain' && _mRb.toks.length === 1 && _mRb.toks[0].type === 'other') _mResolvedBase = _mRb.toks[0].text;
          var _mSymObj = smtSym(_mResolvedBase);
          // Single-string-literal arg: startsWith / endsWith / includes / indexOf
          var _mArgTok = toks[start + 2];
          var _mArgVal = null;
          if (_mArgTok && _mArgTok.type === 'str' && toks[start + 3] && toks[start + 3].type === 'close') {
            _mArgVal = _mArgTok.text;
          }
          if (_mMethod === 'startsWith' && _mArgVal !== null) return smtStrProp(_mSymObj, 'startsWith', _mArgVal);
          if (_mMethod === 'endsWith' && _mArgVal !== null) return smtStrProp(_mSymObj, 'endsWith', _mArgVal);
          if (_mMethod === 'includes' && _mArgVal !== null) return smtStrProp(_mSymObj, 'includes', _mArgVal);
          if (_mMethod === 'indexOf' && _mArgVal !== null) return smtArith('indexOf', _mSymObj, smtConst(_mArgVal));
          // indexOf / startsWith / endsWith / includes with an IDENT
          // second arg — the needle is itself another (potentially
          // tainted) sym. Recursively parse the identifier and emit
          // the corresponding string-theory predicate.
          if ((_mMethod === 'indexOf' || _mMethod === 'startsWith' || _mMethod === 'endsWith' || _mMethod === 'includes') &&
              _mArgTok && _mArgTok.type === 'other' && IDENT_RE.test(_mArgTok.text) && toks[start + 3] && toks[start + 3].type === 'close') {
            var _needleParsed = await smtParseAtom([_mArgTok], 0, 1, resolveFunc, resolvePathFunc);
            if (_needleParsed && _needleParsed.symName) {
              if (_mMethod === 'indexOf') return smtArith('indexOf', _mSymObj, _needleParsed);
              return smtStrProp(_mSymObj, _mMethod, _needleParsed);
            }
          }
          // Single-int-literal arg: charAt(N) → (str.at sym N)
          var _mIntArg = null;
          if (_mArgTok && _mArgTok.type === 'other' && /^-?\d+$/.test(_mArgTok.text) && toks[start + 3] && toks[start + 3].type === 'close') {
            _mIntArg = parseInt(_mArgTok.text, 10);
          }
          if (_mMethod === 'charAt' && _mIntArg !== null) return smtArith('charAt', _mSymObj, smtConst(_mIntArg));
          // Two-int-literal args: substring(START, END), substr(START, LEN), slice(START, END)
          if ((_mMethod === 'substring' || _mMethod === 'substr' || _mMethod === 'slice') &&
              _mArgTok && _mArgTok.type === 'other' && /^-?\d+$/.test(_mArgTok.text) &&
              toks[start + 3] && toks[start + 3].type === 'sep' && toks[start + 3].char === ',' &&
              toks[start + 4] && toks[start + 4].type === 'other' && /^-?\d+$/.test(toks[start + 4].text) &&
              toks[start + 5] && toks[start + 5].type === 'close') {
            var _mA0 = parseInt(_mArgTok.text, 10);
            var _mA1 = parseInt(toks[start + 4].text, 10);
            return smtArith(_mMethod, _mSymObj, smtConst(_mA0), smtConst(_mA1));
          }
          // .length is a property, not a method call.
        }
      }
    }
    // Pattern: IDENT[NUM] — bracket index access. Equivalent to charAt
    // for strings. Example: x[0] === "/" becomes (str.at |x| 0).
    if (end >= start + 4 &&
        toks[start].type === 'other' &&
        toks[start + 1].type === 'open' && toks[start + 1].char === '[' &&
        toks[start + 2].type === 'other' && /^-?\d+$/.test(toks[start + 2].text) &&
        toks[start + 3].type === 'close' && toks[start + 3].char === ']') {
      var _bxBase = toks[start].text;
      var _bxRoot = _bxBase.split('.')[0];
      var _bxRb = await resolveFunc(_bxRoot);
      if (_bxRb) {
        var _bxht = function(b) { if (!b) return false; if (b.kind==='chain') return !!collectChainTaint(b.toks); if (b.kind==='array') { for (var e=0;e<b.elems.length;e++) if (_bxht(b.elems[e])) return true; } if (b.kind==='object') { for (var k in b.props) if (_bxht(b.props[k])) return true; } return false; };
        if (_bxht(_bxRb)) {
          var _bxResolved = _bxBase;
          if (_bxRb.kind === 'chain' && _bxRb.toks.length === 1 && _bxRb.toks[0].type === 'other') _bxResolved = _bxRb.toks[0].text;
          var _bxIdx = parseInt(toks[start + 2].text, 10);
          return smtArith('charAt', smtSym(_bxResolved), smtConst(_bxIdx));
        }
      }
    }
    // Pattern: IDENT.length — property access without call.
    if (end === start + 1 && toks[start].type === 'other' && toks[start].text.endsWith('.length')) {
      var _lBase = toks[start].text.slice(0, -7);
      var _lRoot = _lBase.split('.')[0];
      var _lRb = await resolveFunc(_lRoot);
      if (_lRb) {
        var _lt = function(b) { if (!b) return false; if (b.kind==='chain') return !!collectChainTaint(b.toks); if (b.kind==='array') { for (var e=0;e<b.elems.length;e++) if (_lt(b.elems[e])) return true; } if (b.kind==='object') { for (var k in b.props) if (_lt(b.props[k])) return true; } return false; };
        if (_lt(_lRb)) return smtArith('length', smtSym(_lBase), smtConst(0));
      }
    }
    return smtSym('_expr');
  }

  // --- Integration: check condition satisfiability ---
  // condTokens: raw JS tokens of the condition expression
  // pathConstraintStack: array of SMT formulas from enclosing branches
  // Returns { sat, unsat } or null if purely concrete.
  //
  // The two queries (`pathConj ∧ formula` and `pathConj ∧ ¬formula`)
  // share the entire path setup — same declarations, same may-be
  // lattice extras, same path conjunction. We exploit that by
  // routing both queries through `smtCheckBoth`, which parses the
  // path on the solver ONCE inside a shared push() frame and only
  // pushes the formula's assertion individually for each polarity.
  // The walker still gets a `{ sat, unsat }` result back, but the
  // Z3 round-trip cost drops from ~2× the parse work to ~1×.
  async function smtCheckCondition(condTokens, resolveFunc, resolvePathFunc, pathConstraintStack) {
    var formula = await smtParseExpr(condTokens, 0, condTokens.length, resolveFunc, resolvePathFunc);
    if (!formula) return null;
    var pathConj = null;
    if (pathConstraintStack && pathConstraintStack.length > 0) {
      pathConj = pathConstraintStack[0];
      for (var i = 1; i < pathConstraintStack.length; i++) {
        pathConj = smtAnd(pathConj, pathConstraintStack[i]);
      }
    }
    return await smtCheckBoth(pathConj, formula);
  }

  // Run a sat-and-unsat reachability check against `formula` under
  // optional `pathConj`, sharing the path setup between the two
  // Z3 round-trips. Returns `{ sat, unsat }` where `sat` is true
  // when `pathConj ∧ formula` is satisfiable (true branch reachable)
  // and `unsat` is true when `pathConj ∧ ¬formula` is satisfiable
  // (false branch reachable).
  //
  // Cache short-circuiting: each polarity's result is independently
  // memoised in `_smtCache` under the same `extras + assertText` key
  // smtSat uses, so a previously-seen check skips Z3 entirely. The
  // batched solver path is only entered when at least one polarity
  // is a cache miss.
  async function smtCheckBoth(pathConj, formula) {
    var contextSat, contextUnsat;
    if (pathConj) {
      contextSat = smtAnd(pathConj, formula);
      contextUnsat = smtAnd(pathConj, smtNot(formula));
    } else {
      contextSat = formula;
      contextUnsat = smtNot(formula);
    }
    // Compile-time fold on either side short-circuits the whole
    // batch. `smtSat` already does this fold for individual calls,
    // so we delegate to it whenever the heavyweight batched path
    // can't actually save work.
    if (!contextSat || (contextSat.value && contextSat.value.kind === 'bool')
        || contextSat.incompatible) {
      var sat0 = await smtSat(contextSat);
      var unsat0 = await smtSat(contextUnsat);
      return { sat: sat0, unsat: unsat0 };
    }
    if (!contextUnsat || (contextUnsat.value && contextUnsat.value.kind === 'bool')
        || contextUnsat.incompatible) {
      var sat1 = await smtSat(contextSat);
      var unsat1 = await smtSat(contextUnsat);
      return { sat: sat1, unsat: unsat1 };
    }
    // Build the per-polarity SMT-LIB expression text and cache key
    // exactly the way smtSat would, so cache lookups stay aligned
    // with all the existing memoization.
    var mergedSorts = contextSat.sorts; // both polarities share sorts
    var pendingDecls = '';
    var extras = '';
    for (var name in mergedSorts) {
      if (name === '__conflict') continue;
      var sort = mergedSorts[name] || 'Int';
      var alreadyDeclared = _declaredSorts.get(name);
      if (alreadyDeclared !== sort) {
        if (alreadyDeclared && alreadyDeclared !== sort) {
          // Sort upgrade: fall back to per-call smtSat (which itself
          // routes through _smtSatFullReset). Rare path.
          var sat2 = await smtSat(contextSat);
          var unsat2 = await smtSat(contextUnsat);
          return { sat: sat2, unsat: unsat2 };
        }
        pendingDecls += '(declare-const ' + _quoteSmtName(name) + ' ' + sort + ')\n';
      }
      if (_currentVarMayBe) {
        var lookupKey = _currentMayBeKey ? _currentMayBeKey(name) : name;
        var slot = _currentVarMayBe[lookupKey];
        if (slot && slot.complete && slot.vals && slot.vals.length >= 1) {
          var sortOk = true;
          for (var _vi = 0; _vi < slot.vals.length; _vi++) {
            if (slot.vals[_vi].sort !== sort) { sortOk = false; break; }
          }
          if (sortOk) {
            if (slot.vals.length === 1) {
              extras += '(assert (= ' + _quoteSmtName(name) + ' ' + slot.vals[0].lit + '))\n';
            } else {
              var lits = [];
              for (var _vj = 0; _vj < slot.vals.length; _vj++) {
                lits.push('(= ' + _quoteSmtName(name) + ' ' + slot.vals[_vj].lit + ')');
              }
              extras += '(assert (or ' + lits.join(' ') + '))\n';
            }
          }
        }
      }
    }
    var satAssertText = '(assert ' + _toBool(contextSat) + ')\n';
    var unsatAssertText = '(assert ' + _toBool(contextUnsat) + ')\n';
    var satKey = extras + satAssertText;
    var unsatKey = extras + unsatAssertText;

    var satCached = _smtCache.has(satKey);
    var unsatCached = _smtCache.has(unsatKey);
    if (satCached && unsatCached) {
      return { sat: _smtCache.get(satKey), unsat: _smtCache.get(unsatKey) };
    }

    // At least one polarity is a cache miss — go to Z3, sharing the
    // path setup between both checks.
    var z3 = await _initZ3();
    if (!_sharedSolver) _sharedSolver = new z3.Solver();
    if (pendingDecls) {
      _sharedSolver.fromString(pendingDecls);
      for (var pname in mergedSorts) {
        if (pname === '__conflict') continue;
        var psort = mergedSorts[pname] || 'Int';
        if (_declaredSorts.get(pname) !== psort) _declaredSorts.set(pname, psort);
      }
    }
    // Path frame: declarations stay at level 0; the may-be extras
    // and the formula assertions live in this push so they get
    // cleaned up at the end.
    _sharedSolver.push();
    if (extras) _sharedSolver.fromString(extras);

    var satResult, unsatResult;
    if (satCached) {
      satResult = _smtCache.get(satKey);
    } else {
      _sharedSolver.push();
      _sharedSolver.fromString(satAssertText);
      satResult = (await _sharedSolver.check()) !== 'unsat';
      _sharedSolver.pop();
      _smtCache.set(satKey, satResult);
    }
    if (unsatCached) {
      unsatResult = _smtCache.get(unsatKey);
    } else {
      _sharedSolver.push();
      _sharedSolver.fromString(unsatAssertText);
      unsatResult = (await _sharedSolver.check()) !== 'unsat';
      _sharedSolver.pop();
      _smtCache.set(unsatKey, unsatResult);
    }
    _sharedSolver.pop();
    return { sat: satResult, unsat: unsatResult };
  }

  // -----------------------------------------------------------------------
  // End Taint Analysis Infrastructure
  // -----------------------------------------------------------------------

  // Extract the virtual DOM constructed by the script: every
  // `document.createElement`/`getElementById`/`createTextNode` call
  // produces a tracked element, and subsequent `el.prop = ...`,
  // `el.setAttribute(...)`, `el.appendChild(...)` statements mutate it.
  // Returns { elements, ops, roots, html }, where:
  //   - elements: all tracked virtual elements/text nodes in creation order
  //   - ops:      the sequence of DOM operations the script performs
  //   - roots:    elements that weren't appended to another tracked element
  //   - html:     a per-element HTML serialization (best-effort)
  async function extractAllDOM(input) {
    const trimmed = input.trim();
    if (!trimmed) return { elements: [], ops: [], roots: [], html: {} };
    const tokens = tokenize(trimmed);
    const state = await buildScopeState(tokens, tokens.length, scanMutations(tokens));
    const elements = state.domElements;
    const roots = elements.filter((el) => !el.attached);
    const html = {};
    for (const el of elements) html[el.elementId] = serializeElement(el);
    return {
      elements: elements.map(summarizeElement),
      ops: state.domOps.map((o) => ({
        op: o.op,
        elementId: o.element ? o.element.elementId : null,
        name: o.name, value: o.value ? bindingAsText(o.value) : undefined,
        path: o.path,
      })),
      roots: roots.map(summarizeElement),
      html,
    };
  }

  // Best-effort conversion of a binding to a displayable string/source text.
  function bindingAsText(b) {
    if (!b) return null;
    if (b.kind === 'chain') {
      let s = '';
      for (const t of b.toks) {
        if (t.type === 'plus') continue;
        if (t.type === 'str') s += t.text;
        else if (t.type === 'tmpl') {
          for (const p of t.parts) {
            if (p.kind === 'text') s += p.raw;
            else s += '${' + p.expr + '}';
          }
        } else if (t.type === 'other') s += '${' + t.text + '}';
      }
      return s;
    }
    return null;
  }

  function summarizeElement(el) {
    if (el.kind === 'textNode') {
      return { id: el.elementId, kind: 'textNode', text: bindingAsText(el.text), attached: el.attached };
    }
    return {
      id: el.elementId,
      kind: 'element',
      origin: el.origin,
      attrs: mapValues(el.attrs, bindingAsText),
      props: mapValues(el.props, bindingAsText),
      styles: mapValues(el.styles, bindingAsText),
      classList: el.classList,
      children: el.children.map((c) => c.elementId != null ? c.elementId : null),
      text: bindingAsText(el.text),
      html: bindingAsText(el.html),
      attached: el.attached,
    };
  }

  function mapValues(obj, f) {
    const out = {};
    for (const k in obj) out[k] = f(obj[k]);
    return out;
  }

  // Serialize an element (with its children) to an HTML string, using any
  // known text/html/attrs. Returns a template-literal-style string where
  // unresolved sub-expressions surface as ${expr}.
  function serializeElement(el) {
    if (el.kind === 'textNode') return bindingAsText(el.text) || '';
    const origin = el.origin;
    const tag = origin.kind === 'create' ? origin.tag : null;
    let inner = '';
    // `innerHTML = ...` sets the element's HTML; later appendChild calls
    // add more children on top. Combine both so users see the full DOM.
    if (el.html != null) inner += bindingAsText(el.html) || '';
    else if (el.text != null) inner += escapeHTML(bindingAsText(el.text) || '');
    for (const c of el.children) {
      if (c.kind === 'textNode') inner += escapeHTML(bindingAsText(c.text) || '');
      else if (c.kind === 'textLike') inner += escapeHTML(bindingAsText(c.chain) || '');
      else if (c.kind === 'element') inner += serializeElement(c);
    }
    if (tag) return '<' + tag + serializeAttrs(el) + '>' + inner + '</' + tag + '>';
    // Lookup-origin element without its own tag: emit children only.
    return inner;
  }

  function serializeAttrs(el) {
    let out = '';
    if (el.classList && el.classList.length) {
      out += ' class="' + escapeHTML(el.classList.join(' ')) + '"';
    }
    for (const k in el.attrs) {
      const v = bindingAsText(el.attrs[k]);
      if (v != null) out += ' ' + k + '="' + escapeHTML(v) + '"';
    }
    // IDL reflected props worth echoing into attributes for display.
    const REFLECTED = ['id', 'href', 'src', 'alt', 'title', 'name', 'value', 'type', 'placeholder'];
    for (const k of REFLECTED) {
      if (k in el.props) {
        const v = bindingAsText(el.props[k]);
        if (v != null) out += ' ' + k + '="' + escapeHTML(v) + '"';
      }
    }
    return out;
  }

  function escapeHTML(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Recursively expand loopVar references in a chain token array.
  // lvByName: { varName → [loopVar, ...] } — stack of loopVar entries.
  function expandLoopVars(toks, lvByName) {
    const out = [];
    for (const t of toks) {
      if (t.type === 'other' && IDENT_RE.test(t.text) && lvByName[t.text] && lvByName[t.text].length) {
        const lv = lvByName[t.text].pop();
        for (const vt of expandLoopVars(lv.chain, lvByName)) out.push(vt);
        lvByName[t.text].push(lv);
      } else if (t.type === 'cond') {
        out.push({ type: 'cond', condExpr: t.condExpr, ifTrue: expandLoopVars(t.ifTrue, lvByName), ifFalse: expandLoopVars(t.ifFalse, lvByName), loopId: t.loopId });
      } else if (t.type === 'trycatch') {
        out.push({ type: 'trycatch', tryBody: expandLoopVars(t.tryBody, lvByName), catchBody: expandLoopVars(t.catchBody, lvByName), catchParam: t.catchParam, loopId: t.loopId });
      } else if (t.type === 'switch') {
        out.push({ type: 'switch', discExpr: t.discExpr, branches: t.branches.map(function(br) { return { label: br.label, caseExpr: br.caseExpr, chain: expandLoopVars(br.chain, lvByName) }; }), loopId: t.loopId });
      } else {
        out.push(t);
      }
    }
    return out;
  }

  async function extractAllHTML(input) {
    const trimmed = input.trim();
    if (!trimmed) return [];
    const tokens = tokenize(trimmed);
    const assigns = findAllHtmlAssignments(tokens);

    // Extract each assignment independently first.
    const singles = [];
    for (const assign of assigns) {
      const result = await extractOneAssignment(tokens, assign);
      if (!result) continue;
      result.srcStart = assign.srcStart;
      result.srcEnd = assign.srcEnd;
      result._assign = assign;
      result._tokens = tokens;
      singles.push(result);
    }

    // Group by overlapping source regions. Two extractions overlap
    // if one's build region contains or intersects the other's build
    // region. This detects multi-target patterns where two build vars
    // are constructed in the same loop.
    const groups = [];
    const assigned = new Set();
    for (let si = 0; si < singles.length; si++) {
      if (assigned.has(si)) continue;
      const group = [singles[si]];
      assigned.add(si);
      const s = singles[si];
      const sStart = s.buildVarDeclStart >= 0 ? s.buildVarDeclStart : s.srcStart;
      const sEnd = s.srcEnd;
      // Find other extractions whose build region overlaps.
      for (let sj = si + 1; sj < singles.length; sj++) {
        if (assigned.has(sj)) continue;
        const s2 = singles[sj];
        const s2Start = s2.buildVarDeclStart >= 0 ? s2.buildVarDeclStart : s2.srcStart;
        const s2End = s2.srcEnd;
        // Overlap: one region contains the start of the other.
        if ((s2Start >= sStart && s2Start < sEnd) || (sStart >= s2Start && sStart < s2End)) {
          group.push(s2);
          assigned.add(sj);
        }
      }
      groups.push(group);
    }

    // Convert groups to a format compatible with the rest of the code.
    const byRegion = Object.create(null);
    const regionOrder = [];
    for (let gi = 0; gi < groups.length; gi++) {
      const key = 'g' + gi;
      byRegion[key] = groups[gi];
      regionOrder.push(key);
    }

    const results = [];
    for (const key of regionOrder) {
      const group = byRegion[key];
      if (group.length === 1) {
        results.push(group[0]);
        continue;
      }

      // Multi-target: re-resolve with ALL build vars tracked together.
      // Collect all build var names and their targets.
      const allBuildVars = [];
      const varTargets = {}; // varName → { target, assignProp, assignOp }
      for (const s of group) {
        const assign = s._assign;
        for (let j = assign.rhsStart; j < assign.rhsEnd; j++) {
          const rt = tokens[j];
          if (rt.type !== 'other' || !IDENT_RE.test(rt.text)) continue;
          // Check if it's a build var (has += or = with HTML).
          for (let bi = 0; bi < assign.eqIdx; bi++) {
            if (tokens[bi].type !== 'other' || tokens[bi].text !== rt.text) continue;
            const nt = tokens[bi + 1];
            if (!nt || nt.type !== 'sep') continue;
            if (nt.char === '+=' || nt.char === '=') {
              if (!allBuildVars.includes(rt.text)) allBuildVars.push(rt.text);
              varTargets[rt.text] = { target: s.target, assignProp: s.assignProp, assignOp: s.assignOp };
              break;
            }
          }
        }
      }

      // Build scope state with all build vars tracked.
      const lastAssign = group[group.length - 1]._assign;
      const extMut = scanMutations(tokens);
      const state = await buildScopeState(tokens, lastAssign.rhsStart, extMut, allBuildVars);

      // Extract each build var's chain, expand loopVars, and build
      // a mapping of varName → expanded chain.
      const varChains = {};
      for (const bv of allBuildVars) {
        const binding = state.resolve(bv);
        if (!binding || binding.kind !== 'chain') continue;
        // Expand loopVars for this build var.
        const lvByName = Object.create(null);
        if (state.loopVars) {
          for (const lv of state.loopVars) {
            if (lv.name !== bv) continue;
            if (!lvByName[lv.name]) lvByName[lv.name] = [];
            lvByName[lv.name].push(lv);
          }
        }
        varChains[bv] = expandLoopVars(binding.toks, lvByName);
      }

      // Merge chains: use the first build var's chain as the template.
      // For each cond/trycatch/switch branch that is all preserves in
      // the first chain but has DOM content in another chain, replace
      // the preserves with the other chain's DOM tokens wrapped in
      // target-switch markers.
      const firstBV = allBuildVars[0];
      const firstChain = varChains[firstBV] || [];

      function branchIsPreserve(toks) {
        return toks.every(function(t) { return t.type === 'preserve' || t.type === 'plus'; });
      }
      function branchHasDOM(toks) {
        return toks.some(function(t) { return t.type === 'str' || t.type === 'other' || t.type === 'cond' || t.type === 'trycatch' || t.type === 'switch'; });
      }

      function mergeTokens(baseToks) {
        const out = [];
        for (const t of baseToks) {
          if (t.type === 'cond') {
            let ifTrue = mergeTokens(t.ifTrue);
            let ifFalse = mergeTokens(t.ifFalse);
            // Check if a branch is all preserves and another chain has DOM there.
            for (let vi = 1; vi < allBuildVars.length; vi++) {
              const otherBV = allBuildVars[vi];
              const otherChain = varChains[otherBV] || [];
              // Find matching cond in other chain.
              const otherCond = otherChain.find(function(ot) { return ot.type === 'cond' && ot.condExpr === t.condExpr; });
              if (!otherCond) continue;
              if (branchIsPreserve(ifTrue) && branchHasDOM(otherCond.ifTrue)) {
                const targetExpr = varTargets[otherBV].target;
                ifTrue = [{ type: '_targetPush', target: targetExpr }].concat(mergeTokens(otherCond.ifTrue)).concat([{ type: '_targetPop' }]);
              }
              if (branchIsPreserve(ifFalse) && branchHasDOM(otherCond.ifFalse)) {
                const targetExpr = varTargets[otherBV].target;
                ifFalse = [{ type: '_targetPush', target: targetExpr }].concat(mergeTokens(otherCond.ifFalse)).concat([{ type: '_targetPop' }]);
              }
            }
            out.push({ type: 'cond', condExpr: t.condExpr, ifTrue: ifTrue, ifFalse: ifFalse, loopId: t.loopId });
          } else if (t.type === 'trycatch') {
            out.push({ type: 'trycatch', tryBody: mergeTokens(t.tryBody), catchBody: mergeTokens(t.catchBody), catchParam: t.catchParam, loopId: t.loopId });
          } else if (t.type === 'switch') {
            out.push({ type: 'switch', discExpr: t.discExpr, branches: t.branches.map(function(br) { return { label: br.label, caseExpr: br.caseExpr, chain: mergeTokens(br.chain) }; }), loopId: t.loopId });
          } else {
            out.push(t);
          }
        }
        return out;
      }

      const mergedChain = mergeTokens(firstChain);

      // Produce merged extraction.
      const firstTarget = varTargets[firstBV] || {};
      let widestEnd = 0;
      for (const s of group) { if (s.srcEnd > widestEnd) widestEnd = s.srcEnd; }

      // Add replaceChildren for additional targets as preserve tokens
      // at the start of the chain.
      const initTokens = [];
      for (let vi = 1; vi < allBuildVars.length; vi++) {
        const info = varTargets[allBuildVars[vi]];
        if (info && info.assignOp === '=') {
          initTokens.push({ type: 'preserve', text: info.target + '.replaceChildren()' });
          initTokens.push({ type: 'plus' });
        }
      }

      results.push({
        target: firstTarget.target || group[0].target,
        assignProp: firstTarget.assignProp || 'innerHTML',
        assignOp: firstTarget.assignOp || '=',
        chainTokens: initTokens.concat(mergedChain),
        loopInfoMap: state.loopInfo,
        buildVarDeclStart: group[0].buildVarDeclStart,
        srcStart: group[0].srcStart,
        srcEnd: widestEnd,
        _assign: group[0]._assign,
        _tokens: tokens,
      });
    }

    return results;
  }

  // Produce a { target, assignProp, assignOp, chainTokens, ... } record
  // for a single innerHTML/outerHTML assignment located in `tokens`.
  // Returns null if the target is known to NOT be a DOM element.
  async function extractOneAssignment(tokens, assign) {
    const target = assign.target;
    const assignProp = assign.prop;
    const assignOp = assign.op;
    // Determine build variables from the RHS (single ident or concat of idents).
    const rhsToks = [];
    for (let j = assign.rhsStart; j < assign.rhsEnd; j++) rhsToks.push(tokens[j]);
    // Collect identifiers in the RHS that are build variables: they
    // were built up via `x += "..."` patterns, OR they are the sole
    // RHS identifier and were assigned HTML strings (containing '<')
    // via `x = "..."` before the innerHTML site. The second case
    // handles try-catch/if-else patterns where x is assigned HTML
    // in different branches via = instead of +=.
    const buildVars = [];
    for (const rt of rhsToks) {
      if (rt.type !== 'other' || !IDENT_RE.test(rt.text)) continue;
      let isBuildVar = false;
      for (let bi = 0; bi < assign.eqIdx; bi++) {
        if (tokens[bi].type !== 'other' || tokens[bi].text !== rt.text) continue;
        const nextTok = tokens[bi + 1];
        if (!nextTok || nextTok.type !== 'sep') continue;
        // += is always a build variable indicator.
        if (nextTok.char === '+=') { isBuildVar = true; break; }
        // = with an HTML string on the RHS.
        if (nextTok.char === '=') {
          // Scan the RHS of this assignment for a string containing '<'.
          for (let rbi = bi + 2; rbi < tokens.length; rbi++) {
            const rbt = tokens[rbi];
            if (rbt.type === 'sep' && (rbt.char === ';' || rbt.char === ',')) break;
            if (rbt.type === 'str' && /</.test(rbt.text)) { isBuildVar = true; break; }
          }
          if (isBuildVar) break;
        }
      }
      if (isBuildVar) buildVars.push(rt.text);
    }
    const buildVar = buildVars.length === 1 ? buildVars[0] : null;
    const r = await resolveIdentifiers(tokens, assign.rhsStart, assign.rhsEnd, buildVars.length ? buildVars : null);

    // Verify the target is not a known non-element. Extract the base
    // variable name from the target (e.g. "el" from "el.innerHTML").
    if (r.resolve && target) {
      const baseMatch = target.match(IDENT_RE);
      if (baseMatch) {
        const targetBind = r.resolve(baseMatch[0]);
        // If the base variable resolves to a known non-element type
        // (string, number, array, plain object), skip conversion.
        if (targetBind && targetBind.kind === 'chain') {
          // A chain binding is a string/value — not a DOM element.
          // However, unresolved identifiers (like function params or
          // globals like document.getElementById result) also appear
          // as chain bindings with a single exprRef token. Those are
          // unknown (could be elements) so we allow them.
          const toks = targetBind.toks;
          const isOpaque = toks.length === 1 && toks[0].type === 'other';
          if (!isOpaque) {
            // Target is a known string/value — not a DOM element.
            return null;
          }
        } else if (targetBind && targetBind.kind === 'array') {
          return null; // Arrays don't have innerHTML
        } else if (targetBind && targetBind.kind === 'object') {
          return null; // Plain objects don't have innerHTML
        }
        // targetBind is null (unknown/global), 'element', or opaque —
        // proceed with conversion.
      }
    }
    if (r.parsed) {
      // Recursively expand loopVar references. Multiple loopVars may
      // share the same name (nested loops modifying the same build var).
      // Group by name as a stack: inner loops are pushed first, so the
      // last entry for a name is the outermost. Expansion pops entries
      // so inner loops expand before outer ones.
      const lvByName = Object.create(null);
      if (r.loopVars) {
        // Only expand build variables through loopVars. Non-build
        // variables (counters, flags) should stay as runtime references.
        const buildVarSet = new Set(buildVars);
        for (const lv of r.loopVars) {
          if (!buildVarSet.has(lv.name)) continue;
          if (!lvByName[lv.name]) lvByName[lv.name] = [];
          lvByName[lv.name].push(lv);
        }
      }
      const mainTokens = expandLoopVars(r.tokens, lvByName);
      // Skip conversion when the RHS is a single innerHTML/outerHTML read
      // (e.g. el2.innerHTML = el1.innerHTML) — the READ must stay as-is
      // because it produces the browser's serialized HTML from the DOM.
      if (mainTokens.length === 1 && mainTokens[0].type === 'other' &&
          /\.(innerHTML|outerHTML)$/.test(mainTokens[0].text)) {
        return null;
      }
      return { target, assignProp, assignOp, chainTokens: mainTokens, loopInfoMap: r.loopInfo, buildVarDeclStart: r.buildVarDeclStart };
    }
    // Same check for unparsed tokens.
    if (r.tokens.length === 1 && r.tokens[0].type === 'other' &&
        /\.(innerHTML|outerHTML)$/.test(r.tokens[0].text)) {
      return null;
    }
    return { target, assignProp, assignOp, chainTokens: r.tokens };
  }

  // =========================================================================
  // === jsanalyze public surface (Stage 1: seam + schemas) ===
  //
  // Everything below this banner is part of the planned `jsanalyze`
  // library's public API. It's currently defined inside jsanalyze.js
  // so the existing file layout is preserved, but every function
  // here takes ONLY walker-internal types and produces ONLY values
  // conforming to the jsanalyze-schemas.js public shape. The goal
  // is to mark the boundary now so Stage 5's file split is a
  // mechanical move with no logic changes.
  //
  // Nothing inside this region should reach into walker internals
  // beyond the arguments it's given. Nothing outside this region
  // should reach into public shapes.
  //
  // The boundary function is `bindingToValue` — it converts the
  // walker's internal binding (chain / object / array / function /
  // element) into a public `Value` from jsanalyze-schemas. Every
  // public query primitive goes through this function.
  // =========================================================================

  // Lazy-load the schema module. In Node (tests, consumers) we
  // require() it. In the browser, the schema file is loaded as a
  // separate <script> tag that sets globalThis.JsAnalyzeSchemas
  // before jsanalyze.js runs. `_schemas()` resolves the right one.
  var _schemaCache = null;
  function _schemas() {
    if (_schemaCache) return _schemaCache;
    if (typeof globalThis !== 'undefined' && globalThis.JsAnalyzeSchemas) {
      _schemaCache = globalThis.JsAnalyzeSchemas;
      return _schemaCache;
    }
    if (typeof require !== 'undefined') {
      try {
        _schemaCache = require('./jsanalyze-schemas.js');
        return _schemaCache;
      } catch (_) { /* fall through */ }
    }
    throw new Error('jsanalyze-schemas.js not available');
  }

  // Utility: compute (line, col) for a token start position inside
  // its owning source. Returns { line, col }. 1-indexed.
  // Cached line-start index for the most-recently-seen source string.
  // Without caching, every _tokLineCol / _provFromTok call did an
  // O(pos) scan from byte 0 to the token's position, turning trace
  // construction into a quadratic walk of the source on any file
  // with thousands of recorded findings / call sites. With the index
  // in place, each lookup is O(log lines) and the per-token cost
  // becomes independent of how far into the file we are.
  //
  // The cache is a single "last source" slot rather than a full Map
  // because (a) WeakMap keys have to be objects and source text is
  // a primitive string, and (b) buildScopeState walks a single
  // merged source per analyze() call, so the most-recent slot hits
  // 100% of the time for every token inside that walk. When a new
  // analyze() call passes a different source string, the first
  // _tokLineCol rebuilds the index once and every subsequent
  // lookup on the new source reuses it.
  var _walkerLineSrc = null;
  var _walkerLineStarts = null;
  function _walkerLineStartsFor(src) {
    if (src === _walkerLineSrc) return _walkerLineStarts;
    var starts = [0];
    for (var i = 0; i < src.length; i++) {
      if (src.charCodeAt(i) === 10) starts.push(i + 1);
    }
    _walkerLineSrc = src;
    _walkerLineStarts = starts;
    return starts;
  }
  function _tokLineCol(tok) {
    if (!tok || !tok._src || tok.start == null) return { line: 1, col: 0 };
    var src = tok._src, pos = tok.start | 0;
    var starts = _walkerLineStartsFor(src);
    var lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      var mid = (lo + hi + 1) >>> 1;
      if (starts[mid] <= pos) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, col: pos - starts[lo] };
  }

  // Build a Source (provenance entry) from a walker token and a
  // source kind. `file` is a display name — the caller passes it
  // since the walker doesn't always know the file.
  function _provFromTok(tok, file, kind, snippet) {
    var S = _schemas();
    var lc = _tokLineCol(tok);
    return S.mkSource(file || '<anonymous>', lc.line, lc.col, kind || S.SOURCE_KINDS.INLINE_LITERAL, snippet);
  }

  // Extract the first token with a usable _src field from a
  // walker binding (for fallback provenance when we don't have a
  // dedicated source token).
  function _anyTokFromBinding(b) {
    if (!b) return null;
    if (b.kind === 'chain' && b.toks) {
      for (var i = 0; i < b.toks.length; i++) {
        if (b.toks[i] && b.toks[i]._src) return b.toks[i];
      }
    }
    return null;
  }

  // Try to fold a chain to a single concrete primitive. Returns
  // null if any token is opaque / symbolic. Handles str, tmpl (text
  // parts only), and plus separators. Does NOT recurse into
  // cond/switchjoin/trycatch — those are handled separately by
  // enumeration.
  function _chainToConcrete(toks) {
    if (!toks) return null;
    var s = '';
    var hasContent = false;
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t.type === 'plus') continue;
      if (t.type === 'str') { s += t.text; hasContent = true; continue; }
      if (t.type === 'tmpl' && t.parts) {
        for (var j = 0; j < t.parts.length; j++) {
          var p = t.parts[j];
          if (p.kind === 'text') { s += p.raw || ''; hasContent = true; }
          else return null; // hole with an expression — not concrete
        }
        continue;
      }
      return null;
    }
    return hasContent ? s : null;
  }

  // Enumerate every concrete string a chain could take by
  // distributing over branch tokens (cond/switchjoin/trycatch).
  // Returns an array of strings, or null if any branch is not
  // fully enumerable.
  function _chainEnumerate(toks) {
    if (!toks) return null;
    var accs = [''];
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t.type === 'plus') continue;
      if (t.type === 'str') {
        for (var a = 0; a < accs.length; a++) accs[a] = accs[a] + t.text;
        continue;
      }
      if (t.type === 'tmpl' && t.parts) {
        var sub = [''];
        for (var pi = 0; pi < t.parts.length; pi++) {
          var p = t.parts[pi];
          if (p.kind === 'text') {
            for (var s2 = 0; s2 < sub.length; s2++) sub[s2] = sub[s2] + (p.raw || '');
          } else return null;
        }
        var next0 = [];
        for (var a2 = 0; a2 < accs.length; a2++) for (var s3 = 0; s3 < sub.length; s3++) next0.push(accs[a2] + sub[s3]);
        accs = next0;
        continue;
      }
      if (t.type === 'cond') {
        var l = _chainEnumerate(t.ifTrue), r = _chainEnumerate(t.ifFalse);
        if (!l || !r) return null;
        var next1 = [];
        for (var a3 = 0; a3 < accs.length; a3++) {
          for (var li = 0; li < l.length; li++) next1.push(accs[a3] + l[li]);
          for (var ri = 0; ri < r.length; ri++) next1.push(accs[a3] + r[ri]);
        }
        accs = next1;
        continue;
      }
      if (t.type === 'switchjoin' || t.type === 'switch') {
        if (!t.branches) return null;
        var bs = [];
        for (var bi = 0; bi < t.branches.length; bi++) {
          var be = _chainEnumerate(t.branches[bi].chain);
          if (!be) return null;
          bs.push(be);
        }
        var next2 = [];
        for (var a4 = 0; a4 < accs.length; a4++) for (var b = 0; b < bs.length; b++) for (var v = 0; v < bs[b].length; v++) next2.push(accs[a4] + bs[b][v]);
        accs = next2;
        continue;
      }
      if (t.type === 'trycatch') {
        var tb = _chainEnumerate(t.tryBody), cb = _chainEnumerate(t.catchBody);
        if (!tb || !cb) return null;
        var next3 = [];
        for (var a5 = 0; a5 < accs.length; a5++) {
          for (var ti = 0; ti < tb.length; ti++) next3.push(accs[a5] + tb[ti]);
          for (var ci = 0; ci < cb.length; ci++) next3.push(accs[a5] + cb[ci]);
        }
        accs = next3;
        continue;
      }
      return null; // opaque token (other, etc.)
    }
    // Dedupe
    var seen = Object.create(null), out = [];
    for (var o = 0; o < accs.length; o++) {
      if (!seen[accs[o]]) { seen[accs[o]] = 1; out.push(accs[o]); }
    }
    return out;
  }

  // Infer an UnknownReason for an opaque token (type === 'other').
  // Uses the token's taint set to distinguish user-input from
  // plain unresolved-identifier. Known taint-source expressions
  // (location.hash, document.cookie, etc.) map to user-input.
  // Runtime-random APIs map to runtime-random. Everything else
  // falls through to unresolved-identifier.
  function _inferUnknownReason(tok) {
    var S = _schemas();
    if (tok && tok.taint && (tok.taint.size > 0 || tok.taint.length > 0)) return S.UNKNOWN_REASONS.USER_INPUT;
    var text = tok && tok.text ? tok.text : '';
    if (/\bMath\.random\b/.test(text)) return S.UNKNOWN_REASONS.RUNTIME_RANDOM;
    if (/\bcrypto\.(randomUUID|getRandomValues)\b/.test(text)) return S.UNKNOWN_REASONS.RUNTIME_RANDOM;
    if (/\bDate\.now\b/.test(text) || /\bperformance\.now\b/.test(text)) return S.UNKNOWN_REASONS.RUNTIME_RANDOM;
    if (/^(fetch|XMLHttpRequest|IndexedDB|Cache)\b/.test(text)) return S.UNKNOWN_REASONS.OPAQUE_EXTERNAL;
    return S.UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER;
  }

  // Extract taint labels from a walker token. Internal taint is a
  // Set of label strings; the public schema uses arrays.
  function _tokTaintArray(tok) {
    if (!tok || !tok.taint) return null;
    if (tok.taint instanceof Set) {
      var arr = [];
      tok.taint.forEach(function (l) { arr.push(l); });
      return arr.length ? arr : null;
    }
    if (Array.isArray(tok.taint)) return tok.taint.length ? tok.taint.slice() : null;
    return null;
  }

  // Core boundary: walker binding → public Value.
  //
  // `options` is `{ file, provenanceKind, maxDepth }`. The file
  // name is stamped on generated Source entries. provenanceKind
  // defaults to 'inline-literal' for leaf sources and 'branch-merge'
  // for merged branches. maxDepth guards against cyclic object
  // bindings (rare but possible with self-referential structures).
  function bindingToValue(binding, options) {
    var S = _schemas();
    options = options || {};
    var depth = options._depth || 0;
    var maxDepth = options.maxDepth || 32;
    if (depth >= maxDepth) {
      return S.value.unknown(S.UNKNOWN_REASONS.RECURSION_CAP, null, []);
    }
    var file = options.file || '<anonymous>';

    if (!binding) {
      return S.value.unknown(S.UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER, null, []);
    }

    // --- chain binding ---
    if (binding.kind === 'chain') {
      return _chainBindingToValue(binding, { file: file, _depth: depth + 1, maxDepth: maxDepth });
    }

    // --- object binding ---
    if (binding.kind === 'object') {
      var props = Object.create(null);
      for (var k in binding.props) {
        if (k.indexOf('__') === 0 || k.indexOf('_') === 0) continue;
        props[k] = bindingToValue(binding.props[k], { file: file, _depth: depth + 1, maxDepth: maxDepth });
      }
      var anyTok = null;
      // Try to find a provenance token from any prop
      for (var k2 in binding.props) {
        anyTok = _anyTokFromBinding(binding.props[k2]);
        if (anyTok) break;
      }
      var objProv = anyTok ? [_provFromTok(anyTok, file, S.SOURCE_KINDS.INLINE_LITERAL)] : [];
      return S.value.object(props, objProv);
    }

    // --- array binding ---
    if (binding.kind === 'array') {
      var elems = [];
      for (var i = 0; i < binding.elems.length; i++) {
        elems.push(bindingToValue(binding.elems[i], { file: file, _depth: depth + 1, maxDepth: maxDepth }));
      }
      return S.value.array(elems, []);
    }

    // --- function binding ---
    if (binding.kind === 'function') {
      var paramNames = [];
      if (binding.params) for (var pi = 0; pi < binding.params.length; pi++) paramNames.push(binding.params[pi].name || ('arg' + pi));
      return S.value.function(
        binding.name || null,
        paramNames,
        { bodyStart: binding.bodyStart, bodyEnd: binding.bodyEnd },
        []
      );
    }

    // --- element binding (DOM virtual element) ---
    if (binding.kind === 'element') {
      var elProps = Object.create(null);
      elProps['__element'] = S.value.concrete(true, []);
      elProps['tag'] = S.value.concrete(binding.tag || 'unknown', []);
      if (binding.attrs) {
        var attrProps = Object.create(null);
        for (var an in binding.attrs) {
          attrProps[an] = bindingToValue(binding.attrs[an], { file: file, _depth: depth + 1, maxDepth: maxDepth });
        }
        elProps['attrs'] = S.value.object(attrProps, []);
      }
      return S.value.object(elProps, []);
    }

    // Fallback for unknown binding kinds — surfaces as opaque-external.
    return S.value.unknown(S.UNKNOWN_REASONS.OPAQUE_EXTERNAL, null, []);
  }

  // Chain binding → Value. Handles the common cases:
  //   - single str token                  → concrete
  //   - every tok fold-able to literal    → concrete
  //   - every tok enumerable via branches → oneOf
  //   - single opaque 'other' token       → unknown with inferred reason
  //   - multi-token with symbolic holes   → template
  function _chainBindingToValue(chainBind, options) {
    var S = _schemas();
    var toks = chainBind.toks;
    var file = options.file;
    if (!toks || toks.length === 0) {
      return S.value.unknown(S.UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER, null, []);
    }

    // Single str token — concrete with inline-literal provenance.
    if (toks.length === 1 && toks[0].type === 'str') {
      var prov = toks[0]._src ? [_provFromTok(toks[0], file, S.SOURCE_KINDS.INLINE_LITERAL)] : [];
      return S.value.concrete(toks[0].text, prov);
    }

    // Single opaque 'other' token — unknown with inferred reason + taint.
    if (toks.length === 1 && toks[0].type === 'other') {
      var reason = _inferUnknownReason(toks[0]);
      var taint = _tokTaintArray(toks[0]);
      var oprov = toks[0]._src ? [_provFromTok(toks[0], file, S.SOURCE_KINDS.INLINE_LITERAL, toks[0].text)] : [];
      return S.value.unknown(reason, taint, oprov);
    }

    // Try full concrete fold first.
    var concrete = _chainToConcrete(toks);
    if (concrete !== null) {
      var firstTok = toks.find(function (t) { return t && t._src; });
      var cprov = firstTok ? [_provFromTok(firstTok, file, S.SOURCE_KINDS.INLINE_LITERAL)] : [];
      return S.value.concrete(concrete, cprov);
    }

    // Try enumeration over branches.
    var enumerated = _chainEnumerate(toks);
    if (enumerated && enumerated.length > 0) {
      if (enumerated.length === 1) {
        var e0 = toks.find(function (t) { return t && t._src; });
        var eprov = e0 ? [_provFromTok(e0, file, S.SOURCE_KINDS.BRANCH_MERGE)] : [];
        return S.value.concrete(enumerated[0], eprov);
      }
      var bprov = toks[0] && toks[0]._src ? [_provFromTok(toks[0], file, S.SOURCE_KINDS.BRANCH_MERGE)] : [];
      return S.value.oneOf(enumerated, S.ONE_OF_SOURCES.BRANCH, bprov);
    }

    // Build template: walk tokens, collect literal run + hole runs.
    var parts = [];
    var cur = '';
    for (var ti = 0; ti < toks.length; ti++) {
      var t = toks[ti];
      if (t.type === 'plus') continue;
      if (t.type === 'str') { cur += t.text; continue; }
      if (t.type === 'tmpl' && t.parts) {
        for (var tpi = 0; tpi < t.parts.length; tpi++) {
          var tp = t.parts[tpi];
          if (tp.kind === 'text') cur += (tp.raw || '');
          else {
            if (cur) { parts.push(S.part.literal(cur)); cur = ''; }
            var holeVal = S.value.unknown(S.UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER, null, []);
            parts.push(S.part.hole(holeVal, tp.expr || null));
          }
        }
        continue;
      }
      if (t.type === 'cond' || t.type === 'switchjoin' || t.type === 'switch' || t.type === 'trycatch') {
        if (cur) { parts.push(S.part.literal(cur)); cur = ''; }
        // Recursively convert this branch token as a synthetic chain.
        var branchVal = _chainBindingToValue({ kind: 'chain', toks: [t] }, options);
        parts.push(S.part.hole(branchVal, null));
        continue;
      }
      // Opaque 'other' or anything else
      if (cur) { parts.push(S.part.literal(cur)); cur = ''; }
      var hReason = _inferUnknownReason(t);
      var hTaint = _tokTaintArray(t);
      var hProv = t._src ? [_provFromTok(t, file, S.SOURCE_KINDS.INLINE_LITERAL, t.text)] : [];
      parts.push(S.part.hole(
        S.value.unknown(hReason, hTaint, hProv),
        t.text || null
      ));
    }
    if (cur) parts.push(S.part.literal(cur));

    if (parts.length === 0) {
      return S.value.unknown(S.UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER, null, []);
    }
    // If the template collapsed to a single literal part, return concrete.
    if (parts.length === 1 && parts[0].kind === 'literal') {
      return S.value.concrete(parts[0].value, []);
    }
    return S.value.template(parts, []);
  }

  // =========================================================================
  // === end jsanalyze public surface ===
  // =========================================================================

  // Early global export of the jsanalyze translation layer so tests and
  // consumers can reach it synchronously — before the IIFE's top-level
  // `await convert()` suspends execution. Definitions above this point
  // are hoisted, so referencing them here is safe. The full api export
  // at the end of the IIFE is unchanged and runs after the await.
  if (typeof globalThis !== 'undefined') {
    globalThis.__bindingToValue = bindingToValue;
    globalThis.__jsanalyze = {
      bindingToValue: bindingToValue,
      // buildScopeState / scanMutations / tokenize are hoisted
      // function declarations too; they're callable here.
      buildScopeState: buildScopeState,
      scanMutations: scanMutations,
      tokenize: tokenize,
    };
  }

  async function extractHTML(input) {
    const trimmed = input.trim();
    if (!trimmed) return { target: null, assignProp: null, assignOp: null, chainTokens: [] };
    if (trimmed.startsWith('<')) return { target: null, assignProp: null, assignOp: null, chainTokens: [{ type: 'str', text: trimmed }] };

    const tokens = tokenize(trimmed);

    // If there's an `X.innerHTML = ...` / `X.outerHTML = ...` assignment,
    // restrict HTML extraction to the right-hand side and surface the target.
    const assign = findHtmlAssignment(tokens);
    const target = assign ? assign.target : null;
    const assignProp = assign ? assign.prop : null;
    const assignOp = assign ? assign.op : null;

    // Resolve identifier references inside the RHS using the scope state at
    // the assignment site.
    if (assign) {
      const result = await extractOneAssignment(tokens, assign);
      // If target is a known non-element, fall through to no-innerHTML path.
      if (result) return result;
    }

    // No innerHTML assignment — resolve the entire input as an expression.
    // Only attempt resolution if the input contains potential HTML (< or
    // string concatenation with +).
    const hasHtmlHint = tokens.some(t =>
      (t.type === 'str' && /</.test(t.text)) ||
      (t.type === 'tmpl') ||
      (t.type === 'plus'));
    if (hasHtmlHint) {
      const r = await resolveIdentifiers(tokens, 0, tokens.length);
      if (r.parsed) {
        return { target, assignProp, assignOp, chainTokens: r.tokens, loopInfoMap: r.loopInfo };
      }
      return { target, assignProp, assignOp, chainTokens: r.tokens };
    }
    // Plain text / non-HTML — pass through as-is.
    return { target: null, assignProp: null, assignOp: null, chainTokens: [{ type: 'str', text: trimmed }] };
  }

  // Find the first top-level `<expr>.innerHTML = ...` / `.outerHTML = ...` /
  // `.innerHTML += ...` assignment in the token stream. Returns
  // { target, rhsStart, rhsEnd } or null. The tokenizer lumps identifier
  // chains like `document.body.innerHTML` into a single `other` token, but
  // calls/brackets like `document.getElementById('x').innerHTML` split the
  // target across several tokens; we reconstruct the full expression by
  // walking back through balanced parens/brackets.
  function findHtmlAssignment(tokens) {
    const all = findAllHtmlAssignments(tokens);
    return all.length ? all[0] : null;
  }

  // Find every `X.innerHTML`/`X.outerHTML` `=` / `+=` assignment and
  // `document.write(...)` / `document.writeln(...)` call in the token
  // stream. Returns an array in source order.
  function findAllHtmlAssignments(tokens) {
    const out = [];
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];

      // document.write(...) / document.writeln(...)
      if (t.type === 'other' && (t.text === 'document.write' || t.text === 'document.writeln')) {
        const openParen = tokens[i + 1];
        if (!openParen || openParen.type !== 'open' || openParen.char !== '(') continue;
        // Find matching close paren.
        let depth = 1, j = i + 2;
        while (j < tokens.length && depth > 0) {
          if (tokens[j].type === 'open') depth++;
          else if (tokens[j].type === 'close') depth--;
          if (depth > 0) j++;
        }
        if (depth !== 0) continue;
        const rhsStart = i + 2;
        const rhsEnd = j; // points at )
        const srcStart = t.start;
        let srcEnd = tokens[j].end;
        // Include trailing semicolon if present.
        if (j + 1 < tokens.length && tokens[j + 1].type === 'sep' && tokens[j + 1].char === ';') {
          srcEnd = tokens[j + 1].end;
        }
        // document.write appends to document.body; writeln adds a newline.
        out.push({
          target: 'document.body',
          prop: 'innerHTML',
          op: '+=',
          rhsStart: rhsStart,
          rhsEnd: rhsEnd,
          srcStart: srcStart,
          srcEnd: srcEnd,
          eqIdx: i, // points at the document.write token
          isDocWrite: true,
          addsNewline: t.text === 'document.writeln',
        });
        continue;
      }

      // X.insertAdjacentHTML(position, html)
      if (t.type === 'other' && /\.insertAdjacentHTML$/.test(t.text)) {
        const openParen = tokens[i + 1];
        if (!openParen || openParen.type !== 'open' || openParen.char !== '(') continue;
        // Find the position argument (first arg before comma).
        let j = i + 2;
        let argDepth = 0;
        let commaIdx = -1;
        while (j < tokens.length) {
          if (tokens[j].type === 'open') argDepth++;
          else if (tokens[j].type === 'close') { if (argDepth === 0) break; argDepth--; }
          else if (argDepth === 0 && tokens[j].type === 'sep' && tokens[j].char === ',') { commaIdx = j; break; }
          j++;
        }
        if (commaIdx < 0) continue;
        // Read the position argument.
        const posTok = tokens[i + 2];
        const position = posTok && posTok.type === 'str' ? posTok.text.toLowerCase() : null;
        if (!position) continue; // Dynamic position — can't determine semantics.
        // Find matching close paren for the full call.
        let depth2 = 1, endJ = commaIdx + 1;
        while (endJ < tokens.length && depth2 > 0) {
          if (tokens[endJ].type === 'open') depth2++;
          else if (tokens[endJ].type === 'close') depth2--;
          if (depth2 > 0) endJ++;
        }
        if (depth2 !== 0) continue;
        // Extract the target (everything before .insertAdjacentHTML).
        const targetBase = t.text.replace(/\.insertAdjacentHTML$/, '');
        let target = targetBase;
        let targetSrcStart = -1;
        if (target === '' || target.startsWith('.')) {
          const r = reconstructTarget(tokens, i);
          if (!r) continue;
          target = target.startsWith('.') ? r.text + target : r.text;
          targetSrcStart = r.srcStart;
        }
        // Map position to target+op:
        // 'beforeend' → append to target (innerHTML +=)
        // 'afterbegin' → prepend to target (innerHTML +=, but conceptually first child)
        // 'beforebegin' → insert before target (target.parentNode, +=)
        // 'afterend' → insert after target (target.parentNode, +=)
        if (position === 'beforebegin' || position === 'afterend') {
          target = target + '.parentNode';
        }
        const rhsStart = commaIdx + 1;
        const rhsEnd = endJ; // points at )
        const srcStart = targetSrcStart >= 0 ? targetSrcStart : t.start;
        let srcEnd = tokens[endJ].end;
        if (endJ + 1 < tokens.length && tokens[endJ + 1].type === 'sep' && tokens[endJ + 1].char === ';') {
          srcEnd = tokens[endJ + 1].end;
        }
        out.push({
          target: target,
          prop: 'innerHTML',
          op: '+=',
          rhsStart: rhsStart,
          rhsEnd: rhsEnd,
          srcStart: srcStart,
          srcEnd: srcEnd,
          eqIdx: i,
        });
        continue;
      }

      // X.innerHTML = ... / X.outerHTML = ... / X.innerHTML += ...
      if (i < 1) continue;
      if (t.type !== 'sep') continue;
      if (t.char !== '=' && t.char !== '+=') continue;
      const prev = tokens[i - 1];
      if (!prev || prev.type !== 'other') continue;
      const trail = prev.text.match(/^(.*)\.(innerHTML|outerHTML)$/);
      if (!trail) continue;
      const prop = trail[2];
      let target = trail[1];
      let targetSrcStart = -1;
      if (target === '' || target.startsWith('.')) {
        const r = reconstructTarget(tokens, i - 1);
        if (!r) continue;
        target = target.startsWith('.') ? r.text + target : r.text;
        targetSrcStart = r.srcStart;
      }
      let depth = 0;
      let rhsEnd = tokens.length;
      for (let j = i + 1; j < tokens.length; j++) {
        const tk = tokens[j];
        if (tk.type === 'open') depth++;
        else if (tk.type === 'close') depth--;
        else if (depth === 0 && tk.type === 'sep' && (tk.char === ';' || tk.char === ',')) {
          rhsEnd = j;
          break;
        }
      }
      // Source character positions for the entire statement.
      const srcStart = targetSrcStart >= 0 ? targetSrcStart : prev.start;
      let srcEnd = rhsEnd < tokens.length ? tokens[rhsEnd].end : tokens[tokens.length - 1].end;
      if (rhsEnd < tokens.length && tokens[rhsEnd].type === 'sep' && tokens[rhsEnd].char === ';') {
        srcEnd = tokens[rhsEnd].end;
      }
      out.push({ target, prop, op: t.char, rhsStart: i + 1, rhsEnd, srcStart, srcEnd, eqIdx: i });
    }
    return out;
  }

  // Given an innerHTML assignment and the full token list, find the "build
  // region" — the contiguous span of source code that exists solely to
  // construct the value assigned to innerHTML. Returns
  // { regionStart, regionEnd } (source char positions) or null.
  function reconstructTarget(tokens, accessorIdx) {
    let j = accessorIdx - 1;
    let depth = 0;
    const startAccessor = tokens[accessorIdx];
    while (j >= 0) {
      const tk = tokens[j];
      // Only `)`/`]` act as balanced closers for backward call/index walks.
      // A `}` at depth 0 is a statement boundary (end of the previous block)
      // and must terminate the walk, not start a balanced group.
      if (tk.type === 'close' && (tk.char === ')' || tk.char === ']')) { depth++; j--; continue; }
      if (tk.type === 'close' && tk.char === '}') break;
      if (tk.type === 'open') {
        if (depth === 0) break;
        depth--; j--; continue;
      }
      if (depth > 0) { j--; continue; }
      // At depth 0, accept identifier-like `other` tokens as continuing the
      // member chain. Statement-level tokens (sep, plus, op) terminate.
      if (tk.type === 'other') { j--; continue; }
      break;
    }
    const firstIdx = j + 1;
    if (firstIdx > accessorIdx - 1) return null;
    const first = tokens[firstIdx];
    var text = first._src.slice(first.start, startAccessor.start).trim() || null;
    return text ? { text, srcStart: first.start } : null;
  }

  const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
  const PATH_RE = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$/;
  const IDENT_OR_PATH_RE = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$/;
  const TEMPLATE_EXPR_PATH_RE = /^\s*[A-Za-z_$][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*\s*$/;

  // Pure global builtins whose values are fully determined by their numeric
  // arguments. Called when a known identifier path ends in a `(...)` call
  // whose args are all concrete numbers.
  const BUILTINS = {
    'Math.floor': Math.floor, 'Math.ceil': Math.ceil, 'Math.round': Math.round,
    'Math.trunc': Math.trunc, 'Math.abs': Math.abs, 'Math.sqrt': Math.sqrt,
    'Math.log': Math.log, 'Math.log2': Math.log2, 'Math.log10': Math.log10,
    'Math.exp': Math.exp, 'Math.sin': Math.sin, 'Math.cos': Math.cos, 'Math.tan': Math.tan,
    'Math.min': Math.min, 'Math.max': Math.max, 'Math.pow': Math.pow,
    'Math.sign': Math.sign, 'Math.cbrt': Math.cbrt,
    'parseInt': (s, r) => parseInt(s, r == null ? 10 : r),
    'parseFloat': parseFloat, 'Number': Number, 'Boolean': Boolean,
    'isNaN': isNaN, 'isFinite': isFinite,
    // String(x) can coerce any literal — kept separate so it handles strings.
  };
  // DOM methods recognized on element bindings. Used by the walker's
  // path-method-call handler to route to applyElementMethod.
  const DOM_METHODS = new Set([
    'appendChild', 'append', 'prepend', 'insertBefore', 'replaceChild', 'removeChild',
    'setAttribute', 'removeAttribute', 'setAttributeNS', 'removeAttributeNS',
    'addEventListener', 'removeEventListener',
    'replaceWith', 'remove', 'insertAdjacentHTML', 'insertAdjacentElement',
    'insertAdjacentText', 'replaceChildren', 'toggleAttribute',
    'focus', 'blur', 'click', 'scrollIntoView',
  ]);

  // Method names recognized on typed bindings (chain/array). Used by
  // applySuffixes and readBase's attached-method detection to route to
  // applyMethod for evaluation.
  const KNOWN_METHODS = new Set([
    'concat', 'join',
    'toUpperCase', 'toLowerCase', 'trim', 'trimStart', 'trimEnd', 'trimLeft', 'trimRight',
    'repeat', 'slice', 'substring', 'substr', 'charAt', 'indexOf', 'lastIndexOf',
    'includes', 'startsWith', 'endsWith', 'padStart', 'padEnd', 'toString',
    'split', 'reverse', 'map', 'filter', 'forEach', 'reduce',
    // Promise continuation — applyMethod's then/catch/finally handler
    // walks the callback with the receiver's taint as the first arg.
    'then', 'catch', 'finally',
    // Map / Set / WeakMap / WeakSet key-indexed ops — applyMethod
    // dispatches these against a _mapLike object binding so dispatcher
    // tables and lookup caches flow through the may-be lattice.
    'set', 'get', 'has', 'add', 'delete', 'clear',
  ]);

  const MATH_CONSTANTS = {
    'Math.PI': Math.PI, 'Math.E': Math.E, 'Math.LN2': Math.LN2, 'Math.LN10': Math.LN10,
    'Math.LOG2E': Math.LOG2E, 'Math.LOG10E': Math.LOG10E,
    'Math.SQRT2': Math.SQRT2, 'Math.SQRT1_2': Math.SQRT1_2,
  };

  // A chain binding wraps an array of operand/plus tokens. Object and array
  // bindings hold named or indexed child bindings (each itself a chain,
  // object, or array) so member access and destructuring can walk into them.
  // Each object binding gets a stable identity (`__objId`) so that the
  // may-be lattice and other identity-sensitive analyses can track aliasing
  // (`var x = obj; x.foo = "Y"` → `obj.foo` and `x.foo` resolve to the
  // same lattice slot because they're the same underlying object).
  const chainBinding = (toks) => ({ kind: 'chain', toks });
  var _nextObjId = 0;
  const objectBinding = (props) => ({ kind: 'object', props, __objId: ++_nextObjId });
  const arrayBinding = (elems) => ({ kind: 'array', elems, __objId: ++_nextObjId });
  const functionBinding = (params, bodyStart, bodyEnd, isBlock) => ({
    kind: 'function', params, bodyStart, bodyEnd, isBlock,
  });
  // Virtual DOM element binding factories. Each `buildScopeState` invocation
  // maintains its own element-id counter via a closure (see below). The
  // `origin` records how the element was created: either
  // `{kind:'create', tag}` from document.createElement, `{kind:'lookup',
  // by:'id', value}` from document.getElementById, etc.
  const makeElementFactory = () => {
    let nextElementId = 0;
    return {
      element: (origin) => {
        // Resolve the element's concrete HTMLxElement type via
        // the TypeDB tagMap so the binding is flow-sensitively
        // typed from the moment of creation. Bindings created
        // via `document.createElement('iframe')` get
        // `typeName: 'HTMLIFrameElement'`, and subsequent reads
        // / writes on them resolve sinks through the type
        // chain instead of scanning every HTML subtype.
        var _typeName = null;
        if (origin && origin.kind === 'create' && origin.tag) {
          _typeName = DEFAULT_TYPE_DB.tagMap[origin.tag.toLowerCase()] || 'HTMLElement';
        } else if (origin && origin.kind === 'lookup') {
          // getElementById / querySelector results: unknown
          // concrete subtype at analysis time → HTMLElement.
          _typeName = 'HTMLElement';
        }
        return {
          kind: 'element',
          elementId: nextElementId++,
          origin,
          typeName: _typeName,
          attrs: Object.create(null),
          props: Object.create(null),
          styles: Object.create(null),
          classList: [],
          children: [],
          text: null,
          html: null,
          attached: false,
        };
      },
      textNode: (chain) => ({
        kind: 'textNode',
        elementId: nextElementId++,
        text: chain,
        attached: false,
      }),
    };
  };

  const makeSynthStr = (text) => ({
    type: 'str', quote: "'", raw: text, text, start: 0, end: 0, _src: '',
  });

  // Clone operand tokens, applying a `loopId` tag to operands that don't
  // already carry one. Plus tokens pass through unchanged. Existing tags
  // are preserved, so content carried in through a loop-built variable
  // (pre-tagged with its own loop's id) stays associated with that loop
  // even when spliced through another loop body.
  function tagWithLoop(toks, loopId) {
    return toks.map((t) => {
      if (t.type === 'plus') return t;
      if ('loopId' in t) return t;
      return Object.assign({}, t, { loopId });
    });
  }

  // Represent an unresolved subexpression as a single operand token whose
  // source slice equals `text`. It uses the same `other` token shape the
  // Represent an unresolved expression as a token whose source text is the
  // expression. Uses the same `other` token shape the tokenizer emits.
  const exprRef = (text) => ({
    type: 'other', text, start: 0, end: text.length, _src: text,
  });

  // A synthetic `+` token used when splicing together a concat chain from
  // `.join(sep)` (the original source has no plus there). findBestConcatChain
  // only inspects `type`, so minimal fields are enough.
  const SYNTH_PLUS = { type: 'plus', start: 0, end: 0, _src: '' };
  const TERMS_TOP = { sep: [',', ';'], close: [] };
  const TERMS_ARR = { sep: [','], close: [']'] };
  const TERMS_NONE = { sep: [], close: [] };
  const TERMS_ARG = { sep: [','], close: [')'] };
  const TERMS_OBJ = { sep: [','], close: ['}'] };

  // Walk tokens [0, stopAt), tracking lexical scopes, and return an object
  // with a `resolve(name)` that yields the current binding (an array of
  // operand/plus tokens forming a concat chain, or null) for `name` at
  // position `stopAt`.
  //
  // Scopes follow JavaScript semantics enough for reasonable snippets:
  // - `{ ... }` opens a block scope; `let`/`const` bind there.
  // - `function ... { ... }` and `=> { ... }` open function scopes; `var`
  //   bindings hoist to the nearest function (or global) scope.
  // - Bare `x = v` reassigns the innermost existing binding (or creates an
  //   implicit global) — honoring reassignment order and shadowing.
  // - RHS expressions can mix string/template literals, already-known
  //   identifiers, and `[str,str,...].join(sep)` patterns joined by `+`.
  //   Anything outside that grammar records `null`, clearing any prior value
  //   so stale literals can't leak through.
  // Scan the full token stream for simple-identifier mutations
  // (reassignments `x = ...`, compound `x += ...`, post-fix `x++`/`x--`)
  // and record each name's declaration function-depth and max mutation
  // function-depth. Any name mutated at a greater depth than where it
  // was first declared is considered "externally mutable": a linear
  // walker can't statically predict its value at a given extraction
  // site, so we should resolve it as a name reference instead of its
  // initial literal.
  // Parse a single function parameter starting at `k`. Returns
  // `{ param: { name, defaultStart?, defaultEnd? }, next }` or null.
  // `next` is the index after the param (points at `,` or `)`).
  function parseParamWithDefault(tokens, k, stop) {
    const nm = tokens[k];
    if (!nm || nm.type !== 'other') return null;
    // Rest parameter: ...args
    if (nm.text.startsWith('...') && IDENT_RE.test(nm.text.slice(3))) {
      return { param: { name: nm.text.slice(3), rest: true }, next: k + 1 };
    }
    if (!IDENT_RE.test(nm.text)) return null;
    let j = k + 1;
    const sep = tokens[j];
    if (sep && sep.type === 'sep' && sep.char === '=') {
      const defStart = j + 1;
      let d = 0; j = defStart;
      while (j < stop) {
        const tk = tokens[j];
        if (tk.type === 'open') d++;
        else if (tk.type === 'close') { if (d === 0) break; d--; }
        else if (d === 0 && tk.type === 'sep' && tk.char === ',') break;
        j++;
      }
      return { param: { name: nm.text, defaultStart: defStart, defaultEnd: j }, next: j };
    }
    return { param: { name: nm.text }, next: j };
  }

  function scanMutations(tokens) {
    const declaredAt = Object.create(null);
    const mutatedAt = Object.create(null);
    let depth = 0;
    let pendingFnBrace = false;
    const braceKinds = [];
    const noteDecl = (name) => { if (!(name in declaredAt)) declaredAt[name] = depth; };
    const noteMut = (name) => {
      if (!(name in mutatedAt) || depth > mutatedAt[name]) mutatedAt[name] = depth;
    };
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.type === 'other' && t.text === 'function') { pendingFnBrace = true; continue; }
      if (t.type === 'other' && t.text === '=>') {
        const nt = tokens[i + 1];
        if (nt && nt.type === 'open' && nt.char === '{') pendingFnBrace = true;
        continue;
      }
      if (t.type === 'open' && t.char === '{') {
        if (pendingFnBrace) { depth++; braceKinds.push('fn'); } else { braceKinds.push('block'); }
        pendingFnBrace = false;
        continue;
      }
      if (t.type === 'close' && t.char === '}') {
        const kind = braceKinds.pop();
        if (kind === 'fn') depth--;
        continue;
      }
      if (t.type === 'other' && (t.text === 'var' || t.text === 'let' || t.text === 'const')) {
        let j = i + 1;
        while (j < tokens.length) {
          const nm = tokens[j];
          if (!nm || nm.type !== 'other' || !IDENT_RE.test(nm.text)) break;
          noteDecl(nm.text);
          j++;
          if (tokens[j] && tokens[j].type === 'sep' && tokens[j].char === '=') {
            let d = 0;
            j++;
            while (j < tokens.length) {
              const tk = tokens[j];
              if (tk.type === 'open') d++;
              else if (tk.type === 'close') { if (d === 0) break; d--; }
              else if (d === 0 && tk.type === 'sep' && (tk.char === ',' || tk.char === ';')) break;
              j++;
            }
          }
          if (tokens[j] && tokens[j].type === 'sep' && tokens[j].char === ',') { j++; continue; }
          break;
        }
        i = j - 1;
        continue;
      }
      if (t.type === 'other' && IDENT_RE.test(t.text)) {
        const next = tokens[i + 1];
        if (next && next.type === 'sep' && /^[-+*/%]?=$/.test(next.char)) noteMut(t.text);
        if (next && next.type === 'op' && (next.text === '++' || next.text === '--')) noteMut(t.text);
        // `arr[i] = ...` mutates arr.
        if (next && next.type === 'open' && next.char === '[') {
          let d = 1, j = i + 2;
          while (j < tokens.length && d > 0) {
            if (tokens[j].type === 'open' && tokens[j].char === '[') d++;
            else if (tokens[j].type === 'close' && tokens[j].char === ']') d--;
            j++;
          }
          const eq = tokens[j];
          if (eq && eq.type === 'sep' && eq.char === '=') noteMut(t.text);
        }
      }
      // `arr.push(...)` / `obj.foo = ...` — the path token carries the base
      // name as its prefix.
      if (t.type === 'other' && PATH_RE.test(t.text)) {
        const dot = t.text.indexOf('.');
        const base = t.text.slice(0, dot);
        const rest = t.text.slice(dot + 1);
        const next = tokens[i + 1];
        if (next && next.type === 'sep' && /^[-+*/%]?=$/.test(next.char)) noteMut(base);
        if (next && next.type === 'open' && next.char === '(') {
          const lastDot = rest.lastIndexOf('.');
          const method = lastDot >= 0 ? rest.slice(lastDot + 1) : rest;
          if (/^(push|pop|shift|unshift|splice|sort|reverse|fill|copyWithin)$/.test(method)) noteMut(base);
        }
      }
    }
    const externallyMutable = new Set();
    for (const name in mutatedAt) {
      const dd = declaredAt[name] !== undefined ? declaredAt[name] : 0;
      if (mutatedAt[name] > dd) externallyMutable.add(name);
    }
    return externallyMutable;
  }

  async function buildScopeState(tokens, stopAt, externallyMutable, trackBuildVarInit, taintConfig, options) {
    options = options || {};
    const stack = [{ bindings: Object.create(null), isFunction: true }];
    // Find the token index of the `}` matching the `{` at index
    // `openIdx`. Returns -1 if not found. Used by the IIFE
    // wrapper fast-path in the `{` handler to detect whether a
    // function body is wrapped in `()` followed by `(…)` — the
    // IIFE call pattern.
    function _matchingBrace(openIdx) {
      if (!tokens[openIdx] || tokens[openIdx].type !== 'open' || tokens[openIdx].char !== '{') return -1;
      var depth = 1;
      for (var j = openIdx + 1; j < tokens.length; j++) {
        var tk = tokens[j];
        if (tk.type === 'open' && tk.char === '{') depth++;
        else if (tk.type === 'close' && tk.char === '}') { depth--; if (depth === 0) return j; }
      }
      return -1;
    }
    let pendingFunctionBrace = false;
    let pendingFunctionParams = null;
    // Taint tracking state (active when taintConfig is provided).
    const taintEnabled = !!taintConfig;
    const taintFindings = taintEnabled ? [] : null;
    // SMT path constraint: conjunction of conditions along the current
    // execution path. Pushed when entering a branch, popped when leaving.
    // Each entry is an SMT formula. The full path constraint is AND of all.
    const pathConstraints = taintEnabled ? [] : null;
    // String conditions for display in findings.
    const taintCondStack = taintEnabled ? [] : null;
    // Track whether we're inside an event handler walk. Mutations to
    // outer-scope variables inside handlers produce values that depend
    // on the number of handler invocations (attacker-controlled).
    var inEventHandler = false;
    // Pending callbacks for the phase-2 fixpoint. Each entry is
    // { fn: functionBinding, params: paramBindings, isEventHandler: bool }.
    // The fixpoint in buildScopeState's finalize block re-walks every
    // entry on each iteration so callbacks see the cumulative state
    // of every other callback.
    const _pendingCallbacks = [];
    // Call watchers: external consumers (fetch tracers, API discovery,
    // sink finders, etc.) register callbacks here. The walker invokes
    // every registered watcher for each call site it sees, passing
    // (callee, argBindings, token, info). Watchers read the fully
    // resolved argument bindings — concat chains, object literals,
    // arrays, function refs — and record whatever shape they need.
    // Registration happens via the public options object before
    // buildScopeState runs.
    const _callWatchers = (options && options.callWatchers) ? options.callWatchers.slice() : [];
    // ----------------------------------------------------------------
    // Per-variable may-be value lattice
    // ----------------------------------------------------------------
    // For each variable name we record EVERY value the walker has
    // assigned to it. The set is the JOIN of all reaching definitions
    // and is exactly what an SMT solver needs to reason about state
    // mutated indirectly across callbacks, branches and loops.
    //
    //   _varMayBe[name] = { vals: [binding, ...], keys: { json → true },
    //                       complete: bool }
    //
    // `complete` is true iff EVERY observed assignment was a binding
    // we can faithfully encode as a single SMT-LIB literal (a chain
    // of one literal-string token, or a chain of one literal-number
    // token). Once any assignment of an opaque / tainted / multi-token
    // chain happens, complete flips to false: we can no longer
    // enumerate the value space, so the set is conservatively
    // unbounded and SMT must NOT receive a closed disjunction over
    // it (that would be unsound — it would falsely exclude the
    // unencoded values).
    //
    // smtSat consults _varMayBe at SAT-check time. For every symbol
    // declared in the formula whose may-be set is complete with more
    // than one literal value, smtSat emits an extra
    //   (assert (or (= sym v1) (= sym v2) ...))
    // alongside the main assertion. Z3 then refutes any path that
    // requires sym to take a value outside the enumerated set.
    //
    // The phase-2 callback fixpoint includes _varMayBe in its
    // convergence signature, so iteration continues until no new
    // values are added to any variable's set. The lattice is
    // monotone (values only ever join in, never leave) so
    // convergence is guaranteed in a bounded number of iterations.
    const _varMayBe = Object.create(null);
    // Active for-of / for-in loop variable names. When the body's
    // walker assigns `s = loopVar`, the RHS resolves to an opaque
    // `other:loopVar` reference — without a guard, that would
    // poison `s`'s may-be slot. Loop handlers add the loop var name
    // on entry and remove it on exit; _trackMayBeAssign checks the
    // set and skips the opaque self-reference so the pre-populated
    // per-element values aren't clobbered.
    const _activeForOfVars = new Set();
    function _bindingToConcreteLit(b) {
      // Returns null if the binding cannot be expressed as a single
      // SMT-LIB literal. Returns { lit, sort } otherwise where sort
      // is 'String' or 'Int' and lit is the s-expression form.
      if (!b || b.kind !== 'chain') return null;
      if (b.toks.length !== 1) return null;
      var t = b.toks[0];
      if (t.type !== 'str') return null;
      // collectChainTaint will report any taint on the operand —
      // tainted operands are unencodable.
      if (t.taint && t.taint.size) return null;
      var n = Number(t.text);
      if (!Number.isNaN(n) && String(n) === t.text) {
        return { lit: n < 0 ? '(- ' + (-n) + ')' : String(n), sort: 'Int' };
      }
      // String literal — emit as a quoted SMT string.
      return { lit: _quoteSmtString(t.text), sort: 'String' };
    }
    // Resolve a may-be lattice key. For plain variable names this is
    // just the name. For property paths (`obj.prop` or `obj.a.b.c`)
    // we walk every segment EXCEPT the last through the binding stack,
    // so that the deepest container's stable identity is the key root.
    // This makes both \`obj.inner.v\` and an alias \`x.v\` (where x = obj.inner)
    // canonicalise to the same `#<innerId>.v` slot — the slot belongs
    // to the LEAF object, not the path used to reach it.
    function _mayBeKey(textPath) {
      if (typeof textPath !== 'string') return null;
      var dot = textPath.indexOf('.');
      if (dot < 0) return textPath;
      var parts = textPath.split('.');
      var b = resolve(parts[0]);
      // Walk every segment except the last through the binding stack
      // so the canonical key is rooted at the leaf container's id.
      for (var i = 1; i < parts.length - 1 && b; i++) {
        if (b.kind !== 'object') { b = null; break; }
        b = b.props[parts[i]] || null;
      }
      if (b && (b.kind === 'object' || b.kind === 'array') && b.__objId) {
        return '#' + b.__objId + '.' + parts[parts.length - 1];
      }
      return textPath;
    }
    function _trackMayBeAssign(name, binding) {
      if (!taintEnabled) return;
      var k0 = _mayBeKey(name);
      if (!k0) return;
      if (!_varMayBe[k0]) _varMayBe[k0] = { vals: [], keys: Object.create(null), complete: true, fns: null, fnIds: null };
      var slot = _varMayBe[k0];
      // Function-typed assignments are tracked separately so the
      // walker's indirect-call dispatch can walk EVERY function the
      // variable may resolve to. This is the call-target may-be set;
      // it doesn't contribute to the SMT disjunction (functions can't
      // be encoded as Z3 literals) but it lets us drive the
      // interprocedural analysis through dispatcher patterns.
      if (binding && binding.kind === 'function') {
        if (!slot.fns) { slot.fns = []; slot.fnIds = Object.create(null); }
        var fkey = binding.bodyStart + ':' + binding.bodyEnd;
        if (!slot.fnIds[fkey]) {
          slot.fnIds[fkey] = true;
          slot.fns.push(binding);
        }
        return;
      }
      // If the RHS is an opaque ref to an active for-of loop variable,
      // skip — we've pre-populated every iteration's concrete value
      // via the for-of pre-scan and don't want to poison the slot
      // with the body walker's symbolic view.
      if (binding && binding.kind === 'chain' && binding.toks.length === 1 &&
          binding.toks[0].type === 'other' &&
          _activeForOfVars.has(binding.toks[0].text)) {
        return;
      }
      if (slot.complete === false) return; // already poisoned for SMT
      // Expand a conditional chain `(cond) ? a : b` into two separate
      // may-be entries — both branches are reachable values. Without
      // this, the lattice is poisoned the moment a ternary is assigned
      // to a tracked variable, losing refutation power over loop /
      // switch / branch state.
      if (binding && binding.kind === 'chain' && binding.toks.length === 1 && binding.toks[0].type === 'cond') {
        var _condTok = binding.toks[0];
        if (_condTok.ifTrue) _trackMayBeAssign(name, chainBinding(_condTok.ifTrue));
        if (_condTok.ifFalse) _trackMayBeAssign(name, chainBinding(_condTok.ifFalse));
        return;
      }
      // Same treatment for `trycatch` tokens (try/catch merge) and
      // `switchcase` tokens (switch merge): both are two-alternative
      // join tokens and every alternative is a reachable runtime value.
      if (binding && binding.kind === 'chain' && binding.toks.length === 1 && binding.toks[0].type === 'trycatch') {
        var _tcTok = binding.toks[0];
        if (_tcTok.tryBody) _trackMayBeAssign(name, chainBinding(_tcTok.tryBody));
        if (_tcTok.catchBody) _trackMayBeAssign(name, chainBinding(_tcTok.catchBody));
        return;
      }
      if (binding && binding.kind === 'chain' && binding.toks.length === 1 &&
          (binding.toks[0].type === 'switch' || binding.toks[0].type === 'switchjoin')) {
        var _scTok = binding.toks[0];
        if (_scTok.branches) {
          for (var _sci = 0; _sci < _scTok.branches.length; _sci++) {
            var _sCase = _scTok.branches[_sci];
            if (_sCase && _sCase.chain) _trackMayBeAssign(name, chainBinding(_sCase.chain));
          }
        }
        return;
      }
      // Encode the assignment to detect duplicates and check encodability.
      var lit = _bindingToConcreteLit(binding);
      if (!lit) {
        // Opaque / tainted / multi-token / non-chain assignment —
        // the may-be set can no longer enumerate every reachable value
        // for SMT purposes. (Function entries in slot.fns are still
        // valid; we only poison the SMT side.)
        slot.complete = false;
        slot.vals = null; // free, no longer needed
        slot.keys = null;
        return;
      }
      var k = lit.sort + ':' + lit.lit;
      if (slot.keys[k]) return;
      slot.keys[k] = true;
      slot.vals.push({ lit: lit.lit, sort: lit.sort });
    }
    // Snapshot the scope chain (BY REFERENCE) visible at closure
    // creation time. The returned array holds references to the
    // actual frame objects, so mutations made after the closure is
    // created — whether by the outer function before it returns, or
    // by other callbacks sharing the same var — remain visible when
    // the closure is later invoked.
    //
    // instantiateFunction pushes any captured frames that are not
    // already on the live stack (preventing duplicates when a closure
    // is called synchronously before the outer function has returned)
    // and pops them in reverse order on exit.
    function _snapshotClosureForCapture() {
      // Return a shallow copy of the current stack; each entry is a
      // reference to the same frame object the walker is currently
      // using. If the outer function later pops the frame, our
      // reference keeps it alive for later re-entry.
      return stack.slice();
    }
    // Look up the function may-be set for a call target identifier.
    // Returns the array of function bindings the variable may resolve
    // to, or null if no function entries are tracked.
    function _funcMayBeFor(name) {
      if (!_varMayBe) return null;
      var k = _mayBeKey(name);
      if (!k) return null;
      var slot = _varMayBe[k];
      if (!slot || !slot.fns || slot.fns.length === 0) return null;
      return slot.fns;
    }
    // Track function scope depth for taint. Findings inside function
    // bodies walked at definition time (not via instantiateFunction)
    // should be suppressed because there's no calling context.
    var taintFnDepth = 0;
    // Loop detection stack: each entry is `{ id, kind, headerSrc, bodyEnd,
    // frame, modifiedVars }` recording an enclosing `for`/`while`. Operands
    // added to a binding's chain while a loop is active carry a `loopId` tag
    // so the materializer can wrap them in loop boundaries on output.
    const loopStack = [];
    const loopInfo = Object.create(null); // id -> {kind, headerSrc}
    // Variables whose final value was built inside a loop, captured on
    // loop exit. Each entry: { name, loop: {id,kind,headerSrc}, chain }.
    const loopVars = [];
    // When set, non-build statements inject 'preserve' tokens into this
    // variable's chain so the emitter outputs them at the right position.
    // trackBuildVar can be a string (single build var) or a Set (multiple).
    let trackBuildVar = null;
    // The function scope depth where the build var was declared. Preserve
    // tokens are only injected at this depth — inner functions with their
    // own local `html` var are not affected.
    let trackBuildVarDepth = -1;

    // Check if a token array starts with a given prefix (snapshot).
    // Used by if-else, try-catch, and switch handlers to detect
    // whether a branch appended to the snapshot (+=) or replaced it (=).
    // Reference-equality test first for the hot case where the
    // branch left the prefix untouched (all prefix tokens come from
    // the pre-branch snapshot and have the same object identity).
    // Falls back to the iterative deep comparator for the rare case
    // where the walker reconstructed structurally-equal tokens.
    const chainStartsWith = (full, prefix) => {
      if (full.length < prefix.length) return false;
      for (let s = 0; s < prefix.length; s++) {
        if (full[s] === prefix[s]) continue;
        if (!_chainsDeepEqual(full[s], prefix[s])) return false;
      }
      return true;
    };
    const stripLeadingPlus = (arr) => (arr.length && arr[0].type === 'plus') ? arr.slice(1) : arr;
    if (trackBuildVarInit) {
      if (Array.isArray(trackBuildVarInit)) {
        trackBuildVar = new Set(trackBuildVarInit);
      } else {
        trackBuildVar = new Set([trackBuildVarInit]);
      }
    }
    // Count function scope depth (number of isFunction frames on the stack).
    const funcDepth = () => {
      let d = 0;
      for (let si = 0; si < stack.length; si++) if (stack[si].isFunction) d++;
      return d;
    };
    let buildVarDeclStart = -1;
    let nextLoopId = 0;
    // Swappable token array for the inner parsing functions. The main scope
    // walker always uses `tokens` directly. Helpers like `evalExprSrc` can
    // temporarily swap `tks` to parse an unrelated token sequence (e.g., a
    // template-literal expression that was re-tokenized) while sharing the
    // current scope stack.
    let tks = tokens;
    // Flow-sensitive scope resolver consulted by the TypeDB
    // walkers. Returns `{typeName}` when a name resolves to a
    // typed local binding, `{shadowed: true}` when it resolves
    // to an untyped local binding (user var shadowing any
    // global), or null when the name isn't locally in scope
    // (walker falls back to `db.roots` for unshadowed globals).
    //
    // A binding's `typeName` is set at assignment time — e.g.
    // `var loc = window.location` stashes `Location` on `loc`'s
    // binding — so subsequent reads resolve through type lookups
    // instead of re-matching the original expression text. This
    // is what makes aliasing work:
    //
    //     var loc = window.location;
    //     x.innerHTML = loc.hash;   // detected as `url` source
    //
    // The walker sees `loc` in scope → uses typeName=Location →
    // looks up `hash` on Location → source='url'.
    //
    // Uses `resolve()` for lookup so function parameters,
    // captured closures, and block-scoped locals all
    // participate in the type resolution properly. The
    // legacy `declaredNames.has(...)` hack was a file-wide
    // over-approximation; `resolve` gives the actual active
    // binding at this program point.
    const typedScope = (name) => {
      var b = resolve(name);
      if (!b) return null;
      if (b.typeName) return { typeName: b.typeName };
      return { shadowed: true };
    };
    // Taint checking helpers (no-ops when taintEnabled is false).
    const checkTaintSource = (exprText) => {
      if (!taintEnabled) return null;
      var label = getTaintSource(exprText, typedScope);
      if (label) return new Set([label]);
      return null;
    };
    const checkTaintSourceCall = (callExpr) => {
      if (!taintEnabled) return null;
      var label = getTaintSourceCall(callExpr, typedScope);
      if (label) return new Set([label]);
      return null;
    };
    const recordTaintFinding = (sinkType, severity, prop, elementTag, taintLabels, pathConditions, location) => {
      if (!taintFindings) return;
      // Suppress findings inside function bodies walked at definition time.
      // These are re-walked via instantiateFunction with proper context.
      if (taintFnDepth > 0) return;
      // Snapshot the current SMT path-constraint formulas so a post-hoc
      // verification backend (e.g. Z3) can re-check reachability without
      // re-running the walker. The formulas are internal SMT AST nodes
      // (see smtSym/smtCmp/smtAnd/...).
      var _formulaSnapshot = pathConstraints ? pathConstraints.slice() : [];
      taintFindings.push({
        type: sinkType,
        severity: severity,
        sink: { prop: prop, elementTag: elementTag || null },
        sources: Array.from(taintLabels),
        conditions: pathConditions ? pathConditions.slice() : [],
        formulas: _formulaSnapshot,
        location: location || null,
      });
    };
    // Type-first sink classifier for property writes on a
    // binding. Prefers the binding's `typeName` (set at
    // creation/assignment) over the legacy tag-based
    // resolution, falling back only when the binding has no
    // type yet. This is what turns the TypeDB from a name
    // lookup into real flow-sensitive type tracking.
    const _classifyBindingSink = (bind, propName) => {
      if (bind && bind.typeName) {
        return _classifySinkByTypeViaDB(DEFAULT_TYPE_DB, bind.typeName, propName);
      }
      // Untyped binding — fall back to tag-based lookup for
      // element bindings whose origin tag is known.
      var tag = getElementTag(bind);
      return classifySink(propName, tag);
    };
    const checkSinkAssignment = (el, propName, valBinding, tok) => {
      if (!taintEnabled || !valBinding) return;
      var toks = valBinding.kind === 'chain' ? valBinding.toks : null;
      var taint = toks ? collectChainTaint(toks) : null;
      if (!taint || !taint.size) return;
      var sinkInfo = _classifyBindingSink(el, propName);
      if (sinkInfo && sinkInfo.severity !== 'safe') {
        var tag = getElementTag(el);
        var loc = tok && tok._src ? { expr: tok.text || propName, line: countLines(tok._src, tok.start), pos: tok.start } : null;
        recordTaintFinding(sinkInfo.type, sinkInfo.severity, propName, tag, taint, taintCondStack, loc);
      }
    };
    const checkSinkSetAttribute = (el, attrName, valBinding) => {
      if (!taintEnabled || !valBinding || !attrName) return;
      var toks = valBinding.kind === 'chain' ? valBinding.toks : null;
      var taint = toks ? collectChainTaint(toks) : null;
      if (!taint || !taint.size) return;
      var tag = getElementTag(el);
      // Attribute-name sinks (onclick, style, etc.) via db.attrSinks.
      var attrSinkInfo = _classifyAttrSinkViaDB(DEFAULT_TYPE_DB, attrName);
      if (attrSinkInfo) {
        recordTaintFinding(attrSinkInfo.type, attrSinkInfo.severity, attrName, tag, taint, taintCondStack);
      }
      // Element-specific attribute sinks (iframe.src, a.href,
      // form.action) via the binding's typeName.
      var elSinkInfo = _classifyBindingSink(el, attrName);
      if (elSinkInfo && elSinkInfo.severity !== 'safe') {
        recordTaintFinding(elSinkInfo.type, elSinkInfo.severity, attrName, tag, taint, taintCondStack);
      }
    };
    const checkSinkCall = (callExpr, argBindings, tok) => {
      if (!taintEnabled || !argBindings) return;
      var sinkInfo = _classifyCallSinkViaDB(DEFAULT_TYPE_DB, callExpr, typedScope);
      if (!sinkInfo) return;
      for (var ai = 0; ai < argBindings.length; ai++) {
        var ab = argBindings[ai];
        if (!ab) continue;
        var toks = ab.kind === 'chain' ? ab.toks : null;
        var taint = toks ? collectChainTaint(toks) : null;
        if (taint && taint.size) {
          var loc = tok && tok._src ? { expr: callExpr, line: countLines(tok._src, tok.start), pos: tok.start } : null;
          recordTaintFinding(sinkInfo.type, sinkInfo.severity, callExpr, null, taint, taintCondStack, loc);
          break;
        }
      }
    };

    // Tracked virtual DOM elements, recorded in creation order. Each entry
    // is an elementBinding/textNodeBinding (mutable) so subsequent
    // `el.prop = ...` / `el.appendChild(...)` statements update the same
    // object across references.
    const domElements = [];
    const domOps = [];
    const domFactory = makeElementFactory();
    const elementBinding = domFactory.element;
    const textNodeBinding = domFactory.textNode;
    // Apply a mutation to an element binding's property path.
    const applyElementSet = (el, path, val, tok) => {
      if (!el || el.kind !== 'element') return;
      // Taint: check if assigning a tainted value to a sink property.
      if (path.length === 1) checkSinkAssignment(el, path[0], val, tok);
      const seg = path[0];
      if (path.length === 1) {
        if (seg === 'innerHTML' || seg === 'outerHTML') { el.html = val; }
        else if (seg === 'textContent' || seg === 'innerText' || seg === 'nodeValue') { el.text = val; }
        else if (seg === 'className') {
          const s = val && val.kind === 'chain' ? chainAsKnownString(val) : null;
          el.classList = s === null ? null : s.split(/\s+/).filter(Boolean);
        }
        else { el.props[seg] = val; }
      } else if (path.length === 2 && seg === 'style') {
        el.styles[path[1]] = val;
      } else if (path.length >= 2 && seg === 'dataset') {
        el.attrs['data-' + path[1]] = val;
      }
      domOps.push({ op: 'set', element: el, path, value: val });
    };
    // Apply a DOM method call to an element binding. `argBinds` is an
    // array of bindings (chain / element / etc.) from readCallArgBindings.
    const applyElementMethod = (el, method, argBinds) => {
      if (!el || el.kind !== 'element') return;
      if (method === 'appendChild' || method === 'append' || method === 'prepend') {
        for (const arg of argBinds) {
          if (!arg) continue;
          if (arg.kind === 'element' || arg.kind === 'textNode') {
            arg.attached = true;
            if (method === 'prepend') el.children.unshift(arg);
            else el.children.push(arg);
          } else if (arg.kind === 'chain') {
            // append text / stringified fragment
            if (method === 'prepend') el.children.unshift({ kind: 'textLike', chain: arg });
            else el.children.push({ kind: 'textLike', chain: arg });
          }
        }
        domOps.push({ op: method, element: el, args: argBinds });
        return;
      }
      if (method === 'setAttribute' && argBinds.length === 2) {
        const name = argBinds[0] && argBinds[0].kind === 'chain' ? chainAsKnownString(argBinds[0]) : null;
        if (name !== null) {
          el.attrs[name] = argBinds[1];
          checkSinkSetAttribute(el, name, argBinds[1]);
        }
        domOps.push({ op: 'setAttribute', element: el, name, value: argBinds[1] });
        return;
      }
      if (method === 'removeAttribute' && argBinds.length === 1) {
        const name = argBinds[0] && argBinds[0].kind === 'chain' ? chainAsKnownString(argBinds[0]) : null;
        if (name !== null) delete el.attrs[name];
        domOps.push({ op: 'removeAttribute', element: el, name });
        return;
      }
      domOps.push({ op: method, element: el, args: argBinds });
    };

    // Cache DOM factory results by the token index where the call starts,
    // so repeated readBase attempts at the same position return the same
    // element binding (readValue's two-pass approach can call readBase
    // twice for one source expression).
    const domFactoryCache = Object.create(null);
    const cacheOrCall = (k, make) => {
      if (domFactoryCache[k]) return domFactoryCache[k];
      const r = make();
      if (r) domFactoryCache[k] = r;
      return r;
    };
    // DOM factory functions: `document.createElement(tag)`,
    // `document.getElementById(id)`, etc. Each is called with the arg
    // chain list and returns { bind, next } or null.
    const DOM_FACTORIES = {
      'document.createElement': (args, k, next) => cacheOrCall(k, () => {
        if (args.length !== 1) return null;
        const tag = chainAsKnownString(chainBinding(args[0]));
        if (tag === null) return null;
        const el = elementBinding({ kind: 'create', tag });
        domElements.push(el);
        domOps.push({ op: 'create', element: el });
        return { bind: el, next };
      }),
      'document.createTextNode': (args, k, next) => cacheOrCall(k, () => {
        if (args.length !== 1) return null;
        const chain = chainBinding(args[0]);
        const tn = textNodeBinding(chain);
        domElements.push(tn);
        domOps.push({ op: 'createTextNode', element: tn });
        return { bind: tn, next };
      }),
      'document.getElementById': (args, k, next) => cacheOrCall(k, () => {
        if (args.length !== 1) return null;
        const id = chainAsKnownString(chainBinding(args[0]));
        if (id === null) return null;
        const el = elementBinding({ kind: 'lookup', by: 'id', value: id });
        domElements.push(el);
        domOps.push({ op: 'lookup', element: el, by: 'id', value: id });
        return { bind: el, next };
      }),
      'document.querySelector': (args, k, next) => cacheOrCall(k, () => {
        if (args.length !== 1) return null;
        const sel = chainAsKnownString(chainBinding(args[0]));
        if (sel === null) return null;
        const el = elementBinding({ kind: 'lookup', by: 'selector', value: sel });
        domElements.push(el);
        domOps.push({ op: 'lookup', element: el, by: 'selector', value: sel });
        return { bind: el, next };
      }),
    };

    const topBlock = () => stack[stack.length - 1];
    // Replace the actual value with a name-reference chain for variables
    // the pre-pass flagged as externally mutable, so reads of such names
    // consistently produce an opaque source reference rather than a
    // stale initial value.
    const asRef = (name, value) => {
      if (externallyMutable && externallyMutable.has(name)) {
        return chainBinding([exprRef(name)]);
      }
      return value;
    };
    // Track names explicitly declared with var/let/const/function.
    // Used to distinguish `var location = x` (local) from `location = x` (global write).
    const declaredNames = new Set();
    // Infer a binding's TypeDB type at assignment time and tag
    // it with `typeName`.
    //
    // Three cases:
    //
    //  1. **Chain binding with single opaque ref** (most common):
    //     walk the token text through the TypeDB. Covers
    //     `var loc = window.location`, `var f = eval`,
    //     `var resp = fetch("/api")`, `var fr = new FileReader()`.
    //
    //  2. **Element binding from a tracked `createElement`**:
    //     resolve the tag via `db.tagMap` to the concrete
    //     HTMLxElement type. Covers
    //     `var el = document.createElement("iframe")` →
    //     HTMLIFrameElement.
    //
    //  3. Everything else passes through unchanged.
    //
    // Returns a shallow copy with `typeName` set (never mutates
    // the input) so shared bindings stay safe. Bindings that
    // already carry a typeName pass through unchanged.
    const _withInferredType = (value) => {
      if (!value || value.typeName) return value;
      // Note: element bindings have their `typeName` set at
      // creation time by the element factory, not here. Mutating
      // or copying them would break the identity-based tracking
      // that underlies `applyElementSet` / `applyElementMethod`.
      // Case 1: chain with a single opaque ref.
      if (value.kind !== 'chain') return value;
      if (!value.toks || value.toks.length !== 1) return value;
      var t = value.toks[0];
      if (!t || t.type !== 'other' || !t.text) return value;
      var typeName = _resolveExprTypeViaDB(DEFAULT_TYPE_DB, t.text, typedScope);
      if (!typeName) return value;
      return { kind: 'chain', toks: value.toks, typeName: typeName };
    };
    const declBlock = (name, value) => {
      declaredNames.add(name);
      var tv = _withInferredType(value);
      topBlock().bindings[name] = asRef(name, tv);
      _trackMayBeAssign(name, tv);
    };
    const declFunction = (name, value) => {
      declaredNames.add(name);
      var tv = _withInferredType(value);
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].isFunction) {
          stack[i].bindings[name] = asRef(name, tv);
          _trackMayBeAssign(name, tv);
          return;
        }
      }
    };
    const assignName = (name, value) => {
      var tv = _withInferredType(value);
      for (let i = stack.length - 1; i >= 0; i--) {
        if (name in stack[i].bindings) {
          stack[i].bindings[name] = asRef(name, tv);
          _trackMayBeAssign(name, tv);
          return;
        }
      }
      stack[0].bindings[name] = asRef(name, tv); // implicit global
      _trackMayBeAssign(name, tv);
    };
    const resolve = (name) => {
      for (let i = stack.length - 1; i >= 0; i--) {
        if (name in stack[i].bindings) return stack[i].bindings[name];
      }
      return null;
    };
    // Walk a dotted path ('obj.a.b') resolving into object/array/chain
    // bindings. Handles `.length` specially on arrays and on chains whose
    // operands are all known string/template literals.
    const resolvePath = async (path) => {
      const parts = path.split('.');
      let b = resolve(parts[0]);
      for (let i = 1; i < parts.length && b; i++) {
        const p = parts[i];
        if (b.kind === 'object') {
          // Check for getter: __getter_prop is a function that returns the value.
          var _getter = b.props['__getter_' + p];
          if (_getter && _getter.kind === 'function') {
            var _getResult = await instantiateFunction(_getter, []);
            if (_getResult && _getResult.kind) b = _getResult;
            else if (_getResult) b = chainBinding(_getResult);
            else b = null;
            continue;
          }
          b = b.props[p] || null;
        } else if (b.kind === 'chain' && b.toks.length === 1 && b.toks[0].type === 'other') {
          // Opaque chain (e.g. parameter bound to exprRef) — extend the
          // path so `column.title` becomes `store.columns[i].title`.
          //
          // Type-based resolution: if the chain binding carries
          // a typeName (set at assignment time by
          // `_withInferredType`), walk the remaining path on
          // that type. This is what makes `fr.result` resolve
          // to `file` even though `fr`'s original RHS text was
          // `new FileReader()` — the binding remembers the
          // return type directly instead of relying on
          // expression-text concatenation.
          var _remainingPath = parts.slice(i).join('.');
          var _extText = b.toks[0].text + '.' + _remainingPath;
          var _extLabel = null;
          var _extType = null;
          var _typed = false;
          if (b.typeName) {
            var _typedRootName = '__t' + (Math.random() * 1e9 | 0) + '__';
            var _typedRootScope = (function (rootName, rootType) {
              return function (n) { return n === rootName ? { typeName: rootType } : typedScope(n); };
            })(_typedRootName, b.typeName);
            var _syntheticExpr = _typedRootName + '.' + _remainingPath;
            _extLabel = getTaintSource(_syntheticExpr, _typedRootScope);
            _extType = _resolveExprTypeViaDB(DEFAULT_TYPE_DB, _syntheticExpr, _typedRootScope);
            _typed = (_extLabel != null || _extType != null);
          }
          var _extRef;
          if (_typed) {
            // Type-precise extension: create a fresh ref
            // carrying ONLY the label resolved via the type
            // walk. This narrows a bulk-tainted parameter
            // (e.g. an ErrorEvent param with both `network`
            // and `url` labels) down to the specific prop's
            // label when the user reads `e.filename`.
            _extRef = exprRef(_extText);
            if (_extLabel) {
              _extRef.taint = new Set();
              if (typeof _extLabel === 'string') _extRef.taint.add(_extLabel);
              else for (var _extL of _extLabel) _extRef.taint.add(_extL);
            }
          } else {
            // No type info — inherit the old taint via
            // deriveExprRef and re-check the extended text for
            // source labels. This keeps untyped propagation
            // working for opaque parameter chains.
            _extRef = deriveExprRef(_extText, b.toks);
            var _untypedLabel = checkTaintSource(_extText);
            if (_untypedLabel) {
              if (!_extRef.taint) _extRef.taint = new Set();
              if (typeof _untypedLabel === 'string') _extRef.taint.add(_untypedLabel);
              else for (var _untypedL of _untypedLabel) _extRef.taint.add(_untypedL);
            }
          }
          b = chainBinding([_extRef]);
          if (!_extType) _extType = _resolveExprTypeViaDB(DEFAULT_TYPE_DB, _extText, typedScope);
          if (_extType) b.typeName = _extType;
          break;
        } else if (p === 'length' && b.kind === 'array') {
          b = chainBinding([makeSynthStr(String(b.elems.length))]);
        } else if (p === 'length' && b.kind === 'chain') {
          let n = 0; let ok = true;
          for (const tk of b.toks) {
            if (tk.type === 'plus') continue;
            if (tk.type === 'str') { n += tk.text.length; continue; }
            if (tk.type === 'tmpl') {
              let hasExpr = false; let tl = 0;
              for (const part of tk.parts) {
                if (part.kind === 'text') tl += decodeJsString(part.raw, '`').length;
                else { hasExpr = true; break; }
              }
              if (hasExpr) { ok = false; break; }
              n += tl;
              continue;
            }
            ok = false; break;
          }
          b = ok ? chainBinding([makeSynthStr(String(n))]) : null;
        } else {
          return null;
        }
      }
      return b;
    };
    // Flatten a binding to plain text if possible (all parts are string
    // literals or templates whose exprs all resolve). Returns null otherwise.
    const bindingToText = async (b) => {
      if (!b) return null;
      if (b.kind !== 'chain') return null;
      let text = '';
      for (const t of b.toks) {
        if (t.type === 'plus') continue;
        if (t.type === 'str') { text += t.text; continue; }
        if (t.type === 'tmpl') {
          const rw = await templateToText(t);
          if (rw === null) return null;
          text += rw;
          continue;
        }
        return null;
      }
      return text;
    };
    // Re-tokenize an expression source string and parse it as a concat chain
    // using the in-scope bindings. Returns the chain token list or null.
    const evalExprSrc = async (src) => {
      const exprTokens = tokenize(src);
      if (!exprTokens.length) return null;
      const saved = tks;
      tks = exprTokens;
      const r = await readConcatExpr(0, exprTokens.length, TERMS_NONE);
      tks = saved;
      if (!r || r.next !== exprTokens.length) return null;
      return r.toks;
    };

    // Rewrite a template literal as plain text by resolving each ${expr}.
    // Returns null if any expr can't be resolved to plain text.
    const templateToText = async (tok) => {
      let text = '';
      for (const p of tok.parts) {
        if (p.kind === 'text') { text += decodeJsString(p.raw, '`'); continue; }
        // Fast path: bare identifier/member path.
        if (TEMPLATE_EXPR_PATH_RE.test(p.expr)) {
          const path = p.expr.replace(/\s+/g, '');
          const b = await resolvePath(path);
          if (!b) return null;
          const t2 = await bindingToText(b);
          if (t2 === null) return null;
          text += t2;
          continue;
        }
        // General expression: re-tokenize and evaluate as a concat chain.
        const chain = await evalExprSrc(p.expr);
        if (!chain) return null;
        const t2 = await bindingToText(chainBinding(chain));
        if (t2 === null) return null;
        text += t2;
      }
      return text;
    };
    // Rewrite a tmpl token in place to inline every resolvable expr; falls
    // back to the original token if any expr can't be resolved.
    const rewriteTemplate = async (tok) => {
      if (tok.type !== 'tmpl') return tok;
      // All-resolvable fast path: full text.
      const asText = await templateToText(tok);
      if (asText !== null) return makeSynthStr(asText);
      // Partial rewrite: replace resolvable exprs with their plain text, keep
      // others. Coalesce adjacent text parts afterward.
      let changed = false;
      const parts = [];
      for (const p of tok.parts) {
        if (p.kind === 'text') { parts.push({ kind: 'text', raw: p.raw }); continue; }
        let resolvedText = null;
        var _tmplChain = null;
        if (TEMPLATE_EXPR_PATH_RE.test(p.expr)) {
          const path = p.expr.replace(/\s+/g, '');
          const b = await resolvePath(path);
          if (b) { resolvedText = await bindingToText(b); if (b.kind === 'chain') _tmplChain = b.toks; }
        } else {
          const chain = await evalExprSrc(p.expr);
          _tmplChain = chain;
          if (chain) {
            // Check if the chain contains structured tokens (cond, trycatch, switch).
            const hasStructured = chain.some(t => t.type === 'cond' || t.type === 'trycatch' || t.type === 'switch' || t.type === 'iter');
            if (hasStructured) {
              // Can't embed in template — flatten by converting this
              // template into a concat chain. Return the full chain with
              // the structured tokens spliced in at this position.
              const out = [];
              for (const prev of parts) {
                if (out.length) out.push(SYNTH_PLUS);
                if (prev.kind === 'text') out.push(makeSynthStr(decodeJsString(prev.raw, '`')));
                else out.push(exprRef(prev.expr));
              }
              if (out.length) out.push(SYNTH_PLUS);
              for (const ct of chain) out.push(ct);
              // Process remaining parts.
              for (let ri = tok.parts.indexOf(p) + 1; ri < tok.parts.length; ri++) {
                const rp = tok.parts[ri];
                out.push(SYNTH_PLUS);
                if (rp.kind === 'text') out.push(makeSynthStr(decodeJsString(rp.raw, '`')));
                else out.push(exprRef(rp.expr));
              }
              // Return a synthetic chain token that expandChain can handle.
              return { type: '_chain', toks: out };
            }
            resolvedText = await bindingToText(chainBinding(chain));
          }
        }
        if (resolvedText !== null) {
          // Taint: if the resolved chain carries taint, don't inline as
          // text — keep as expr so collectChainTaint can find it.
          if (taintEnabled && _tmplChain && collectChainTaint(_tmplChain)) {
            parts.push({ kind: 'expr', expr: p.expr, toks: _tmplChain });
            changed = true;
            continue;
          }
          const raw = resolvedText.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
          parts.push({ kind: 'text', raw });
          changed = true;
          continue;
        }
        // Attach resolved chain toks to expr parts so collectChainTaint can find them.
        var _exprPart = { kind: 'expr', expr: p.expr };
        if (taintEnabled && _tmplChain && collectChainTaint(_tmplChain)) {
          _exprPart.toks = _tmplChain;
          changed = true;
        }
        parts.push(_exprPart);
      }
      if (!changed) return tok;
      // Coalesce adjacent text parts.
      const merged = [];
      for (const p of parts) {
        const last = merged[merged.length - 1];
        if (p.kind === 'text' && last && last.kind === 'text') last.raw += p.raw;
        else merged.push({ ...p });
      }
      return { type: 'tmpl', parts: merged, start: tok.start, end: tok.end, _src: tok._src };
    };

    // Skip over the RHS expression of a declarator or assignment starting at
    // index `k`, returning the index of the terminating `,`/`;` (or `stop`).
    const skipExpr = (k, stop) => {
      let depth = 0;
      while (k < stop) {
        const tk = tks[k];
        if (tk.type === 'open') depth++;
        else if (tk.type === 'close') {
          if (depth === 0) break;
          depth--;
        } else if (depth === 0 && tk.type === 'sep' && (tk.char === ',' || tk.char === ';')) break;
        k++;
      }
      return k;
    };

    // Scan forward from `i` until a top-level `,` or the pattern's closing
    // bracket is reached. Used to capture the default-value expression after
    // `=` inside a destructuring pattern. Returns the index of the terminator.
    const scanDefaultEnd = (i, stop) => {
      let depth = 0;
      while (i < stop) {
        const tk = tks[i];
        if (tk.type === 'open') { depth++; i++; continue; }
        if (tk.type === 'close') {
          if (depth === 0) return i;
          depth--; i++; continue;
        }
        if (depth === 0 && tk.type === 'sep' && tk.char === ',') return i;
        i++;
      }
      return i;
    };

    // Read a destructuring pattern starting at an opening `{` or `[`.
    // Supported:
    //   object: { a }, { a: b }, { a, b: c }, { a = 1 }, { a: b = 1 },
    //           { a, ...rest }
    //   array:  [ a, b ], [ a, , b ] (holes bind nothing), [ a = 1 ],
    //           [ a, ...rest ]
    // Returns { pattern, next } or null. Pattern shapes:
    //   { kind:'obj-pattern', entries: [{key, name, dflt}], rest }
    //   { kind:'arr-pattern', entries: [{name, dflt}|null], rest }
    // `dflt` is `{start, end}` token-range or null; `rest` is a name or null.
    const readDestructurePattern = (k, stop) => {
      const open = tks[k];
      if (!open || open.type !== 'open') return null;
      if (open.char === '{') {
        const entries = [];
        let rest = null;
        let i = k + 1;
        while (i < stop) {
          const tk = tks[i];
          if (tk.type === 'close' && tk.char === '}') break;
          // Object rest: `...name` must be the final entry.
          if (tk.type === 'other' && tk.text.startsWith('...') && IDENT_RE.test(tk.text.slice(3))) {
            rest = tk.text.slice(3);
            i++;
            break;
          }
          let key = null;
          let name = null;
          if (tk.type === 'other') {
            if (IDENT_RE.test(tk.text)) {
              key = tk.text;
              i++;
              const sep = tks[i];
              if (sep && sep.type === 'other' && sep.text === ':') {
                i++;
                const alias = tks[i];
                // Nested destructuring: { key: { ... } } or { key: [ ... ] }
                if (alias && alias.type === 'open' && (alias.char === '{' || alias.char === '[')) {
                  var nested = readDestructurePattern(i, stop);
                  if (nested) {
                    entries.push({ key, nested: nested.pattern });
                    i = nested.next;
                    if (tks[i] && tks[i].type === 'sep' && tks[i].char === ',') i++;
                    continue;
                  }
                  return null;
                }
                if (!alias || alias.type !== 'other' || !IDENT_RE.test(alias.text)) return null;
                name = alias.text;
                i++;
              } else {
                name = key;
              }
            } else if (tk.text.endsWith(':') && IDENT_RE.test(tk.text.slice(0, -1))) {
              key = tk.text.slice(0, -1);
              i++;
              const alias = tks[i];
              if (!alias || alias.type !== 'other' || !IDENT_RE.test(alias.text)) return null;
              name = alias.text;
              i++;
            } else {
              return null;
            }
          } else {
            return null;
          }
          let dflt = null;
          const maybeEq = tks[i];
          if (maybeEq && maybeEq.type === 'sep' && maybeEq.char === '=') {
            const dStart = i + 1;
            const dEnd = scanDefaultEnd(dStart, stop);
            dflt = { start: dStart, end: dEnd };
            i = dEnd;
          }
          entries.push({ key, name, dflt });
          const comma = tks[i];
          if (comma && comma.type === 'sep' && comma.char === ',') { i++; continue; }
          break;
        }
        const close = tks[i];
        if (!close || close.type !== 'close' || close.char !== '}') return null;
        return { pattern: { kind: 'obj-pattern', entries, rest }, next: i + 1 };
      }
      if (open.char === '[') {
        const entries = [];
        let rest = null;
        let i = k + 1;
        while (i < stop) {
          const tk = tks[i];
          if (tk.type === 'close' && tk.char === ']') break;
          if (tk.type === 'sep' && tk.char === ',') { entries.push(null); i++; continue; }
          // Array rest: `...name` must be the final entry.
          if (tk.type === 'other' && tk.text.startsWith('...') && IDENT_RE.test(tk.text.slice(3))) {
            rest = tk.text.slice(3);
            i++;
            break;
          }
          if (tk.type === 'other' && IDENT_RE.test(tk.text)) {
            const name = tk.text;
            i++;
            let dflt = null;
            const maybeEq = tks[i];
            if (maybeEq && maybeEq.type === 'sep' && maybeEq.char === '=') {
              const dStart = i + 1;
              const dEnd = scanDefaultEnd(dStart, stop);
              dflt = { start: dStart, end: dEnd };
              i = dEnd;
            }
            entries.push({ name, dflt });
            const comma = tks[i];
            if (comma && comma.type === 'sep' && comma.char === ',') { i++; continue; }
            break;
          }
          return null;
        }
        const close = tks[i];
        if (!close || close.type !== 'close' || close.char !== ']') return null;
        return { pattern: { kind: 'arr-pattern', entries, rest }, next: i + 1 };
      }
      return null;
    };

    // Resolve a default-value token range to a binding. Falls through to a
    // chain reference if the expression isn't foldable, so the name still
    // binds to *something* deterministic rather than null.
    const resolveDefault = async (dflt) => {
      if (!dflt) return null;
      const r = await readValue(dflt.start, dflt.end, null);
      if (r && r.binding) return r.binding;
      const toks = [];
      for (let j = dflt.start; j < dflt.end; j++) toks.push(tks[j]);
      return chainBinding(toks.length ? toks : [exprRef('undefined')]);
    };

    // Extract the source's "path prefix" from an opaque chain binding.
    // The walker often resolves a root like `location`, `e.data`, or
    // `window.location` to a single-token chain carrying an exprRef
    // with the original source text. When we then destructure that
    // binding — `const { search } = location` — each destructured
    // name is semantically equivalent to reading `<prefix>.<key>`
    // off the same path, so recovering the prefix lets us check
    // whether `<prefix>.<key>` is itself a known taint source AND
    // synthesize a tainted opaque ref for the destructured binding.
    // Returns null when the source isn't a single-token opaque ref.
    const _pathPrefixFromSource = (source) => {
      if (!source || source.kind !== 'chain' || !source.toks || source.toks.length !== 1) return null;
      const tok = source.toks[0];
      if (!tok || tok.type !== 'other') return null;
      if (!IDENT_RE.test(tok.text) && tok.text.indexOf('.') < 0) return null;
      return tok.text;
    };
    // Bind names from `pattern` by walking into `source` (a binding).
    // When `source` is an opaque taint-carrying ref or a known
    // dotted path (e.g. `location`, `e.data`), each destructured
    // entry inherits the taint AND — when its full path matches a
    // TAINT_SOURCES entry — picks up the path's source label.
    const applyPatternBindings = async (pattern, source, bind) => {
      // Compute per-source-wide helpers once: the set of taint
      // labels already attached to the source chain (via earlier
      // resolution / sink propagation) and, for opaque refs, the
      // dotted path prefix we can append each destructured key to.
      const srcTaint = source ? collectChainTaint(source.kind === 'chain' ? source.toks : null) : null;
      const srcPathPrefix = _pathPrefixFromSource(source);
      // Build a tainted opaque chain for a destructured entry whose
      // value couldn't be resolved directly from the source (common
      // when the source is an event param, a taint root, or any
      // other opaque chain). The synthesized chain carries the same
      // taint labels as the source PLUS any label attached to the
      // specific dotted path.
      const _synthesizeChild = (keyText) => {
        if (!source) return null;
        const pathText = srcPathPrefix ? (srcPathPrefix + '.' + keyText) : keyText;
        const ref = exprRef(pathText);
        // Attach the accumulated taint (source labels + path-specific).
        let labels = null;
        if (srcTaint) labels = new Set(srcTaint);
        // getTaintSource returns a single label string (or null).
        const pathLabel = getTaintSource(pathText, typedScope);
        if (pathLabel) {
          if (!labels) labels = new Set();
          labels.add(pathLabel);
        }
        if (labels && labels.size > 0) {
          ref.taint = labels;
          return chainBinding([ref]);
        }
        // No taint at all — return null so the caller falls back to
        // its default-value handling (or leaves the binding null,
        // same as the old behaviour).
        return null;
      };
      if (pattern.kind === 'obj-pattern') {
        const props = source && source.kind === 'object' ? source.props : null;
        const seen = Object.create(null);
        for (const entry of pattern.entries) {
          seen[entry.key] = true;
          let val = props ? (props[entry.key] || null) : null;
          if (val === null) val = _synthesizeChild(entry.key);
          if (val === null && entry.dflt) val = await resolveDefault(entry.dflt);
          if (entry.nested) {
            // Nested destructuring: recursively apply pattern.
            await applyPatternBindings(entry.nested, val, bind);
          } else {
            bind(entry.name, val);
          }
        }
        if (pattern.rest) {
          if (props) {
            const restProps = Object.create(null);
            for (const k of Object.keys(props)) {
              if (!seen[k]) restProps[k] = props[k];
            }
            bind(pattern.rest, objectBinding(restProps));
          } else {
            // Opaque source rest: propagate the source's taint onto
            // a synthesized rest-object ref so later reads don't
            // lose the taint signal.
            bind(pattern.rest, source || null);
          }
        }
        return;
      }
      if (pattern.kind === 'arr-pattern') {
        const elems = source && source.kind === 'array' ? source.elems : null;
        for (let i = 0; i < pattern.entries.length; i++) {
          const entry = pattern.entries[i];
          if (entry === null) continue;
          let val = elems ? (elems[i] || null) : null;
          if (val === null) val = _synthesizeChild(String(i));
          if (val === null && entry.dflt) val = await resolveDefault(entry.dflt);
          bind(entry.name, val);
        }
        if (pattern.rest) {
          if (elems) {
            bind(pattern.rest, arrayBinding(elems.slice(pattern.entries.length)));
          } else {
            bind(pattern.rest, source || null);
          }
        }
        return;
      }
    };

    // --- Unified evaluation stack for iterative expression parsing ---
    // Every expression parser function is a step function driven by this
    // loop. No JS-stack recursion for any nesting depth. Step functions
    // push child frames onto _evalStack and return; the loop processes
    // them iteratively. Results pass through _resultSlot.
    const _evalStack = [];
    const _resultSlot = { value: null, has: false };
    const _completeFrame = (result) => { _evalStack.pop(); _resultSlot.value = result; _resultSlot.has = true; };
    const _consumeResult = () => { if (!_resultSlot.has) return undefined; const v = _resultSlot.value; _resultSlot.value = null; _resultSlot.has = false; return v; };
    const _evalLoop = async () => {
      const baseDepth = _evalStack.length - 1;
      while (_evalStack.length > baseDepth) {
        const _f = _evalStack[_evalStack.length - 1];
        switch (_f.type) {
          case 'READ_ARRAY_LIT':         await _stepReadArrayLit(_f); break;
          case 'READ_OBJECT_LIT':        await _stepReadObjectLit(_f); break;
          case 'READ_CALL_ARG_BINDINGS': await _stepReadCallArgBindings(_f); break;
          case 'READ_CONCAT_ARGS':       _stepReadConcatArgs(_f); break;
          case 'READ_CALL_ARG_BINDINGS': await _stepReadCallArgBindings(_f); break;
          case 'READ_CONCAT_ARGS':       _stepReadConcatArgs(_f); break;
          case 'READ_VALUE':             { const r = await readValue(_f.k, _f.stop, _f.terms); _completeFrame(r); break; }
          case 'READ_CONCAT_EXPR':       { const r = await readConcatExpr(_f.i, _f.stop, _f.terms); _completeFrame(r); break; }
          default: _completeFrame(null); break;
        }
      }
      return _consumeResult();
    };

    // Read an object literal `{ key: value, ... }` starting at index `k`.
    // Keys are bare identifiers or quoted strings. Values are any readValue
    // (chain, nested object, or nested array). Returns { binding, next }.
    const readObjectLit = async (k, stop) => {
      if (!tks[k] || tks[k].type !== 'open' || tks[k].char !== '{') return null;
      _evalStack.push({ type: 'READ_OBJECT_LIT', i: k + 1, stop, props: Object.create(null), _waitingKey: null });
      return await _evalLoop();
    };
    const _stepReadObjectLit = async (frame) => {
      // Consume child result based on resume phase
      if (_resultSlot.has) {
        if (frame._rp === 'val') {
          const val = _consumeResult();
          if (!val) { _completeFrame(null); return; }
          frame.props[frame._waitingKey] = val.binding; frame.i = val.next;
          const sep = tks[frame.i]; if (sep && sep.type === 'sep' && sep.char === ',') frame.i++;
          frame._rp = null;
        } else if (frame._rp === 'computed') {
          const inner = _consumeResult();
          if (!inner || !inner.toks || inner.toks.length !== 1 || inner.toks[0].type !== 'str') { _completeFrame(null); return; }
          frame._pendingKey = inner.toks[0].text;
          frame.i = frame._computedEnd + 1;
          frame._rp = null;
        }
      }
      const props = frame.props, stop = frame.stop;
      while (frame.i < stop) {
        const tk = tks[frame.i];
        if (!tk) { _completeFrame(null); return; }
        if (tk.type === 'close' && tk.char === '}') break;
        if (tk.type === 'other' && tk.text.startsWith('...')) {
          const name = tk.text.slice(3);
          if (IDENT_OR_PATH_RE.test(name)) { const b = await resolvePath(name); if (b && b.kind === 'object') { for (const kk in b.props) props[kk] = b.props[kk]; frame.i++; const sep = tks[frame.i]; if (sep && sep.type === 'sep' && sep.char === ',') { frame.i++; continue; } break; } }
          _completeFrame(null); return;
        }
        var keyName = frame._pendingKey || null; frame._pendingKey = null;
        if (!keyName) {
          if (tk.type === 'str') { keyName = tk.text; frame.i++; }
          else if (tk.type === 'other') {
            if (tk.text.endsWith(':') && IDENT_RE.test(tk.text.slice(0, -1))) {
              keyName = tk.text.slice(0, -1); frame.i++;
              frame._waitingKey = keyName; frame._rp = 'val';
              _evalStack.push({ type: 'READ_VALUE', k: frame.i, stop, terms: TERMS_OBJ, phase: 0 });
              return;
            }
            if (IDENT_RE.test(tk.text)) {
              if ((tk.text === 'get' || tk.text === 'set' || tk.text === 'async') && tks[frame.i + 1] && tks[frame.i + 1].type === 'other' && IDENT_RE.test(tks[frame.i + 1].text) && tks[frame.i + 2] && tks[frame.i + 2].type === 'open' && tks[frame.i + 2].char === '(') {
                var _gsPrefix = tk.text; frame.i++; keyName = tks[frame.i].text; frame.i++;
                var _gsParams = [], _gsJ = frame.i;
                if (tks[_gsJ] && tks[_gsJ].type === 'open' && tks[_gsJ].char === '(') { _gsJ++; while (_gsJ < stop) { if (tks[_gsJ].type === 'close' && tks[_gsJ].char === ')') { _gsJ++; break; } var _gsp = parseParamWithDefault(tks, _gsJ, stop); if (_gsp) { _gsParams.push(_gsp.param); _gsJ = _gsp.next; } else _gsJ++; if (tks[_gsJ] && tks[_gsJ].type === 'sep' && tks[_gsJ].char === ',') _gsJ++; } }
                if (tks[_gsJ] && tks[_gsJ].type === 'open' && tks[_gsJ].char === '{') {
                  var _gsBD = 1, _gsBE = _gsJ + 1;
                  while (_gsBE < stop && _gsBD > 0) { if (tks[_gsBE].type === 'open' && tks[_gsBE].char === '{') _gsBD++; if (tks[_gsBE].type === 'close' && tks[_gsBE].char === '}') _gsBD--; _gsBE++; }
                  var _gsFnBind = functionBinding(_gsParams, _gsJ, _gsBE, true);
                  if (_gsPrefix === 'get') props['__getter_' + keyName] = _gsFnBind; else props[keyName] = _gsFnBind;
                  frame.i = _gsBE; if (tks[frame.i] && tks[frame.i].type === 'sep' && tks[frame.i].char === ',') frame.i++;
                  continue;
                }
              } else { keyName = tk.text; frame.i++; }
            } else { _completeFrame(null); return; }
          } else if (tk.type === 'open' && tk.char === '[') {
            let depth = 1, j = frame.i + 1;
            while (j < stop && depth > 0) { if (tks[j].type === 'open' && tks[j].char === '[') depth++; else if (tks[j].type === 'close' && tks[j].char === ']') depth--; if (depth === 0) break; j++; }
            if (!tks[j] || tks[j].type !== 'close') { _completeFrame(null); return; }
            frame._rp = 'computed'; frame._computedEnd = j;
            _evalStack.push({ type: 'READ_CONCAT_EXPR', i: frame.i + 1, stop: j, terms: TERMS_NONE, phase: 0, out: [] });
            return;
          } else { _completeFrame(null); return; }
        }
        if (tks[frame.i] && tks[frame.i].type === 'open' && tks[frame.i].char === '(') {
          let d = 1; frame.i++; while (frame.i < stop && d > 0) { if (tks[frame.i].type === 'open' && tks[frame.i].char === '(') d++; if (tks[frame.i].type === 'close' && tks[frame.i].char === ')') d--; frame.i++; }
          if (tks[frame.i] && tks[frame.i].type === 'open' && tks[frame.i].char === '{') { let bd = 1; frame.i++; while (frame.i < stop && bd > 0) { if (tks[frame.i].type === 'open' && tks[frame.i].char === '{') bd++; if (tks[frame.i].type === 'close' && tks[frame.i].char === '}') bd--; frame.i++; } }
          const sep = tks[frame.i]; if (sep && sep.type === 'sep' && sep.char === ',') { frame.i++; continue; } break;
        }
        if (tks[frame.i] && (tks[frame.i].type === 'sep' && (tks[frame.i].char === ',' || tks[frame.i].char === ';') || tks[frame.i].type === 'close' && tks[frame.i].char === '}')) {
          const b = resolve(keyName); props[keyName] = b || chainBinding([exprRef(keyName)]);
          if (tks[frame.i].type === 'sep' && tks[frame.i].char === ',') { frame.i++; continue; } break;
        }
        const colon = tks[frame.i];
        if (!colon) { _completeFrame(null); return; }
        if (colon.type === 'other' && colon.text === ':') { frame.i++; }
        else if (colon.type === 'other' && colon.text.startsWith(':')) { _completeFrame(null); return; }
        else { _completeFrame(null); return; }
        frame._waitingKey = keyName; frame._rp = 'val';
        _evalStack.push({ type: 'READ_VALUE', k: frame.i, stop, terms: TERMS_OBJ, phase: 0 });
        return;
      }
      const close = tks[frame.i];
      if (!close || close.type !== 'close' || close.char !== '}') { _completeFrame(null); return; }
      _completeFrame({ binding: objectBinding(props), next: frame.i + 1 });
    };

    // Read an array literal `[ v, v, ... ]`. Returns { binding, next } or null.
    const readArrayLit = async (k, stop) => {
      if (!tks[k] || tks[k].type !== 'open' || tks[k].char !== '[') return null;
      _evalStack.push({ type: 'READ_ARRAY_LIT', i: k + 1, stop, elems: [] });
      return await _evalLoop();
    };
    const _stepReadArrayLit = async (frame) => {
      if (_resultSlot.has) {
        const val = _consumeResult();
        if (!val) { _completeFrame(null); return; }
        frame.elems.push(val.binding);
        frame.i = val.next;
        const sep = tks[frame.i];
        if (sep && sep.type === 'sep' && sep.char === ',') frame.i++;
        else { const c = tks[frame.i]; if (c && c.type === 'close' && c.char === ']') { _completeFrame({ binding: arrayBinding(frame.elems), next: frame.i + 1 }); } else { _completeFrame(null); } return; }
      }
      while (frame.i < frame.stop) {
        const tk = tks[frame.i];
        if (!tk) { _completeFrame(null); return; }
        if (tk.type === 'close' && tk.char === ']') break;
        if (tk.type === 'other' && tk.text.startsWith('...')) {
          const name = tk.text.slice(3);
          if (IDENT_OR_PATH_RE.test(name)) {
            const b = await resolvePath(name);
            if (b && b.kind === 'array') { for (const e of b.elems) frame.elems.push(e); frame.i++; const sep = tks[frame.i]; if (sep && sep.type === 'sep' && sep.char === ',') { frame.i++; continue; } break; }
          }
          _completeFrame(null); return;
        }
        // Push READ_VALUE child frame and yield.
        _evalStack.push({ type: 'READ_VALUE', k: frame.i, stop: frame.stop, terms: TERMS_ARR, phase: 0 });
        return; // result consumed at top on next _evalLoop iteration
      }
      const close = tks[frame.i];
      if (!close || close.type !== 'close' || close.char !== ']') { _completeFrame(null); return; }
      _completeFrame({ binding: arrayBinding(frame.elems), next: frame.i + 1 });
    };

    // Detect an arrow-function head starting at `k`. Supports the forms
    // `() => body`, `(p1, p2) => body`, and `x => body`. Returns
    // { params, arrowNext } where `arrowNext` is the index just after `=>`,
    // or null if `k` doesn't start an arrow function.
    const peekArrow = (k, stop) => {
      let t = tks[k];
      if (!t) return null;
      // `async` prefix: `async ident => ...` / `async (params) => ...`.
      // The walker doesn't distinguish async from sync arrows — await
      // propagates through its argument as a transparent operator —
      // so we simply skip the keyword and parse the rest normally.
      if (t.type === 'other' && t.text === 'async') {
        k = k + 1;
        t = tks[k];
        if (!t) return null;
      }
      // Single-param form: `ident => body`.
      if (t.type === 'other' && IDENT_RE.test(t.text)) {
        const arrow = tks[k + 1];
        if (arrow && arrow.type === 'other' && arrow.text === '=>') {
          return { params: [{ name: t.text }], arrowNext: k + 2 };
        }
        return null;
      }
      // Paren form: `(params) => body`.
      if (t.type !== 'open' || t.char !== '(') return null;
      const params = [];
      let i = k + 1;
      const first = tks[i];
      if (first && first.type === 'close' && first.char === ')') {
        const arrow = tks[i + 1];
        if (arrow && arrow.type === 'other' && arrow.text === '=>') {
          return { params, arrowNext: i + 2 };
        }
        return null;
      }
      while (i < stop) {
        const pt = parseParamWithDefault(tks, i, stop);
        if (!pt) return null;
        params.push(pt.param);
        i = pt.next;
        const sep = tks[i];
        if (sep && sep.type === 'close' && sep.char === ')') { i++; break; }
        if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
        return null;
      }
      const arrow = tks[i];
      if (!arrow || arrow.type !== 'other' || arrow.text !== '=>') return null;
      return { params, arrowNext: i + 1 };
    };

    // Given the token index just after `=>`, determine the body range.
    // Returns { bodyStart, bodyEnd, isBlock } or null. For expression bodies,
    // the body extends up to the first top-level `,`/`;`/stop terminator.
    const readArrowBody = (arrowNext, stop) => {
      const t = tks[arrowNext];
      if (!t) return null;
      if (t.type === 'open' && t.char === '{') {
        // Find matching closing `}`.
        let depth = 1;
        let i = arrowNext + 1;
        while (i < stop && depth > 0) {
          const tk = tks[i];
          if (tk.type === 'open' && tk.char === '{') depth++;
          else if (tk.type === 'close' && tk.char === '}') depth--;
          i++;
        }
        if (depth !== 0) return null;
        return { bodyStart: arrowNext + 1, bodyEnd: i - 1, isBlock: true, next: i };
      }
      const end = skipExpr(arrowNext, stop);
      return { bodyStart: arrowNext, bodyEnd: end, isBlock: false, next: end };
    };

    // Read any value at index `k`: arrow function, chain, object literal, or
    // array literal. `terms` defines the expression terminators for chain
    // parsing. Returns { binding, next } or null.
    // Parse a function expression: function [name](params) { body }.
    // Returns { binding: functionBinding, next } or null.
    const readFunctionExpr = async (k, stop) => {
      var ft = tks[k];
      if (!ft || ft.type !== 'other') return null;
      // Optional `async` prefix: `async function (...) {...}`. Skip
      // it so the IIFE handler can detect `(async function(){})()`
      // patterns the same way it detects `(function(){})()`.
      if (ft.text === 'async') {
        var _afterAsync = tks[k + 1];
        if (_afterAsync && _afterAsync.type === 'other' && _afterAsync.text === 'function') {
          ft = _afterAsync;
          k = k + 1;
        }
      }
      if (ft.text !== 'function') return null;
      var fk = k + 1;
      // Optional function name.
      if (tks[fk] && tks[fk].type === 'other' && IDENT_RE.test(tks[fk].text) && tks[fk].text !== 'function') fk++;
      // Parameter list.
      if (!tks[fk] || tks[fk].type !== 'open' || tks[fk].char !== '(') return null;
      var params = [];
      var fj = fk + 1;
      while (fj < stop) {
        var pt = tks[fj];
        if (pt && pt.type === 'close' && pt.char === ')') { fj++; break; }
        // Rest parameter: ...args (single token "...args" or two tokens "..." + "args")
        if (pt && pt.type === 'other' && pt.text.startsWith('...')) {
          var _restName = pt.text.slice(3);
          if (IDENT_RE.test(_restName)) {
            params.push({ name: _restName, rest: true });
            fj++;
            if (tks[fj] && tks[fj].type === 'sep' && tks[fj].char === ',') fj++;
            continue;
          }
        }
        if (pt && pt.type === 'other' && IDENT_RE.test(pt.text)) {
          var paramObj = { name: pt.text };
          // Check for default value: param = defaultExpr.
          if (tks[fj + 1] && tks[fj + 1].type === 'sep' && tks[fj + 1].char === '=') {
            paramObj.defaultStart = fj + 2;
            var dd = fj + 2;
            while (dd < stop && !(tks[dd].type === 'sep' && tks[dd].char === ',') && !(tks[dd].type === 'close' && tks[dd].char === ')')) {
              if (tks[dd].type === 'open') { var dep = 1; dd++; while (dd < stop && dep > 0) { if (tks[dd].type === 'open') dep++; if (tks[dd].type === 'close') dep--; dd++; } continue; }
              dd++;
            }
            paramObj.defaultEnd = dd;
            fj = dd;
          } else {
            fj++;
          }
          params.push(paramObj);
        } else {
          fj++;
        }
        if (tks[fj] && tks[fj].type === 'sep' && tks[fj].char === ',') fj++;
      }
      // Body: { ... }
      if (!tks[fj] || tks[fj].type !== 'open' || tks[fj].char !== '{') return null;
      var depth = 1, bodyEnd = fj + 1;
      while (bodyEnd < stop && depth > 0) {
        if (tks[bodyEnd].type === 'open' && tks[bodyEnd].char === '{') depth++;
        else if (tks[bodyEnd].type === 'close' && tks[bodyEnd].char === '}') depth--;
        bodyEnd++;
      }
      var _fnBind = functionBinding(params, fj, bodyEnd, true);
      // Closure capture: snapshot every binding visible at function-
      // expression creation time. When the function is later called
      // (potentially after the creating scope has returned), the
      // captured bindings are pushed onto the stack so reads from
      // within the body still see the outer-scope values — including
      // any taint attached to them.
      _fnBind.capturedScope = _snapshotClosureForCapture();
      return { binding: _fnBind, next: bodyEnd };
    };

    const readValue = async (k, stop, terms) => {
      const t = tks[k];
      if (!t) return null;
      // Function expression: function(params) { body }
      var fnExpr = await readFunctionExpr(k, stop);
      if (fnExpr) return fnExpr;
      // Arrow function (it can start with `(` or with an ident).
      const arrow = peekArrow(k, stop);
      if (arrow) {
        const body = readArrowBody(arrow.arrowNext, stop);
        if (!body) return null;
        var _aBind = functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock);
        _aBind.capturedScope = _snapshotClosureForCapture();
        return {
          binding: _aBind,
          next: body.next,
        };
      }
      // Try the expression as an arithmetic expression with postfix
      // accessors. This folds arithmetic/bitwise/logical/comparison/ternary
      // ops while preserving typed bindings (array/object/function) when
      // the RHS is a bare literal or member access. If the next top-level
      // token is `+`, escalate to concat-chain parsing so the result
      // becomes the first operand.
      const arith = await parseArithExpr(k, stop, 0);
      if (arith && arith.bind) {
        const nt = tks[arith.next];
        if (nt && nt.type === 'plus') {
          const r = await readConcatExpr(k, stop, terms);
          if (r) return { binding: chainBinding(r.toks), next: r.next };
        }
        return { binding: arith.bind, next: arith.next };
      }
      // Fall back to readBase for typed bindings (array/object) that
      // parseArithExpr rejected because they're not chain results.
      const base = await readBase(k, stop);
      if (base) {
        const s = await applySuffixes(base.bind, base.next, stop);
        if (s.bind) {
          const nt = tks[s.next];
          if (nt && nt.type === 'plus') {
            const r = await readConcatExpr(k, stop, terms);
            if (r) return { binding: chainBinding(r.toks), next: r.next };
          }
          return { binding: s.bind, next: s.next };
        }
      }
      // Fall through: chain parsing (with opaque-capture for unresolved).
      const r = await readConcatExpr(k, stop, terms);
      if (r) return { binding: chainBinding(r.toks), next: r.next };
      return null;
    };

    // Detect a primitive literal token and return its string form, or null.
    const primitiveAsString = (text) => {
      if (/^-?\d+$/.test(text)) return text.replace(/^-?0+(?=\d)/, (m) => m.startsWith('-') ? '-' : '');
      if (/^-?\d*\.\d+$/.test(text)) return text;
      if (text === 'true' || text === 'false' || text === 'null' || text === 'undefined') return text;
      return null;
    };

    // Apply `[key]` subscripts and separate-token `.method(args)` calls as
    // postfix accessors on a typed binding. Returns { bind, next }.
    const applySuffixes = async (bind, next, stop) => {
      while (next < stop && bind) {
        const t = tks[next];
        if (!t) break;
        // Optional chaining `?.`: access a property/index/call on `bind`
        // the same way the non-optional form would. Drops the optional
        // semantics because we never propagate null/undefined through
        // the resolver anyway.
        if (t.type === 'op' && t.text === '?.') {
          const nt = tks[next + 1];
          if (nt && nt.type === 'other' && IDENT_RE.test(nt.text)) {
            const prop = nt.text;
            if (bind.kind === 'object') bind = bind.props[prop] || null;
            else if (prop === 'length' && bind.kind === 'array') bind = chainBinding([makeSynthStr(String(bind.elems.length))]);
            else if (prop === 'length' && bind.kind === 'chain') {
              const s = chainAsKnownString(bind);
              bind = s === null ? null : chainBinding([makeSynthStr(String(s.length))]);
            } else bind = null;
            next += 2;
            continue;
          }
          // `?.[expr]` or `?.(args)` — skip the `?.` and let the next
          // iteration handle the bracket/call normally.
          if (nt && nt.type === 'open' && (nt.char === '[' || nt.char === '(')) { next++; continue; }
          break;
        }
        // Bracket subscript: parse inner expression and use it as a key if
        // it folds to a numeric or string literal. Marks the subscript
        // result as unknown otherwise.
        if (t.type === 'open' && t.char === '[') {
          let depth = 1, j = next + 1;
          while (j < stop && depth > 0) {
            const tk = tks[j];
            if (tk.type === 'open' && tk.char === '[') depth++;
            else if (tk.type === 'close' && tk.char === ']') depth--;
            if (depth === 0) break;
            j++;
          }
          const close = tks[j];
          if (!close || close.type !== 'close' || close.char !== ']') break;
          let resolved = false;
          if (j > next + 1) {
            const inner = await parseArithExpr(next + 1, j, 0);
            if (inner && inner.next === j && inner.bind && inner.bind.toks.length === 1 && inner.bind.toks[0].type === 'str') {
              const keyText = inner.bind.toks[0].text;
              const asNum = Number(keyText);
              const isNumeric = !Number.isNaN(asNum) && String(asNum) === keyText;
              if (bind.kind === 'array' && isNumeric) {
                bind = bind.elems[asNum] || null;
                resolved = true;
              } else if (bind.kind === 'object') {
                bind = bind.props[keyText] || null;
                resolved = true;
              } else if (bind.kind === 'array' && /^\d+$/.test(keyText)) {
                bind = bind.elems[parseInt(keyText, 10)] || null;
                resolved = true;
              }
            }
          }
          if (!resolved) {
            // Opaque index: produce a symbolic chain so downstream
            // property access (.v) and operators (===, ?) can form
            // valid expressions instead of returning null.
            // For taint: collect taint from ALL array elements since
            // any element could be accessed at runtime.
            var _elemTaintSources = [];
            if (taintEnabled && bind) {
              if (bind.kind === 'array') {
                for (var _ei = 0; _ei < bind.elems.length; _ei++) {
                  if (bind.elems[_ei] && bind.elems[_ei].kind === 'chain') _elemTaintSources.push(bind.elems[_ei].toks);
                }
              } else if (bind.kind === 'object') {
                for (var _ok in bind.props) {
                  if (bind.props[_ok] && bind.props[_ok].kind === 'chain') _elemTaintSources.push(bind.props[_ok].toks);
                }
              }
            }
            const baseText = bind.kind === 'chain' && bind.toks.length === 1 && bind.toks[0].type === 'other'
              ? bind.toks[0].text
              : (tks[next - 1] && tks[next - 1]._src ? tks[next - 1]._src.slice(tks[next - 1].start, tks[next - 1].end) : null);
            if (baseText) {
              const idxText = tks[next + 1] && tks[next + 1]._src ? tks[next + 1]._src.slice(tks[next + 1].start, tks[j - 1].end) : 'i';
              bind = chainBinding([deriveExprRef.apply(null, [baseText + '[' + idxText + ']', bind ? bind.toks : null].concat(_elemTaintSources))]);
            } else {
              bind = null;
            }
          }
          next = j + 1;
          continue;
        }
        // Bare trailing call on a function-valued result:
        // `outer()()`, `a()()()`, `(cond ? f : g)()`, `obj.factory()()`.
        // Without this the second `(` is unreachable and the returned
        // closure's body is never walked.
        if (t.type === 'open' && t.char === '(' && bind && bind.kind === 'function') {
          var _bcallArgs = await readCallArgBindings(next, stop);
          if (!_bcallArgs) break;
          var _bcallResult = await instantiateFunction(bind, _bcallArgs.bindings, null);
          if (_bcallResult && _bcallResult.kind && _bcallResult.kind !== 'chain') {
            bind = _bcallResult;
          } else if (_bcallResult && _bcallResult.kind === 'chain') {
            bind = _bcallResult;
          } else if (_bcallResult && Array.isArray(_bcallResult)) {
            bind = chainBinding(_bcallResult);
          } else {
            // Opaque result: keep the chain going with an unknown ref.
            bind = chainBinding([exprRef('()')]);
          }
          next = _bcallArgs.next;
          continue;
        }
        // Separate-token method call: `].join(sep)` or `'a'.concat(...)`.
        // Also handles `.prop.concat(...)` / `.prop.join(...)` when attached.
        if (t.type === 'other' && /^(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$/.test(t.text)) {
          const paren = tks[next + 1];
          const isCall = paren && paren.type === 'open' && paren.char === '(';
          const segs = t.text.slice(1).split('.');
          const lastSeg = segs[segs.length - 1];
          const isMethodCall = isCall && KNOWN_METHODS.has(lastSeg);
          // Walk any leading property segments. Special-cases: `.length` on
          // a known array returns the element count; `.length` on a chain
          // whose operands are all string/template literals returns the
          // concatenated string length.
          const propSegs = isMethodCall ? segs.slice(0, -1) : segs;
          let cur = bind;
          for (const p of propSegs) {
            if (!cur) break;
            if (cur.kind === 'object') {
              cur = cur.props[p] || null;
            } else if (p === 'length' && cur.kind === 'array') {
              cur = chainBinding([makeSynthStr(String(cur.elems.length))]);
            } else if (p === 'length' && cur.kind === 'chain') {
              let n = 0; let ok = true;
              for (const tk of cur.toks) {
                if (tk.type === 'plus') continue;
                if (tk.type === 'str') { n += tk.text.length; continue; }
                if (tk.type === 'tmpl') {
                  let hasExpr = false; let tl = 0;
                  for (const part of tk.parts) {
                    if (part.kind === 'text') tl += decodeJsString(part.raw, '`').length;
                    else { hasExpr = true; break; }
                  }
                  if (hasExpr) { ok = false; break; }
                  n += tl;
                  continue;
                }
                ok = false; break;
              }
              cur = ok ? chainBinding([makeSynthStr(String(n))]) : null;
            } else if (cur.kind === 'chain' && cur.toks.length === 1 && cur.toks[0].type === 'other') {
              // Opaque chain: extend the expression text with the property.
              cur = chainBinding([deriveExprRef(cur.toks[0].text + '.' + p, cur.toks)]);
            } else {
              cur = null;
              break;
            }
          }
          if (isMethodCall) {
            const r = await applyMethod(cur, lastSeg, next + 1, stop);
            if (r) {
              bind = r.bind;
              next = r.next;
              continue;
            }
            // applyMethod returned null — fall through to the
            // object-method-call path below for cases like a thenable
            // object whose .then property is a user-defined function.
            // (applyMethod's then handler only fires when the receiver
            // is a chain; an object with a .then function should be
            // dispatched via the inline-method path.)
            if (cur && cur.kind === 'object' && cur.props && cur.props[lastSeg] && cur.props[lastSeg].kind === 'function') {
              // fall through to the function-call branch below
            } else {
              break;
            }
          }
          // Object method call: cur is a function binding accessed via .prop,
          // followed by (args). Inline the function.
          if (isCall && cur && cur.kind === 'object' && cur.props && cur.props[lastSeg] && cur.props[lastSeg].kind === 'function') {
            var _omFn = cur.props[lastSeg];
            var _omArgs = await readCallArgBindings(next + 1, stop);
            if (_omArgs) {
              var _omResult = await instantiateFunction(_omFn, _omArgs.bindings, cur);
              if (_omResult && _omResult.kind) { bind = _omResult; next = _omArgs.next; continue; }
              if (_omResult) { bind = chainBinding(_omResult); next = _omArgs.next; continue; }
              bind = chainBinding([exprRef('()')]);
              next = _omArgs.next;
              continue;
            }
          }
          if (isCall && cur && cur.kind === 'function') {
            var _omArgs = await readCallArgBindings(next + 1, stop);
            if (_omArgs) {
              // Pass the receiver object as 'this' for method calls.
              var _omResult = await instantiateFunction(cur, _omArgs.bindings, bind);
              if (_omResult && _omResult.kind) { bind = _omResult; next = _omArgs.next; continue; }
              if (_omResult) { bind = chainBinding(_omResult); next = _omArgs.next; continue; }
              // Void method: no return value. Still consume the whole
              // `.method(args)` range and produce an opaque chain so
              // the bare-trailing-call handler above doesn't re-invoke
              // the method without `this` on the next iteration.
              bind = chainBinding([exprRef('()')]);
              next = _omArgs.next;
              continue;
            }
          }
          // Getter on object: auto-invoke.
          if (!isCall && cur && cur.kind === 'object' && cur.props['__getter_' + lastSeg]) {
            var _gtrFn = cur.props['__getter_' + lastSeg];
            if (_gtrFn.kind === 'function') {
              var _gtrResult = await instantiateFunction(_gtrFn, []);
              if (_gtrResult && _gtrResult.kind) { cur = _gtrResult; }
              else if (_gtrResult) { cur = chainBinding(_gtrResult); }
            }
          }
          bind = cur;
          next = next + 1;
          continue;
        }
        break;
      }
      return { bind, next };
    };

    // Apply a method call: .concat on chain, or .join on array.
    const applyMethod = async (bind, method, parenIdx, stop) => {
      // Map / Set / WeakMap / WeakSet — model key-indexed ops as plain
      // object prop reads/writes so dispatcher tables built via
      // `.set(key, fn)` / `.get(key)` flow through the same may-be
      // lattice as object dispatchers.
      if (bind && bind.kind === 'object' && bind._mapLike) {
        if (method === 'set') {
          var _msArgs = await readCallArgBindings(parenIdx, stop);
          if (_msArgs && _msArgs.bindings.length >= 2) {
            var _msKey = chainAsKnownString(_msArgs.bindings[0]);
            var _msVal = _msArgs.bindings[1];
            if (_msKey !== null) {
              bind.props[_msKey] = _msVal;
              // Feed may-be lattice so indirect-dispatch walking sees
              // every function registered under ANY key.
              if (_msVal && _msVal.kind === 'function') {
                var _msSlotKey = '#' + bind.__objId + '.' + _msKey;
                if (!_varMayBe[_msSlotKey]) _varMayBe[_msSlotKey] = { vals: [], keys: Object.create(null), complete: true, fns: null, fnIds: null };
                var _msSlot = _varMayBe[_msSlotKey];
                if (!_msSlot.fns) { _msSlot.fns = []; _msSlot.fnIds = Object.create(null); }
                var _msFkey = _msVal.bodyStart + ':' + _msVal.bodyEnd;
                if (!_msSlot.fnIds[_msFkey]) { _msSlot.fnIds[_msFkey] = true; _msSlot.fns.push(_msVal); }
              }
            } else {
              // Opaque key — stash under a wildcard slot so indirect
              // dispatch still sees the function.
              if (_msVal && _msVal.kind === 'function') {
                var _mswKey = '#' + bind.__objId + '.*';
                if (!bind.props['__mapStar']) bind.props['__mapStar'] = [];
                bind.props['__mapStar'].push(_msVal);
              }
            }
            return { bind: bind, next: _msArgs.next };
          }
        }
        if (method === 'get') {
          var _mgArgs = await readCallArgBindings(parenIdx, stop);
          if (_mgArgs && _mgArgs.bindings.length >= 1) {
            var _mgKey = chainAsKnownString(_mgArgs.bindings[0]);
            if (_mgKey !== null && bind.props[_mgKey]) {
              return { bind: bind.props[_mgKey], next: _mgArgs.next };
            }
            // Opaque key: return an opaque chain so a subsequent
            // bare-call through applySuffixes falls back to the
            // indirect-call dispatch path over the may-be fn set.
            return { bind: chainBinding([exprRef('map.get(*)')]), next: _mgArgs.next };
          }
        }
        if (method === 'has') {
          var _mhArgs = await readCallArgBindings(parenIdx, stop);
          if (_mhArgs) return { bind: chainBinding([exprRef('map.has(*)')]), next: _mhArgs.next };
        }
        if (method === 'add' && bind._mapLike === 'Set') {
          var _maArgs = await readCallArgBindings(parenIdx, stop);
          if (_maArgs && _maArgs.bindings.length >= 1) {
            var _maKey = chainAsKnownString(_maArgs.bindings[0]);
            if (_maKey !== null) bind.props[_maKey] = chainBinding([makeSynthStr('true')]);
            return { bind: bind, next: _maArgs.next };
          }
        }
        if (method === 'delete' || method === 'clear') {
          var _mdArgs = await readCallArgBindings(parenIdx, stop);
          if (_mdArgs) return { bind: chainBinding([makeSynthStr('true')]), next: _mdArgs.next };
        }
      }
      if (method === 'concat') {
        // Array concat: [].concat(arr) → merge elements.
        if (bind && bind.kind === 'array') {
          var _cArgs = await readCallArgBindings(parenIdx, stop);
          if (_cArgs) {
            var _cElems = bind.elems.slice();
            for (var _ci = 0; _ci < _cArgs.bindings.length; _ci++) {
              var _ca = _cArgs.bindings[_ci];
              if (_ca && _ca.kind === 'array') { for (var _cj = 0; _cj < _ca.elems.length; _cj++) _cElems.push(_ca.elems[_cj]); }
              else if (_ca) _cElems.push(_ca);
            }
            return { bind: arrayBinding(_cElems), next: _cArgs.next };
          }
        }
        // String concat.
        if (!bind || bind.kind !== 'chain') return null;
        const args = await readConcatArgs(parenIdx, stop);
        if (!args) return null;
        const toks = bind.toks.slice();
        for (const a of args.args) { toks.push(SYNTH_PLUS); for (const v of a) toks.push(v); }
        return { bind: chainBinding(toks), next: args.next };
      }
      if (method === 'join' && bind && bind.kind === 'mapped') {
        const lp = tks[parenIdx];
        if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
        const sepTok = tks[parenIdx + 1];
        const rp = tks[parenIdx + (sepTok && (sepTok.type === 'str' || sepTok.type === 'tmpl') ? 2 : 1)];
        const endIdx = rp && rp.type === 'close' && rp.char === ')' ? (parenIdx + (sepTok && (sepTok.type === 'str' || sepTok.type === 'tmpl') ? 3 : 2)) : null;
        if (!endIdx) return null;
        return {
          bind: chainBinding([{
            type: 'iter', iterExpr: bind.iterExpr, paramName: bind.paramName,
            perElemChain: bind.perElemChain,
          }]),
          next: endIdx,
        };
      }
      if (method === 'join') {
        if (!bind || bind.kind !== 'array') return null;
        const lp = tks[parenIdx];
        if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
        const sepTok = tks[parenIdx + 1];
        if (!sepTok || (sepTok.type !== 'str' && sepTok.type !== 'tmpl')) return null;
        const rp = tks[parenIdx + 2];
        if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
        const elems = bind.elems;
        if (elems.length === 0) return { bind: chainBinding([makeSynthStr('')]), next: parenIdx + 3 };
        const out = [];
        for (let e = 0; e < elems.length; e++) {
          const eb = elems[e];
          if (!eb || eb.kind !== 'chain') return null;
          if (e > 0) { out.push(SYNTH_PLUS); out.push(await rewriteTemplate(sepTok)); out.push(SYNTH_PLUS); }
          for (const vt of eb.toks) out.push(vt);
        }
        return { bind: chainBinding(out), next: parenIdx + 3 };
      }
      // Pure string methods on a known chain string: evaluate when all args
      // are concrete literals. Non-evaluatable cases return null.
      if (bind && bind.kind === 'chain') {
        const s = chainAsKnownString(bind);
        if (s !== null) {
          const args = await readConcatArgs(parenIdx, stop);
          if (!args) return null;
          const argVals = [];
          let allConcrete = true;
          for (const a of args.args) {
            const ch = chainBinding(a);
            const n = chainAsNumber(ch);
            if (n !== null) { argVals.push(n); continue; }
            const k = chainAsKnownString(ch);
            if (k !== null) { argVals.push(k); continue; }
            allConcrete = false; break;
          }
          if (!allConcrete) return null;
          let result;
          try {
            switch (method) {
              case 'toUpperCase': if (argVals.length === 0) result = s.toUpperCase(); break;
              case 'toLowerCase': if (argVals.length === 0) result = s.toLowerCase(); break;
              case 'trim': if (argVals.length === 0) result = s.trim(); break;
              case 'trimStart': case 'trimLeft': if (argVals.length === 0) result = s.trimStart(); break;
              case 'trimEnd': case 'trimRight': if (argVals.length === 0) result = s.trimEnd(); break;
              case 'repeat': if (argVals.length === 1) result = s.repeat(argVals[0]); break;
              case 'slice': if (argVals.length <= 2) result = s.slice(...argVals); break;
              case 'substring': if (argVals.length <= 2) result = s.substring(...argVals); break;
              case 'substr': if (argVals.length <= 2) result = s.substr(...argVals); break;
              case 'charAt': if (argVals.length === 1) result = s.charAt(argVals[0]); break;
              case 'indexOf': if (argVals.length <= 2) result = String(s.indexOf(...argVals)); break;
              case 'lastIndexOf': if (argVals.length <= 2) result = String(s.lastIndexOf(...argVals)); break;
              case 'includes': if (argVals.length <= 2) result = String(s.includes(...argVals)); break;
              case 'startsWith': if (argVals.length <= 2) result = String(s.startsWith(...argVals)); break;
              case 'endsWith': if (argVals.length <= 2) result = String(s.endsWith(...argVals)); break;
              case 'padStart': if (argVals.length <= 2) result = s.padStart(...argVals); break;
              case 'padEnd': if (argVals.length <= 2) result = s.padEnd(...argVals); break;
              case 'toString': if (argVals.length === 0) result = s; break;
              case 'split': {
                if (argVals.length === 1) {
                  const parts = s.split(argVals[0]);
                  return { bind: arrayBinding(parts.map((p) => chainBinding([makeSynthStr(p)]))), next: args.next };
                }
                break;
              }
            }
          } catch (_) { return null; }
          if (result === undefined) return null;
          return { bind: chainBinding([makeSynthStr(result)]), next: args.next };
        }
      }
      // Array methods on known array bindings.
      if (bind && bind.kind === 'array') {
        // `.map(fn)`, `.filter(fn)`, `.forEach(fn)`: the argument is a
        // callback function rather than a concat-chain value. Parse the
        // arrow, invoke it once per element with the element bound to
        // the single parameter, and collect/filter the results.
        if (method === 'map' || method === 'filter' || method === 'forEach') {
          const lp = tks[parenIdx];
          if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
          // Try arrow function, then function expression, then identifier.
          var fn = null, fnNext = 0;
          const arrow = peekArrow(parenIdx + 1, stop);
          if (arrow) {
            const body = readArrowBody(arrow.arrowNext, stop);
            if (body) { fn = functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock); fn.capturedScope = _snapshotClosureForCapture(); fnNext = body.next; }
          }
          if (!fn) {
            var fexpr = await readFunctionExpr(parenIdx + 1, stop);
            if (fexpr) { fn = fexpr.binding; fnNext = fexpr.next; }
          }
          if (!fn) {
            // Try identifier reference to a function.
            var cbTok = tks[parenIdx + 1];
            if (cbTok && cbTok.type === 'other' && IDENT_RE.test(cbTok.text)) {
              var refB = resolve(cbTok.text);
              if (refB && refB.kind === 'function') { fn = refB; fnNext = parenIdx + 2; }
            }
          }
          if (!fn) return null;
          const rp = tks[fnNext];
          if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
          if (method === 'forEach') {
            // Walk callback for each element to detect side effects
            // (e.g. el.innerHTML = item inside the callback).
            for (const el of bind.elems) {
              if (el) await instantiateFunction(fn, [el]);
            }
            return { bind: chainBinding([makeSynthStr('undefined')]), next: fnNext + 1 };
          }
          const results = [];
          for (const el of bind.elems) {
            if (!el) return null;
            const toks = await instantiateFunction(fn, [el]);
            if (!toks) return null;
            if (method === 'map') {
              results.push(chainBinding(toks));
              continue;
            }
            // method === 'filter': keep element when the callback's
            // return value is truthy (concrete only; unknowns bail).
            const resChain = chainBinding(toks);
            const n = chainAsNumber(resChain);
            const s = n === null ? chainAsKnownString(resChain) : null;
            const truthy = (n !== null && n !== 0) || (s !== null && s !== '' && s !== 'false' && s !== 'null' && s !== 'undefined' && s !== '0' && s !== 'NaN');
            const falsy = n === 0 || s === '' || s === 'false' || s === 'null' || s === 'undefined' || s === '0' || s === 'NaN';
            if (truthy) results.push(el);
            else if (falsy) { /* skip */ }
            else {
              // Can't determine at compile time: result could contain any
              // element. Return opaque binding with taint from all elements.
              var _allElToks = [];
              for (var _fe = 0; _fe < bind.elems.length; _fe++) {
                if (bind.elems[_fe] && bind.elems[_fe].kind === 'chain') _allElToks.push(bind.elems[_fe].toks);
              }
              var _filterRef = deriveExprRef.apply(null, [chainAsExprText(chainBinding([exprRef('filtered')]))||'filtered'].concat(_allElToks));
              return { bind: chainBinding([_filterRef]), next: fnNext + 1 };
            }
          }
          return { bind: arrayBinding(results), next: fnNext + 1 };
        }
        // `.reduce(fn, init)` — two-arg reducer: invoke the callback
        // per element with (accumulator, element) and thread the
        // running result through.
        if (method === 'reduce') {
          const lp = tks[parenIdx];
          if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
          // Try arrow, function expression, or identifier.
          var reduceFn = null, reduceFnNext = 0;
          const arrow = peekArrow(parenIdx + 1, stop);
          if (arrow && arrow.params.length === 2) {
            const body = readArrowBody(arrow.arrowNext, stop);
            if (body) { reduceFn = functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock); reduceFn.capturedScope = _snapshotClosureForCapture(); reduceFnNext = body.next; }
          }
          if (!reduceFn) {
            var rfexpr = await readFunctionExpr(parenIdx + 1, stop);
            if (rfexpr && rfexpr.binding.params && rfexpr.binding.params.length === 2) { reduceFn = rfexpr.binding; reduceFnNext = rfexpr.next; }
          }
          if (!reduceFn) {
            var rcbTok = tks[parenIdx + 1];
            if (rcbTok && rcbTok.type === 'other' && IDENT_RE.test(rcbTok.text)) {
              var rrefB = resolve(rcbTok.text);
              if (rrefB && rrefB.kind === 'function' && rrefB.params && rrefB.params.length === 2) { reduceFn = rrefB; reduceFnNext = parenIdx + 2; }
            }
          }
          if (!reduceFn) return null;
          const sep = tks[reduceFnNext];
          if (!sep || sep.type !== 'sep' || sep.char !== ',') return null;
          const init = await readConcatExpr(reduceFnNext + 1, stop, { sep: [], close: [')'] });
          if (!init) return null;
          const rp = tks[init.next];
          if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
          const fn = reduceFn;
          let accBind = chainBinding(init.toks);
          for (const el of bind.elems) {
            if (!el) return null;
            const toks = await instantiateFunction(fn, [accBind, el]);
            if (!toks) return null;
            accBind = chainBinding(toks);
          }
          const acc = accBind.toks;
          return { bind: chainBinding(acc), next: init.next + 1 };
        }
        const args = await readConcatArgs(parenIdx, stop);
        if (!args) return null;
        const argVals = [];
        let allConcrete = true;
        for (const a of args.args) {
          const ch = chainBinding(a);
          const n = chainAsNumber(ch);
          if (n !== null) { argVals.push(n); continue; }
          const k = chainAsKnownString(ch);
          if (k !== null) { argVals.push(k); continue; }
          allConcrete = false; break;
        }
        if (!allConcrete) return null;
        if (method === 'slice' && argVals.length <= 2) {
          return { bind: arrayBinding(bind.elems.slice(...argVals)), next: args.next };
        }
        if (method === 'indexOf' && argVals.length === 1) {
          const target = argVals[0];
          let idx = -1;
          for (let i = 0; i < bind.elems.length; i++) {
            const es = bind.elems[i] && bind.elems[i].kind === 'chain' ? chainAsKnownString(bind.elems[i]) : null;
            if (es === target || (typeof target === 'number' && Number(es) === target)) { idx = i; break; }
          }
          return { bind: chainBinding([makeSynthStr(String(idx))]), next: args.next };
        }
        if (method === 'includes' && argVals.length === 1) {
          const target = argVals[0];
          let has = false;
          for (const el of bind.elems) {
            const es = el && el.kind === 'chain' ? chainAsKnownString(el) : null;
            if (es === target || (typeof target === 'number' && Number(es) === target)) { has = true; break; }
          }
          return { bind: chainBinding([makeSynthStr(String(has))]), next: args.next };
        }
        if (method === 'reverse' && argVals.length === 0) {
          return { bind: arrayBinding(bind.elems.slice().reverse()), next: args.next };
        }
      }

      // .map(fn).join('') on an opaque iterable: extract the callback's
      // per-element return chain and produce an iter token that
      // The emitter converts map/join into a forEach loop.
      if (method === 'map') {
        const lp = tks[parenIdx];
        if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
        // Try arrow: `.map(x => ...)` or `.map((x) => ...)`
        let fn = null, fnEnd = null;
        const arrow = peekArrow(parenIdx + 1, stop);
        if (arrow) {
          const body = readArrowBody(arrow.arrowNext, stop);
          if (body) {
            fn = functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock);
            fn.capturedScope = _snapshotClosureForCapture();
            fnEnd = body.next;
          }
        }
        // Try function expression: `.map(function(x) { ... })`
        if (!fn) {
          var _fexpr = await readFunctionExpr(parenIdx + 1, stop);
          if (_fexpr) {
            fn = _fexpr.binding;
            fnEnd = _fexpr.next;
          }
        }
        if (!fn) return null;
        const rp = tks[fnEnd];
        if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
        const paramBinds = fn.params.map((p) => chainBinding([exprRef(p.name)]));
        const toks = await instantiateFunction(fn, paramBinds);
        if (!toks) return null;
        const iterExpr = bind ? chainAsExprText(bind) : null;
        return {
          bind: { kind: 'mapped', iterExpr: iterExpr || '/* iterable */', paramName: fn.params[0] ? fn.params[0].name : '_', perElemChain: toks },
          next: fnEnd + 1,
        };
      }
      // --- Promise tracking: .then / .catch / .finally on a chain ---
      // The receiver is a Promise (typically opaque + tainted, e.g. the
      // result of fetch()). The callback's first argument is the Promise's
      // resolved value, which carries the receiver's taint. The callback's
      // return value is the new Promise's resolved value, which inherits
      // taint from both the callback body and the receiver.
      if ((method === 'then' || method === 'catch' || method === 'finally') &&
          bind && bind.kind === 'chain') {
        const lp = tks[parenIdx];
        if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
        // Parse the callback (arrow / function expression / identifier).
        var pfn = null, pfnEnd = 0;
        const parrow = peekArrow(parenIdx + 1, stop);
        if (parrow) {
          const pbody = readArrowBody(parrow.arrowNext, stop);
          if (pbody) { pfn = functionBinding(parrow.params, pbody.bodyStart, pbody.bodyEnd, pbody.isBlock); pfnEnd = pbody.next; }
        }
        if (!pfn) {
          var pfexpr = await readFunctionExpr(parenIdx + 1, stop);
          if (pfexpr) { pfn = pfexpr.binding; pfnEnd = pfexpr.next; }
        }
        if (!pfn) {
          var pcbTok = tks[parenIdx + 1];
          if (pcbTok && pcbTok.type === 'other' && IDENT_RE.test(pcbTok.text)) {
            var prefB = resolve(pcbTok.text);
            if (prefB && prefB.kind === 'function') { pfn = prefB; pfnEnd = parenIdx + 2; }
          }
        }
        if (!pfn) return null;
        const prp = tks[pfnEnd];
        if (!prp || prp.type !== 'close' || prp.char !== ')') return null;
        // The first arg of the callback receives the Promise's resolved
        // value — which is just the receiver chain itself, because the
        // analyzer doesn't distinguish a Promise<T> from its T. Pass the
        // receiver as the first arg so any taint flows through.
        var receiverTaint = collectChainTaint(bind.toks);
        var firstArgChain = chainBinding(bind.toks.slice());
        if (receiverTaint && firstArgChain.toks.length) {
          // Tag the first token with the receiver's taint so the inlined
          // body sees a tainted parameter.
          var pTok0 = Object.assign({}, firstArgChain.toks[0]);
          if (!pTok0.taint) pTok0.taint = new Set();
          for (var ptl of receiverTaint) pTok0.taint.add(ptl);
          firstArgChain.toks[0] = pTok0;
        }
        var pParamBinds = pfn.params.map(function (p, idx) {
          if (idx === 0) return firstArgChain;
          return chainBinding([exprRef(p.name)]);
        });
        var pCallbackResult = await instantiateFunction(pfn, pParamBinds);
        // Register the .then/.catch/.finally callback for the
        // phase-2 fixpoint so it sees mutations made by other
        // callbacks (e.g. another fetch's .then writing to a global).
        if (_pendingCallbacks && taintEnabled) {
          _pendingCallbacks.push({ fn: pfn, params: pParamBinds, isEventHandler: false });
        }
        // The callback's return value is the new Promise's resolved value.
        // Wrap it as an opaque chain that inherits taint from both the
        // receiver and the callback's return.
        var pResultToks;
        if (pCallbackResult && Array.isArray(pCallbackResult)) {
          pResultToks = pCallbackResult;
        } else if (pCallbackResult && pCallbackResult.kind === 'chain') {
          pResultToks = pCallbackResult.toks;
        } else {
          pResultToks = [exprRef('promise.' + method + '()')];
        }
        // Propagate receiver taint into the result chain so chained
        // .then(...).then(...) keeps flowing taint forward.
        if (receiverTaint && pResultToks.length) {
          var pRTok0 = Object.assign({}, pResultToks[0]);
          if (!pRTok0.taint) pRTok0.taint = new Set();
          for (var prtl of receiverTaint) pRTok0.taint.add(prtl);
          pResultToks = [pRTok0].concat(pResultToks.slice(1));
        }
        return { bind: chainBinding(pResultToks), next: pfnEnd + 1 };
      }
      return null;
    };

    // Materialize a chain binding to its concrete string value if all of
    // its operands are fully known string/template literals. Returns null
    // otherwise (e.g. chain contains an opaque expression reference).
    // Convert a binding to its concrete JS value for JSON serialization.
    // Returns undefined if any leaf isn't fully known.
    const bindingToJson = (b) => {
      if (!b) return undefined;
      if (b.kind === 'chain') {
        const s = chainAsKnownString(b);
        if (s === null) return undefined;
        const n = chainAsNumber(b);
        if (n !== null) return n;
        if (s === 'true') return true;
        if (s === 'false') return false;
        if (s === 'null') return null;
        return s;
      }
      if (b.kind === 'array') {
        const out = [];
        for (const el of b.elems) {
          const v = bindingToJson(el);
          if (v === undefined) return undefined;
          out.push(v);
        }
        return out;
      }
      if (b.kind === 'object') {
        const out = {};
        for (const k in b.props) {
          const v = bindingToJson(b.props[k]);
          if (v === undefined) return undefined;
          out[k] = v;
        }
        return out;
      }
      return undefined;
    };
    // Convert a plain JS value back into a binding (for JSON.parse).
    const jsonToBinding = (v) => {
      if (v === null) return chainBinding([makeSynthStr('null')]);
      if (typeof v === 'boolean') return chainBinding([makeSynthStr(String(v))]);
      if (typeof v === 'number') return chainBinding([makeSynthStr(String(v))]);
      if (typeof v === 'string') return chainBinding([makeSynthStr(v)]);
      if (Array.isArray(v)) return arrayBinding(v.map(jsonToBinding));
      if (typeof v === 'object') {
        const props = Object.create(null);
        for (const k in v) props[k] = jsonToBinding(v[k]);
        return objectBinding(props);
      }
      return chainBinding([makeSynthStr('null')]);
    };

    const chainAsKnownString = (chain) => {
      if (!chain || chain.kind !== 'chain') return null;
      let s = '';
      for (const t of chain.toks) {
        if (t.type === 'plus') continue;
        if (t.type === 'str') { s += t.text; continue; }
        if (t.type === 'tmpl') {
          for (const p of t.parts) {
            if (p.kind === 'text') s += decodeJsString(p.raw, '`');
            else return null;
          }
          continue;
        }
        return null;
      }
      return s;
    };

    // Read a "base" value before any suffixes: literals, identifiers/paths
    // (with optional attached .concat/.join method), parenthesized
    // subexpressions, array literals, and object literals.
    const readBase = async (k, stop) => {
      // Collect prefix operators iteratively instead of recursing.
      const prefixes = [];
      while (k < stop) {
        const pt = tks[k];
        if (!pt) return null;
        if (pt.type === 'other' && (pt.text === 'await' || pt.text === 'yield' || pt.text === 'typeof' || pt.text === 'void' || pt.text === 'delete')) {
          prefixes.push({ kind: 'keyword', text: pt.text }); k++; continue;
        }
        if (pt.type === 'op' && (pt.text === '-' || pt.text === '+' || pt.text === '!' || pt.text === '~')) {
          prefixes.push({ kind: 'unary', text: pt.text }); k++; continue;
        }
        break;
      }
      var baseResult = await _readBaseCore(k, stop);
      if (!baseResult) return null;
      for (var _pi = prefixes.length - 1; _pi >= 0; _pi--) {
        var _pf = prefixes[_pi];
        if (_pf.kind === 'keyword') {
          // `await` and `yield` are unwrapping operations on Promises /
          // generators — for taint analysis they're transparent: the
          // result has the same taint as the inner expression. Pass the
          // binding through unchanged so taint flows from `await fetch(...)`
          // into the awaited value.
          if (_pf.text === 'await' || _pf.text === 'yield') {
            // baseResult unchanged — keep the binding's taint.
            continue;
          }
          var _et = chainAsExprText(baseResult.bind);
          if (_et === null) return null;
          // Preserve the inner binding's taint on the wrapped expression.
          var _wrappedRef = exprRef(_pf.text + ' ' + _et);
          if (baseResult.bind && baseResult.bind.kind === 'chain') {
            var _innerTaint = collectChainTaint(baseResult.bind.toks);
            if (_innerTaint) _wrappedRef.taint = _innerTaint;
          }
          baseResult = { bind: chainBinding([_wrappedRef]), next: baseResult.next };
        } else {
          var _applied = applyUnary(_pf.text, baseResult.bind);
          if (!_applied) return null;
          baseResult = { bind: _applied, next: baseResult.next };
        }
      }
      return baseResult;
    };
    const _readBaseCore = async (k, stop) => {
      const t = tks[k];
      if (!t) return null;
      // `new X(args)` / `new X.Y` / `new X` — absorb the constructor call
      // and its arguments as a single opaque expression reference.
      if (t.type === 'other' && t.text === 'new') {
        // Check if the constructor is a known class.
        var _newName = tks[k + 1];
        if (_newName && _newName.type === 'other' && IDENT_RE.test(_newName.text)) {
          var _newBind = resolve(_newName.text);
          if (_newBind && _newBind.kind === 'object' && _newBind._isClass) {
            // Class instantiation: create instance with class methods,
            // then run the constructor with `this` bound to the new
            // instance so any `this.prop = arg` writes populate the
            // instance object (and feed the may-be lattice).
            var _instProps = Object.create(null);
            for (var _ck in _newBind.props) _instProps[_ck] = _newBind.props[_ck];
            var _inst = objectBinding(_instProps);
            var _newJ = k + 2;
            var _ctorArgs = null;
            if (tks[_newJ] && tks[_newJ].type === 'open' && tks[_newJ].char === '(') {
              // Parse constructor args as concat chains so tainted
              // arguments flow into `this.foo = arg` assignments.
              _ctorArgs = await readCallArgBindings(_newJ, stop);
              if (_ctorArgs) {
                _newJ = _ctorArgs.next;
              } else {
                // Parse failed: skip balanced parens.
                var _nd = 1; _newJ++;
                while (_newJ < stop && _nd > 0) { if (tks[_newJ].type === 'open' && tks[_newJ].char === '(') _nd++; if (tks[_newJ].type === 'close' && tks[_newJ].char === ')') _nd--; _newJ++; }
              }
            }
            var _ctorFn = _instProps['constructor'];
            if (_ctorFn && _ctorFn.kind === 'function') {
              var _ctorArgBinds = _ctorArgs ? _ctorArgs.bindings : [];
              await instantiateFunction(_ctorFn, _ctorArgBinds, _inst);
            }
            return { bind: _inst, next: _newJ };
          }
          // `new Map()` / `new Set()` / `new WeakMap()` / `new WeakSet()` —
          // model as an empty object binding. The shared method-call path
          // at applyMethod / applySuffixes then treats `.set(k, v)` as a
          // key-indexed write and `.get(k)` as a read, so dispatchers
          // and lookup tables propagate taint + flow through the same
          // machinery plain objects use.
          if (_newName.text === 'Map' || _newName.text === 'Set' ||
              _newName.text === 'WeakMap' || _newName.text === 'WeakSet') {
            var _mObj = objectBinding(Object.create(null));
            _mObj._mapLike = _newName.text;
            var _mJ = k + 2;
            if (tks[_mJ] && tks[_mJ].type === 'open' && tks[_mJ].char === '(') {
              // Skip balanced parens; initializer entries are ignored
              // (rare in practice for dispatcher tables).
              var _mnd = 1; _mJ++;
              while (_mJ < stop && _mnd > 0) {
                if (tks[_mJ].type === 'open' && tks[_mJ].char === '(') _mnd++;
                else if (tks[_mJ].type === 'close' && tks[_mJ].char === ')') _mnd--;
                _mJ++;
              }
            }
            return { bind: _mObj, next: _mJ };
          }
        }
        let j = k + 1;
        var _newCtorTok = null;
        if (tks[j] && tks[j].type === 'other' && IDENT_OR_PATH_RE.test(tks[j].text)) { _newCtorTok = tks[j]; j++; }
        // `new Ctor(args)` — fire the universal call watchers so
        // consumers (fetch-trace, dead-code detector, etc.) can
        // observe constructor calls the same way they observe bare
        // function calls. The walker otherwise treats new-calls as
        // opaque refs with just argument taint propagation.
        if (_callWatchers && _callWatchers.length > 0 && _newCtorTok &&
            tks[j] && tks[j].type === 'open' && tks[j].char === '(') {
          try {
            var _nwArgs = await readCallArgBindings(j, stop);
            if (_nwArgs) {
              var _nwInfo = {
                stage: 'new',
                reached: true,
                pathConditions: taintCondStack ? taintCondStack.slice() : [],
                pathFormulas: pathConstraints ? pathConstraints.slice() : [],
                mayBe: _varMayBe,
                resolve: resolve,
                resolvePath: resolvePath,
              };
              for (var _nwi = 0; _nwi < _callWatchers.length; _nwi++) {
                try { _callWatchers[_nwi](_newCtorTok.text, _nwArgs.bindings, _newCtorTok, _nwInfo); } catch (_) {}
              }
            }
          } catch (_) { /* fall through to opaque handling */ }
        }
        if (tks[j] && tks[j].type === 'open' && tks[j].char === '(') {
          let d = 1; j++;
          while (j < stop && d > 0) {
            const tk = tks[j];
            if (tk.type === 'open' && tk.char === '(') d++;
            else if (tk.type === 'close' && tk.char === ')') d--;
            j++;
          }
        }
        if (j === k + 1) return null;
        const first = tks[k];
        const last = tks[j - 1];
        var _newText = first._src.slice(first.start, last.end);
        var _newRef = exprRef(_newText);
        var _newTaint = checkTaintSource(_newText);
        if (_newTaint) _newRef.taint = _newTaint;
        return { bind: chainBinding([_newRef]), next: j };
      }
      if (t.type === 'str') return { bind: chainBinding([t]), next: k + 1 };
      if (t.type === 'tmpl') {
        const rw = await rewriteTemplate(t);
        if (rw.type === '_chain') return { bind: chainBinding(rw.toks), next: k + 1 };
        return { bind: chainBinding([rw]), next: k + 1 };
      }
      if (t.type === 'regex') return { bind: chainBinding([exprRef(t.text)]), next: k + 1 };
      if (t.type === 'open' && t.char === '(') {
        // Handle comma operator: (expr1, expr2, ..., exprN) → value is exprN.
        var _lastToks = null, _parenNext = k + 1;
        while (_parenNext < stop) {
          var _pr = await readConcatExpr(_parenNext, stop, { sep: [','], close: [')'] });
          if (!_pr) break;
          _lastToks = _pr.toks;
          _parenNext = _pr.next;
          if (tks[_parenNext] && tks[_parenNext].type === 'sep' && tks[_parenNext].char === ',') { _parenNext++; continue; }
          break;
        }
        if (!_lastToks) return null;
        const rp = tks[_parenNext];
        if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
        return { bind: chainBinding(_lastToks), next: _parenNext + 1 };
      }
      if (t.type === 'open' && t.char === '[') {
        const a = await readArrayLit(k, stop);
        if (!a) return null;
        return { bind: a.binding, next: a.next };
      }
      if (t.type === 'open' && t.char === '{') {
        const o = await readObjectLit(k, stop);
        if (!o) return null;
        return { bind: o.binding, next: o.next };
      }
      // Function expression in expression position.
      if (t.type === 'other' && t.text === 'function') {
        var _fnExpr = await readFunctionExpr(k, stop);
        if (_fnExpr) return { bind: _fnExpr.binding, next: _fnExpr.next };
      }
      if (t.type !== 'other') return null;
      // Primitive literal.
      const lit = primitiveAsString(t.text);
      if (lit !== null) return { bind: chainBinding([makeSynthStr(lit)]), next: k + 1 };
      // Identifier/path, possibly with attached .concat/.join method call.
      if (IDENT_OR_PATH_RE.test(t.text)) {
        const paren = tks[k + 1];
        const isCall = paren && paren.type === 'open' && paren.char === '(';
        // Tagged template: tag`...` — call the tag function with template parts.
        if (paren && paren.type === 'tmpl') {
          var tagBind = await resolvePath(t.text);
          if (tagBind && tagBind.kind === 'function') {
            // Build arguments: first arg is strings array, rest are expression values.
            var _tagArgs = [chainBinding([makeSynthStr('')])]; // strings placeholder
            if (paren.parts) {
              for (var _tp = 0; _tp < paren.parts.length; _tp++) {
                if (paren.parts[_tp].kind === 'expr') {
                  var _tagExpr = await evalExprSrc(paren.parts[_tp].expr);
                  if (_tagExpr) _tagArgs.push(chainBinding(_tagExpr));
                  else _tagArgs.push(chainBinding([exprRef(paren.parts[_tp].expr)]));
                }
              }
            }
            var _tagResult = await instantiateFunction(tagBind, _tagArgs);
            if (_tagResult && _tagResult.kind) return { bind: _tagResult, next: k + 2 };
            if (_tagResult) return { bind: chainBinding(_tagResult), next: k + 2 };
          }
          // Unknown tag: result is opaque (tag function transforms the template).
          // Propagate taint from any expression parts.
          var _tagSrc = t._src ? t._src.slice(t.start, paren.end) : t.text + '`...`';
          var _tagRef = exprRef(_tagSrc);
          if (paren.parts) {
            for (var _tp2 = 0; _tp2 < paren.parts.length; _tp2++) {
              if (paren.parts[_tp2].kind === 'expr') {
                var _te = await evalExprSrc(paren.parts[_tp2].expr);
                var _tt = _te ? collectChainTaint(_te) : null;
                if (_tt) { if (!_tagRef.taint) _tagRef.taint = new Set(); for (var _tl of _tt) _tagRef.taint.add(_tl); }
              }
            }
          }
          return { bind: chainBinding([_tagRef]), next: k + 2 };
        }
        // Known math/numeric constants like `Math.PI`.
        if (!isCall && MATH_CONSTANTS[t.text] !== undefined) {
          return { bind: chainBinding([makeSynthStr(String(MATH_CONSTANTS[t.text]))]), next: k + 1 };
        }
        // Known global builtin function call (numeric Math.*, parseInt...).
        if (isCall && BUILTINS[t.text]) {
          const args = await readConcatArgs(k + 1, stop);
          if (args) {
            const nums = [];
            let allNum = true;
            for (const a of args.args) {
              const ch = chainBinding(a);
              const n = chainAsNumber(ch);
              if (n === null) { allNum = false; break; }
              nums.push(n);
            }
            if (allNum) {
              const v = BUILTINS[t.text](...nums);
              return { bind: chainBinding([makeSynthStr(String(v))]), next: args.next };
            }
          }
        }
        // Object.keys/values/entries on known object bindings.
        if (isCall && (t.text === 'Object.keys' || t.text === 'Object.values' || t.text === 'Object.entries')) {
          const argRes = await readCallArgBindings(k + 1, stop);
          if (argRes && argRes.bindings.length === 1) {
            const ob = argRes.bindings[0];
            if (ob && ob.kind === 'object') {
              const keys = Object.keys(ob.props);
              if (t.text === 'Object.keys') {
                return { bind: arrayBinding(keys.map((k) => chainBinding([makeSynthStr(k)]))), next: argRes.next };
              }
              if (t.text === 'Object.values') {
                return { bind: arrayBinding(keys.map((k) => ob.props[k])), next: argRes.next };
              }
              if (t.text === 'Object.entries') {
                return { bind: arrayBinding(keys.map((k) => arrayBinding([
                  chainBinding([makeSynthStr(k)]),
                  ob.props[k],
                ]))), next: argRes.next };
              }
            }
          }
        }
        // Array.isArray / Array.from / Array.of on known bindings.
        if (isCall && t.text === 'Array.isArray') {
          const argRes = await readCallArgBindings(k + 1, stop);
          if (argRes && argRes.bindings.length === 1) {
            const ob = argRes.bindings[0];
            const v = ob && ob.kind === 'array' ? 'true' : (ob && (ob.kind === 'object' || ob.kind === 'chain') ? 'false' : null);
            if (v !== null) return { bind: chainBinding([makeSynthStr(v)]), next: argRes.next };
          }
        }
        if (isCall && t.text === 'Array.of') {
          const argRes = await readCallArgBindings(k + 1, stop);
          if (argRes) return { bind: arrayBinding(argRes.bindings.slice()), next: argRes.next };
        }
        if (isCall && t.text === 'Array.from') {
          const argRes = await readCallArgBindings(k + 1, stop);
          if (argRes && argRes.bindings.length >= 1) {
            const src = argRes.bindings[0];
            const mapFn = argRes.bindings[1] || null;
            if (src && src.kind === 'array') {
              let out = src.elems.slice();
              if (mapFn && mapFn.kind === 'function') {
                const mapped = [];
                for (let idx = 0; idx < out.length; idx++) {
                  const el = out[idx];
                  if (!el) return null;
                  const toks = await instantiateFunction(mapFn, [el, chainBinding([makeSynthStr(String(idx))])]);
                  if (!toks) return null;
                  mapped.push(chainBinding(toks));
                }
                out = mapped;
              }
              return { bind: arrayBinding(out), next: argRes.next };
            }
            // Array.from({length: n}) with optional mapFn.
            if (src && src.kind === 'object') {
              const lenB = src.props.length;
              const lenN = lenB ? chainAsNumber(lenB) : null;
              if (lenN !== null && lenN >= 0 && lenN < 10000) {
                const out = [];
                for (let idx = 0; idx < lenN; idx++) {
                  if (mapFn && mapFn.kind === 'function') {
                    const toks = await instantiateFunction(mapFn, [
                      chainBinding([exprRef('undefined')]),
                      chainBinding([makeSynthStr(String(idx))]),
                    ]);
                    if (!toks) return null;
                    out.push(chainBinding(toks));
                  } else {
                    out.push(chainBinding([exprRef('undefined')]));
                  }
                }
                return { bind: arrayBinding(out), next: argRes.next };
              }
            }
          }
        }
        // JSON.stringify on known scalar / object / array bindings.
        if (isCall && (t.text === 'JSON.stringify' || t.text === 'JSON.parse')) {
          const argRes = await readCallArgBindings(k + 1, stop);
          if (argRes && argRes.bindings.length >= 1) {
            // Check taint BEFORE concrete evaluation — if the argument
            // carries taint, the result should too regardless of concrete value.
            var _argBind = argRes.bindings[0];
            var _jTaint = null;
            if (_argBind) {
              if (_argBind.kind === 'chain') _jTaint = collectChainTaint(_argBind.toks);
              else if (_argBind.kind === 'object') { for (var _jk in _argBind.props) { var _jpt = _argBind.props[_jk]; if (_jpt && _jpt.kind === 'chain' && collectChainTaint(_jpt.toks)) { _jTaint = collectChainTaint(_jpt.toks); break; } } }
              else if (_argBind.kind === 'array') { for (var _ji = 0; _ji < _argBind.elems.length; _ji++) { var _jet = _argBind.elems[_ji]; if (_jet && _jet.kind === 'chain' && collectChainTaint(_jet.toks)) { _jTaint = collectChainTaint(_jet.toks); break; } } }
            }
            if (_jTaint) {
              return { bind: chainBinding([deriveExprRef(t.text + '(...)', _argBind.kind === 'chain' ? _argBind.toks : [exprRef(t.text)])]), next: argRes.next };
            }
            const val = bindingToJson(_argBind);
            if (val !== undefined) {
              if (t.text === 'JSON.stringify') {
                return { bind: chainBinding([makeSynthStr(JSON.stringify(val))]), next: argRes.next };
              }
              if (typeof val === 'string') {
                try {
                  const parsed = JSON.parse(val);
                  return { bind: jsonToBinding(parsed), next: argRes.next };
                } catch (_) { /* fall through */ }
              }
            }
            // Tainted/opaque argument: result carries the same taint.
            var _argBind = argRes.bindings[0];
            if (_argBind && _argBind.kind === 'chain') {
              var _jTaint = collectChainTaint(_argBind.toks);
              if (_jTaint) {
                return { bind: chainBinding([deriveExprRef(t.text + '(...)', _argBind.toks)]), next: argRes.next };
              }
            }
          }
        }
        // DOM factories return a tracked virtual element.
        if (isCall && DOM_FACTORIES[t.text]) {
          const args = await readConcatArgs(k + 1, stop);
          if (args) {
            const r = DOM_FACTORIES[t.text](args.args, k, args.next, t);
            if (r) return r;
          }
        }
        // `String(x)` coerces any literal to its string form.
        if (isCall && t.text === 'String') {
          const args = await readConcatArgs(k + 1, stop);
          if (args && args.args.length === 1) {
            const ch = chainBinding(args.args[0]);
            if (ch.toks.length === 1 && ch.toks[0].type === 'str') {
              return { bind: ch, next: args.next };
            }
          }
        }
        if (isCall) {
          const dot = t.text.lastIndexOf('.');
          if (dot > 0) {
            const method = t.text.slice(dot + 1);
            if (KNOWN_METHODS.has(method)) {
              const prefix = t.text.slice(0, dot);
              const prefBind = await resolvePath(prefix) || chainBinding([exprRef(prefix)]);
              const r = await applyMethod(prefBind, method, k + 1, stop);
              if (r) return { bind: r.bind, next: r.next };
            }
            // Fall through to the opaque-ident handling below for unknown
            // methods or unresolved prefixes.
          }
        }
        const b = await resolvePath(t.text);
        // Taint: check call-based sinks even in expression position
        // (e.g. var x = eval(tainted)).
        if (taintEnabled && isCall && _classifyCallSinkViaDB(DEFAULT_TYPE_DB, t.text, typedScope)) {
          var _sinkCallArgs = await readCallArgBindings(k + 1, stop);
          if (_sinkCallArgs) checkSinkCall(t.text, _sinkCallArgs.bindings, t);
        }
        if (!b) {
          // Unresolved identifier: return it as an opaque chain carrying
          // its source text. If followed by a balanced `(...)` (call) or
          // `[...]` (subscript) or `.prop` chain, absorb those too so the
          // whole postfix expression becomes one symbolic operand.
          let end = k + 1;
          while (end < stop) {
            const nx = tks[end];
            if (!nx) break;
            // Stop before Promise continuation methods so applySuffixes
            // can route them through applyMethod's .then/.catch/.finally
            // handler. This is what makes \`fetch(...).then(d => sink(d))\`
            // propagate taint into the callback.
            if (nx.type === 'other' && /^\.(then|catch|finally)$/.test(nx.text)) {
              break;
            }
            if (nx.type === 'open' && (nx.char === '(' || nx.char === '[')) {
              const matchChar = nx.char === '(' ? ')' : ']';
              let depth = 1, j = end + 1;
              while (j < stop && depth > 0) {
                const tk = tks[j];
                if (tk.type === 'open' && tk.char === nx.char) depth++;
                else if (tk.type === 'close' && tk.char === matchChar) depth--;
                if (depth === 0) break;
                j++;
              }
              if (depth !== 0) break;
              end = j + 1;
              continue;
            }
            if (nx.type === 'other' && /^(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$/.test(nx.text)) {
              end++;
              continue;
            }
            break;
          }
          const first = tks[k];
          const last = tks[end - 1];
          var _opaqueText = first._src.slice(first.start, last.end);
          var _opaqueRef = exprRef(_opaqueText);
          // Path-based taint sources (TAINT_SOURCES + member paths).
          var _opaqueTaint = checkTaintSource(_opaqueText);
          // Call-based taint sources: extract everything before the first
          // '(' and check it against TAINT_SOURCE_CALLS. Covers
          // fetch("/api"), new XMLHttpRequest(), IndexedDB / Cache reads.
          if (!_opaqueTaint) {
            var _parenIdx = _opaqueText.indexOf('(');
            if (_parenIdx > 0) {
              var _callName = _opaqueText.slice(0, _parenIdx).replace(/^new\s+/, '');
              var _callTaint = checkTaintSourceCall(_callName);
              if (_callTaint) _opaqueTaint = _callTaint;
            }
          }
          // Argument-taint propagation: parse the immediate `(...)` after
          // the callee and collect taint from each arg. Promise.resolve(x),
          // Promise.reject(x), wrapper functions like setTimeout(cb, ms),
          // and any opaque call all preserve their arguments' taint
          // through the opaque result. This is the same propagation the
          // inlined-function path does at line ~3933.
          var _firstParen = -1;
          for (var _fp = k + 1; _fp < end; _fp++) {
            if (tks[_fp] && tks[_fp].type === 'open' && tks[_fp].char === '(') { _firstParen = _fp; break; }
          }
          if (_firstParen >= 0 && taintEnabled && !isSanitizer(t.text, typedScope)) {
            var _opaqueArgs = await readConcatArgs(_firstParen, stop);
            if (_opaqueArgs) {
              var _opaqueArgTaint = null;
              for (var _oai = 0; _oai < _opaqueArgs.args.length; _oai++) {
                var _oat = collectChainTaint(_opaqueArgs.args[_oai]);
                if (_oat) {
                  if (!_opaqueArgTaint) _opaqueArgTaint = new Set();
                  for (var _oal of _oat) _opaqueArgTaint.add(_oal);
                }
              }
              if (_opaqueArgTaint) {
                if (!_opaqueTaint) _opaqueTaint = _opaqueArgTaint;
                else for (var _oalt of _opaqueArgTaint) _opaqueTaint.add(_oalt);
              }
            }
          }
          if (_opaqueTaint) _opaqueRef.taint = _opaqueTaint;
          return { bind: chainBinding([_opaqueRef]), next: end };
        }
        if (b) {
          // Call syntax: `name(args)` where name resolves to a function binding.
          if (b.kind === 'function' && isCall) {
            const args = await readConcatArgs(k + 1, stop);
            if (!args) return null;
            // For method calls (dotted path), bind 'this' to the receiver object.
            var _thisBind = null;
            var _dot = t.text.lastIndexOf('.');
            if (_dot > 0) {
              _thisBind = await resolvePath(t.text.slice(0, _dot));
            }
            var _fnResult = await instantiateFunction(b, args.args.map((a) => chainBinding(a)), _thisBind);
            // Non-chain return (object/array/function binding).
            if (_fnResult && _fnResult.kind && _fnResult.kind !== 'chain') {
              return { bind: _fnResult, next: args.next };
            }
            var toks = (typeof _fnResult === 'object' && _fnResult && !_fnResult.kind) ? _fnResult : _fnResult;
            if (!toks || (Array.isArray(toks) && toks.length === 0)) toks = null;
            if (!toks) {
              // Function couldn't be inlined (e.g. pre-pass converted).
              // Produce an opaque call expression.
              const first = tks[k];
              const last = tks[args.next - 1];
              var _callRef = exprRef(first._src.slice(first.start, last.end));
              // Taint: check if this is a sanitizer (clears taint) or propagates it.
              if (taintEnabled && !isSanitizer(t.text, typedScope)) {
                var _argTaint = null;
                for (var _ai = 0; _ai < args.args.length; _ai++) {
                  var _at = collectChainTaint(args.args[_ai]);
                  if (_at) { if (!_argTaint) _argTaint = new Set(); for (var _l of _at) _argTaint.add(_l); }
                }
                if (_argTaint) _callRef.taint = _argTaint;
              }
              return { bind: chainBinding([_callRef]), next: args.next };
            }
            // Taint: for inlined functions, check if it's a sanitizer.
            if (taintEnabled && isSanitizer(t.text, typedScope)) {
              return { bind: chainBinding(toks.map(function(tk) { var c = Object.assign({}, tk); delete c.taint; return c; })), next: args.next };
            }
            return { bind: chainBinding(toks), next: args.next };
          }
          return { bind: b, next: k + 1 };
        }
      }
      return null;
    };

    // Invoke a function binding with a list of argument chains (token lists).
    // Pushes a temporary scope with param→arg bindings, parses the body
    // expression in the original token array, then pops the scope.
    // Recursion guard for instantiateFunction. Each entry is the
    // function body range `"<bodyStart>:<bodyEnd>"`. The analyser
    // walks a function body symbolically; if the same body is
    // already live on the call stack we return a conservative
    // opaque chain so direct, indirect, and mutual recursion
    // terminate without polluting the output with synthetic tokens.
    // The guard is strict-recursion only — there is no depth cap
    // and no per-body walk-count cap, so distinct-lineage calls to
    // the same helper all get their full walk.
    const _callStack = [];
    const instantiateFunction = async (fn, argBindings, thisBinding) => {
      var _fnKey = (fn && fn.bodyStart != null) ? (fn.bodyStart + ':' + fn.bodyEnd) : null;
      // Detect recursion: the same function body is already being
      // walked. Return null so the caller falls back to its own
      // opaque-call handling (which preserves the original source
      // text and computes taint from the argument bindings). This
      // prevents runaway recursive walks, mutual recursion, and
      // pathological graphs from unbounding the analyser without
      // polluting the output with synthetic tokens.
      if (_fnKey && _callStack.indexOf(_fnKey) >= 0) return null;
      if (_fnKey) _callStack.push(_fnKey);
      // Closure capture: push any captured-scope frames (by reference)
      // that aren't already on the live stack, so reads of outer
      // variables resolve through the closure. We push only
      // previously-popped frames to avoid duplicates when a closure
      // is called synchronously within its defining scope.
      //
      // The "already-live" check used to be `stack.indexOf(capFr)`,
      // which is O(stack_depth) per captured frame. For helpers
      // declared deep inside an outer function and called hundreds
      // of times, this collapses into the dominant per-call cost
      // (closure with 10 captured frames × stack depth 20 = 200
      // comparisons per call × thousands of calls = a real chunk
      // of wall time). Use a Set lookup instead — O(1) per frame —
      // and only build the Set when there's actually something to
      // push, so the no-closure case stays free.
      var _pushedCaptureFrames = [];
      if (fn.capturedScope && fn.capturedScope.length > 0) {
        // Use a Set for O(1) "is this captured frame already live?"
        // checks when there's enough work to amortise the Set
        // construction. Below the threshold, the linear stack.indexOf
        // is faster because the set construction would dominate.
        // The threshold is chosen so that the break-even point sits
        // around `capturedScope.length * stack.length ≈ 32`, which
        // is roughly where Map insertion overhead crosses linear
        // scan in V8 micro-benchmarks.
        if (fn.capturedScope.length * stack.length >= 32) {
          var _liveSet = new Set();
          for (var _li = 0; _li < stack.length; _li++) _liveSet.add(stack[_li]);
          for (var _ci = 0; _ci < fn.capturedScope.length; _ci++) {
            var capFr = fn.capturedScope[_ci];
            if (!capFr) continue;
            if (_liveSet.has(capFr)) continue;
            stack.push(capFr);
            _liveSet.add(capFr);
            _pushedCaptureFrames.push(capFr);
          }
        } else {
          for (var _ci2 = 0; _ci2 < fn.capturedScope.length; _ci2++) {
            var capFr2 = fn.capturedScope[_ci2];
            if (!capFr2) continue;
            if (stack.indexOf(capFr2) >= 0) continue;
            stack.push(capFr2);
            _pushedCaptureFrames.push(capFr2);
          }
        }
      }
      stack.push({ bindings: Object.create(null), isFunction: true });
      const frame = stack[stack.length - 1];
      // Bind 'this' if provided (for method calls on objects).
      if (thisBinding) frame.bindings['this'] = thisBinding;
      // instantiateFunction walks the body with calling context —
      // taint findings are valid here (unlike definition-time walks).
      var savedTaintFnDepth = taintFnDepth;
      // Only enable findings (taintFnDepth=0) when called from the main
      // walk. Inside definition-time body walks (taintFnDepth > 0),
      // nested instantiateFunction calls stay suppressed.
      if (savedTaintFnDepth === 0) taintFnDepth = 0;
      const savedTks = tks;
      tks = tokens;
      for (let p = 0; p < fn.params.length; p++) {
        const pi = fn.params[p];
        if (pi.rest) {
          // Rest parameter: collect remaining args into an array.
          frame.bindings[pi.name] = arrayBinding(argBindings.slice(p));
          break;
        }
        const a = argBindings[p];
        if (a) {
          frame.bindings[pi.name] = a;
        } else if (pi.defaultStart != null) {
          // Evaluate the parameter's default expression in the current
          // (call-site) scope so enclosing bindings can be referenced.
          const r = await readConcatExpr(pi.defaultStart, pi.defaultEnd, TERMS_NONE);
          frame.bindings[pi.name] = (r && r.next === pi.defaultEnd) ? chainBinding(r.toks) : null;
        } else {
          frame.bindings[pi.name] = null;
        }
      }
      let result = null;
      var fnReturnBinding = null; // non-chain return (object/array/function)
      var fnLoopVars = null;
      if (fn.isBlock) {
        // Skip functions already converted by the pre-pass to return
        // DocumentFragments — inlining them produces nonsense.
        if (tks[fn.bodyStart] && tks[fn.bodyStart]._src) {
          const peekSrc = tks[fn.bodyStart]._src.slice(tks[fn.bodyStart].start, tks[fn.bodyStart].start + 80);
          if (/var __f\s*=\s*document\.createDocumentFragment/.test(peekSrc)) {
            tks = savedTks;
            stack.pop();
            return null;
          }
        }
        // Walk the function body to process var declarations, assignments,
        // and control flow. This ensures inner `var html` declarations are
        // bound in the function frame, not resolved from outer scope.
        let bodyStart = fn.bodyStart;
        let bodyEnd = fn.bodyEnd;
        if (tks[bodyStart] && tks[bodyStart].type === 'open' && tks[bodyStart].char === '{') bodyStart++;
        if (tks[bodyEnd - 1] && tks[bodyEnd - 1].type === 'close' && tks[bodyEnd - 1].char === '}') bodyEnd--;
        // Find the return statement first so we know which variable
        // to track as the build var inside the function body.
        let returnVar = null;
        for (let ri = bodyStart; ri < bodyEnd; ri++) {
          if (tks[ri] && tks[ri].type === 'other' && tks[ri].text === 'return') {
            const nextTok = tks[ri + 1];
            if (nextTok && nextTok.type === 'other' && IDENT_RE.test(nextTok.text)) {
              returnVar = nextTok.text;
            }
            break;
          }
          if (tks[ri] && tks[ri].type === 'open' && tks[ri].char === '{') {
            let d = 1; ri++;
            while (ri < bodyEnd && d > 0) { if (tks[ri].type === 'open' && tks[ri].char === '{') d++; else if (tks[ri].type === 'close' && tks[ri].char === '}') d--; ri++; }
            continue;
          }
        }
        // Enable trackBuildVar for the returned variable so loops
        // inside the function body properly tag chain tokens.
        const savedTrackBuildVar = trackBuildVar;
        const savedTrackDepth = trackBuildVarDepth;
        const savedBuildVarDeclStart = buildVarDeclStart;
        if (returnVar) {
          trackBuildVar = new Set([returnVar]);
          trackBuildVarDepth = funcDepth();
        } else {
          trackBuildVar = null;
        }
        buildVarDeclStart = -1; // reset so inner decls don't leak out
        const lvBefore = loopVars.length;
        await walkRange(bodyStart, bodyEnd);
        fnLoopVars = loopVars.splice(lvBefore);
        trackBuildVar = savedTrackBuildVar;
        trackBuildVarDepth = savedTrackDepth;
        buildVarDeclStart = savedBuildVarDeclStart;
        // Find the return value and resolve the returned expression.
        let ri = bodyStart;
        while (ri < bodyEnd) {
          const t = tks[ri];
          if (t && t.type === 'other' && t.text === 'return') {
            // Use readValue to preserve object/array/function bindings.
            const rv = await readValue(ri + 1, bodyEnd, TERMS_TOP);
            if (rv && rv.binding) {
              if (rv.binding.kind === 'chain') { result = rv.binding.toks; }
              else { fnReturnBinding = rv.binding; }
            } else {
              const r = await readConcatExpr(ri + 1, bodyEnd, TERMS_TOP);
              if (r) result = r.toks;
            }
            break;
          }
          if (t && t.type === 'open' && t.char === '{') {
            let depth = 1; ri++;
            while (ri < bodyEnd && depth > 0) {
              if (tks[ri].type === 'open' && tks[ri].char === '{') depth++;
              else if (tks[ri].type === 'close' && tks[ri].char === '}') depth--;
              ri++;
            }
            continue;
          }
          ri++;
        }
      } else {
        // Expression-body arrow: `v => expr`. We run the statement
        // walker over [bodyStart, bodyEnd) too, so assignment-shaped
        // expression bodies like `v => document.body.innerHTML = v`
        // trigger sink detection (the statement walker's element /
        // element-attribute sink handlers fire during walkRange).
        // Then we also read the expression's value for the caller's
        // return-value taint propagation.
        if (taintEnabled) {
          try { await walkRange(fn.bodyStart, fn.bodyEnd); } catch (_) {}
        }
        const r = await readConcatExpr(fn.bodyStart, fn.bodyEnd, TERMS_NONE);
        if (r && r.next === fn.bodyEnd) result = r.toks;
      }
      tks = savedTks;
      taintFnDepth = savedTaintFnDepth;
      stack.pop();
      // Pop captured frames in reverse order of push.
      for (var _pc = _pushedCaptureFrames.length - 1; _pc >= 0; _pc--) {
        var _top = stack[stack.length - 1];
        if (_top === _pushedCaptureFrames[_pc]) stack.pop();
      }
      // Pop recursion guard entry for this invocation.
      if (_fnKey && _callStack[_callStack.length - 1] === _fnKey) _callStack.pop();
      // Expand any loopVars created during the function body walk.
      if (result && fnLoopVars && fnLoopVars.length > 0) {
        const lvByName = Object.create(null);
        for (const lv of fnLoopVars) {
          if (!lvByName[lv.name]) lvByName[lv.name] = [];
          lvByName[lv.name].push(lv);
        }
        result = expandLoopVars(result, lvByName);
      }
      // Return non-chain binding directly (object/array from return statement).
      if (!result && fnReturnBinding) return fnReturnBinding;
      return result;
    };

    // Locate the end of an operand expression: the next `+` at depth 0 or
    // the first terminator in `terms`.
    const skipOperand = (k, stop, terms) => {
      let depth = 0;
      while (k < stop) {
        const tk = tks[k];
        if (tk.type === 'open') depth++;
        else if (tk.type === 'close') {
          if (depth === 0) return k;
          depth--;
        } else if (depth === 0) {
          if (tk.type === 'plus') return k;
          if (tk.type === 'sep' && terms.sep.includes(tk.char)) return k;
        }
        k++;
      }
      return k;
    };

    // Read one operand of a concat chain. An operand is either fully
    // resolvable (returned as its chain of string/template tokens) or opaque
    // (captured as a single expression-ref operand whose source slice spans
    // the original text — the same representation used for standalone
    // unresolved identifiers already emitted by the tokenizer). This dual
    // representation is the tool's fundamental model for string expressions:
    // known parts become string tokens, unknown parts become expression refs.
    const readOperand = async (k, stop, terms) => {
      const parsed = await parseArithExpr(k, stop);
      if (parsed) {
        const boundary = skipOperand(parsed.next, stop, terms);
        if (boundary === parsed.next) {
          if (parsed.bind.kind === 'chain') return { toks: parsed.bind.toks.slice(), next: parsed.next };
          // Non-chain binding (function/array/object): return opaque ref
          // so concat chains can include it without crashing.
          return { toks: [exprRef(tks[k]._src.slice(tks[k].start, tks[parsed.next - 1].end))], next: parsed.next };
        }
      }
      const end = skipOperand(k, stop, terms);
      if (end === k) return null;
      const first = tks[k];
      const last = tks[end - 1];
      // Collect taint from any tokens in the captured range.
      var _rangeRef = exprRef(first._src.slice(first.start, last.end));
      if (taintEnabled) {
        for (var _ri = k; _ri < end; _ri++) {
          var _rt = tks[_ri];
          if (_rt.type === 'other' && IDENT_RE.test(_rt.text)) {
            var _rb = resolve(_rt.text);
            if (_rb && _rb.kind === 'chain') {
              var _rTaint = collectChainTaint(_rb.toks);
              if (_rTaint) { if (!_rangeRef.taint) _rangeRef.taint = new Set(); for (var _rl of _rTaint) _rangeRef.taint.add(_rl); }
            }
          }
        }
      }
      return {
        toks: [_rangeRef],
        next: end,
      };
    };

    // Binary operator precedence table (higher binds tighter). `**` is the
    // only right-associative operator we support.
    const BINOP_PREC = {
      '**': 14,
      '*': 13, '/': 13, '%': 13,
      '-': 12,
      '<<': 11, '>>': 11, '>>>': 11,
      '<': 10, '>': 10, '<=': 10, '>=': 10,
      '==': 9, '!=': 9, '===': 9, '!==': 9,
      '&': 8, '^': 7, '|': 6,
      '&&': 5, '||': 4, '??': 4,
    };

    // Precedence-climbing parser for arithmetic/bitwise/logical/comparison
    // expressions. Reads an atom then greedily consumes operator-operand
    // pairs while their precedence is at least `minPrec`. Concrete operands
    // fold to literals; unknown subparts yield canonical symbolic text.
    // Classify a token as a binary operator and return its precedence.
    const _getOpPrec = (tok) => {
      if (!tok) return null;
      if (tok.type === 'op' && BINOP_PREC[tok.text] !== undefined)
        return { text: tok.text, prec: BINOP_PREC[tok.text] };
      if (tok.type === 'plus') return { text: '+', prec: 12 };
      if (tok.type === 'other' && (tok.text === 'in' || tok.text === 'instanceof'))
        return { text: tok.text, prec: 10 };
      return null;
    };
    // Iterative Pratt parser. Uses explicit stacks instead of recursive
    // calls so deeply nested expressions can't overflow the JS call stack.
    const parseArithExpr = async (k, stop, minPrec) => {
      minPrec = minPrec || 0;
      const opStack = [];
      const ternStack = [];
      var pos = k;
      var curMinPrec = minPrec;
      var cur = null;
      var next = pos;
      var needOperand = true;
      for (;;) {
        if (needOperand) {
          const base = await readBase(pos, stop);
          if (!base) {
            while (opStack.length > 0) {
              const top = opStack.pop();
              if (cur) { const c = combineArith(top.left, top.op, cur); if (c) { cur = c; curMinPrec = top.minPrec; continue; } }
              cur = top.left; next = top.nextPos; curMinPrec = top.minPrec;
            }
            if (!cur) return null;
            break;
          }
          const r = await applySuffixes(base.bind, base.next, stop);
          cur = r.bind;
          next = r.next;
          needOperand = false;
        }
        // Non-chain bindings pass through when no operators applied.
        if (cur && cur.kind !== 'chain' && opStack.length === 0 && ternStack.length === 0) return { bind: cur, next };
        const opInfo = (cur && cur.kind === 'chain') ? _getOpPrec(tks[next]) : null;
        if (opInfo && opInfo.prec >= curMinPrec && next < stop) {
          opStack.push({ left: cur, op: opInfo.text, minPrec: curMinPrec, nextPos: next });
          curMinPrec = opInfo.text === '**' ? opInfo.prec : opInfo.prec + 1;
          pos = next + 1;
          needOperand = true;
          continue;
        }
        if (opStack.length > 0) {
          const top = opStack[opStack.length - 1];
          const c = combineArith(top.left, top.op, cur);
          if (!c) {
            opStack.pop();
            cur = top.left; next = top.nextPos; curMinPrec = top.minPrec;
            while (opStack.length > 0) {
              const t2 = opStack.pop();
              const c2 = combineArith(t2.left, t2.op, cur);
              if (c2) { cur = c2; curMinPrec = t2.minPrec; }
              else { cur = t2.left; next = t2.nextPos; curMinPrec = t2.minPrec; }
            }
            break;
          }
          opStack.pop();
          cur = c; curMinPrec = top.minPrec;
          continue;
        }
        if (!cur || cur.kind !== 'chain') break;
        const q = tks[next];
        if (q && q.type === 'other' && q.text === '?') {
          ternStack.push({ cond: cur, ifTrue: null });
          pos = next + 1; curMinPrec = 0; needOperand = true;
          continue;
        }
        if (ternStack.length > 0) {
          const top = ternStack[ternStack.length - 1];
          if (top.ifTrue === null) {
            const colon = tks[next];
            if (colon && colon.type === 'other' && colon.text === ':') {
              top.ifTrue = cur; pos = next + 1; curMinPrec = 0; needOperand = true;
              continue;
            }
            ternStack.pop(); cur = top.cond;
          } else {
            ternStack.pop();
            cur = combineTernary(top.cond, top.ifTrue, cur);
            if (!cur) return null;
            continue;
          }
        }
        break;
      }
      if (!cur) return null;
      if (cur.kind !== 'chain') return { bind: cur, next };
      return { bind: cur, next };
    };

    // Fold a ternary when the condition is a concrete value; otherwise
    // produce a conditional chain token that preserves both branches.
    const combineTernary = (cond, ifT, ifF) => {
      if (!cond || cond.kind !== 'chain') return null;
      if (!ifT || ifT.kind !== 'chain') return null;
      if (!ifF || ifF.kind !== 'chain') return null;
      const cNum = chainAsNumber(cond);
      if (cNum !== null) return cNum ? ifT : ifF;
      // Check for known boolean-ish strings.
      if (cond.toks.length === 1 && cond.toks[0].type === 'str') {
        const text = cond.toks[0].text;
        if (text === 'true') return ifT;
        if (text === 'false' || text === 'null' || text === 'undefined' || text === '') return ifF;
      }
      const ct = chainAsExprText(cond);
      if (ct === null) return null;
      // Produce a conditional token that holds both branches as token
      // arrays. The direct chain parser will emit if/else blocks.
      return chainBinding([{
        type: 'cond', condExpr: ct,
        ifTrue: ifT.toks, ifFalse: ifF.toks,
      }]);
    };

    // Combine two chain bindings via a binary operator. If both sides are
    // single literal numbers/booleans, the result is computed. Otherwise
    // returns a chain holding one opaque operand whose source is the
    // parenthesized partial expression, preserving any already-evaluated
    // sub-results.
    const combineArith = (left, op, right) => {
      if (!left || left.kind !== 'chain' || !right || right.kind !== 'chain') return null;
      // `in` / `instanceof` are always symbolic — they depend on runtime
      // prototype/object state we don't model. Skip straight to symbolic.
      if (op === 'in' || op === 'instanceof') {
        const lt = chainAsExprText(left);
        const rt = chainAsExprText(right);
        if (lt === null || rt === null) return null;
        return chainBinding([deriveExprRef('(' + lt + ' ' + op + ' ' + rt + ')', left.toks, right.toks)]);
      }
      const lNum = chainAsNumber(left);
      const rNum = chainAsNumber(right);
      if (lNum !== null && rNum !== null) {
        let v;
        switch (op) {
          case '+': v = lNum + rNum; break;
          case '-': v = lNum - rNum; break;
          case '*': v = lNum * rNum; break;
          case '/': v = lNum / rNum; break;
          case '%': v = lNum % rNum; break;
          case '**': v = lNum ** rNum; break;
          case '|': v = lNum | rNum; break;
          case '&': v = lNum & rNum; break;
          case '^': v = lNum ^ rNum; break;
          case '<<': v = lNum << rNum; break;
          case '>>': v = lNum >> rNum; break;
          case '>>>': v = lNum >>> rNum; break;
          case '<': v = lNum < rNum; break;
          case '>': v = lNum > rNum; break;
          case '<=': v = lNum <= rNum; break;
          case '>=': v = lNum >= rNum; break;
          case '==': v = lNum == rNum; break;
          case '!=': v = lNum != rNum; break;
          case '===': v = lNum === rNum; break;
          case '!==': v = lNum !== rNum; break;
          case '&&': v = lNum && rNum; break;
          case '||': v = lNum || rNum; break;
          case '??': v = (lNum === null || lNum === undefined) ? rNum : lNum; break;
          default: return null;
        }
        return chainBinding([makeSynthStr(String(v))]);
      }
      // String comparison: fold ===, !==, ==, != when both sides are known strings.
      const lStr2 = chainAsKnownString(left);
      const rStr2 = chainAsKnownString(right);
      if (lStr2 !== null && rStr2 !== null) {
        let v;
        switch (op) {
          case '===': case '==': v = lStr2 === rStr2; break;
          case '!==': case '!=': v = lStr2 !== rStr2; break;
          case '<': v = lStr2 < rStr2; break;
          case '>': v = lStr2 > rStr2; break;
          case '<=': v = lStr2 <= rStr2; break;
          case '>=': v = lStr2 >= rStr2; break;
          default: v = null;
        }
        if (v !== null) return chainBinding([makeSynthStr(String(v))]);
      }
      // `+` is overloaded in JS: numeric addition or string concatenation.
      // Treat as arithmetic when both operands are single-token non-string
      // references (identifiers, numbers, or arithmetic sub-expressions).
      // Fall through to concat when either side contains a user string
      // literal (quotes in the source) or a multi-token resolved chain
      // (which came from string concatenation).
      if (op === '+') {
        // Check if either operand is definitively a source-level string
        // (not a number that was stringified).
        const isSourceString = (bind) => {
          if (bind.toks.length > 1) return true; // multi-token = concat result
          const t = bind.toks[0];
          if (t.type === 'str') {
            // A str token from a user string literal has a quote property.
            // Synthetic str tokens from number folding don't.
            // Check: if it parses as a number, it's numeric, not a string.
            const n = Number(t.text);
            if (!Number.isNaN(n) && String(n) === t.text) return false;
            if (t.text === 'true' || t.text === 'false' || t.text === 'null' || t.text === 'undefined' || t.text === 'NaN') return false;
            return true; // Real string value
          }
          return false;
        };
        if (!isSourceString(left) && !isSourceString(right)) {
          const lt = chainAsExprText(left);
          const rt = chainAsExprText(right);
          if (lt !== null && rt !== null) {
            return chainBinding([deriveExprRef('(' + lt + ' + ' + rt + ')', left.toks, right.toks)]);
          }
        }
        return null;
      }
      // Short-circuit logical/nullish operators using whichever concrete
      // value (number or string) the left-hand side has.
      const lStr = lNum === null ? chainAsKnownString(left) : null;
      const lTruthy = (lNum !== null && lNum !== 0) || (lStr !== null && lStr !== '' && lStr !== 'false' && lStr !== 'null' && lStr !== 'undefined' && lStr !== '0' && lStr !== 'NaN');
      const lFalsy = lNum === 0 || lStr === '' || lStr === 'false' || lStr === 'null' || lStr === 'undefined' || lStr === '0' || lStr === 'NaN';
      const lNullish = lStr === 'null' || lStr === 'undefined';
      if (op === '&&') { if (lFalsy) return left; if (lTruthy) return right; }
      else if (op === '||') { if (lTruthy) return left; if (lFalsy) return right; }
      else if (op === '??') { if (lNullish) return right; if (lStr !== null || lNum !== null) return left; }
      // Symbolic: combine texts.
      const lt = chainAsExprText(left);
      const rt = chainAsExprText(right);
      if (lt === null || rt === null) return null;
      const text = '(' + lt + ' ' + op + ' ' + rt + ')';
      return chainBinding([deriveExprRef(text, left.toks, right.toks)]);
    };

    // Apply a unary prefix operator to a chain binding. Folds to a literal
    // when the operand is concrete; otherwise produces canonical symbolic
    // text like `(-x)` or `(!cond)`.
    const applyUnary = (op, operand) => {
      if (!operand || operand.kind !== 'chain') return null;
      const n = chainAsNumber(operand);
      if (n !== null) {
        let v;
        switch (op) {
          case '-': v = -n; break;
          case '+': v = +n; break;
          case '!': v = !n; break;
          case '~': v = ~n; break;
          default: return null;
        }
        return chainBinding([makeSynthStr(String(v))]);
      }
      const et = chainAsExprText(operand);
      if (et === null) return null;
      const text = op + et;
      return chainBinding([deriveExprRef(text, operand.toks)]);
    };

    const chainAsNumber = (chain) => {
      if (chain.toks.length !== 1) return null;
      const t = chain.toks[0];
      if (t.type !== 'str') return null;
      const n = Number(t.text);
      if (Number.isNaN(n)) return null;
      if (String(n) !== t.text) return null;
      return n;
    };

    // Evaluate truthiness of a chain binding. Returns true, false, or null (unknown).
    const evalTruthiness = (bind) => {
      if (!bind || bind.kind !== 'chain') return null;
      if (bind.toks.length === 1 && bind.toks[0].type === 'str') {
        const text = bind.toks[0].text;
        if (text === 'true') return true;
        if (text === 'false' || text === 'null' || text === 'undefined' || text === 'NaN') return false;
      }
      const n = chainAsNumber(bind);
      if (n !== null) return n !== 0;
      const s = chainAsKnownString(bind);
      if (s !== null) return s !== '';
      return null;
    };

    // Unified reachability check for ALL branch decisions.
    // Takes a token range (start, end) in the main tokens array.
    // Returns: true (always true), false (always false), null (both possible).
    // Uses concrete evaluation first, then SMT with path constraints.
    const checkReachability = async (start, end) => {
      if (start >= end) return null;
      var condVal = await readValue(start, end, null);
      var concrete = condVal ? evalTruthiness(condVal.binding) : null;
      if (taintEnabled) {
        var condToks = [];
        for (var ci = start; ci < end; ci++) condToks.push(tokens[ci]);
        var smtResult = await smtCheckCondition(condToks, resolve, resolvePath, pathConstraints);
        if (smtResult) {
          if (smtResult.sat && smtResult.unsat) return null;
          if (smtResult.sat && !smtResult.unsat) return true;
          if (!smtResult.sat && smtResult.unsat) return false;
          if (!smtResult.sat && !smtResult.unsat) return false; // neither = dead
        }
      }
      return concrete;
    };

    const chainAsExprText = (chain) => {
      // Render a single-token chain.
      const renderTok = (t) => {
        if (t.type === 'str') {
          const n = Number(t.text);
          if (!Number.isNaN(n) && String(n) === t.text) return t.text;
          return JSON.stringify(t.text);
        }
        if (t.type === 'other') return t.text;
        if (t.type === 'cond') {
          const tt = chainAsExprText(chainBinding(t.ifTrue));
          const ft = chainAsExprText(chainBinding(t.ifFalse));
          if (tt !== null && ft !== null) return '(' + t.condExpr + ' ? ' + tt + ' : ' + ft + ')';
          return null;
        }
        if (t.type === 'trycatch') {
          const tb = chainAsExprText(chainBinding(t.tryBody));
          const cb = chainAsExprText(chainBinding(t.catchBody));
          if (tb !== null && cb !== null) return '(try ' + tb + ' catch ' + cb + ')';
          return null;
        }
        if ((t.type === 'switch' || t.type === 'switchjoin') && t.branches) {
          var _brParts = [];
          for (var _bi = 0; _bi < t.branches.length; _bi++) {
            var _brT = chainAsExprText(chainBinding(t.branches[_bi].chain));
            if (_brT === null) return null;
            _brParts.push(_brT);
          }
          return '(switch ' + _brParts.join(' | ') + ')';
        }
        return null;
      };
      if (chain.toks.length === 1) return renderTok(chain.toks[0]);
      // Multi-token concat chain: alternate operand / `plus` tokens. Render
      // each operand and join with `+`. This lets the walker pass concat
      // conditions like `"http://" + x === "http://abc"` to the SMT layer
      // where smtArith translates `+` between String operands to (str.++).
      var parts = [];
      for (var ci = 0; ci < chain.toks.length; ci++) {
        var tk = chain.toks[ci];
        if (tk.type === 'plus') { parts.push('+'); continue; }
        var rendered = renderTok(tk);
        if (rendered === null) return null;
        parts.push(rendered);
      }
      return parts.join(' ');
    };

    // Parse `( chain, chain, ... )` starting at the `(` token index. Returns
    // { args: [tks[], ...], next } or null.
    // Parse `( arg, arg, ... )` where each arg is a full value (binding),
    // returning { bindings: [binding|null, ...], next } or null. Used by
    // the DOM method call handler so element-typed arguments stay intact.
    const readCallArgBindings = async (k, stop) => {
      if (!tks[k] || tks[k].type !== 'open' || tks[k].char !== '(') return null;
      if (tks[k + 1] && tks[k + 1].type === 'close' && tks[k + 1].char === ')') return { bindings: [], next: k + 2 };
      _evalStack.push({ type: 'READ_CALL_ARG_BINDINGS', i: k + 1, stop, bindings: [] });
      return await _evalLoop();
    };
    const _stepReadCallArgBindings = async (frame) => {
      if (_resultSlot.has) {
        const v = _consumeResult();
        if (!v) { _completeFrame(null); return; }
        frame.bindings.push(v.binding); frame.i = v.next;
        const sep = tks[frame.i];
        if (sep && sep.type === 'sep' && sep.char === ',') frame.i++;
        else { const rp = tks[frame.i]; if (rp && rp.type === 'close' && rp.char === ')') { _completeFrame({ bindings: frame.bindings, next: frame.i + 1 }); } else { _completeFrame(null); } return; }
      }
      while (frame.i < frame.stop) {
        if (tks[frame.i] && tks[frame.i].type === 'close' && tks[frame.i].char === ')') break;
        if (tks[frame.i] && tks[frame.i].type === 'other' && tks[frame.i].text.startsWith('...')) {
          var _sn = tks[frame.i].text.slice(3);
          var _sb = IDENT_RE.test(_sn) ? await resolvePath(_sn) : null;
          if (_sb && _sb.kind === 'array') { for (var _si = 0; _si < _sb.elems.length; _si++) if (_sb.elems[_si]) frame.bindings.push(_sb.elems[_si]); }
          else frame.bindings.push(chainBinding([deriveExprRef(_sn, _sb && _sb.kind === 'chain' ? _sb.toks : null)]));
          frame.i++; if (tks[frame.i] && tks[frame.i].type === 'sep' && tks[frame.i].char === ',') { frame.i++; continue; } break;
        }
        _evalStack.push({ type: 'READ_VALUE', k: frame.i, stop: frame.stop, terms: TERMS_ARG, phase: 0 });
        return; // result consumed at top on next _evalLoop iteration
      }
      const rp = tks[frame.i];
      if (!rp || rp.type !== 'close' || rp.char !== ')') { _completeFrame(null); return; }
      _completeFrame({ bindings: frame.bindings, next: frame.i + 1 });
    };

    const readConcatArgs = async (k, stop) => {
      if (!tks[k] || tks[k].type !== 'open' || tks[k].char !== '(') return null;
      if (tks[k + 1] && tks[k + 1].type === 'close' && tks[k + 1].char === ')') return { args: [], next: k + 2 };
      _evalStack.push({ type: 'READ_CONCAT_ARGS', i: k + 1, stop, args: [] });
      return await _evalLoop();
    };
    const _stepReadConcatArgs = (frame) => {
      if (_resultSlot.has) {
        const arg = _consumeResult();
        if (!arg) { _completeFrame(null); return; }
        frame.args.push(arg.toks); frame.i = arg.next;
        const sep = tks[frame.i];
        if (sep && sep.type === 'sep' && sep.char === ',') frame.i++;
        else { const rp = tks[frame.i]; if (rp && rp.type === 'close' && rp.char === ')') { _completeFrame({ args: frame.args, next: frame.i + 1 }); } else { _completeFrame(null); } return; }
      }
      if (tks[frame.i] && tks[frame.i].type === 'close' && tks[frame.i].char === ')') { _completeFrame({ args: frame.args, next: frame.i + 1 }); return; }
      if (frame.i < frame.stop) {
        _evalStack.push({ type: 'READ_CONCAT_EXPR', i: frame.i, stop: frame.stop, terms: TERMS_ARG, phase: 0, out: [] });
        return; // result consumed at top on next iteration
      }
      _completeFrame(null);
    };

    // Read a concat chain (operand [+ operand]*) starting at `k`, stopping at
    // the first top-level token matching any terminator in `terms`
    // (`{ sep: [...], close: [...] }`). Returns `{ toks, next }` or null.
    const readConcatExpr = async (k, stop, terms) => {
      const out = [];
      const endAt = (tk) => {
        if (!tk) return true;
        if (tk.type === 'sep' && terms.sep.includes(tk.char)) return true;
        if (tk.type === 'close' && terms.close.includes(tk.char)) return true;
        return false;
      };
      let i = k;
      // Read first operand.
      if (endAt(tks[i])) return null;
      let op = await readOperand(i, stop, terms);
      if (!op) return null;
      for (const t of op.toks) out.push(t);
      i = op.next;
      // Read subsequent (+ operand)* pairs.
      while (i < stop && !endAt(tks[i])) {
        const plus = tks[i];
        if (!plus || plus.type !== 'plus') return null;
        i++;
        op = await readOperand(i, stop, terms);
        if (!op) return null;
        out.push(plus);
        for (const t of op.toks) out.push(t);
        i = op.next;
      }
      return { toks: out, next: i };
    };

    // Top-level RHS reader: reads a concat chain up to `,`/`;`/stop.
    const readInit = async (k, stop) => {
      const r = await readConcatExpr(k, stop, TERMS_TOP);
      return r ? r.toks : null;
    };

    let stop = Math.min(stopAt, tokens.length);
    // Shared helpers for iterative walkRange state machine.
    // Structural equality over chain-token arrays using reference
    // equality on each element. The walker caches plus/paren/synthetic
    // marker tokens by reference, and passes live source tokens by
    // reference out of the tokenizer, so "both branches produced the
    // same binding" collapses to "both arrays contain the same token
    // references in the same order". Used by the if/else merge hot
    // path to avoid the O(tree_size) JSON.stringify round-trip that
    // used to dominate wall time on function-heavy files.
    function _chainToksRefEqual(a, b) {
      if (a === b) return true;
      if (!a || !b) return false;
      if (a.length !== b.length) return false;
      for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
      }
      return true;
    }

    // Iterative deep structural equality for chain-token arrays.
    //
    // The walker's cond-merge logic produces synthetic `cond` /
    // `trycatch` / `switchjoin` tokens that wrap the previous value
    // of a variable inside themselves. On large function-heavy
    // inputs the same variable can pick up dozens of layers of
    // wrapping over the course of a single phase-1 walk, and the
    // resulting trees grow into the hundreds of thousands of nodes.
    // The previous JSON.stringify-based equality check fell off a
    // cliff at that scale: stringify is O(tree_size), it allocates
    // a string proportional to the tree's serialized form, and
    // beyond V8's ~512 MB max-string ceiling it throws
    // "Invalid string length" outright.
    //
    // The iterative comparator below avoids both costs:
    //
    //   - It walks both structures in lockstep using an explicit
    //     stack, so the native call stack stays at O(1) regardless
    //     of how deep the cond nesting goes.
    //   - It short-circuits on the first reference-equal subtree
    //     OR the first structural difference, so the typical case
    //     where the tree changed in just one place pays only for
    //     the path to the change.
    //   - It allocates nothing per leaf — primitive comparisons
    //     happen in place, no temporary strings.
    //
    // Returns true iff the two values would JSON.stringify to the
    // same output (modulo property order, which we explicitly
    // canonicalise via Object.keys().sort() inside the loop).
    function _chainsDeepEqual(a, b) {
      var stack = [a, b];
      while (stack.length) {
        var y = stack.pop();
        var x = stack.pop();
        if (x === y) continue;
        if (x === null || y === null || typeof x !== typeof y) return false;
        if (typeof x !== 'object') {
          if (x !== y) return false;
          continue;
        }
        var xIsArr = Array.isArray(x);
        var yIsArr = Array.isArray(y);
        if (xIsArr !== yIsArr) return false;
        if (xIsArr) {
          if (x.length !== y.length) return false;
          for (var i = 0; i < x.length; i++) { stack.push(x[i]); stack.push(y[i]); }
          continue;
        }
        var xKeys = Object.keys(x);
        var yKeys = Object.keys(y);
        if (xKeys.length !== yKeys.length) return false;
        xKeys.sort();
        yKeys.sort();
        for (var k = 0; k < xKeys.length; k++) {
          if (xKeys[k] !== yKeys[k]) return false;
          stack.push(x[xKeys[k]]);
          stack.push(y[xKeys[k]]);
        }
      }
      return true;
    }
    const _expandBindWithLVs = (bind, branchLVs) => {
      if (!bind || bind.kind !== 'chain') return bind ? bind.toks : [];
      // Hot-path shortcut: branch had no captured loop vars, so
      // expansion is a no-op and we can return the underlying token
      // array by reference. The caller only READS the result (for
      // structural equality checks and cond-token construction), so
      // returning the shared array is safe. Saves an O(len) allocation
      // that the if/else merge loop pays once per visited variable on
      // every merge — hundreds of thousands of allocations on large
      // function-heavy files.
      if (!branchLVs || branchLVs.length === 0) return bind.toks;
      const lvMap = Object.create(null);
      for (const lv of branchLVs) { if (!lvMap[lv.name]) lvMap[lv.name] = []; lvMap[lv.name].push(lv); }
      // Second hot-path shortcut: even with branchLVs present, if
      // none of the chain's tokens reference a captured loopvar name
      // we still don't need to allocate a new array.
      let needsExpand = false;
      for (const t of bind.toks) {
        if (t.type === 'other' && IDENT_RE.test(t.text) && lvMap[t.text] && lvMap[t.text].length) {
          needsExpand = true;
          break;
        }
      }
      if (!needsExpand) return bind.toks;
      const expand = (toks) => {
        const out = [];
        for (const t of toks) {
          if (t.type === 'other' && IDENT_RE.test(t.text) && lvMap[t.text] && lvMap[t.text].length) {
            const lv = lvMap[t.text].pop(); for (const vt of expand(lv.chain)) out.push(vt); lvMap[t.text].push(lv);
          } else out.push(t);
        }
        return out;
      };
      return expand(bind.toks);
    };
    // Per-snapshot frame-index map: alongside the usual name→value
    // object, we record which stack frame each name lives in at
    // snapshot time. Restoration then becomes an O(1) frame lookup
    // per name instead of an O(stack_depth) top-down scan. The index
    // is stored on the snap object under a symbol so normal
    // `name in snap` iteration still sees only the binding names.
    const _SNAP_FRAMES = typeof Symbol !== 'undefined' ? Symbol('snapFrames') : '__snapFrames__';
    const _snapshotBindings = () => {
      const snap = Object.create(null);
      const frames = Object.create(null);
      for (let si = stack.length - 1; si >= 0; si--) {
        const frame = stack[si];
        const frameBindings = frame.bindings;
        for (const name in frameBindings) {
          if (!(name in snap)) {
            snap[name] = frameBindings[name];
            frames[name] = frame;
          }
        }
      }
      snap[_SNAP_FRAMES] = frames;
      return snap;
    };
    // Restore a variable's binding from a snapshot without feeding the
    // may-be lattice. Snapshots are purely structural rewinds — the
    // lattice already recorded every prior value the variable held, so
    // re-running _trackMayBeAssign on an opaque synthetic restoration
    // chain (e.g. the post-loop deriveExprRef) would poison the slot
    // and destroy refutation power for every branch that follows.
    //
    // Takes an optional `snap` parameter: when provided, the pre-
    // recorded frame index is used to restore the binding in place
    // on the exact frame it came from (O(1)). When omitted, falls
    // back to the top-down scan used by callers that don't have a
    // snapshot around (loop restore paths, catch-parameter binding).
    const _restoreBinding = (name, value, snap) => {
      if (snap) {
        const frames = snap[_SNAP_FRAMES];
        const frame = frames && frames[name];
        if (frame && stack.indexOf(frame) >= 0) {
          frame.bindings[name] = value;
          return;
        }
      }
      for (let si = stack.length - 1; si >= 0; si--) {
        if (name in stack[si].bindings) {
          stack[si].bindings[name] = value;
          return;
        }
      }
      if (stack.length > 0) stack[0].bindings[name] = value;
    };
    // -------------------------------------------------------------------
    // walkRange: iterative SMT-integrated state machine
    // -------------------------------------------------------------------
    //
    // The walker models JavaScript statement evaluation as a state machine
    // whose configuration is the tuple:
    //
    //     (S, B, P, T, L)
    //
    //   S  — scope stack (lexical bindings: block/function frames)
    //   B  — symbolic bindings for each live variable (chain/array/object)
    //   P  — SMT path-constraint stack (conjunction of formulas proved
    //        true on the current control-flow path, used to prune
    //        unreachable branches and refine taint reachability)
    //   T  — taint-condition stack (string descriptions of P, for
    //        user-visible finding reports)
    //   L  — loop stack (enclosing for/while frames with bodyEnd,
    //        modifiedVars, and per-loop SMT obligations)
    //
    // Each task on the LIFO work stack (`_ws`) is a transition in the
    // machine. Task types and their effects on (S,B,P,T,L):
    //
    //   range         — execute statements in [start,end); dispatches to
    //                   per-statement transitions (assign, if, loop,
    //                   switch, try, function, class, ...).
    //   if_restore    — rollback B to pre-if snapshot, flip P/T from
    //                   `cond` to `!cond`, queue else-body range.
    //   if_merge      — pop P/T for `!cond`, merge if/else bindings into
    //                   a `cond` token for build vars.
    //   try_restore   — rollback B after try body, queue catch range.
    //   try_merge     — merge try/catch bindings; queue finally range.
    //   switch_case   — rollback to snapshot, push case-equality into P,
    //                   SMT-check reachability, queue case body.
    //   switch_capture— pop case-equality from P, capture post-case B.
    //   switch_merge  — combine caseResults into a `switch` token.
    //   loop_pop      — pop loop condition from P/T and restore L after
    //                   crossing a loop-body boundary (inlined via
    //                   loopStack bookkeeping below).
    //
    // SMT integration: every branching transition pushes an SMT formula
    // onto P before walking and pops it after. The theory solver in
    // smtSat() then decides branch reachability for nested conditions.
    // When a formula is irreducible the walker still walks the branch
    // but records a symbolic path-condition for taint reports.
    //
    // The machine is strictly iterative — walkRange never recurses into
    // itself. Tasks chain via LIFO push order (push restore/merge tasks
    // BEFORE pushing the range they depend on so the range runs first).
    // -------------------------------------------------------------------
    const _ws = [];
    // SMT path constraint lifecycle helpers. Centralising push/pop
    // makes all transitions use the same mechanism so the P/T stacks
    // can never drift out of sync with the work stack.
    const _pushPathConstraint = (formula, condExpr) => {
      if (pathConstraints && formula) pathConstraints.push(formula);
      if (taintCondStack && condExpr) taintCondStack.push(condExpr);
    };
    const _popPathConstraint = (formula, condExpr) => {
      if (pathConstraints && formula) pathConstraints.pop();
      if (taintCondStack && condExpr) taintCondStack.pop();
    };
    // Build an SMT formula from a raw token range (header tokens of
    // an if/while/for/switch-case/...).
    const _smtFormulaFromRange = async (start, end) => {
      if (!taintEnabled || start >= end) return null;
      var toks = [];
      for (var _fi = start; _fi < end; _fi++) toks.push(tokens[_fi]);
      return await smtParseExpr(toks, 0, toks.length, resolve, resolvePath);
    };
    // Registered transition types. Each entry documents the handler's
    // effect on the machine configuration (S, B, P, T, L). This is both
    // self-documenting and an invariant fixture — any task type pushed
    // onto _ws that isn't listed here is a bug.
    const TASK_TYPES = {
      // Walk the statements in [start, end). The statement dispatcher
      // inside the range handler may push further tasks.
      range:          'exec statements in [start,end)',
      // Rollback B to the pre-`if` snapshot, flip (P,T) from `cond` to
      // `!cond`, and queue the else range (if any).
      if_restore:     'rollback B; flip P from cond to !cond; queue else',
      // Merge if/else bindings into a cond token; pop `!cond` from (P,T).
      if_merge:       'merge if/else; pop !cond from P',
      // Rollback B after the try body; queue the catch range.
      try_restore:    'rollback B after try; queue catch range',
      // Merge try/catch bindings into a trycatch token; queue finally.
      try_merge:      'merge try/catch; queue finally range',
      // Rollback to pre-switch snapshot; SMT-check case reachability;
      // push `disc === caseExpr` onto (P,T); queue case body range.
      switch_case:    'rollback B; push disc===case to P; queue body',
      // Pop the case equality from (P,T); capture post-case bindings.
      switch_capture: 'pop case-equality from P; capture case bindings',
      // Combine all case results into a switch token; queue post-switch range.
      switch_merge:   'merge cases into switch token; queue tail range',
    };
    // Statement-kind transitions fired from within the `range` task's
    // dispatcher. This table doesn't directly drive dispatch (the
    // dispatcher is still an if-chain for historical reasons) but it
    // documents every statement kind the state machine recognises and
    // names its effect on the configuration (S, B, P, T, L).
    const STATEMENT_DISPATCH = {
      // Scoping
      'var':           'decl-function-scope(name); mutate B',
      'let':           'decl-block-scope(name); mutate B',
      'const':         'decl-block-scope(name); mutate B',
      // Control flow — branching
      'if':            'queue if_restore/if_merge; push cond to P; walk if-body',
      'else':          'handled inline by preceding `if`',
      'switch':        'queue switch_merge; fan out switch_case tasks',
      'case':          'handled inside switch_case transition',
      'default':       'handled inside switch_case transition',
      // Control flow — iteration
      'for':           'compute loop cond formula; push to P; walk body; pop on exit',
      'while':         'compute loop cond formula; push to P; walk body; pop on exit',
      'do':            'walk body then eval while-cond; push/pop cond on P',
      'break':         'advance past innermost loopStack bodyEnd',
      'continue':      'advance to next iteration (approx: run to bodyEnd)',
      // Control flow — exceptions
      'try':           'queue try_restore/try_merge; walk try-body',
      'catch':         'handled inside try_restore transition',
      'finally':       'handled inside try_merge transition',
      'throw':         'mark rest of range dead (current scope)',
      // Functions & classes
      'function':      'bind function in outer frame; walk body in new frame',
      'class':         'parse methods into classBinding; walk body',
      'return':        'mark rest of range dead within function frame',
      // Modules & misc
      'import':        'skip statement',
      'export':        'strip and walk decl',
      'with':          'skip body (scope unpredictable)',
      'debugger':      'skip',
    };
    // State-machine invariant: keep track of the intended path-constraint
    // stack depth so mismatched push/pop on the `pathConstraints` /
    // `taintCondStack` pair can be detected early (in debug builds).
    const _pcBaseDepth = pathConstraints ? pathConstraints.length : 0;
    const _tcBaseDepth = taintCondStack ? taintCondStack.length : 0;
    const walkRange = async (startI, endI) => {
    // Per-invocation work stack: recursive walkRange calls (e.g.
    // from instantiateFunction walking a function body) get their
    // own stack and never drain parent tasks.
    const _ws = [];
    _ws.push({ type: 'range', start: startI, end: endI });
    while (_ws.length > 0) {
    const _task = _ws.pop();
    // State-machine guard: every task must be a registered transition.
    if (!TASK_TYPES[_task.type]) {
      // Unknown task — skip rather than crash; this is a defensive
      // guard so malformed transitions don't stall the walker.
      continue;
    }
    // --- Transition: restore after if-body, flip P from `cond` to `!cond`, queue else ---
    if (_task.type === 'if_restore') {
      _task.ctx.ifLoopVars = loopVars.splice(_task.ctx.lvBefore);
      _popPathConstraint(_task.ctx.pathFormula, _task.ctx.condExpr);
      _task.ctx.ifBindings = _snapshotBindings();
      for (const name in _task.snapshot) _restoreBinding(name, _task.snapshot[name], _task.snapshot);
      _pushPathConstraint(smtNot(_task.ctx.pathFormula), '!(' + _task.ctx.condExpr + ')');
      _task.ctx.negPushed = true;
      _task.ctx.lvBefore2 = loopVars.length;
      if (_task.elseStart > 0 && _task.elseEnd > _task.elseStart)
        _ws.push({ type: 'range', start: _task.elseStart, end: _task.elseEnd });
      continue;
    }
    // --- Transition: merge if/else branches, pop `!cond` from P ---
    if (_task.type === 'if_merge') {
      if (_task.ctx.negPushed) _popPathConstraint(smtNot(_task.ctx.pathFormula), '!(' + _task.ctx.condExpr + ')');
      const ctx = _task.ctx;
      const elseLoopVars = loopVars.splice(ctx.lvBefore2);
      const elseBindings = _snapshotBindings();
      // Track which names were merged as cond tokens by the first
      // loop so the second loop's opaque fallback doesn't overwrite
      // them (and poison the may-be lattice with an exprRef).
      const _mergedAsCond = new Set();
      for (const name in ctx.ifBindings) {
        const ifB = ctx.ifBindings[name];
        const elB = elseBindings[name] || _task.snapshot[name];
        if (!ifB || ifB.kind !== 'chain' || !elB || elB.kind !== 'chain') continue;
        // Reference-equal shortcut: neither branch touched this name,
        // so both sides came from the same pre-branch snapshot entry.
        // Avoids the O(tree) _expandBindWithLVs + JSON.stringify on
        // the hot path.
        if (ifB === elB) { _mergedAsCond.add(name); continue; }
        const ifFull = _expandBindWithLVs(ifB, ctx.ifLoopVars);
        const elFull = _expandBindWithLVs(elB, elseLoopVars);
        // Fast structural equality: iterate both token arrays and
        // check reference equality of each element. Walker-generated
        // chain tokens are reused by reference when the walker
        // produces semantically identical bindings, so this catches
        // most "nothing changed" cases in O(n) instead of the
        // O(tree_size) JSON.stringify round-trip it used to fall
        // back to. Only fall back to JSON.stringify if the fast
        // path finds a structural difference that MIGHT still be
        // equal under deep comparison.
        if (_chainToksRefEqual(ifFull, elFull)) { _mergedAsCond.add(name); continue; }
        if (_chainsDeepEqual(ifFull, elFull)) { _mergedAsCond.add(name); continue; }
        const snapB = _task.snapshot[name];
        if (snapB && snapB.kind === 'chain') {
          const snapFull = snapB.toks;
          const ifAppended = chainStartsWith(ifFull, snapFull);
          const elAppended = chainStartsWith(elFull, snapFull);
          const ifExtra = ifAppended ? stripLeadingPlus(ifFull.slice(snapFull.length)) : ifFull;
          const elExtra = elAppended ? stripLeadingPlus(elFull.slice(snapFull.length)) : elFull;
          const currentLoopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
          const condTok = (!ifAppended || !elAppended)
            ? { type: 'cond', condExpr: ctx.condExpr, ifTrue: ifFull, ifFalse: elFull }
            : { type: 'cond', condExpr: ctx.condExpr, ifTrue: ifExtra, ifFalse: elExtra };
          if (currentLoopId !== null) condTok.loopId = currentLoopId;
          assignName(name, (!ifAppended || !elAppended) ? chainBinding([condTok]) : chainBinding([...snapB.toks, SYNTH_PLUS, condTok]));
          if (loopStack.length > 0) loopStack[loopStack.length - 1].modifiedVars.add(name);
          _mergedAsCond.add(name);
        }
      }
      for (const name in ctx.ifBindings) {
        if (trackBuildVar && trackBuildVar.has(name)) continue;
        if (_mergedAsCond.has(name)) continue;
        const ifB = ctx.ifBindings[name], elB = elseBindings[name] || _task.snapshot[name];
        if (ifB === elB) continue;
        // Fast structural-equality fallback before the expensive
        // JSON.stringify — same rationale as the cond-merge path
        // above, avoids O(tree) stringify on hot walker paths.
        if (ifB && elB && ifB.kind === 'chain' && elB.kind === 'chain' &&
            _chainToksRefEqual(ifB.toks, elB.toks)) continue;
        if (_chainsDeepEqual(ifB, elB)) continue;
        assignName(name, chainBinding([deriveExprRef(name, ifB && ifB.kind === 'chain' ? ifB.toks : null, elB && elB.kind === 'chain' ? elB.toks : null)]));
      }
      continue;
    }
    // --- Action: restore after try-body, queue catch ---
    if (_task.type === 'try_restore') {
      const tryLoopVars = loopVars.splice(_task.lvBefore);
      const tryBindings = _snapshotBindings();
      for (const name in _task.snapshot) _restoreBinding(name, _task.snapshot[name], _task.snapshot);
      _task.ctx.tryBindings = tryBindings;
      _task.ctx.tryLoopVars = tryLoopVars;
      _task.ctx.lvBefore2 = loopVars.length;
      // Bind the catch parameter to an opaque chain tagged with every
      // taint source that could flow through a throw inside the try
      // body (including throws inside any function called from it).
      // Without this, `throw location.hash` → `catch (e) { sink(e) }`
      // looks like a safe use of an unbound variable.
      if (taintEnabled && _task.catchStart >= 0 && _task.ctx.catchParamName) {
        var _tcCatchRef = exprRef(_task.ctx.catchParamName);
        if (_task.ctx.throwTaint && _task.ctx.throwTaint.size) {
          _tcCatchRef.taint = new Set(_task.ctx.throwTaint);
        }
        // Declare the catch parameter in the current block so the
        // catch body can resolve it. The body's `{` will push a new
        // block frame on top, but declBlock attaches to the current
        // topBlock() which is the ambient frame — good enough for
        // lookups since catch params shadow nothing else.
        declBlock(_task.ctx.catchParamName, chainBinding([_tcCatchRef]));
      }
      if (_task.catchStart >= 0)
        _ws.push({ type: 'range', start: _task.catchStart, end: _task.catchEnd });
      continue;
    }
    // --- Action: merge try/catch, queue finally ---
    if (_task.type === 'try_merge') {
      const ctx = _task.ctx;
      const catchLoopVars = loopVars.splice(ctx.lvBefore2);
      const catchBindings = _snapshotBindings();
      for (const name in ctx.tryBindings) {
        if (!ctx.tryBindings[name] || ctx.tryBindings[name].kind !== 'chain') continue;
        const tryB = ctx.tryBindings[name], catchB = catchBindings[name] || _task.snapshot[name];
        if (!catchB || catchB.kind !== 'chain') continue;
        if (tryB === catchB) continue;
        const tryFull = _expandBindWithLVs(tryB, ctx.tryLoopVars);
        const catchFull = _expandBindWithLVs(catchB, catchLoopVars);
        if (_chainToksRefEqual(tryFull, catchFull)) continue;
        if (_chainsDeepEqual(tryFull, catchFull)) continue;
        const snapB = _task.snapshot[name];
        // Always emit a `trycatch` join token so the may-be lattice
        // can split it into both reachable branches. The build-var
        // path still gets its full snapshot-appended form for
        // serialization; non-build vars get the bare trycatch token
        // which _trackMayBeAssign expands into tryBody / catchBody.
        if (snapB && snapB.kind === 'chain' && trackBuildVar && trackBuildVar.has(name)) {
          const snapFull = snapB.toks;
          const tryAppended = chainStartsWith(tryFull, snapFull);
          const catchAppended = chainStartsWith(catchFull, snapFull);
          const tryExtra = tryAppended ? stripLeadingPlus(tryFull.slice(snapFull.length)) : tryFull;
          const catchExtra = catchAppended ? stripLeadingPlus(catchFull.slice(snapFull.length)) : catchFull;
          const tryCatchTok = { type: 'trycatch', tryBody: tryExtra, catchBody: catchExtra, catchParam: _task.catchParam };
          if (tryAppended && catchAppended) assignName(name, chainBinding([...snapB.toks, SYNTH_PLUS, tryCatchTok]));
          else assignName(name, chainBinding([tryCatchTok]));
        } else {
          var _tcFullTok = { type: 'trycatch', tryBody: tryFull, catchBody: catchFull, catchParam: _task.catchParam };
          assignName(name, chainBinding([_tcFullTok]));
        }
      }
      if (_task.finallyStart >= 0) _ws.push({ type: 'range', start: _task.finallyStart, end: _task.finallyEnd });
      continue;
    }
    // --- Transition: switch case — rollback to pre-switch bindings,
    //     compute `disc === caseExpr` as an SMT formula, SMT-check
    //     reachability against the enclosing path constraints, push the
    //     formula onto P/T while walking the body, and queue switch_capture
    //     to pop P/T and record the resulting bindings. ---
    if (_task.type === 'switch_case') {
      for (const name in _task.snapshot) _restoreBinding(name, _task.snapshot[name], _task.snapshot);
      var _cs = _task.cs;
      var _caseFormula = null;
      var _caseCondExpr = null;
      if (taintEnabled && _cs.label !== 'default' && _cs.caseExpr) {
        for (var _csi = 0; _csi < tokens.length; _csi++) {
          if (tokens[_csi].start === _cs.srcStart && tokens[_csi].text === 'case') {
            var _ceStart = _csi + 1, _ceEnd = _ceStart;
            for (var _csj = _ceStart; _csj < tokens.length; _csj++) {
              if (tokens[_csj].type === 'other' && tokens[_csj].text === ':') { _ceEnd = _csj; break; }
            }
            if (_ceEnd > _ceStart) {
              var _ceToks = [];
              for (var _ck = _ceStart; _ck < _ceEnd; _ck++) _ceToks.push(tokens[_ck]);
              var _discB = _task.discVal ? _task.discVal.binding : null;
              var _discIsTrueConst = _discB && _discB.kind === 'chain' && _discB.toks.length === 1 && _discB.toks[0].type === 'str' && _discB.toks[0].text === 'true';
              if (_discIsTrueConst) _caseFormula = await smtParseExpr(_ceToks, 0, _ceToks.length, resolve, resolvePath);
              else {
                var _ceSmtExpr = await smtParseAtom(_ceToks, 0, _ceToks.length, resolve, resolvePath);
                var _discSmtExpr = _discB ? (await smtParseAtom([{ type: 'other', text: _task.discExpr || 'disc' }], 0, 1, resolve, resolvePath)) : null;
                if (_ceSmtExpr && _discSmtExpr) _caseFormula = smtCmp('===', _discSmtExpr, _ceSmtExpr);
              }
              _caseCondExpr = (_task.discExpr || 'disc') + ' === ' + _cs.caseExpr;
            }
            break;
          }
        }
        if (_caseFormula) {
          var _fullCaseFormula = _caseFormula;
          if (pathConstraints && pathConstraints.length > 0) for (var _pi = 0; _pi < pathConstraints.length; _pi++) _fullCaseFormula = smtAnd(pathConstraints[_pi], _fullCaseFormula);
          if (!(await smtSat(_fullCaseFormula))) {
            _task.caseResults.push({ label: _cs.label, caseExpr: _cs.caseExpr, bindings: _task.snapshot });
            continue;
          }
        }
      }
      // Push case-equality as a path constraint while walking the body,
      // so nested `if`/loop reachability within the case body can use it.
      _pushPathConstraint(_caseFormula, _caseCondExpr);
      _ws.push({ type: 'switch_capture', cs: _cs, caseResults: _task.caseResults, pathFormula: _caseFormula, condExpr: _caseCondExpr });
      _ws.push({ type: 'range', start: _cs.bodyStart, end: _cs.bodyEnd });
      continue;
    }
    if (_task.type === 'switch_capture') {
      // Pop the case path constraint pushed by switch_case.
      _popPathConstraint(_task.pathFormula, _task.condExpr);
      _task.caseResults.push({ label: _task.cs.label, caseExpr: _task.cs.caseExpr, bindings: _snapshotBindings() });
      continue;
    }
    if (_task.type === 'switch_merge') {
      const caseResults = _task.caseResults, snapshot = _task.snapshot;
      if (trackBuildVar) {
        for (const bv of trackBuildVar) {
          const snapB = snapshot[bv];
          if (!snapB || snapB.kind !== 'chain') continue;
          const snapFull = snapB.toks, branches = [];
          let allAppended = true;
          for (const cr of caseResults) {
            const b = cr.bindings[bv];
            if (b && b.kind === 'chain') {
              const full = b.toks, appended = chainStartsWith(full, snapFull);
              if (!appended) allAppended = false;
              branches.push({ label: cr.label, caseExpr: cr.caseExpr, chain: appended ? stripLeadingPlus(full.slice(snapFull.length)) : full });
            }
          }
          if (branches.length) {
            const switchTok = { type: 'switch', discExpr: _task.discExpr || '/* switch */', branches };
            assignName(bv, allAppended ? chainBinding([...snapB.toks, SYNTH_PLUS, switchTok]) : chainBinding([switchTok]));
          }
        }
      }
      const switchChanged = new Set();
      for (const cr2 of caseResults) for (const name in cr2.bindings) {
        if (trackBuildVar && trackBuildVar.has(name)) continue;
        const b = cr2.bindings[name], snap = snapshot[name];
        if (!b) continue;
        if (snap && (b === snap ||
            (b.kind === 'chain' && snap.kind === 'chain' && _chainToksRefEqual(b.toks, snap.toks)))) continue;
        if (snap && _chainsDeepEqual(b, snap)) continue;
        switchChanged.add(name);
      }
      for (const name of switchChanged) {
        // Emit a `switchjoin` token with one entry per case's chain
        // so _trackMayBeAssign can split each branch into a separate
        // may-be lattice entry. This lets post-switch refutations
        // over values never assigned in any case fire properly.
        var _swBranches = [];
        for (var _cr of caseResults) {
          if (_cr.bindings[name] && _cr.bindings[name].kind === 'chain') {
            _swBranches.push({ label: _cr.label, caseExpr: _cr.caseExpr, chain: _cr.bindings[name].toks });
          }
        }
        if (_swBranches.length) {
          var _swTok = { type: 'switchjoin', discExpr: _task.discExpr || '/* switch */', branches: _swBranches };
          assignName(name, chainBinding([_swTok]));
        }
      }
      _ws.push({ type: 'range', start: _task.switchEnd, end: _task.resumeEnd });
      continue;
    }
    // --- Process a token range ---
    var _rangeEnd = _task.end;
    for (let i = _task.start; i < _rangeEnd; i++) {
      // Pop any loops whose body we've walked past (and their shadow frames).
      // For each variable modified during the loop, capture its final chain
      // as a loopVar entry AND replace its binding with a single reference
      // token carrying the variable's name, so subsequent code reads it
      // as a named variable rather than inlining the one-iteration chain.
      while (loopStack.length > 0 && i >= loopStack[loopStack.length - 1].bodyEnd) {
        const entry = loopStack.pop();
        // Release the for-of loop var guard so subsequent lattice
        // updates to unrelated vars aren't accidentally suppressed.
        if (entry.forOfVarName) _activeForOfVars.delete(entry.forOfVarName);
        // Pop enhanced constraints first (reverse order of push).
        if (entry.extraFormulas && entry.extraFormulas.length) {
          for (var _ef = entry.extraFormulas.length - 1; _ef >= 0; _ef--) {
            _popPathConstraint(entry.extraFormulas[_ef], entry.extraExprs[_ef]);
          }
        }
        // Pop the loop condition from P/T — the post-loop world has no
        // guarantee that the loop predicate still holds (we approximate
        // it as unknown rather than as `!cond`, since loop exit can
        // also happen via break, and bounded iteration is symbolic).
        if (entry.pathFormula || entry.condExpr) {
          _popPathConstraint(entry.pathFormula, entry.condExpr);
        }
        // Collect names that were pre-scanned as opaque in the loop frame.
        const preScanNames = entry.frame ? Object.keys(entry.frame.bindings) : [];
        // Capture modified variable bindings BEFORE removing the loop frame,
        // since resolve() would return the pre-loop outer value after removal.
        const allModified = new Set(entry.modifiedVars);
        for (const n of preScanNames) allModified.add(n);
        var _loopBindings = {};
        for (const name of allModified) {
          _loopBindings[name] = resolve(name);
        }
        const topIdx = stack.indexOf(entry.frame);
        if (topIdx >= 0) stack.splice(topIdx, 1);
        for (const name of allModified) {
          const b = _loopBindings[name];
          if (b && b.kind === 'chain') {
            // Store the chain UNSTRIPPED; strip the outer loop's tags only
            // at display time via loopVarHtml. The unstripped chain is
            // needed when unrolling references in a main-chain substitution.
            loopVars.push({
              name,
              loop: { id: entry.id, kind: entry.kind, headerSrc: entry.headerSrc },
              chain: b.toks,
            });
            // Replace the binding in place without poisoning the may-be
            // lattice. The per-iteration body assignments have already
            // fed every reachable literal into the lattice; the opaque
            // post-loop synthetic value is only needed so downstream
            // references resolve to a stable name for extraction /
            // serialization purposes. Calling assignName here would
            // route through _trackMayBeAssign and poison the slot.
            var _postLoopChain = chainBinding([deriveExprRef(name, b.toks)]);
            for (let _sf = stack.length - 1; _sf >= 0; _sf--) {
              if (name in stack[_sf].bindings) {
                stack[_sf].bindings[name] = _postLoopChain;
                break;
              }
            }
          }
        }
      }
      const t = tokens[i];

      if (t.type === 'open' && t.char === '{') {
        // IIFE wrapper fast-path. When we're about to open a
        // function body AND the matching `}` is immediately
        // followed by `)` `(` … `)` — i.e. the pattern
        // `(function(){})()` / `(() => {})()` — skip the phase-1
        // statement walk of this body entirely. The IIFE handler
        // at `})()` later calls instantiateFunction on the same
        // body, which is the walk that actually emits taint
        // findings (phase 1's def-time walk suppresses them via
        // taintFnDepth). Walking the body twice — once suppressed,
        // once emitting — is pure waste AND triggers combinatorial
        // re-work on nested function definitions.
        //
        // Detection:
        //   current token i = `{`
        //   matching `}` at _bodyClose
        //   next tokens: _bodyClose+1 is `)`, _bodyClose+2 is `(`
        // That `)(` is the IIFE call pattern the IIFE handler
        // below is looking for.
        if (pendingFunctionBrace) {
          var _iifeBodyClose = _matchingBrace(i);
          if (_iifeBodyClose > 0 &&
              tokens[_iifeBodyClose + 1] && tokens[_iifeBodyClose + 1].type === 'close' && tokens[_iifeBodyClose + 1].char === ')' &&
              tokens[_iifeBodyClose + 2] && tokens[_iifeBodyClose + 2].type === 'open' && tokens[_iifeBodyClose + 2].char === '(') {
            // Skip the body. The walker's next iteration will land
            // on _iifeBodyClose + 1 (the outer `)`) and then the
            // IIFE handler will fire on `)(`.
            pendingFunctionBrace = false;
            pendingFunctionParams = null;
            i = _iifeBodyClose;  // for-loop will increment past `}`
            continue;
          }
        }
        const frame = { bindings: Object.create(null), isFunction: pendingFunctionBrace };
        if (taintEnabled && pendingFunctionBrace) taintFnDepth++;
        if (pendingFunctionBrace && pendingFunctionParams) {
          // Bind function parameters as references to their own names so
          // uses within the body surface when the body is
          // parsed in scope (e.g. for an innerHTML assignment inside the
          // function). At call sites, instantiateFunction rebinds them.
          for (const p of pendingFunctionParams) {
            frame.bindings[p.name] = chainBinding([exprRef(p.name)]);
          }
        }
        stack.push(frame);
        pendingFunctionBrace = false;
        pendingFunctionParams = null;
        continue;
      }
      if (t.type === 'close' && t.char === '}') {
        if (stack.length > 1) {
          var _popped = stack.pop();
          if (taintEnabled && _popped.isFunction) taintFnDepth--;
        }
        continue;
      }

      // IIFE: ')(' pattern — (function(){...})() or (()=>{...})()
      if (t.type === 'close' && t.char === ')' && tokens[i + 1] && tokens[i + 1].type === 'open' && tokens[i + 1].char === '(') {
        var _iifeOpenIdx = -1, _iifeDep = 1;
        for (var _ii = i - 1; _ii >= 0; _ii--) {
          if (tokens[_ii].type === 'close' && tokens[_ii].char === ')') _iifeDep++;
          if (tokens[_ii].type === 'open' && tokens[_ii].char === '(') { _iifeDep--; if (_iifeDep === 0) { _iifeOpenIdx = _ii; break; } }
        }
        if (_iifeOpenIdx >= 0) {
          var _iifeFnE = await readFunctionExpr(_iifeOpenIdx + 1, i);
          var _iifeFn = _iifeFnE ? _iifeFnE.binding : null;
          if (!_iifeFn) {
            var _iifeArr = peekArrow(_iifeOpenIdx + 1, i);
            if (_iifeArr) { var _iifeB = readArrowBody(_iifeArr.arrowNext, i); if (_iifeB) _iifeFn = functionBinding(_iifeArr.params, _iifeB.bodyStart, _iifeB.bodyEnd, _iifeB.isBlock); }
          }
          if (_iifeFn) {
            // Phase 1's statement walker skips IIFE-wrapper bodies
            // (via the `}` IIFE fast-path in the `{` handler above)
            // so this is the ONLY walk of the body. It runs with
            // call-time context, which is what emits taint findings.
            var _iifeA = await readCallArgBindings(i + 1, stop);
            if (_iifeA) { await instantiateFunction(_iifeFn, _iifeA.bindings); i = _iifeA.next - 1; continue; }
          }
        }
      }

      if (t.type !== 'other') continue;

      // break / continue — preserve as runtime flow control so they
      // execute at the right point in the converted loop body.
      if (t.text === 'break' || t.text === 'continue') {
        if (trackBuildVar && loopStack.length > 0 && (trackBuildVarDepth < 0 || funcDepth() === trackBuildVarDepth)) {
          // Include optional label and semicolon.
          let stmtEnd = i + 1;
          if (stmtEnd < _rangeEnd && tokens[stmtEnd].type === 'other' && IDENT_RE.test(tokens[stmtEnd].text)) stmtEnd++;
          if (stmtEnd < _rangeEnd && tokens[stmtEnd].type === 'sep' && tokens[stmtEnd].char === ';') stmtEnd++;
          const first = tokens[i];
          const last = tokens[stmtEnd - 1];
          const stmtSrc = first._src.slice(first.start, last.end);
          for (const bv of trackBuildVar) {
            const bCur = resolve(bv);
            if (bCur && bCur.kind === 'chain') {
              const loopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
              const preserveTok = { type: 'preserve', text: stmtSrc };
              if (loopId !== null) preserveTok.loopId = loopId;
              assignName(bv, chainBinding([...bCur.toks, SYNTH_PLUS, preserveTok]));
            }
          }
          i = stmtEnd - 1;
          continue;
        }
      }

      // `if (cond) { ... } [else { ... }]` — when the condition is
      // concrete, walk only the matching branch. When opaque, walk both
      // branches; if a build variable is mutated in only one branch,
      // produce a cond token so the direct parser emits if/else blocks.
      if (t.text === 'if') {
        const lp = tokens[i + 1];
        if (lp && lp.type === 'open' && lp.char === '(') {
          // Find closing `)`.
          let depth = 1, j = i + 2;
          while (j < stop && depth > 0) {
            const tk = tokens[j];
            if (tk.type === 'open' && tk.char === '(') depth++;
            else if (tk.type === 'close' && tk.char === ')') depth--;
            if (depth === 0) break;
            j++;
          }
          if (j < stop) {
            // Evaluate the condition via unified reachability check.
            const condVal = await readValue(i + 2, j, null);
            var concrete = taintEnabled ? (await checkReachability(i + 2, j)) : (condVal ? evalTruthiness(condVal.binding) : null);
            // Determine if-body range.
            const bodyTok = tokens[j + 1];
            let ifEnd;
            if (bodyTok && bodyTok.type === 'open' && bodyTok.char === '{') {
              let d = 1, k = j + 2;
              while (k < stop && d > 0) {
                const tk = tokens[k];
                if (tk.type === 'open' && tk.char === '{') d++;
                else if (tk.type === 'close' && tk.char === '}') d--;
                k++;
              }
              ifEnd = k;
            } else {
              let sd = 0, k = j + 1;
              while (k < stop) {
                const tk = tokens[k];
                if (tk.type === 'open') sd++;
                else if (tk.type === 'close') sd--;
                else if (sd === 0 && tk.type === 'sep' && tk.char === ';') { k++; break; }
                k++;
              }
              ifEnd = k;
            }
            // Determine else-body range (if present).
            let elseStart = -1, elseEnd = -1;
            if (tokens[ifEnd] && tokens[ifEnd].type === 'other' && tokens[ifEnd].text === 'else') {
              const nt = tokens[ifEnd + 1];
              if (nt && nt.type === 'open' && nt.char === '{') {
                let d = 1, k = ifEnd + 2;
                while (k < stop && d > 0) {
                  const tk = tokens[k];
                  if (tk.type === 'open' && tk.char === '{') d++;
                  else if (tk.type === 'close' && tk.char === '}') d--;
                  k++;
                }
                elseStart = ifEnd + 1; elseEnd = k;
              } else if (nt && nt.type === 'other' && nt.text === 'if') {
                // else if — find the full extent of the else-if chain.
                // The else body is `if (cond) { ... } [else ...]`.
                elseStart = ifEnd + 1;
                // Recursively find end of the if/else-if/else chain.
                let ei = ifEnd + 1; // points to `if`
                while (ei < stop) {
                  const eiTok = tokens[ei];
                  if (!eiTok || eiTok.type !== 'other' || eiTok.text !== 'if') break;
                  // Skip if(cond)
                  const eiLp = tokens[ei + 1];
                  if (!eiLp || eiLp.type !== 'open' || eiLp.char !== '(') break;
                  let ed = 1, ej = ei + 2;
                  while (ej < stop && ed > 0) {
                    if (tokens[ej].type === 'open' && tokens[ej].char === '(') ed++;
                    else if (tokens[ej].type === 'close' && tokens[ej].char === ')') ed--;
                    if (ed === 0) break; ej++;
                  }
                  // Skip body
                  const eBody = tokens[ej + 1];
                  if (eBody && eBody.type === 'open' && eBody.char === '{') {
                    let ed2 = 1, ek = ej + 2;
                    while (ek < stop && ed2 > 0) {
                      if (tokens[ek].type === 'open' && tokens[ek].char === '{') ed2++;
                      else if (tokens[ek].type === 'close' && tokens[ek].char === '}') ed2--;
                      ek++;
                    }
                    ei = ek;
                  } else {
                    let sd = 0, ek = ej + 1;
                    while (ek < stop) {
                      if (tokens[ek].type === 'open') sd++;
                      else if (tokens[ek].type === 'close') sd--;
                      else if (sd === 0 && tokens[ek].type === 'sep' && tokens[ek].char === ';') { ek++; break; }
                      ek++;
                    }
                    ei = ek;
                  }
                  // Check for another else
                  if (tokens[ei] && tokens[ei].type === 'other' && tokens[ei].text === 'else') {
                    const eiNt = tokens[ei + 1];
                    if (eiNt && eiNt.type === 'other' && eiNt.text === 'if') {
                      ei = ei + 1; continue; // another else-if
                    }
                    // else { ... }
                    if (eiNt && eiNt.type === 'open' && eiNt.char === '{') {
                      let ed3 = 1, ek = ei + 2;
                      while (ek < stop && ed3 > 0) {
                        if (tokens[ek].type === 'open' && tokens[ek].char === '{') ed3++;
                        else if (tokens[ek].type === 'close' && tokens[ek].char === '}') ed3--;
                        ek++;
                      }
                      ei = ek;
                    } else {
                      // else <single-statement>;
                      let sd = 0, ek = ei + 1;
                      while (ek < stop) {
                        if (tokens[ek].type === 'open') sd++;
                        else if (tokens[ek].type === 'close') sd--;
                        else if (sd === 0 && tokens[ek].type === 'sep' && tokens[ek].char === ';') { ek++; break; }
                        ek++;
                      }
                      ei = ek;
                    }
                  }
                  break;
                }
                elseEnd = ei;
              } else {
                let sd = 0, k = ifEnd + 1;
                while (k < stop) {
                  const tk = tokens[k];
                  if (tk.type === 'open') sd++;
                  else if (tk.type === 'close') sd--;
                  else if (sd === 0 && tk.type === 'sep' && tk.char === ';') { k++; break; }
                  k++;
                }
                elseStart = ifEnd + 1; elseEnd = k;
              }
            }
            if (concrete === true) {
              var _resume = (elseEnd > 0 ? elseEnd : ifEnd);
              _ws.push({ type: 'range', start: _resume, end: _rangeEnd });
              _rangeEnd = ifEnd; i = j; continue;
            } else if (concrete === false) {
              var _resume = (elseEnd > 0 ? elseEnd : ifEnd);
              if (elseStart > 0) {
                _ws.push({ type: 'range', start: _resume, end: _rangeEnd });
                _rangeEnd = elseEnd; i = elseStart - 1; continue;
              }
              i = _resume - 1; continue;
            }
            // Opaque condition: use iterative state machine with SMT.
            const condExpr = condVal ? chainAsExprText(condVal.binding) : null;
            if (condExpr) {
              const snapshot = _snapshotBindings();
              var _pathFormula = null;
              if (pathConstraints) {
                var _condToks = [];
                for (var _pi = i + 2; _pi < j; _pi++) _condToks.push(tokens[_pi]);
                _pathFormula = await smtParseExpr(_condToks, 0, _condToks.length, resolve, resolvePath);
              }
              var _elS = (elseStart > 0 && elseEnd > elseStart) ? elseStart : 0;
              var _elE = (elseStart > 0 && elseEnd > elseStart) ? elseEnd : 0;
              var _resumeAt = (elseEnd > 0 ? elseEnd : ifEnd);
              var _oCtx = { condExpr, lvBefore: loopVars.length, pathFormula: _pathFormula, negPushed: false };
              _ws.push({ type: 'range', start: _resumeAt, end: _rangeEnd });
              _ws.push({ type: 'if_merge', ctx: _oCtx, snapshot });
              _ws.push({ type: 'if_restore', ctx: _oCtx, snapshot, elseStart: _elS, elseEnd: _elE });
              _pushPathConstraint(_pathFormula, condExpr);
              _rangeEnd = ifEnd; i = j; continue;
            }
            // Condition too complex to represent — preserve the entire
            // if/else as raw source so no code is silently dropped.
            if (trackBuildVar && (trackBuildVarDepth < 0 || funcDepth() === trackBuildVarDepth)) {
              const ifStmtEnd = elseEnd > 0 ? elseEnd : ifEnd;
              const first = tokens[i];
              const last = tokens[ifStmtEnd - 1];
              if (first && last) {
                const stmtSrc = first._src.slice(first.start, last.end);
                for (const bv of trackBuildVar) {
                  const cur = resolve(bv);
                  if (cur && cur.kind === 'chain') {
                    assignName(bv, chainBinding([...cur.toks, SYNTH_PLUS, { type: 'preserve', text: stmtSrc }]));
                  }
                }
              }
            }
            i = (elseEnd > 0 ? elseEnd : ifEnd) - 1;
            continue;
          }
        }
      }

      // Helpers for finding matching braces/parens in the token stream.
      const findBlockEnd = (openIdx) => {
        let d = 1, k = openIdx + 1;
        while (k < stop && d > 0) {
          if (tokens[k].type === 'open' && tokens[k].char === '{') d++;
          else if (tokens[k].type === 'close' && tokens[k].char === '}') d--;
          k++;
        }
        return k;
      };
      const findCloseParen = (openIdx) => {
        let d = 1, k = openIdx + 1;
        while (k < stop && d > 0) {
          if (tokens[k].type === 'open' && tokens[k].char === '(') d++;
          else if (tokens[k].type === 'close' && tokens[k].char === ')') d--;
          k++;
        }
        return k;
      };

      // `try { ... } catch(e) { ... } finally { ... }` — walk each block
      // with snapshot/restore so build-var mutations become cond tokens
      // (try-branch vs catch-branch). The finally block runs unconditionally.
      if (t.text === 'try') {
        const tryOpen = tokens[i + 1];
        if (tryOpen && tryOpen.type === 'open' && tryOpen.char === '{') {
          const tryEnd = findBlockEnd(i + 1);
          let catchStart = -1, catchEnd = -1, catchParam = '';
          let finallyStart = -1, finallyEnd = -1;
          let k = tryEnd;
          // catch
          if (tokens[k] && tokens[k].type === 'other' && tokens[k].text === 'catch') {
            const cp = tokens[k + 1];
            if (cp && cp.type === 'open' && cp.char === '(') {
              const cpEnd = findCloseParen(k + 1);
              catchParam = tokens[k + 2] ? tokens[k + 2].text : 'e';
              const catchOpen = tokens[cpEnd];
              if (catchOpen && catchOpen.type === 'open' && catchOpen.char === '{') {
                catchStart = cpEnd;
                catchEnd = findBlockEnd(cpEnd);
                k = catchEnd;
              }
            } else if (cp && cp.type === 'open' && cp.char === '{') {
              catchStart = k + 1;
              catchEnd = findBlockEnd(k + 1);
              k = catchEnd;
            }
          }
          // finally
          if (tokens[k] && tokens[k].type === 'other' && tokens[k].text === 'finally') {
            const finOpen = tokens[k + 1];
            if (finOpen && finOpen.type === 'open' && finOpen.char === '{') {
              finallyStart = k + 1;
              finallyEnd = findBlockEnd(k + 1);
              k = finallyEnd;
            }
          }
          // Use state machine for try/catch/finally.
          const snapshot = _snapshotBindings();
          var _tCtx = { lvBefore: loopVars.length };
          // Scan the try body for `throw <expr>` statements and any
          // functions called that might throw. Collect the union of
          // every taint source reachable via a throw so the catch
          // param gets bound to an opaque chain carrying that taint.
          // This makes `try { throw location.hash } catch (e) { sink(e) }`
          // a taint flow the analyser can see.
          var _throwTaint = null;
          if (taintEnabled) {
            var _scanThrowsIn = function(scanStart, scanEnd, visited) {
              visited = visited || Object.create(null);
              for (var _ti = scanStart; _ti < scanEnd; _ti++) {
                var _tk = tokens[_ti];
                if (!_tk) continue;
                if (_tk.type === 'other' && _tk.text === 'throw') {
                  // Find the end of the throw expression.
                  var _teEnd = _ti + 1, _td = 0;
                  while (_teEnd < scanEnd) {
                    var _tet = tokens[_teEnd];
                    if (_tet.type === 'open') _td++;
                    else if (_tet.type === 'close') _td--;
                    else if (_td === 0 && _tet.type === 'sep' && _tet.char === ';') break;
                    _teEnd++;
                  }
                  // Collect any taint source in the throw expression range.
                  for (var _tej = _ti + 1; _tej < _teEnd; _tej++) {
                    var _ttk = tokens[_tej];
                    if (_ttk && _ttk.type === 'other') {
                      var _tsrc = checkTaintSource(_ttk.text);
                      if (_tsrc) {
                        if (!_throwTaint) _throwTaint = new Set();
                        for (var _tsl of _tsrc) _throwTaint.add(_tsl);
                      }
                    }
                  }
                  continue;
                }
                // Recurse into called functions (up to a fixed depth).
                if (_tk.type === 'other' && IDENT_OR_PATH_RE.test(_tk.text)) {
                  var _tnext = tokens[_ti + 1];
                  if (_tnext && _tnext.type === 'open' && _tnext.char === '(') {
                    var _tfb = resolve(_tk.text.split('.')[0]);
                    if (_tfb && _tfb.kind === 'function') {
                      var _tfKey = _tfb.bodyStart + ':' + _tfb.bodyEnd;
                      if (!visited[_tfKey]) {
                        visited[_tfKey] = true;
                        _scanThrowsIn(_tfb.bodyStart, _tfb.bodyEnd, visited);
                      }
                    }
                  }
                }
              }
            };
            _scanThrowsIn(i + 2, tryEnd - 1);
          }
          _tCtx.throwTaint = _throwTaint;
          _tCtx.catchParamName = catchParam;
          if (catchStart < 0) {
            // No catch — try body state persists. Just walk try + finally.
            _ws.push({ type: 'range', start: k, end: _rangeEnd });
            if (finallyStart >= 0) _ws.push({ type: 'range', start: finallyStart, end: finallyEnd });
            _rangeEnd = tryEnd; continue;
          }
          // LIFO: push resume, finally, merge, restore (which queues catch), then try-body runs next.
          _ws.push({ type: 'range', start: k, end: _rangeEnd });
          if (finallyStart >= 0) _ws.push({ type: 'range', start: finallyStart, end: finallyEnd });
          _ws.push({ type: 'try_merge', ctx: _tCtx, snapshot, catchParam, finallyStart, finallyEnd });
          _ws.push({ type: 'try_restore', ctx: _tCtx, snapshot, catchStart, catchEnd, lvBefore: loopVars.length });
          _rangeEnd = tryEnd; continue;
        }
      }

      // `switch (expr) { case ...: ... }` — walk each case body with
      // snapshot/restore so build-var mutations become a 'switchcase' token.
      if (t.text === 'switch') {
        const lp = tokens[i + 1];
        if (lp && lp.type === 'open' && lp.char === '(') {
          const cp = findCloseParen(i + 1);
          // Read the discriminant expression.
          const discVal = await readValue(i + 2, cp - 1, null);
          const discExpr = discVal ? chainAsExprText(discVal.binding) : null;
          const bodyOpen = tokens[cp];
          if (bodyOpen && bodyOpen.type === 'open' && bodyOpen.char === '{') {
            const switchEnd = findBlockEnd(cp);
            // Find case/default labels and their body ranges.
            const cases = [];
            let depth = 0;
            for (let j = cp + 1; j < switchEnd - 1; j++) {
              const tk = tokens[j];
              if (tk.type === 'open' && tk.char === '{') depth++;
              if (tk.type === 'close' && tk.char === '}') depth--;
              if (depth > 0) continue;
              if (tk.type === 'other' && (tk.text === 'case' || tk.text === 'default')) {
                // Find the colon.
                let colonIdx = j + 1;
                while (colonIdx < switchEnd - 1 && !(tokens[colonIdx].type === 'other' && tokens[colonIdx].text === ':')) colonIdx++;
                const label = tk.text === 'default' ? 'default' : null;
                const caseExpr = tk.text === 'case' ? (await (async function() {
                  const v = await readValue(j + 1, colonIdx, null);
                  return v ? chainAsExprText(v.binding) : null;
                })()) : null;
                cases.push({ label, caseExpr, bodyStart: colonIdx + 1, bodyEnd: -1, srcStart: tk.start });
              }
            }
            // Set body ends: each case runs until the next case/default or switchEnd.
            for (let c = 0; c < cases.length; c++) {
              cases[c].bodyEnd = c + 1 < cases.length ? cases[c + 1].srcStart : switchEnd - 1;
              // Find token index for bodyEnd position.
              for (let j = cases[c].bodyStart; j < switchEnd; j++) {
                if (tokens[j].start >= (c + 1 < cases.length ? cases[c + 1].srcStart : tokens[switchEnd - 2].start)) {
                  cases[c].bodyEnd = j;
                  break;
                }
              }
            }
            // Snapshot and walk each case.
            const snapshot = Object.create(null);
            for (let si = stack.length - 1; si >= 0; si--) {
              for (const name in stack[si].bindings) {
                if (!(name in snapshot)) snapshot[name] = stack[si].bindings[name];
              }
            }
            const caseResults = [];
            // Use state machine to walk each case body iteratively.
            _ws.push({ type: 'switch_merge', snapshot, cases, caseResults, discExpr, switchEnd, resumeEnd: _rangeEnd });
            for (var _ci = cases.length - 1; _ci >= 0; _ci--) {
              _ws.push({ type: 'switch_case', snapshot, cs: cases[_ci], caseResults, discVal, discExpr });
            }
            _rangeEnd = i; continue;
            // (merge logic in switch_merge action handler)
          }
        }
      }

      // `do { ... } while (cond);`
      if (t.text === 'do') {
        const bodyOpen = tokens[i + 1];
        if (bodyOpen && bodyOpen.type === 'open' && bodyOpen.char === '{') {
          const bodyEnd = findBlockEnd(i + 1);
          // Find `while (cond);` after the body.
          const whTok = tokens[bodyEnd];
          if (whTok && whTok.type === 'other' && whTok.text === 'while') {
            const wp = tokens[bodyEnd + 1];
            if (wp && wp.type === 'open' && wp.char === '(') {
              const wcp = findCloseParen(bodyEnd + 1);
              let doEnd = wcp;
              if (tokens[doEnd] && tokens[doEnd].type === 'sep' && tokens[doEnd].char === ';') doEnd++;
              const headerFirst = tokens[bodyEnd + 2];
              const headerLast = tokens[wcp - 2];
              const headerSrc = headerFirst ? headerFirst._src.slice(headerFirst.start, headerLast.end) : '/* do-while */';
              const id = nextLoopId++;
              loopInfo[id] = { kind: 'do', headerSrc };
              const loopFrame = { bindings: Object.create(null), isFunction: false };
              // Pre-scan body for non-build modified variables (same as for/while).
              for (let h = i + 1; h < bodyEnd; h++) {
                const hk = tokens[h];
                if (hk.type === 'op' && (hk.text === '++' || hk.text === '--')) {
                  const hn = tokens[h + 1];
                  if (hn && hn.type === 'other' && IDENT_RE.test(hn.text) &&
                      !(trackBuildVar && trackBuildVar.has(hn.text))) {
                    if (!loopFrame.bindings[hn.text]) loopFrame.bindings[hn.text] = chainBinding([exprRef(hn.text)]);
                  }
                }
                if (hk.type === 'other' && IDENT_RE.test(hk.text)) {
                  if (trackBuildVar && trackBuildVar.has(hk.text)) continue;
                  const hn = tokens[h + 1];
                  if (hn && hn.type === 'sep' && (hn.char === '=' || hn.char === '+=' || hn.char === '-=' || hn.char === '*=' || hn.char === '/=')) {
                    if (!loopFrame.bindings[hk.text]) loopFrame.bindings[hk.text] = chainBinding([exprRef(hk.text)]);
                  }
                  if (hn && hn.type === 'op' && (hn.text === '++' || hn.text === '--')) {
                    if (!loopFrame.bindings[hk.text]) loopFrame.bindings[hk.text] = chainBinding([exprRef(hk.text)]);
                  }
                }
              }
              stack.push(loopFrame);
              loopStack.push({
                id, kind: 'do', headerSrc, bodyEnd: doEnd, frame: loopFrame,
                modifiedVars: new Set(),
              });
              _ws.push({ type: 'range', start: doEnd, end: _rangeEnd });
              _rangeEnd = bodyEnd; continue;
            }
          }
        }
      }

      if (t.text === 'for' || t.text === 'while') {
        // Detect loop header and body range. The body is either a `{ ... }`
        // block or a single statement terminated by `;`.
        const openParen = tokens[i + 1];
        if (openParen && openParen.type === 'open' && openParen.char === '(') {
          let depth = 1, j = i + 2;
          while (j < stop && depth > 0) {
            const tk = tokens[j];
            if (tk.type === 'open' && tk.char === '(') depth++;
            else if (tk.type === 'close' && tk.char === ')') depth--;
            if (depth === 0) break;
            j++;
          }
          if (j < stop && tokens[j].type === 'close' && tokens[j].char === ')' && j > i + 2) {
            const headerFirst = tokens[i + 2];
            const headerLast = tokens[j - 1];
            // Detect body range first so we can find mutated variables.
            const bodyTok = tokens[j + 1];
            let bodyEnd;
            if (bodyTok && bodyTok.type === 'open' && bodyTok.char === '{') {
              let d = 1, k = j + 2;
              while (k < stop && d > 0) {
                const tk = tokens[k];
                if (tk.type === 'open' && tk.char === '{') d++;
                else if (tk.type === 'close' && tk.char === '}') d--;
                k++;
              }
              bodyEnd = k;
            } else {
              let sd = 0, k = j + 1;
              while (k < stop) {
                const tk = tokens[k];
                if (tk.type === 'open') sd++;
                else if (tk.type === 'close') sd--;
                else if (sd === 0 && tk.type === 'sep' && tk.char === ';') { k++; break; }
                k++;
              }
              bodyEnd = k;
            }
            // for-in / for-of: resolve iterable and store taint info
            // so the loop frame binding can carry it (set after frame push below).
            // When the iterable has concrete entries, also stash each
            // entry so we can pre-populate the may-be lattice for any
            // variable simply assigned from the loop variable inside
            // the body (e.g. `var s; for (var v of ["a","b"]) { s = v; }`).
            var _forInOfTaint = null;
            var _forInOfKnownValues = null;
            var _forInOfLoopVarName = null;
            if (taintEnabled) {
              for (var _fi = i + 2; _fi < j; _fi++) {
                if (tokens[_fi].type === 'other' && (tokens[_fi].text === 'in' || tokens[_fi].text === 'of')) {
                  var _forInOf = tokens[_fi].text;
                  var _fiVarStart = i + 2;
                  if (tokens[_fiVarStart].type === 'other' && (tokens[_fiVarStart].text === 'var' || tokens[_fiVarStart].text === 'let' || tokens[_fiVarStart].text === 'const')) _fiVarStart++;
                  var _fiVarName = tokens[_fiVarStart] && IDENT_RE.test(tokens[_fiVarStart].text) ? tokens[_fiVarStart].text : null;
                  if (_fiVarName) {
                    _forInOfLoopVarName = _fiVarName;
                    var _fiExprVal = await readValue(_fi + 1, j, null);
                    var _fiIterBind = _fiExprVal ? _fiExprVal.binding : null;
                    var _fiTaintSources = [];
                    var _fiKnownVals = [];
                    if (_fiIterBind && _fiIterBind.kind === 'array') {
                      for (var _fie = 0; _fie < _fiIterBind.elems.length; _fie++) {
                        var _fiElem = _fiIterBind.elems[_fie];
                        if (_fiElem && _fiElem.kind === 'chain') {
                          _fiTaintSources.push(_fiElem.toks);
                          _fiKnownVals.push(_fiElem);
                        }
                      }
                    } else if (_fiIterBind && _fiIterBind.kind === 'object' && _forInOf === 'in') {
                      // for-in over object literal: loop var takes each
                      // property NAME in turn (not the value).
                      for (var _fip in _fiIterBind.props) {
                        _fiKnownVals.push(chainBinding([makeSynthStr(_fip)]));
                      }
                    } else if (_fiIterBind && _fiIterBind.kind === 'object' && _forInOf === 'of') {
                      for (var _fipv in _fiIterBind.props) {
                        if (_fiIterBind.props[_fipv] && _fiIterBind.props[_fipv].kind === 'chain') {
                          _fiTaintSources.push(_fiIterBind.props[_fipv].toks);
                          _fiKnownVals.push(_fiIterBind.props[_fipv]);
                        }
                      }
                    } else if (_fiIterBind && _fiIterBind.kind === 'chain') {
                      _fiTaintSources.push(_fiIterBind.toks);
                    }
                    if (_fiTaintSources.length) _forInOfTaint = { varName: _fiVarName, sources: _fiTaintSources };
                    if (_fiKnownVals.length) _forInOfKnownValues = _fiKnownVals;
                  }
                  break;
                }
              }
            }
            // Collect variables mutated in the loop body (=, +=, ++, --)
            // so we don't resolve them in the header to their initial value.
            var mutatedInBody = new Set();
            if (trackBuildVar) for (const bv of trackBuildVar) mutatedInBody.add(bv);
            for (var bi = j + 1; bi < bodyEnd; bi++) {
              var bt = tokens[bi];
              if (bt.type === 'other' && IDENT_RE.test(bt.text)) {
                var bnext = tokens[bi + 1];
                if (bnext && bnext.type === 'op' && (bnext.text === '=' || bnext.text === '+=' || bnext.text === '-=' || bnext.text === '++' || bnext.text === '--')) {
                  mutatedInBody.add(bt.text);
                }
                var bprev = tokens[bi - 1];
                if (bprev && bprev.type === 'op' && (bprev.text === '++' || bprev.text === '--')) {
                  mutatedInBody.add(bt.text);
                }
              }
            }
            // Also check the for-loop update clause (third part after second ;)
            if (t.text === 'for') {
              var semiCount = 0;
              for (var fi = i + 2; fi < j; fi++) {
                if (tokens[fi].type === 'sep' && tokens[fi].char === ';') semiCount++;
                if (semiCount >= 2 && tokens[fi].type === 'other' && IDENT_RE.test(tokens[fi].text)) {
                  mutatedInBody.add(tokens[fi].text);
                }
              }
            }
            // Build header text, resolving identifiers through scope
            // (important for loops inside inlined functions where
            // parameter names need to be replaced with argument values).
            var headerParts = [];
            for (var hi = i + 2; hi <= j - 1; hi++) {
              var ht = tokens[hi];
              if (ht.type === 'other' && (IDENT_RE.test(ht.text) || IDENT_OR_PATH_RE.test(ht.text))) {
                // Don't resolve variables mutated in the loop body/header.
                var htRoot = ht.text.split('.')[0];
                if (mutatedInBody.has(htRoot)) {
                  var prevEnd2 = hi > i + 2 ? tokens[hi - 1].end : headerFirst.start;
                  var gap2 = ht._src.slice(prevEnd2, ht.start);
                  headerParts.push(gap2 + ht._src.slice(ht.start, ht.end));
                  continue;
                }
                var resolved = await resolvePath(ht.text);
                if (resolved && resolved.kind === 'chain') {
                  var exprText = chainAsExprText(resolved);
                  if (exprText !== null && exprText !== ht.text) {
                    headerParts.push(exprText);
                    continue;
                  }
                }
              }
              // Preserve original source text with surrounding whitespace.
              var prevEnd = hi > i + 2 ? tokens[hi - 1].end : headerFirst.start;
              var gap = ht._src.slice(prevEnd, ht.start);
              headerParts.push(gap + ht._src.slice(ht.start, ht.end));
            }
            const headerSrc = headerParts.join('');
            const id = nextLoopId++;
            loopInfo[id] = { kind: t.text, headerSrc };
            // Extract loop variables from the init clause (`var/let/const X`)
            // and push a shadow block scope for the loop body — the walker
            // processes the init clause with this frame on top, but `var`
            // bindings still hoist to the enclosing function scope. Loop
            // counters resolve through this frame to reference tokens so
            // per-iteration values surface as opaque references. This
            // works for both block-bodied (`for (...) { ... }`) and
            // single-statement (`for (...) stmt;`) loops.
            const loopFrame = { bindings: Object.create(null), isFunction: false };
            // Scan the header for var/let/const declarations.
            for (let h = i + 2; h < j; h++) {
              const hk = tokens[h];
              if (hk.type === 'other' && (hk.text === 'var' || hk.text === 'let' || hk.text === 'const')) {
                const nm = tokens[h + 1];
                if (nm && nm.type === 'other' && IDENT_RE.test(nm.text)) {
                  loopFrame.bindings[nm.text] = chainBinding([exprRef(nm.text)]);
                }
              }
            }
            // Pre-scan the loop body for non-build variables modified by
            // =, +=, ++, -- and make them opaque. This ensures references
            // to loop counters like `i` resolve to the runtime value, not
            // a stale initial value, even when the mutation (i++) comes
            // after the reference (html += i). Build variables are excluded
            // because their += mutations are tracked by the chain system.
            for (let h = j + 1; h < bodyEnd; h++) {
              const hk = tokens[h];
              // Pre-increment/decrement: ++IDENT or --IDENT
              if (hk.type === 'op' && (hk.text === '++' || hk.text === '--')) {
                const hn = tokens[h + 1];
                if (hn && hn.type === 'other' && IDENT_RE.test(hn.text) &&
                    !(trackBuildVar && trackBuildVar.has(hn.text))) {
                  if (!loopFrame.bindings[hn.text]) loopFrame.bindings[hn.text] = chainBinding([exprRef(hn.text)]);
                }
              }
              if (hk.type === 'other' && IDENT_RE.test(hk.text)) {
                if (trackBuildVar && trackBuildVar.has(hk.text)) continue;
                const hn = tokens[h + 1];
                if (hn && hn.type === 'sep' && (hn.char === '=' || hn.char === '+=' || hn.char === '-=' || hn.char === '*=' || hn.char === '/=')) {
                  if (!loopFrame.bindings[hk.text]) loopFrame.bindings[hk.text] = chainBinding([exprRef(hk.text)]);
                }
                if (hn && hn.type === 'op' && (hn.text === '++' || hn.text === '--')) {
                  if (!loopFrame.bindings[hk.text]) loopFrame.bindings[hk.text] = chainBinding([exprRef(hk.text)]);
                }
              }
            }
            // Check loop condition reachability AND compute the SMT
            // formula for the condition so it can be pushed onto the
            // path-constraint stack while walking the body.
            var _loopPathFormula = null;
            var _loopCondExpr = null;
            {
              var _loopCondStart = -1, _loopCondEnd = -1;
              if (t.text === 'while') {
                _loopCondStart = i + 2; _loopCondEnd = j;
              } else {
                // for: condition is between 1st and 2nd semicolons.
                for (var _lsi = i + 2; _lsi < j; _lsi++) {
                  if (tokens[_lsi].type === 'sep' && tokens[_lsi].char === ';') {
                    if (_loopCondStart < 0) _loopCondStart = _lsi + 1;
                    else { _loopCondEnd = _lsi; break; }
                  }
                }
              }
              if (_loopCondStart >= 0 && _loopCondEnd > _loopCondStart) {
                var _loopReach = await checkReachability(_loopCondStart, _loopCondEnd);
                if (_loopReach === false) { i = bodyEnd - 1; continue; }
                // SMT: build the loop condition formula for inner tasks.
                // While walking the body we know `cond` is true (this is
                // an over-approximation for the last iteration where the
                // loop exits, but matches the semantics for "inside body").
                _loopPathFormula = await _smtFormulaFromRange(_loopCondStart, _loopCondEnd);
                if (taintCondStack) {
                  var _lcToks = tokens[_loopCondStart]._src.slice(
                    tokens[_loopCondStart].start,
                    tokens[_loopCondEnd - 1].end
                  );
                  _loopCondExpr = _lcToks;
                }
              }
            }
            stack.push(loopFrame);
            // Apply for-in/for-of taint to the loop frame binding.
            if (_forInOfTaint && loopFrame.bindings[_forInOfTaint.varName]) {
              loopFrame.bindings[_forInOfTaint.varName] = chainBinding([deriveExprRef.apply(null, [_forInOfTaint.varName].concat(_forInOfTaint.sources))]);
            }
            // Pre-populate the may-be lattice for variables assigned
            // from the for-of/for-in loop variable. For a body like
            // `s = v` where `v` is the loop variable and the iterable
            // is a known array, feed every element's value into `s`'s
            // slot so post-loop refutations over values the loop
            // never produces fire correctly. Only handles simple
            // `IDENT = loopVar` assignments — compound RHS (e.g.
            // `s = v + "x"`) stays opaque on the slot.
            if (taintEnabled && _forInOfKnownValues && _forInOfLoopVarName) {
              for (var _asi = j + 1; _asi < bodyEnd; _asi++) {
                var _ast = tokens[_asi];
                if (_ast && _ast.type === 'other' && IDENT_RE.test(_ast.text) && _ast.text !== _forInOfLoopVarName) {
                  var _aeq = tokens[_asi + 1];
                  var _avar = tokens[_asi + 2];
                  var _aend = tokens[_asi + 3];
                  if (_aeq && _aeq.type === 'sep' && _aeq.char === '=' &&
                      _avar && _avar.type === 'other' && _avar.text === _forInOfLoopVarName &&
                      _aend && _aend.type === 'sep' && _aend.char === ';') {
                    for (var _afv = 0; _afv < _forInOfKnownValues.length; _afv++) {
                      _trackMayBeAssign(_ast.text, _forInOfKnownValues[_afv]);
                    }
                  }
                }
              }
              // Also feed the loop variable's OWN may-be slot with every
              // iterable element. When a nested condition tests the loop
              // variable (e.g. `if (v === "trusted")`), smtParseAtom
              // consults the lattice and emits a disjunction over the
              // concrete element set, letting Z3 refute branches the
              // iterable can never produce.
              for (var _lfv = 0; _lfv < _forInOfKnownValues.length; _lfv++) {
                _trackMayBeAssign(_forInOfLoopVarName, _forInOfKnownValues[_lfv]);
              }
              // Suppress the body walker's opaque `loopVar` assignments
              // into the may-be lattice — the pre-population above has
              // already fed every concrete value, and letting the body
              // walk add `other:v` would poison the slot.
              _activeForOfVars.add(_forInOfLoopVarName);
            }
            // ---------- Enhanced SMT path constraints for loops ----------
            // (a) for-of / for-in: push `<iter>.length > 0` so nested
            //     conditions inside the body can reason about iteration.
            // (b) Counter loops `for (var i = INT; i OP INT; ...)`: push
            //     bound constraints on `i` tight to the init value so
            //     nested conditions testing `i` can fold.
            var _extraLoopFormulas = [];
            var _extraLoopExprs = [];
            if (taintEnabled && t.text === 'for') {
              // Detect for-of / for-in and push iter.length > 0.
              for (var _foi = i + 2; _foi < j; _foi++) {
                if (tokens[_foi].type === 'other' && (tokens[_foi].text === 'in' || tokens[_foi].text === 'of')) {
                  var _iterStart = _foi + 1;
                  var _iterEnd = j;
                  if (_iterStart < _iterEnd) {
                    var _iterSrc = tokens[_iterStart]._src.slice(
                      tokens[_iterStart].start,
                      tokens[_iterEnd - 1].end
                    );
                    // Construct a length>0 atom via a synthetic token.
                    var _iterToks = [{ type: 'other', text: _iterSrc + '.length', _src: tokens[_iterStart]._src, start: tokens[_iterStart].start, end: tokens[_iterEnd - 1].end }];
                    var _lenAtom = await smtParseAtom(_iterToks, 0, 1, resolve, resolvePath);
                    if (_lenAtom) {
                      var _lenFormula = smtCmp('>', _lenAtom, smtConst(0));
                      _extraLoopFormulas.push(_lenFormula);
                      _extraLoopExprs.push(_iterSrc + '.length > 0');
                    }
                  }
                  break;
                }
              }
              // Detect counter loop `for (var i = INT; i OP ...; i++/--)`.
              // Only activate when ALL three pieces match (otherwise skip).
              (function() {
                var _ci = i + 2;
                // Skip `var`/`let`/`const`.
                if (tokens[_ci] && tokens[_ci].type === 'other' &&
                    (tokens[_ci].text === 'var' || tokens[_ci].text === 'let' || tokens[_ci].text === 'const')) _ci++;
                var _cName = tokens[_ci] && tokens[_ci].type === 'other' && IDENT_RE.test(tokens[_ci].text) ? tokens[_ci].text : null;
                if (!_cName) return;
                // `=` literal int.
                var _eqTok = tokens[_ci + 1];
                if (!_eqTok || !((_eqTok.type === 'sep' && _eqTok.char === '=') || (_eqTok.type === 'op' && _eqTok.text === '='))) return;
                var _cInitTok = tokens[_ci + 2];
                if (!_cInitTok || _cInitTok.type !== 'other' || !/^-?\d+$/.test(_cInitTok.text)) return;
                var _cInit = parseInt(_cInitTok.text, 10);
                // The update clause (third section) must contain `i++`/`i--`/`i+=N`/`i-=N`
                // so we know direction. Find it via semicolons.
                var _sc1 = -1, _sc2 = -1;
                for (var _sk = i + 2; _sk < j; _sk++) {
                  if (tokens[_sk].type === 'sep' && tokens[_sk].char === ';') {
                    if (_sc1 < 0) _sc1 = _sk; else { _sc2 = _sk; break; }
                  }
                }
                if (_sc1 < 0 || _sc2 < 0) return;
                // Direction and step: `i++` / `i+=N` → ascending step N;
                //                     `i--` / `i-=N` → descending step N.
                var _ascending = null;
                var _step = 1;
                // Detect `i++`, `i--`, `i += N`, `i -= N`, `++i`, `--i`.
                // The tokenizer emits `++`/`--`/`+=`/`-=` as either
                // type:'op' with a `text` property OR type:'sep'
                // with a `char` property depending on context;
                // treat both shapes as the same logical operator.
                function _updTxt(tok) {
                  if (!tok) return null;
                  if (tok.type === 'op') return tok.text;
                  if (tok.type === 'sep') return tok.char;
                  return null;
                }
                for (var _uk = _sc2 + 1; _uk < j; _uk++) {
                  var _ut = tokens[_uk];
                  if (_ut.type === 'other' && _ut.text === _cName) {
                    var _un = tokens[_uk + 1];
                    var _unText = _updTxt(_un);
                    if (_unText === '++') { _ascending = true; _step = 1; break; }
                    if (_unText === '--') { _ascending = false; _step = 1; break; }
                    if (_unText === '+=' || _unText === '-=') {
                      var _sTok = tokens[_uk + 2];
                      if (_sTok && _sTok.type === 'other' && /^\d+$/.test(_sTok.text)) {
                        _ascending = _unText === '+=';
                        _step = parseInt(_sTok.text, 10);
                        break;
                      }
                    }
                  }
                  var _utText = _updTxt(_ut);
                  if (_utText === '++' || _utText === '--') {
                    var _un2 = tokens[_uk + 1];
                    if (_un2 && _un2.type === 'other' && _un2.text === _cName) {
                      _ascending = _utText === '++'; _step = 1;
                      break;
                    }
                  }
                }
                if (_ascending === null || _step <= 0) return;
                var _cSym = smtSym(_cName);
                // Push init-side bound: `i >= init` (ascending) or `i <= init` (descending).
                var _cFormula = smtCmp(_ascending ? '>=' : '<=', _cSym, smtConst(_cInit));
                _extraLoopFormulas.push(_cFormula);
                _extraLoopExprs.push(_cName + ' ' + (_ascending ? '>=' : '<=') + ' ' + _cInit);
                // Upper-bound + step-parity SMT refinement. The goal
                // is to pin the counter's value set exactly — i.e.
                // capture what Z3 needs to prove any path condition
                // on `i` that depends either on the bound OR on the
                // step size. The encoding has three parts, each
                // O(1) in the emitted SMT-LIB regardless of how many
                // iterations the loop actually runs:
                //
                //   (1) `i >= init`                       (already pushed above)
                //   (2) `i OP bound`                      (emitted below)
                //   (3) `(i - init) mod step === 0`       (step-parity, step>1 only)
                //
                // Parts 1 + 2 bound the interval. Part 3 restricts
                // `i` to the arithmetic progression the loop actually
                // visits, so step > 1 loops like
                // `for (i = 0; i < 200; i += 2)` still refute
                // `i === 3` inside the body.
                //
                // We deliberately do NOT emit a per-iteration
                // disjunction `(or (= i 0) (= i 2) …)` even though
                // it would also be sound, because that spelling
                // grows linearly with the concrete iteration count
                // and would blow up the emitted SMT-LIB string for
                // any loop over a few dozen iterations — slowing
                // Z3 on every query inside the body and exploding
                // our smt-cache key space. The (range + mod) spelling
                // has the same solution set in Z3's linear integer
                // theory and stays O(1).
                var _boundTok = null;
                var _boundOp = null;
                // Condition parsed as `i OP LIT` or `LIT OP i`.
                for (var _bk = _sc1 + 1; _bk < _sc2; _bk++) {
                  var _bt = tokens[_bk];
                  if (_bt.type === 'op' && /^(<|<=|>|>=)$/.test(_bt.text)) {
                    var _lhs = tokens[_bk - 1], _rhs = tokens[_bk + 1];
                    if (_lhs && _rhs && _lhs.type === 'other' && _rhs.type === 'other') {
                      if (_lhs.text === _cName && /^-?\d+$/.test(_rhs.text)) {
                        _boundTok = _rhs; _boundOp = _bt.text;
                      } else if (_rhs.text === _cName && /^-?\d+$/.test(_lhs.text)) {
                        _boundTok = _lhs;
                        // Flip op when counter is on the right.
                        _boundOp = { '<':'>', '>':'<', '<=':'>=', '>=':'<=' }[_bt.text];
                      }
                    }
                    break;
                  }
                }
                if (_boundTok) {
                  // Emit the upper-bound constraint: `i OP bound`.
                  // `_boundOp` is already normalised so the counter
                  // is on the left-hand side.
                  var _bndFormula = smtCmp(_boundOp, _cSym, smtConst(parseInt(_boundTok.text, 10)));
                  _extraLoopFormulas.push(_bndFormula);
                  _extraLoopExprs.push(_cName + ' ' + _boundOp + ' ' + _boundTok.text);
                }
                // Step-parity refinement (step > 1 only). Emits
                // `(i - init) mod step === 0` so the theory solver
                // knows `i` is restricted to the arithmetic
                // progression `init, init+step, init+2*step, …`
                // (ascending) or `init, init-step, init-2*step, …`
                // (descending). For step === 1 the congruence is
                // trivially true and we skip the formula.
                if (_step > 1) {
                  var _diffExpr, _diffExprText;
                  if (_ascending) {
                    // (i - init)
                    _diffExpr = smtArith('-', _cSym, smtConst(_cInit));
                    _diffExprText = '(' + _cName + ' - ' + _cInit + ')';
                  } else {
                    // (init - i)
                    _diffExpr = smtArith('-', smtConst(_cInit), _cSym);
                    _diffExprText = '(' + _cInit + ' - ' + _cName + ')';
                  }
                  if (_diffExpr) {
                    var _modExpr = smtArith('%', _diffExpr, smtConst(_step));
                    if (_modExpr) {
                      var _parityFormula = smtCmp('===', _modExpr, smtConst(0));
                      if (_parityFormula) {
                        _extraLoopFormulas.push(_parityFormula);
                        _extraLoopExprs.push(_diffExprText + ' % ' + _step + ' === 0');
                      }
                    }
                  }
                }
              })();
            }
            // Push the loop condition onto P/T — it holds inside the body.
            _pushPathConstraint(_loopPathFormula, _loopCondExpr);
            // Push the enhanced constraints (iterator length / counter bound).
            for (var _elf = 0; _elf < _extraLoopFormulas.length; _elf++) {
              _pushPathConstraint(_extraLoopFormulas[_elf], _extraLoopExprs[_elf]);
            }
            loopStack.push({
              id, kind: t.text, headerSrc, bodyEnd, frame: loopFrame,
              modifiedVars: new Set(),
              pathFormula: _loopPathFormula,
              condExpr: _loopCondExpr,
              extraFormulas: _extraLoopFormulas,
              extraExprs: _extraLoopExprs,
              // Carry for-of loop var name so the cleanup at loop
              // exit can pop it out of _activeForOfVars.
              forOfVarName: _forInOfKnownValues && _forInOfLoopVarName ? _forInOfLoopVarName : null,
            });
            // Skip past the loop header — the init/cond/update clauses
            // don't count as body mutations, so we resume at the body's
            // opening token (j is the `)` token index; loop's i++ takes
            // us to j, which is the close-paren we safely skip past).
            i = j - 1;
            continue;
          }
        }
        continue;
      }
      if (t.text === 'function') {
        // Try to capture a function declaration: `function NAME(params) { body }`.
        const nameTok = tokens[i + 1];
        const openParen = tokens[i + 2];
        if (nameTok && nameTok.type === 'other' && IDENT_RE.test(nameTok.text) &&
            openParen && openParen.type === 'open' && openParen.char === '(') {
          const params = [];
          let j = i + 3;
          const firstP = tokens[j];
          if (firstP && firstP.type === 'close' && firstP.char === ')') { j++; }
          else {
            let ok = true;
            while (j < stop) {
              const pt = parseParamWithDefault(tokens, j, stop);
              if (!pt) { ok = false; break; }
              params.push(pt.param);
              j = pt.next;
              const sep = tokens[j];
              if (sep && sep.type === 'close' && sep.char === ')') { j++; break; }
              if (sep && sep.type === 'sep' && sep.char === ',') { j++; continue; }
              ok = false; break;
            }
            if (!ok) { pendingFunctionBrace = true; continue; }
          }
          const openBrace = tokens[j];
          if (openBrace && openBrace.type === 'open' && openBrace.char === '{') {
            let depth = 1;
            let k = j + 1;
            while (k < stop && depth > 0) {
              const tk = tokens[k];
              if (tk.type === 'open' && tk.char === '{') depth++;
              else if (tk.type === 'close' && tk.char === '}') depth--;
              k++;
            }
            if (depth === 0) {
              declFunction(nameTok.text, functionBinding(params, j + 1, k - 1, true));
              // Fall through to let the walker traverse the body in a new
              // function scope, so inner `var`/`let`/`const` and assignments
              // (including `this.innerHTML = ...` sites) remain visible to
              // parseRange while staying isolated from the outer scope.
              pendingFunctionBrace = true;
              pendingFunctionParams = params;
              i = j - 1;
              continue;
            }
          }
        }
        pendingFunctionBrace = true;
        continue;
      }
      // Class declaration: class Name { method(params) { body } ... }
      if (t.text === 'class') {
        var _clsName = tokens[i + 1];
        var _clsOpen = null;
        var _clsIdx = i + 1;
        // Optional name.
        if (_clsName && _clsName.type === 'other' && IDENT_RE.test(_clsName.text)) _clsIdx++;
        else _clsName = null;
        // Optional extends.
        if (tokens[_clsIdx] && tokens[_clsIdx].type === 'other' && tokens[_clsIdx].text === 'extends') {
          _clsIdx++; // skip extends
          if (tokens[_clsIdx] && tokens[_clsIdx].type === 'other') _clsIdx++; // skip parent class name
        }
        _clsOpen = tokens[_clsIdx];
        if (_clsOpen && _clsOpen.type === 'open' && _clsOpen.char === '{') {
          // Find the matching }.
          var _clsEnd = _clsIdx + 1, _clsD = 1;
          while (_clsEnd < stop && _clsD > 0) {
            if (tokens[_clsEnd].type === 'open' && tokens[_clsEnd].char === '{') _clsD++;
            if (tokens[_clsEnd].type === 'close' && tokens[_clsEnd].char === '}') _clsD--;
            _clsEnd++;
          }
          // Parse methods inside the class body.
          var _clsProps = Object.create(null);
          var _clsJ = _clsIdx + 1;
          while (_clsJ < _clsEnd - 1) {
            var _mTok = tokens[_clsJ];
            if (!_mTok) break;
            // Skip static, async, get, set keywords for now — just find method name + parens.
            var _isGetter = false, _isSetter = false;
            if (_mTok.type === 'other' && _mTok.text === 'static') { _clsJ++; _mTok = tokens[_clsJ]; }
            if (_mTok && _mTok.type === 'other' && _mTok.text === 'async') { _clsJ++; _mTok = tokens[_clsJ]; }
            if (_mTok && _mTok.type === 'other' && _mTok.text === 'get') {
              var _gnext = tokens[_clsJ + 1];
              if (_gnext && _gnext.type === 'open' && _gnext.char === '(') { /* method named 'get' */ }
              else { _isGetter = true; _clsJ++; _mTok = tokens[_clsJ]; }
            }
            if (_mTok && _mTok.type === 'other' && _mTok.text === 'set') {
              var _snext = tokens[_clsJ + 1];
              if (_snext && _snext.type === 'open' && _snext.char === '(') { /* method named 'set' */ }
              else { _isSetter = true; _clsJ++; _mTok = tokens[_clsJ]; }
            }
            if (_mTok && _mTok.type === 'other' && IDENT_RE.test(_mTok.text)) {
              var _mName = _mTok.text;
              var _mParen = tokens[_clsJ + 1];
              if (_mParen && _mParen.type === 'open' && _mParen.char === '(') {
                // Parse params.
                var _mParams = [], _mJ = _clsJ + 2;
                while (_mJ < _clsEnd) {
                  var _mp = parseParamWithDefault(tokens, _mJ, _clsEnd);
                  if (!_mp) break;
                  _mParams.push(_mp.param);
                  _mJ = _mp.next;
                  if (tokens[_mJ] && tokens[_mJ].type === 'close' && tokens[_mJ].char === ')') { _mJ++; break; }
                  if (tokens[_mJ] && tokens[_mJ].type === 'sep' && tokens[_mJ].char === ',') { _mJ++; continue; }
                  break;
                }
                if (tokens[_mJ - 1] && tokens[_mJ - 1].type === 'close' && tokens[_mJ - 1].char === ')') { /* ok */ }
                else if (tokens[_mJ] && tokens[_mJ].type === 'close' && tokens[_mJ].char === ')') _mJ++;
                // Parse body.
                if (tokens[_mJ] && tokens[_mJ].type === 'open' && tokens[_mJ].char === '{') {
                  var _mBD = 1, _mBE = _mJ + 1;
                  while (_mBE < _clsEnd && _mBD > 0) {
                    if (tokens[_mBE].type === 'open' && tokens[_mBE].char === '{') _mBD++;
                    if (tokens[_mBE].type === 'close' && tokens[_mBE].char === '}') _mBD--;
                    _mBE++;
                  }
                  if (_isGetter) {
                    // Getter: store as a function, resolve when property is accessed.
                    _clsProps['__getter_' + _mName] = functionBinding(_mParams, _mJ, _mBE, true);
                  } else {
                    _clsProps[_mName] = functionBinding(_mParams, _mJ, _mBE, true);
                  }
                  _clsJ = _mBE;
                  continue;
                }
              }
            }
            _clsJ++;
          }
          // Store class as an object binding with method properties.
          if (_clsName) {
            var _clsBinding = objectBinding(_clsProps);
            _clsBinding._isClass = true;
            declFunction(_clsName.text, _clsBinding);
          }
          // Don't skip body — let the walker continue through it
          // so extraction and inner declarations are processed. The
          // `for` loop's `i++` will land on `_clsIdx` (the `{`), where
          // the frame-push handler runs and bumps taintFnDepth so
          // method bodies walked raw don't emit findings without a
          // calling context.
          i = _clsIdx - 1;
          pendingFunctionBrace = true;
          continue;
        }
      }
      if (t.text === '=>') {
        // Only arrow bodies of the form `=> { ... }` open a function scope;
        // expression arrows (`x => x + 1`) don't.
        const next = tokens[i + 1];
        if (next && next.type === 'open' && next.char === '{') pendingFunctionBrace = true;
        continue;
      }

      // Skip ES-module `import` statements entirely — their bindings are
      // opaque to us and the `from`/`{}` syntax would otherwise confuse the
      // walker. `export` is stripped: if it fronts a declaration we let the
      // walker see the underlying `const`/`let`/`var`/`function`, otherwise
      // skip to the statement terminator.
      if (t.text === 'import') {
        let j = i + 1;
        while (j < stop) {
          const tk = tokens[j];
          if (tk.type === 'sep' && tk.char === ';') break;
          j++;
        }
        i = j;
        continue;
      }
      if (t.text === 'export') {
        const nx = tokens[i + 1];
        if (nx && nx.type === 'other' && (nx.text === 'var' || nx.text === 'let' || nx.text === 'const' || nx.text === 'function' || nx.text === 'class' || nx.text === 'default' && tokens[i + 2] && tokens[i + 2].type === 'other' && (tokens[i + 2].text === 'function' || tokens[i + 2].text === 'class'))) {
          // Strip `export` (and `export default` when followed by a decl);
          // fall through so the next keyword is processed normally.
          continue;
        }
        let j = i + 1;
        while (j < stop) {
          const tk = tokens[j];
          if (tk.type === 'sep' && tk.char === ';') break;
          j++;
        }
        i = j;
        continue;
      }

      if (t.text === 'var' || t.text === 'let' || t.text === 'const') {
        const kind = t.text;
        const declBind = (name, v) => {
          if (kind === 'var') declFunction(name, v);
          else declBlock(name, v);
        };
        let j = i + 1;
        while (j < stop) {
          const head = tokens[j];
          if (!head) break;
          // Destructuring: { ... } = rhs  OR  [ ... ] = rhs
          if (head.type === 'open' && (head.char === '{' || head.char === '[')) {
            const pat = readDestructurePattern(j, stop);
            if (!pat) { j = skipExpr(j, stop); break; }
            const eqTok = tokens[pat.next];
            if (!eqTok || eqTok.type !== 'sep' || eqTok.char !== '=') {
              // Not a destructuring-with-init (could be shorthand we don't
              // understand); just skip.
              j = skipExpr(pat.next, stop);
              break;
            }
            const val = await readValue(pat.next + 1, stop, TERMS_TOP);
            const srcBinding = val ? val.binding : null;
            await applyPatternBindings(pat.pattern, srcBinding, declBind);
            j = val ? val.next : skipExpr(pat.next + 1, stop);
            if (tokens[j] && tokens[j].type === 'sep' && tokens[j].char === ',') { j++; continue; }
            break;
          }
          if (head.type !== 'other' || !IDENT_RE.test(head.text)) break;
          const nameTok = head;
          const eqTok = tokens[j + 1];
          let value = null;
          let hasInit = false;
          let k = j + 1;
          if (eqTok && eqTok.type === 'sep' && eqTok.char === '=') {
            hasInit = true;
            // readValue handles function expressions, arrows, and all
            // other value types through a single code path.
            const r = await readValue(j + 2, stop, TERMS_TOP);
            value = r ? r.binding : null;
            // For function bindings use the precise end; for chains use
            // skipExpr to ensure we consume the full statement.
            k = (r && r.binding && r.binding.kind === 'function') ? r.next : skipExpr(j + 2, stop);
          }
          if (hasInit) {
            declBind(nameTok.text, value);
            // Object literal initializer: register every property's
            // initial value in the may-be lattice keyed by the full
            // path. This catches `var s = {v: "init"}` so that later
            // `s.v = "X"` joins into the same lattice slot.
            if (value && value.kind === 'object' && taintEnabled) {
              for (var _olP in value.props) {
                _trackMayBeAssign(nameTok.text + '.' + _olP, value.props[_olP]);
              }
            }
            if (trackBuildVar && trackBuildVar.has(nameTok.text)) {
              // Only set buildVarDeclStart at the outer scope level, not
              // inside inlined functions. When instantiateFunction enables
              // trackBuildVar for the function's internal build var, the
              // declaration is inside the function body — we don't want
              // the inline rewriter to replace from inside the function.
              if (trackBuildVarDepth < 0 || funcDepth() <= trackBuildVarDepth) {
                buildVarDeclStart = tokens[i].start;
                trackBuildVarDepth = funcDepth();
              }
            }
          } else {
            if (kind === 'var') {
              if (!hasBinding(stack, nameTok.text)) declFunction(nameTok.text, null);
            } else {
              declBlock(nameTok.text, null);
            }
          }
          j = k;
          if (tokens[j] && tokens[j].type === 'sep' && tokens[j].char === ',') { j++; continue; }
          break;
        }
        // Preserve var declarations for non-build variables
        // (only at the same function scope depth as the build var).
        if (trackBuildVar && (trackBuildVarDepth < 0 || funcDepth() === trackBuildVarDepth)) {
          const first = tokens[i];
          const last = tokens[j - 1];
          let declaresBuildVar = false;
          for (let d = i + 1; d < j; d++) {
            if (tokens[d].type === "other" && trackBuildVar && trackBuildVar.has(tokens[d].text)) { declaresBuildVar = true; break; }
          }
          if (!declaresBuildVar && first && last) {
            for (const bv of trackBuildVar) {
              const cur = resolve(bv);
              if (cur && cur.kind === 'chain') {
                const stmtSrc = first._src.slice(first.start, last.end);
                const loopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
                const preserveTok = { type: 'preserve', text: stmtSrc };
                if (loopId !== null) preserveTok.loopId = loopId;
                assignName(bv, chainBinding([...cur.toks, SYNTH_PLUS, preserveTok]));
              }
            }
          }
        }
        i = j - 1;
        continue;
      }

      // Bare assignment: IDENT = <value>, or compound `IDENT += <value>`
      // (which translates to `IDENT = IDENT + <value>`).
      if (IDENT_RE.test(t.text)) {
        const eqTok = tokens[i + 1];
        // Navigation sink: bare assignment to a navigation global (location = expr).
        if (taintEnabled && eqTok && eqTok.type === 'sep' && eqTok.char === '=' && isNavSink(t.text, typedScope)) {
          var _bNavR = await readValue(i + 2, stop, TERMS_TOP);
          if (_bNavR && _bNavR.binding && _bNavR.binding.kind === 'chain') {
            var _bNavTaint = collectChainTaint(_bNavR.binding.toks);
            if (_bNavTaint && _bNavTaint.size) {
              recordTaintFinding('navigation', 'high', t.text, null, _bNavTaint, taintCondStack,
                { expr: t.text, line: countLines(t._src, t.start) });
            }
          }
        }
        if (eqTok && eqTok.type === 'sep' && eqTok.char === '=') {
          const stmtEndIdx = skipExpr(i + 2, stop);
          // Handle chained assignment: a = b = c = expr.
          // Collect all targets, then assign the final value to all.
          var _chainTargets = [t.text];
          var _rhsStart = i + 2;
          while (_rhsStart + 1 < stmtEndIdx) {
            var _ct = tokens[_rhsStart];
            var _ce = tokens[_rhsStart + 1];
            if (_ct && _ct.type === 'other' && IDENT_RE.test(_ct.text) && _ce && _ce.type === 'sep' && _ce.char === '=') {
              _chainTargets.push(_ct.text);
              _rhsStart += 2;
            } else break;
          }
          const r = await readValue(_rhsStart, stop, TERMS_TOP);
          // Detect prepend pattern: x = expr + x (builds string in reverse).
          // Treat as equivalent to x += expr but with the new content prepended.
          // For build variables assigned via = inside a loop (prepend
          // pattern: x = newContent + x), tag the new content with the
          // current loopId so it repeats per iteration.
          if (r && r.binding && r.binding.kind === 'chain' && trackBuildVar && trackBuildVar.has(t.text) && loopStack.length > 0) {
            const loopId = loopStack[loopStack.length - 1].id;
            const tagged = tagWithLoop(r.binding.toks, loopId);
            assignName(t.text, chainBinding(tagged));
          } else {
            var _assignVal = r ? r.binding : null;
            for (var _ci = 0; _ci < _chainTargets.length; _ci++) assignName(_chainTargets[_ci], _assignVal);
          }
          // Preserve non-build-var assignments in the build var's chain
          // so the emitter outputs them at the correct position.
          if (trackBuildVar && !trackBuildVar.has(t.text) && (trackBuildVarDepth < 0 || funcDepth() === trackBuildVarDepth)) {
            for (const bv of trackBuildVar) {
              const cur = resolve(bv);
              if (cur && cur.kind === 'chain') {
                const first = tokens[i];
                const last = tokens[stmtEndIdx - 1];
                const stmtSrc = first._src.slice(first.start, last.end);
                const loopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
                const preserveTok = { type: 'preserve', text: stmtSrc };
                if (loopId !== null) preserveTok.loopId = loopId;
                assignName(bv, chainBinding([...cur.toks, SYNTH_PLUS, preserveTok]));
              }
            }
          }
          i = stmtEndIdx - 1;
          continue;
        }
        if (eqTok && eqTok.type === 'sep' && eqTok.char === '+=') {
          const r = await readValue(i + 2, stop, TERMS_TOP);
          const rhs = r ? r.binding : null;
          const cur = resolve(t.text);
          let combined = null;
          if (cur && cur.kind === 'chain' && rhs && rhs.kind === 'chain') {
            const loopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
            const tagged = loopId !== null ? tagWithLoop(rhs.toks, loopId) : rhs.toks;
            combined = chainBinding([...cur.toks, SYNTH_PLUS, ...tagged]);
          }
          assignName(t.text, combined);
          if (loopStack.length > 0) loopStack[loopStack.length - 1].modifiedVars.add(t.text);
          // For non-build variables modified by +=, preserve the statement
          // in the build chain AND make the variable opaque. This prevents
          // numeric accumulators (total += x) from being expanded as text
          // nodes — the variable stays as a runtime reference.
          if (trackBuildVar && !trackBuildVar.has(t.text) && (trackBuildVarDepth < 0 || funcDepth() === trackBuildVarDepth)) {
            // Make the variable opaque so later references to it produce
            // the variable name, not the expanded chain.
            assignName(t.text, chainBinding([exprRef(t.text)]));
            for (const bv of trackBuildVar) {
              const bCur = resolve(bv);
              if (bCur && bCur.kind === 'chain') {
                const stmtEndIdx = skipExpr(i + 2, stop);
                const first = tokens[i];
                const last = tokens[stmtEndIdx - 1];
                const stmtSrc = first._src.slice(first.start, last.end);
                const loopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
                const preserveTok = { type: 'preserve', text: stmtSrc };
                if (loopId !== null) preserveTok.loopId = loopId;
                assignName(bv, chainBinding([...bCur.toks, SYNTH_PLUS, preserveTok]));
              }
            }
          }
          i = skipExpr(i + 2, stop) - 1;
          continue;
        }
        // Post-increment/decrement: IDENT++ or IDENT--.
        if (eqTok && eqTok.type === 'op' && (eqTok.text === '++' || eqTok.text === '--')) {
          const cur = resolve(t.text);
          const n = cur && cur.kind === 'chain' ? chainAsNumber(cur) : null;
          if (inEventHandler) {
            // Value depends on handler invocation count (symbolic).
            var _ehRef2 = exprRef(t.text);
            _ehRef2.taint = new Set(['event']);
            assignName(t.text, chainBinding([_ehRef2]));
          } else if (n !== null && loopStack.length === 0) {
            const delta = eqTok.text === '++' ? 1 : -1;
            assignName(t.text, chainBinding([makeSynthStr(String(n + delta))]));
          } else {
            assignName(t.text, chainBinding([exprRef(t.text)]));
          }
          // Preserve as non-build statement.
          if (trackBuildVar && !trackBuildVar.has(t.text) && (trackBuildVarDepth < 0 || funcDepth() === trackBuildVarDepth)) {
            for (const bv of trackBuildVar) {
              const bCur = resolve(bv);
              if (bCur && bCur.kind === 'chain') {
                const stmtSrc = t.text + eqTok.text;
                const loopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
                const preserveTok = { type: 'preserve', text: stmtSrc };
                if (loopId !== null) preserveTok.loopId = loopId;
                assignName(bv, chainBinding([...bCur.toks, SYNTH_PLUS, preserveTok]));
              }
            }
          }
          if (loopStack.length > 0) loopStack[loopStack.length - 1].modifiedVars.add(t.text);
          i = i + 1;
          continue;
        }
        // Logical assignment: IDENT ||= expr, IDENT &&= expr, IDENT ??= expr
        if (eqTok && eqTok.type === 'sep' && (eqTok.char === '||=' || eqTok.char === '&&=' || eqTok.char === '??=')) {
          var _laR = await readValue(i + 2, stop, TERMS_TOP);
          var _laRhs = _laR ? _laR.binding : null;
          var _laCur = resolve(t.text);
          var _laOp = eqTok.char;
          // Evaluate the LHS concretely to determine which branch executes.
          var _laTruth = _laCur ? evalTruthiness(_laCur) : null;
          var _laIsNull = _laCur && _laCur.kind === 'chain' && _laCur.toks.length === 1 && (_laCur.toks[0].text === 'null' || _laCur.toks[0].text === 'undefined');
          if (_laOp === '||=') {
            // x ||= y: if x is truthy, keep x; else x = y.
            if (_laTruth === true) { /* keep current, no change */ }
            else if (_laTruth === false) { if (_laRhs) assignName(t.text, _laRhs); }
            else {
              // Unknown: could be either. Merge taint from both.
              if (_laRhs && _laRhs.kind === 'chain' && _laCur && _laCur.kind === 'chain') {
                assignName(t.text, chainBinding([deriveExprRef(t.text, _laCur.toks, _laRhs.toks)]));
              } else if (_laRhs) { assignName(t.text, _laRhs); }
            }
          } else if (_laOp === '&&=') {
            // x &&= y: if x is falsy, keep x; else x = y.
            if (_laTruth === false) { /* keep current, no change */ }
            else if (_laTruth === true) { if (_laRhs) assignName(t.text, _laRhs); }
            else {
              if (_laRhs && _laRhs.kind === 'chain' && _laCur && _laCur.kind === 'chain') {
                assignName(t.text, chainBinding([deriveExprRef(t.text, _laCur.toks, _laRhs.toks)]));
              } else if (_laRhs) { assignName(t.text, _laRhs); }
            }
          } else { // ??=
            // x ??= y: if x is non-null/undefined, keep x; else x = y.
            if (_laCur && !_laIsNull && _laTruth !== null) { /* keep current */ }
            else if (_laIsNull || !_laCur) { if (_laRhs) assignName(t.text, _laRhs); }
            else {
              if (_laRhs && _laRhs.kind === 'chain' && _laCur && _laCur.kind === 'chain') {
                assignName(t.text, chainBinding([deriveExprRef(t.text, _laCur.toks, _laRhs.toks)]));
              } else if (_laRhs) { assignName(t.text, _laRhs); }
            }
          }
          i = skipExpr(i + 2, stop) - 1;
          continue;
        }
      }

      // setTimeout/setInterval with function callback: walk the callback.
      if (t.type === 'other' && (t.text === 'setTimeout' || t.text === 'setInterval') && !declaredNames.has(t.text)) {
        var _timerParen = tokens[i + 1];
        if (_timerParen && _timerParen.type === 'open' && _timerParen.char === '(') {
          var _timerArgs = await readCallArgBindings(i + 1, stop);
          if (_timerArgs && _timerArgs.bindings.length >= 1) {
            var _timerCb = _timerArgs.bindings[0];
            if (_timerCb && _timerCb.kind === 'function') {
              await instantiateFunction(_timerCb, []);
              if (_pendingCallbacks && taintEnabled) {
                _pendingCallbacks.push({ fn: _timerCb, params: [], isEventHandler: false });
              }
            }
            i = _timerArgs.next - 1;
            continue;
          }
        }
      }
      // Bare-method Promise continuation: `p.then(...)` / `p.catch(...)`
      // / `p.finally(...)` as a statement, where p is a stored Promise
      // (a chain produced by fetch / await / etc.). When p resolves to
      // a chain (Promise-shaped value), route through readValue so
      // applyMethod's then/catch/finally handler walks the callback
      // with the receiver's taint. When p resolves to a real object
      // with a .then function property (a "thenable"), let the existing
      // bare-call handler dispatch through resolvePath instead — its
      // path-walking is what makes inline thenables work.
      if (taintEnabled && t.type === 'other' && /\.(then|catch|finally)$/.test(t.text)) {
        var _bmParen = tokens[i + 1];
        if (_bmParen && _bmParen.type === 'open' && _bmParen.char === '(') {
          var _bmRoot = t.text.slice(0, t.text.lastIndexOf('.')).split('.')[0];
          var _bmRootBind = resolve(_bmRoot);
          if (_bmRootBind && _bmRootBind.kind === 'chain') {
            var _bmResult = await readValue(i, stop, TERMS_TOP);
            if (_bmResult) { i = _bmResult.next - 1; continue; }
          }
        }
      }
      // Bare `new ClassName(...)` as a statement, possibly with trailing
      // method calls: `new C().go();`, `new C(x).a().b();`. The walker
      // otherwise has no handler for statement-initial `new`, so the
      // instantiation and every chained method would go unanalysed.
      // Route the whole expression through readValue so readBaseCore's
      // `new` handler returns the instance and applySuffixes walks the
      // trailing `.method(args)` chain with the instance as `this`.
      if (t.type === 'other' && t.text === 'new') {
        var _newResult = await readValue(i, stop, TERMS_TOP);
        if (_newResult) { i = _newResult.next - 1; continue; }
      }
      // Bare function call as a statement: `render(input);` or `obj.method(args);`.
      // Resolve the callee; if it's a function binding, inline it for side effects.
      if (t.type === 'other' && IDENT_OR_PATH_RE.test(t.text)) {
        const callParen = tokens[i + 1];
        if (callParen && callParen.type === 'open' && callParen.char === '(') {
          // Chained-call peek: `outer()()`, `factory()()`, `a()()()`.
          // If what follows the first `)` is another `(`, route the
          // whole chain through readValue so applySuffixes's bare-call
          // handler walks each invocation and the returned closure's
          // body is actually analysed (including captured taint).
          if (taintEnabled) {
            var _ccDepth = 1, _ccK = i + 2;
            while (_ccK < stop && _ccDepth > 0) {
              if (tokens[_ccK].type === 'open' && tokens[_ccK].char === '(') _ccDepth++;
              else if (tokens[_ccK].type === 'close' && tokens[_ccK].char === ')') _ccDepth--;
              if (_ccDepth === 0) break;
              _ccK++;
            }
            if (_ccDepth === 0) {
              var _ccAfter = tokens[_ccK + 1];
              if (_ccAfter && _ccAfter.type === 'open' && _ccAfter.char === '(') {
                var _ccResult = await readValue(i, stop, TERMS_TOP);
                if (_ccResult) { i = _ccResult.next - 1; continue; }
              }
            }
          }
          // Promise continuation peek BEFORE the inline-call path:
          // `load().then(d => sink(d))` should be routed through
          // readValue so the .then callback flows through applyMethod
          // with the receiver's taint. If we let the bare-call handler
          // inline load() in isolation, the trailing .then is lost.
          if (taintEnabled) {
            var _bcDepth = 1, _bcK = i + 2;
            while (_bcK < stop && _bcDepth > 0) {
              if (tokens[_bcK].type === 'open' && tokens[_bcK].char === '(') _bcDepth++;
              else if (tokens[_bcK].type === 'close' && tokens[_bcK].char === ')') _bcDepth--;
              if (_bcDepth === 0) break;
              _bcK++;
            }
            if (_bcDepth === 0) {
              var _bcAfter = tokens[_bcK + 1];
              if (_bcAfter && _bcAfter.type === 'other' && /^\.(then|catch|finally)$/.test(_bcAfter.text)) {
                var _bcResult = await readValue(i, stop, TERMS_TOP);
                if (_bcResult) { i = _bcResult.next - 1; continue; }
              }
            }
          }
          var calleeBind = await resolvePath(t.text);
          // Universal call watcher: when a recorder is registered,
          // fire it for every bare-statement call regardless of whether
          // the callee is resolvable. This is how external analyses
          // (fetch/XHR tracers, sink finders, dead-code reporters)
          // observe call sites without having to duplicate the
          // walker. The recorder sees fully resolved argument
          // bindings — chain tokens, object literals, arrays — as
          // they exist at this call site.
          if (_callWatchers && _callWatchers.length > 0) {
            var _cwArgs = await readCallArgBindings(i + 1, stop);
            if (_cwArgs) {
              // Snapshot the active path constraint stack so watchers
              // can reason about *under what conditions* this call is
              // reachable. taintCondStack is human-readable JS-ish; the
              // parallel pathConstraints array holds SMT formula nodes.
              var _cwInfo = {
                stage: 'statement',
                reached: true,
                pathConditions: taintCondStack ? taintCondStack.slice() : [],
                pathFormulas: pathConstraints ? pathConstraints.slice() : [],
                mayBe: _varMayBe,
                resolve: resolve,
                resolvePath: resolvePath,
              };
              for (var _cwi = 0; _cwi < _callWatchers.length; _cwi++) {
                try { _callWatchers[_cwi](t.text, _cwArgs.bindings, t, _cwInfo); } catch (_) {}
              }
            }
          }
          if (calleeBind && calleeBind.kind === 'function') {
            var callArgs = await readCallArgBindings(i + 1, stop);
            if (callArgs) {
              // Method call on an object path: bind the receiver as
              // `this` so the body can read/write `this.prop` against
              // the instance. Without this, `c.setIt(v)` where setIt
              // does `this.foo = v` loses the assignment because
              // `this` resolves to null.
              var _calleeThis = null;
              var _calleeDot = t.text.lastIndexOf('.');
              if (_calleeDot > 0) {
                _calleeThis = await resolvePath(t.text.slice(0, _calleeDot));
              }
              await instantiateFunction(calleeBind, callArgs.bindings, _calleeThis);
              // Indirect-call may-be: if the callee variable was also
              // assigned OTHER function values (e.g. `var f = cond ? a : b`
              // or sequential reassignment from different code paths),
              // walk every alternative target. Without this, only the
              // single binding the walker happens to see at this point
              // gets analysed — anything assigned earlier is missed.
              if (taintEnabled) {
                var _altTargets = _funcMayBeFor(t.text);
                if (_altTargets) {
                  for (var _ati = 0; _ati < _altTargets.length; _ati++) {
                    if (_altTargets[_ati] !== calleeBind) {
                      await instantiateFunction(_altTargets[_ati], callArgs.bindings);
                      // Register for the phase-2 fixpoint so the
                      // alternative target's body sees mutations from
                      // every other callback.
                      if (_pendingCallbacks) {
                        _pendingCallbacks.push({ fn: _altTargets[_ati], params: callArgs.bindings, isEventHandler: false });
                      }
                    }
                  }
                }
              }
              i = callArgs.next - 1;
              if (taintEnabled && _classifyCallSinkViaDB(DEFAULT_TYPE_DB, t.text, typedScope)) {
                checkSinkCall(t.text, callArgs.bindings, t);
              }
              continue;
            }
          }
          // Indirect call: the variable resolves to something that
          // isn't a known function binding (e.g. a chain produced by a
          // ternary), but the may-be lattice tracked function targets
          // assigned to it. Walk all of them.
          if (taintEnabled && (!calleeBind || calleeBind.kind !== 'function')) {
            var _icTargets = _funcMayBeFor(t.text);
            if (_icTargets && _icTargets.length > 0) {
              var _icArgs = await readCallArgBindings(i + 1, stop);
              if (_icArgs) {
                for (var _ici = 0; _ici < _icTargets.length; _ici++) {
                  await instantiateFunction(_icTargets[_ici], _icArgs.bindings);
                  if (_pendingCallbacks) {
                    _pendingCallbacks.push({ fn: _icTargets[_ici], params: _icArgs.bindings, isEventHandler: false });
                  }
                }
                i = _icArgs.next - 1;
                continue;
              }
            }
          }
          // Taint: even if callee isn't inlinable, check if it's a call-based sink.
          if (taintEnabled && _classifyCallSinkViaDB(DEFAULT_TYPE_DB, t.text, typedScope)) {
            var sinkArgs = await readCallArgBindings(i + 1, stop);
            if (sinkArgs) {
              checkSinkCall(t.text, sinkArgs.bindings, t);
              i = sinkArgs.next - 1;
              continue;
            }
          }
          // Bare-call expression statement followed by a Promise
          // continuation method (`.then` / `.catch` / `.finally`):
          // run the whole expression through readValue so applySuffixes
          // routes the .then(callback) to applyMethod, which walks the
          // callback with the receiver's taint as the first arg. This
          // lets fetch("/api").then(d => sink(d)) flow taint into the
          // callback even though it's a bare expression statement.
          if (taintEnabled) {
            var _peekContEnd = -1;
            var _peekDepth = 1, _peekJ = i + 2;
            while (_peekJ < stop && _peekDepth > 0) {
              if (tokens[_peekJ].type === 'open' && tokens[_peekJ].char === '(') _peekDepth++;
              else if (tokens[_peekJ].type === 'close' && tokens[_peekJ].char === ')') _peekDepth--;
              if (_peekDepth === 0) { _peekContEnd = _peekJ; break; }
              _peekJ++;
            }
            if (_peekContEnd > 0) {
              var _peekNext = tokens[_peekContEnd + 1];
              if (_peekNext && _peekNext.type === 'other' && /^\.(then|catch|finally)$/.test(_peekNext.text)) {
                var _exprResult = await readValue(i, stop, TERMS_TOP);
                if (_exprResult) { i = _exprResult.next - 1; continue; }
              }
            }
          }
        }
      }

      // DOM factory call as a statement: `document.getElementById("x").prop = value`
      // or `document.createElement("div").method(...)`. Resolve the call,
      // then handle trailing property assignment or method call on the result.
      if (t.type === 'other' && DOM_FACTORIES[t.text]) {
        const factoryParen = tokens[i + 1];
        if (factoryParen && factoryParen.type === 'open' && factoryParen.char === '(') {
          const factoryArgs = await readConcatArgs(i + 1, stop);
          if (factoryArgs) {
            const factoryResult = DOM_FACTORIES[t.text](factoryArgs.args, i, factoryArgs.next, t);
            if (factoryResult && factoryResult.bind) {
              var afterCall = factoryResult.next;
              // Check for trailing .prop = value or .method(args).
              var trailTok = tokens[afterCall];
              if (trailTok && trailTok.type === 'other' && trailTok.text[0] === '.') {
                var trailProp = trailTok.text.slice(1);
                var trailEq = tokens[afterCall + 1];
                if (trailEq && trailEq.type === 'sep' && (trailEq.char === '=' || trailEq.char === '+=')) {
                  // Property assignment on DOM factory result.
                  var trailR = await readValue(afterCall + 2, stop, TERMS_TOP);
                  var trailVal = trailR ? trailR.binding : null;
                  if (factoryResult.bind.kind === 'element') {
                    applyElementSet(factoryResult.bind, [trailProp], trailVal, trailTok);
                  }
                  i = skipExpr(afterCall + 2, stop) - 1;
                  continue;
                } else if (trailEq && trailEq.type === 'open' && trailEq.char === '(') {
                  // Method call on DOM factory result.
                  if (factoryResult.bind.kind === 'element' && DOM_METHODS.has(trailProp)) {
                    var methodArgs = await readCallArgBindings(afterCall + 1, stop);
                    if (methodArgs) {
                      applyElementMethod(factoryResult.bind, trailProp, methodArgs.bindings);
                      i = methodArgs.next - 1;
                      continue;
                    }
                  }
                }
              }
              i = afterCall - 1;
              continue;
            }
          }
        }
      }

      // Navigation sink detection: location.href = expr, location = expr,
      // location.assign(expr), opener.location = expr, etc.
      if (t.type === 'other' && (PATH_RE.test(t.text) || IDENT_RE.test(t.text))) {
        var _navType = isNavSink(t.text, typedScope);
        // Check for navigation property assignment: location.href = expr, location = expr
        if (_navType) {
          var _navEq = tokens[i + 1];
          if (_navEq && _navEq.type === 'sep' && (_navEq.char === '=' || _navEq.char === '+=')) {
            var _navR = await readValue(i + 2, stop, TERMS_TOP);
            var _navVal = _navR ? _navR.binding : null;
            // Record as navigation sink finding.
            if (taintEnabled && _navVal && _navVal.kind === 'chain') {
              var _navTaint = collectChainTaint(_navVal.toks);
              if (_navTaint && _navTaint.size) {
                recordTaintFinding('navigation', 'high', t.text, null, _navTaint, taintCondStack,
                  { expr: t.text, line: countLines(t._src, t.start) });
              }
            }
            i = skipExpr(i + 2, stop) - 1;
            continue;
          }
          // Check for navigation method call: location.assign(expr), location.replace(expr)
          var _navParen = tokens[i + 1];
          if (_navParen && _navParen.type === 'open' && _navParen.char === '(') {
            var _navCallArgs = await readCallArgBindings(i + 1, stop);
            if (_navCallArgs && taintEnabled) {
              checkSinkCall(t.text, _navCallArgs.bindings, t);
            }
            if (_navCallArgs) { i = _navCallArgs.next - 1; continue; }
          }
        }
        // Check: frame.contentWindow.location[.href] = expr
        // or opener.location[.href] = expr (handled by navType above for globals).
        // For element-based: el.contentWindow.location.href = expr
        if (t.text.endsWith('.contentWindow.location') || t.text.endsWith('.contentWindow.location.href')) {
          var _cwParts = t.text.split('.');
          var _cwBase = _cwParts[0];
          var _cwBind = resolve(_cwBase);
          if (_cwBind && _cwBind.kind === 'element') {
            var _cwTag = getElementTag(_cwBind);
            if (_cwTag === 'iframe' || _cwTag === 'frame') {
              var _cwEq = tokens[i + 1];
              if (_cwEq && _cwEq.type === 'sep' && _cwEq.char === '=') {
                var _cwR = await readValue(i + 2, stop, TERMS_TOP);
                var _cwVal = _cwR ? _cwR.binding : null;
                if (taintEnabled && _cwVal && _cwVal.kind === 'chain') {
                  var _cwTaint = collectChainTaint(_cwVal.toks);
                  if (_cwTaint && _cwTaint.size) {
                    recordTaintFinding('navigation', 'high', t.text, _cwTag, _cwTaint, taintCondStack,
                      { expr: t.text, line: countLines(t._src, t.start) });
                  }
                }
                i = skipExpr(i + 2, stop) - 1;
                continue;
              }
            }
          }
        }
      }

      // Path assignment on a tracked DOM element: `el.prop = value`,
      // `el.style.color = value`, etc. Records the mutation on the
      // element binding so subsequent DOM serialization sees it.
      if (t.type === 'other' && PATH_RE.test(t.text)) {
        const eqTok = tokens[i + 1];
        // Path post-increment/decrement: obj.prop++ / obj.prop--
        if (eqTok && eqTok.type === 'op' && (eqTok.text === '++' || eqTok.text === '--')) {
          const parts = t.text.split('.');
          const baseBind = resolve(parts[0]);
          if (baseBind && baseBind.kind === 'object' && parts.length === 2) {
            var cur = baseBind.props[parts[1]];
            var n = cur && cur.kind === 'chain' ? chainAsNumber(cur) : null;
            var delta = eqTok.text === '++' ? 1 : -1;
            if (inEventHandler) {
              // Inside event handler: result depends on invocation count
              // (attacker-controlled). Tag as event-derived taint.
              var _ehRef = exprRef(t.text);
              _ehRef.taint = new Set(['event']);
              baseBind.props[parts[1]] = chainBinding([_ehRef]);
            } else {
              baseBind.props[parts[1]] = n !== null
                ? chainBinding([makeSynthStr(String(n + delta))])
                : chainBinding([deriveExprRef(t.text, cur ? cur.toks : null)]);
            }
            _trackMayBeAssign(t.text, baseBind.props[parts[1]]);
          }
          i = i + 1;
          continue;
        }
        // Path compound assignment: obj.prop += value
        if (eqTok && eqTok.type === 'sep' && (eqTok.char === '=' || eqTok.char === '+=')) {
          const parts = t.text.split('.');
          const baseBind = resolve(parts[0]);
          // Object property assignment: obj.prop = value, or
          // multi-segment obj.a.b.c = value. Walk through the
          // intermediate segments to find the deepest object,
          // then set the final segment.
          if (baseBind && baseBind.kind === 'object' && parts.length >= 2) {
            // Walk to the leaf container.
            var _container = baseBind;
            var _walkOk = true;
            for (var _pi = 1; _pi < parts.length - 1; _pi++) {
              var _next = _container.props[parts[_pi]];
              if (!_next || _next.kind !== 'object') { _walkOk = false; break; }
              _container = _next;
            }
            if (_walkOk) {
              const r = await readValue(i + 2, stop, TERMS_TOP);
              if (r && r.binding) {
                var _leaf = parts[parts.length - 1];
                if (eqTok.char === '+=') {
                  var prev = _container.props[_leaf];
                  if (prev && prev.kind === 'chain' && r.binding.kind === 'chain') {
                    _container.props[_leaf] = chainBinding([...prev.toks, SYNTH_PLUS, ...r.binding.toks]);
                  } else {
                    _container.props[_leaf] = r.binding;
                  }
                } else {
                  _container.props[_leaf] = r.binding;
                }
                // May-be lattice: track the full path so smtSat can emit
                // a (or (= |obj.prop| v1) (= |obj.prop| v2) ...) disjunction.
                // _mayBeKey will canonicalise via __objId so any alias of
                // the leaf container hits the same slot.
                _trackMayBeAssign(t.text, _container.props[_leaf]);
              }
              i = skipExpr(i + 2, stop) - 1;
              continue;
            }
          }
          if (baseBind && baseBind.kind === 'element') {
            const r = await readValue(i + 2, stop, TERMS_TOP);
            const val = r ? r.binding : null;
            applyElementSet(baseBind, parts.slice(1), val, t);
            i = skipExpr(i + 2, stop) - 1;
            continue;
          }
          // Taint: check for sink property assignments on non-tracked elements.
          if (taintEnabled && parts.length >= 2) {
            const sinkProp = parts[parts.length - 1];
            if (_propIsEverASink(DEFAULT_TYPE_DB, sinkProp)) {
              const r = await readValue(i + 2, stop, TERMS_TOP);
              const val = r ? r.binding : null;
              if (val && val.kind === 'chain') {
                var _taint = collectChainTaint(val.toks);
                if (_taint && _taint.size) {
                  // Type-first classification: if the base
                  // binding carries a typeName, look up sink
                  // on THAT type. Falls back to tag-based
                  // (for element bindings) or null.
                  var _elTag = baseBind ? getElementTag(baseBind) : null;
                  var _sinkInfo = _classifyBindingSink(baseBind, sinkProp);
                  if (_sinkInfo && _sinkInfo.severity !== 'safe') {
                    recordTaintFinding(_sinkInfo.type, _sinkInfo.severity, sinkProp, _elTag, _taint, taintCondStack,
                      { expr: t.text, line: countLines(t._src, t.start) });
                  }
                }
              }
              i = skipExpr(i + 2, stop) - 1;
              continue;
            }
          }
        }
        // Path method call: `el.appendChild(child)`, `el.setAttribute(...)`.
        const parenTok = tokens[i + 1];
        if (parenTok && parenTok.type === 'open' && parenTok.char === '(') {
          const dot = t.text.lastIndexOf('.');
          if (dot > 0) {
            const base = t.text.slice(0, dot);
            const method = t.text.slice(dot + 1);
            const baseBind = resolve(base);
            if (baseBind && baseBind.kind === 'element' && DOM_METHODS.has(method)) {
              const argResult = await readCallArgBindings(i + 1, stop);
              if (argResult) {
                applyElementMethod(baseBind, method, argResult.bindings);
                i = argResult.next - 1;
                continue;
              }
            }
            // Map / Set / WeakMap / WeakSet statements: `.set(k, v)`,
            // `.add(v)`, `.delete(k)`, `.clear()` mutate the receiver
            // in place. Route through applyMethod which handles the
            // mapLike dispatch (see the Map/Set block at the top of
            // applyMethod for semantics).
            if (baseBind && baseBind.kind === 'object' && baseBind._mapLike &&
                (method === 'set' || method === 'add' || method === 'delete' || method === 'clear' || method === 'has' || method === 'get')) {
              var _mapStmtResult = await applyMethod(baseBind, method, i + 1, stop);
              if (_mapStmtResult) {
                i = _mapStmtResult.next - 1;
                continue;
              }
            }
            // Array methods as statements: forEach, push, unshift.
            if (baseBind && baseBind.kind === 'array' && (method === 'forEach' || method === 'map' || method === 'filter')) {
              // Use applyMethod to handle the call — it walks forEach callbacks.
              var arrMethodResult = await applyMethod(baseBind, method, i + 1, stop);
              if (arrMethodResult) {
                i = arrMethodResult.next - 1;
                continue;
              }
            }
            if (baseBind && baseBind.kind === 'array' && (method === 'push' || method === 'unshift')) {
              var arrArgs = await readCallArgBindings(i + 1, stop);
              if (arrArgs) {
                for (var _ai = 0; _ai < arrArgs.bindings.length; _ai++) {
                  if (arrArgs.bindings[_ai]) {
                    if (method === 'push') baseBind.elems.push(arrArgs.bindings[_ai]);
                    else baseBind.elems.unshift(arrArgs.bindings[_ai]);
                  }
                }
                i = arrArgs.next - 1;
                continue;
              }
            }
            // Taint: detect addEventListener on ANY object (window, document, element).
            // readCallArgBindings now handles function expressions and arrows
            // via readValue → readFunctionExpr, so no special parser needed.
            if (taintEnabled && method === 'addEventListener') {
              var _evArgs = await readCallArgBindings(i + 1, stop);
              if (_evArgs && _evArgs.bindings.length >= 2) {
                var _evTypeStr = _evArgs.bindings[0] && _evArgs.bindings[0].kind === 'chain' ? chainAsKnownString(_evArgs.bindings[0]) : null;
                var _evHandler = _evArgs.bindings[1];
                if (_evHandler && _evHandler.kind === 'function') {
                  // Build the event-param binding. When the
                  // event name resolves to a known Event
                  // subtype via db.eventMap, tag the param's
                  // binding with that typeName. Inside the
                  // handler body, property reads on the param
                  // walk through the TypeDB and pick up the
                  // specific `source` label on each descriptor,
                  // yielding precise per-prop taint (no bulk
                  // label union).
                  var _evParamBindings = [];
                  var _evTypeName = _evTypeStr ? DEFAULT_TYPE_DB.eventMap[_evTypeStr] : null;
                  if (_evHandler.params && _evHandler.params.length > 0) {
                    var _pn = _evHandler.params[0].name;
                    var _evRef = exprRef(_pn);
                    var _evParamBinding = chainBinding([_evRef]);
                    if (_evTypeName) _evParamBinding.typeName = _evTypeName;
                    _evParamBindings.push(_evParamBinding);
                  }
                  // Walk the handler body once. Convergence (re-walking
                  // until state stabilises) is handled at the OUTER
                  // level, in buildScopeState's whole-program callback
                  // fixpoint loop, so that every callback sees the
                  // effects of every other callback.
                  var _prevInEH = inEventHandler;
                  inEventHandler = true;
                  await instantiateFunction(_evHandler, _evParamBindings);
                  inEventHandler = _prevInEH;
                  // Register for the phase-2 fixpoint re-walk.
                  if (_pendingCallbacks) {
                    _pendingCallbacks.push({ fn: _evHandler, params: _evParamBindings, isEventHandler: true });
                  }
                }
                i = _evArgs.next - 1;
                continue;
              }
            }
            // Taint: detect call-based sinks (eval, document.write, etc.).
            if (taintEnabled && _classifyCallSinkViaDB(DEFAULT_TYPE_DB, t.text, typedScope)) {
              const argResult = await readCallArgBindings(i + 1, stop);
              if (argResult) {
                checkSinkCall(t.text, argResult.bindings, t);
                i = argResult.next - 1;
                continue;
              }
            }
          }
        }
      }

      // Bracket-access statement: `ident[expr]...` — assignments
      // (`items[i] = ...`, `items[i].prop = ...`) or method calls
      // (`items[i].sort()`). Walk through the bracket and any trailing
      // property/call chain to find the statement boundary, then preserve
      // the full statement if it has side effects.
      if (t.type === 'other' && IDENT_RE.test(t.text)) {
        const bracketTok = tokens[i + 1];
        if (bracketTok && bracketTok.type === 'open' && bracketTok.char === '[') {
          // Walk past balanced [...] and any following .prop, [...], or (...)
          let j = i + 1;
          while (j < _rangeEnd) {
            const jt = tokens[j];
            if (jt.type === 'open' && (jt.char === '[' || jt.char === '(')) {
              const match = jt.char === '[' ? ']' : ')';
              let d = 1; j++;
              while (j < _rangeEnd && d > 0) {
                if (tokens[j].type === 'open' && tokens[j].char === jt.char) d++;
                else if (tokens[j].type === 'close' && tokens[j].char === match) d--;
                j++;
              }
            } else if (jt.type === 'other' && jt.text.startsWith('.')) {
              j++;
            } else {
              break;
            }
          }
          // Check what follows: = (assignment), += etc., or ; (expression stmt).
          const afterTok = tokens[j];
          if (afterTok && afterTok.type === 'sep' &&
              (afterTok.char === '=' || afterTok.char === '+=' || afterTok.char === '-=' ||
               afterTok.char === '*=' || afterTok.char === '/=')) {
            // Bracket-access assignment: items[i].seen = true
            // Update object/array bindings when the key is known.
            var _baseBind = resolve(t.text);
            if (_baseBind && afterTok.char === '=') {
              // Find the key: tokens between [ and ] in the first bracket.
              var _keyStart = i + 2, _keyEnd = i + 2;
              var _kd = 1;
              for (var _ki = i + 2; _ki < j && _kd > 0; _ki++) {
                if (tokens[_ki].type === 'open' && tokens[_ki].char === '[') _kd++;
                if (tokens[_ki].type === 'close' && tokens[_ki].char === ']') { _kd--; if (_kd === 0) { _keyEnd = _ki; break; } }
              }
              if (_keyEnd > _keyStart) {
                var _keyVal = await readValue(_keyStart, _keyEnd, null);
                var _keyStr = _keyVal ? chainAsKnownString(_keyVal.binding) : null;
                if (_keyStr !== null) {
                  var _rhsVal = await readValue(j + 1, stop, TERMS_TOP);
                  if (_rhsVal && _rhsVal.binding) {
                    if (_baseBind.kind === 'object') _baseBind.props[_keyStr] = _rhsVal.binding;
                    if (_baseBind.kind === 'array' && /^\d+$/.test(_keyStr)) _baseBind.elems[parseInt(_keyStr, 10)] = _rhsVal.binding;
                  }
                }
              }
            }
            const stmtEndIdx = skipExpr(j + 1, _rangeEnd);
            // Preserve the statement in build var chains.
            if (trackBuildVar && (trackBuildVarDepth < 0 || funcDepth() === trackBuildVarDepth)) {
              const first = tokens[i];
              const last = tokens[stmtEndIdx - 1];
              if (first && last && first._src) {
                const stmtSrc = first._src.slice(first.start, last.end);
                for (const bv of trackBuildVar) {
                  const bCur = resolve(bv);
                  if (bCur && bCur.kind === 'chain') {
                    const loopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
                    const preserveTok = { type: 'preserve', text: stmtSrc };
                    if (loopId !== null) preserveTok.loopId = loopId;
                    assignName(bv, chainBinding([...bCur.toks, SYNTH_PLUS, preserveTok]));
                  }
                }
              }
            }
            i = stmtEndIdx - 1;
            continue;
          }
          // Indirect dispatcher call: `dispatch[expr]()` or `dispatch[expr](args)`.
          // The bracket key is opaque (e.g. e.data) so we can't pick a
          // single property — instead, walk EVERY function-typed
          // property of the dispatcher object so any callback that
          // could fire at runtime sees its body analysed.
          if (taintEnabled) {
            // Detect: ident [ ... ] ( ... )  with no further suffixes.
            // j currently points at the first non-bracket-non-dot token
            // after the chain we already walked. Look back to see if
            // the chain ended with a `(`...`)` group right after a `]`.
            var _dpBase = resolve(t.text);
            if (_dpBase && _dpBase.kind === 'object') {
              // Find the last `[` … `]` and the `(` that follows it.
              var _bkOpen = i + 1;
              var _bkClose = -1;
              var _bkD = 1, _bkK = i + 2;
              while (_bkK < _rangeEnd && _bkD > 0) {
                if (tokens[_bkK].type === 'open' && tokens[_bkK].char === '[') _bkD++;
                if (tokens[_bkK].type === 'close' && tokens[_bkK].char === ']') { _bkD--; if (_bkD === 0) { _bkClose = _bkK; break; } }
                _bkK++;
              }
              if (_bkClose > 0) {
                var _argOpen = _bkClose + 1;
                if (tokens[_argOpen] && tokens[_argOpen].type === 'open' && tokens[_argOpen].char === '(') {
                  // The bracket key isn't a known string → walk every
                  // function property. Otherwise the existing handlers
                  // resolve the specific target.
                  var _bkVal = await readValue(_bkOpen + 1, _bkClose, null);
                  var _bkStr = _bkVal && _bkVal.binding ? chainAsKnownString(_bkVal.binding) : null;
                  if (_bkStr === null) {
                    var _dispatchArgs = await readCallArgBindings(_argOpen, stop);
                    if (_dispatchArgs) {
                      for (var _dpName in _dpBase.props) {
                        var _dpProp = _dpBase.props[_dpName];
                        if (_dpProp && _dpProp.kind === 'function') {
                          await instantiateFunction(_dpProp, _dispatchArgs.bindings);
                          if (_pendingCallbacks) {
                            _pendingCallbacks.push({ fn: _dpProp, params: _dispatchArgs.bindings, isEventHandler: false });
                          }
                        }
                      }
                      i = _dispatchArgs.next - 1;
                      continue;
                    }
                  } else {
                    // Known-key bracket call: dispatch["arm"]()
                    var _knownProp = _dpBase.props[_bkStr];
                    if (_knownProp && _knownProp.kind === 'function') {
                      var _knArgs = await readCallArgBindings(_argOpen, stop);
                      if (_knArgs) {
                        await instantiateFunction(_knownProp, _knArgs.bindings);
                        if (_pendingCallbacks) {
                          _pendingCallbacks.push({ fn: _knownProp, params: _knArgs.bindings, isEventHandler: false });
                        }
                        i = _knArgs.next - 1;
                        continue;
                      }
                    }
                  }
                }
              }
            }
          }
          // Bracket-access followed by ; or end — expression statement
          // (e.g. items[i].doSomething()). Skip to statement boundary.
          let stmtEnd = j;
          let sd = 0;
          while (stmtEnd < _rangeEnd) {
            const st = tokens[stmtEnd];
            if (st.type === 'open') sd++;
            else if (st.type === 'close') sd--;
            else if (sd === 0 && st.type === 'sep' && (st.char === ';' || st.char === ',')) { stmtEnd++; break; }
            stmtEnd++;
          }
          if (trackBuildVar && (trackBuildVarDepth < 0 || funcDepth() === trackBuildVarDepth) && stmtEnd > i + 1) {
            const first = tokens[i];
            const last = tokens[stmtEnd - 1];
            if (first && last && first._src) {
              const stmtSrc = first._src.slice(first.start, last.end);
              for (const bv of trackBuildVar) {
                const bCur = resolve(bv);
                if (bCur && bCur.kind === 'chain') {
                  const loopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
                  const preserveTok = { type: 'preserve', text: stmtSrc };
                  if (loopId !== null) preserveTok.loopId = loopId;
                  assignName(bv, chainBinding([...bCur.toks, SYNTH_PLUS, preserveTok]));
                }
              }
            }
          }
          i = stmtEnd - 1;
          continue;
        }
      }
    }
    } // end while (_ws)
    // Invariant: after the work stack drains, any nested push onto the
    // path-constraint or taint-condition stacks must have been matched
    // by a corresponding pop. If we ever observe imbalance at top level
    // it indicates a broken transition; reset to the base depth so the
    // next walkRange call starts from a clean configuration.
    if (pathConstraints && pathConstraints.length > _pcBaseDepth) {
      pathConstraints.length = _pcBaseDepth;
    }
    if (taintCondStack && taintCondStack.length > _tcBaseDepth) {
      taintCondStack.length = _tcBaseDepth;
    }
    };
    // ----------------------------------------------------------------
    // Top-level walk + whole-program callback fixpoint (taint mode)
    // ----------------------------------------------------------------
    // The walker uses a two-phase strategy when taint-enabled:
    //
    //   Phase 1 — top-level walk. walkRange runs once over the program
    //     in source order. var/let/const declarations execute, function
    //     bodies are inlined at call sites, addEventListener registers
    //     and walks the handler body once. Phase 1 produces an initial
    //     binding state and an initial set of findings.
    //
    //   Phase 2 — callback fixpoint. Every callback registered during
    //     phase 1 (event handlers, setTimeout/setInterval, .then/.catch,
    //     etc.) gets a re-walk request added to _pendingCallbacks. After
    //     phase 1 returns, the analyser repeatedly re-walks every
    //     pending callback in turn, observing the bindings + findings
    //     produced by every other callback. This continues until the
    //     program's observable state stops changing.
    //
    // Why the split? Re-running phase 1 would re-execute var
    // declarations (`var state = "idle"`) and undo any mutations
    // earlier callbacks made — the fixpoint would never advance. By
    // freezing top-level state after phase 1 and only iterating the
    // callback set, mutations from one callback persist into the next
    // iteration of every other callback. This is what lets a finding
    // gated on `state === "ready"` (set in callback A) fire from
    // callback B even when neither callback alone reaches it.
    //
    // Findings are de-duplicated by source location so a callback
    // emitting the same finding twice doesn't break convergence.

    const _findingKey = function (f) {
      return (f.type || '') + '|' + (f.sink ? (f.sink.prop || '') + ':' + (f.sink.elementTag || '') : '') +
             '|' + (f.location ? (f.location.line || 0) + ':' + (f.location.pos || 0) + ':' + (f.location.expr || '') : '') +
             '|' + (f.sources ? f.sources.slice().sort().join(',') : '');
    };
    const _dedupeFindings = function () {
      if (!taintFindings) return;
      var seen = Object.create(null);
      var kept = [];
      for (var _fi = 0; _fi < taintFindings.length; _fi++) {
        var k = _findingKey(taintFindings[_fi]);
        if (seen[k]) continue;
        seen[k] = true;
        kept.push(taintFindings[_fi]);
      }
      taintFindings.length = 0;
      for (var _kj = 0; _kj < kept.length; _kj++) taintFindings.push(kept[_kj]);
    };

    // Activate the per-walk may-be lattice. smtSat reads
    // _currentVarMayBe at SAT-check time so the same _varMayBe map
    // we populate during walks is what feeds the disjunction extras.
    // _currentMayBeKey lets the IIFE-level smtSat / smtParseAtom
    // resolve textual paths to identity-keyed canonical form
    // (alias-aware lookups).
    var _savedCurrentVarMayBe = _currentVarMayBe;
    var _savedCurrentMayBeKey = _currentMayBeKey;
    if (taintEnabled) {
      _currentVarMayBe = _varMayBe;
      _currentMayBeKey = _mayBeKey;
    }
    try {

    // Phase 1: single forward walk.
    await walkRange(0, stop);
    // Dedupe after phase 1 so duplicate findings emitted from the
    // same source location (e.g. a class-method body walked both at
    // class-definition time and at `new C().go()` call-site time)
    // collapse before either the user sees them or the phase-2
    // convergence signature is computed.
    if (taintEnabled) _dedupeFindings();

    // Phase 2: callback fixpoint. Iterate all callbacks registered
    // during phase 1 until findings + bindings + may-be lattices
    // stabilise. The may-be lattice is monotone (values only join
    // in, never leave) so adding it to the convergence signature
    // doesn't break termination.
    if (taintEnabled && _pendingCallbacks && _pendingCallbacks.length > 0) {
      // Fixpoint convergence signature — monotone components only.
      //
      // The signature captures only lattice state that we can prove
      // is monotone (never shrinks across iterations):
      //
      //   - `_varMayBe` — the may-be lattice. Each slot either adds
      //     new values, upgrades to a bounded function set, or
      //     collapses to "incomplete" (complete=false). None of
      //     those transitions are reversible.
      //   - `taintFindings` — deduped across the iteration, so a
      //     finding emitted once stays in the set forever.
      //
      // Crucially we do NOT snapshot the raw binding chain tokens
      // in the convergence key. The walker's cond-merge logic wraps
      // a variable's prior value inside a fresh `cond` node on each
      // iteration (`cond(P, new, cond(P, new, old))`), so stringified
      // bindings grow exponentially and the signature would never
      // repeat — the fixpoint would then run until JSON.stringify
      // blew the native call stack. Restricting the signature to
      // (may-be, findings) makes the convergence condition equivalent
      // to "no callback can see any new information", which is the
      // only outcome that can make a further iteration do new work.
      // Termination is guaranteed because both components live in
      // finite lattices (the may-be lattice is bounded by the set of
      // distinct literals observed in the program, and findings are
      // bounded by the set of distinct source locations).
      const _snapshotMayBe = function () {
        var keys = Object.keys(_varMayBe).sort();
        var out = '';
        for (var _mki = 0; _mki < keys.length; _mki++) {
          var slot = _varMayBe[keys[_mki]];
          out += keys[_mki] + '=' + (slot.complete ? '*' : '#');
          if (slot.complete && slot.vals) {
            for (var _mvi = 0; _mvi < slot.vals.length; _mvi++) {
              out += '|' + slot.vals[_mvi].sort + ':' + slot.vals[_mvi].lit;
            }
          }
          if (slot.fns) out += '|fns=' + slot.fns.length;
          out += ';';
        }
        return out;
      };
      var _prevSig = '';
      while (true) {
        for (var _cbi = 0; _cbi < _pendingCallbacks.length; _cbi++) {
          var _cb = _pendingCallbacks[_cbi];
          var _prevInEH = inEventHandler;
          if (_cb.isEventHandler) inEventHandler = true;
          try { await instantiateFunction(_cb.fn, _cb.params); }
          finally { inEventHandler = _prevInEH; }
        }
        _dedupeFindings();
        var _sig = 'MB:' + _snapshotMayBe() + '||' +
                   (taintFindings ? taintFindings.length + ':' + taintFindings.map(_findingKey).sort().join('|') : '');
        if (_sig === _prevSig) break;
        _prevSig = _sig;
      }
    }

    } finally {
      _currentVarMayBe = _savedCurrentVarMayBe;
      _currentMayBeKey = _savedCurrentMayBeKey;
    }

    // Advance the scope walker to a new stop position, processing all
    // tokens between the current stop and the new one. This allows
    // the caller to incrementally build scope state for each statement
    // in a build region.
    const advanceTo = async (newStop) => {
      const ns = Math.min(newStop, tokens.length);
      if (ns > stop) { await walkRange(stop, ns); stop = ns; }
    };

    // Parse tokens[start, end) as a concat chain, expanding identifier
    // references, member paths, `[...].join(sep)`, and `.concat(...)` calls.
    // Returns the flat chain tokens (alternating operand / plus) or null.
    const parseRange = async (start, end) => {
      const r = await readConcatExpr(start, end, TERMS_NONE);
      if (!r || r.next !== end) return null;
      return r.toks;
    };

    const inScope = (name) => {
      for (let i = stack.length - 1; i >= 0; i--) if (name in stack[i].bindings) return true;
      return false;
    };
    const setTrackBuildVar = (name) => { trackBuildVar = name ? new Set(Array.isArray(name) ? name : [name]) : null; };
    const getBuildVarDeclStart = () => buildVarDeclStart;
    return { resolve, resolvePath, parseRange, rewriteTemplate, advanceTo, setTrackBuildVar, getBuildVarDeclStart, loopInfo, loopVars, inScope, declaredNames, domElements, domOps, taintFindings, resolveForTaint: resolve };
  }

  function hasBinding(stack, name) {
    for (let i = stack.length - 1; i >= 0; i--) if (name in stack[i].bindings) return true;
    return false;
  }

  // Expand tokens[startIdx, endIdx) using the scope state at startIdx.
  // First tries to parse the range as a full concat chain (expanding member
  // paths, `.join(sep)`, `.concat(...)`, and template interpolation); if that
  // fails, falls back to per-identifier substitution so downstream chain
  // detection can still find partial matches.
  async function resolveIdentifiers(tokens, startIdx, endIdx, buildVarOrVars) {
    const externallyMutable = scanMutations(tokens);
    const state = await buildScopeState(tokens, startIdx, externallyMutable, buildVarOrVars);
    const full = await state.parseRange(startIdx, endIdx);
    if (full) return { tokens: full, parsed: true, loopInfo: state.loopInfo, loopVars: state.loopVars, buildVarDeclStart: state.getBuildVarDeclStart(), inScope: state.inScope, resolve: state.resolve };
    const out = [];
    for (let i = startIdx; i < endIdx; i++) {
      const t = tokens[i];
      if (t.type === 'tmpl') {
        const rw = await state.rewriteTemplate(t);
        if (rw.type === '_chain') { for (const ct of rw.toks) out.push(ct); }
        else out.push(rw);
        continue;
      }
      if (t.type === 'other' && IDENT_OR_PATH_RE.test(t.text)) {
        const next = tokens[i + 1];
        const isLhs = next && next.type === 'sep' && next.char === '=';
        if (!isLhs) {
          const b = await state.resolvePath(t.text);
          if (b && b.kind === 'chain') { for (const vt of b.toks) out.push(vt); continue; }
        }
      }
      out.push(t);
    }
    return { tokens: out, parsed: false, loopInfo: state.loopInfo, loopVars: state.loopVars, inScope: state.inScope, resolve: state.resolve };
  }



  // --- Tokenizer ---
  function tokenize(src) {
    const tokens = [];
    let i = 0;
    const n = src.length;
    function push(tok) { tok._src = src; tokens.push(tok); }
    // ASI: track whether a newline was crossed in whitespace. When the
    // previous token could end a statement and the next token could start
    // one, insert a synthetic semicolon.
    let sawNewline = false;
    const canEndStmt = () => {
      if (!tokens.length) return false;
      const last = tokens[tokens.length - 1];
      if (last.type === 'str' || last.type === 'tmpl') return true;
      if (last.type === 'other') return true; // identifiers, numbers, keywords like return/break/continue
      if (last.type === 'close') return true; // ) ] }
      if (last.type === 'op' && (last.text === '++' || last.text === '--')) return true;
      return false;
    };
    const canStartStmt = (ch) => {
      // Tokens that can start a new statement.
      return /[A-Za-z_$'"`({[]/.test(ch) || ch === '!' || ch === '~' || ch === '+' || ch === '-';
    };
    while (i < n) {
      const c = src[i];
      if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }
      if (c === '\n') { sawNewline = true; i++; continue; }
      if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; sawNewline = true; continue; }
      if (c === '/' && src[i + 1] === '*') { i += 2; while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] === '\n') sawNewline = true; i++; } i += 2; continue; }
      // ASI: insert synthetic semicolon if newline crossed between
      // a statement-ending token and a statement-starting token.
      if (sawNewline && canEndStmt() && canStartStmt(c)) {
        push({ type: 'sep', char: ';', start: i, end: i });
      }
      sawNewline = false;
      if (c === "'" || c === '"') {
        const start = i; const quote = c; i++;
        let raw = '';
        while (i < n && src[i] !== quote) {
          if (src[i] === '\\' && i + 1 < n) { raw += src[i] + src[i + 1]; i += 2; }
          else { raw += src[i]; i++; }
        }
        i++;
        push({ type: 'str', quote, raw, text: decodeJsString(raw, quote), start, end: i });
        continue;
      }
      if (c === '`') {
        const start = i; i++;
        const parts = [];
        let cur = '';
        while (i < n && src[i] !== '`') {
          if (src[i] === '\\' && i + 1 < n) { cur += src[i] + src[i + 1]; i += 2; }
          else if (src[i] === '$' && src[i + 1] === '{') {
            parts.push({ kind: 'text', raw: cur }); cur = '';
            i += 2;
            let depth = 1; const exprStart = i;
            while (i < n && depth > 0) {
              const ch = src[i];
              if (ch === "'" || ch === '"') {
                const q = ch; i++;
                while (i < n && src[i] !== q) { if (src[i] === '\\') i += 2; else i++; }
                i++;
              } else if (ch === '`') {
                // Nested template literal: skip its content properly,
                // handling strings and nested ${...} with brace tracking.
                i++;
                while (i < n && src[i] !== '`') {
                  if (src[i] === '\\' && i + 1 < n) { i += 2; }
                  else if (src[i] === '$' && src[i + 1] === '{') {
                    i += 2; let d = 1;
                    while (i < n && d > 0) {
                      if (src[i] === "'" || src[i] === '"') {
                        const q = src[i]; i++;
                        while (i < n && src[i] !== q) { if (src[i] === '\\') i += 2; else i++; }
                        i++;
                      } else if (src[i] === '`') {
                        // Recurse: skip nested template. Use simple depth
                        // tracking since deeply nested templates are rare.
                        i++; let td = 0;
                        while (i < n && !(src[i] === '`' && td === 0)) {
                          if (src[i] === '\\' && i + 1 < n) i += 2;
                          else if (src[i] === '$' && src[i + 1] === '{') { td++; i += 2; }
                          else if (src[i] === '}' && td > 0) { td--; i++; }
                          else i++;
                        }
                        if (i < n) i++; // past closing `
                      } else {
                        if (src[i] === '{') d++;
                        else if (src[i] === '}') d--;
                        if (d > 0) i++;
                      }
                    }
                  }
                  else i++;
                }
                i++;
              } else if (ch === '{') { depth++; i++; }
              else if (ch === '}') { depth--; if (depth === 0) break; i++; }
              else i++;
            }
            parts.push({ kind: 'expr', expr: src.slice(exprStart, i) });
            i++;
          } else { cur += src[i]; i++; }
        }
        parts.push({ kind: 'text', raw: cur });
        i++;
        push({ type: 'tmpl', parts, start, end: i });
        continue;
      }
      if (c === '+' && src[i + 1] !== '+' && src[i + 1] !== '=') { push({ type: 'plus', start: i, end: i + 1 }); i++; continue; }
      if (c === ',' || c === ';') { push({ type: 'sep', char: c, start: i, end: i + 1 }); i++; continue; }
      if (c === ':') { push({ type: 'other', text: ':', start: i, end: i + 1 }); i++; continue; }
      if (c === '?') {
        // ??= must be checked before ?? to avoid consuming ?? and leaving = separate.
        if (src[i + 1] === '?' && src[i + 2] === '=') { push({ type: 'sep', char: '??=', start: i, end: i + 3 }); i += 3; continue; }
        if (src[i + 1] === '?') { push({ type: 'op', text: '??', start: i, end: i + 2 }); i += 2; continue; }
        if (src[i + 1] === '.' && !/[0-9]/.test(src[i + 2] || '')) {
          push({ type: 'op', text: '?.', start: i, end: i + 2 }); i += 2; continue;
        }
        push({ type: 'other', text: '?', start: i, end: i + 1 }); i++; continue;
      }
      // Assignment operators (including compound) act as chain terminators.
      {
        const assigns = ['**=', '<<=', '>>>=', '>>=', '&&=', '||=', '??=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^='];
        let matched = false;
        for (const op of assigns) {
          if (src.startsWith(op, i)) { push({ type: 'sep', char: op, start: i, end: i + op.length }); i += op.length; matched = true; break; }
        }
        if (matched) continue;
        if (c === '=' && src[i + 1] !== '=' && src[i + 1] !== '>') {
          push({ type: 'sep', char: '=', start: i, end: i + 1 });
          i++;
          continue;
        }
      }
      // Equality operators starting with '='.
      if (c === '=' && src[i + 1] === '=') {
        const len = src[i + 2] === '=' ? 3 : 2;
        push({ type: 'op', text: src.slice(i, i + len), start: i, end: i + len });
        i += len;
        continue;
      }
      if (c === '=' && src[i + 1] === '>') { push({ type: 'other', text: '=>', start: i, end: i + 2 }); i += 2; continue; }
      if (c === '(' || c === '[' || c === '{') { push({ type: 'open', char: c, start: i, end: i + 1 }); i++; continue; }
      if (c === ')' || c === ']' || c === '}') { push({ type: 'close', char: c, start: i, end: i + 1 }); i++; continue; }
      // Multi-char arithmetic/comparison/bitwise/logical operators.
      {
        const multiOps = ['===', '!==', '>>>', '**', '<<', '>>', '<=', '>=', '==', '!=', '&&', '||', '??', '?.', '++', '--'];
        let matched = false;
        for (const op of multiOps) {
          if (src.startsWith(op, i)) { push({ type: 'op', text: op, start: i, end: i + op.length }); i += op.length; matched = true; break; }
        }
        if (matched) continue;
      }
      // Single-char operators.
      if ('-*%<>|&^!~'.indexOf(c) !== -1) { push({ type: 'op', text: c, start: i, end: i + 1 }); i++; continue; }
      if (c === '/' && src[i + 1] !== '/' && src[i + 1] !== '*') {
        // Distinguish regex literals from division by looking at the
        // previous token: regex follows things that can only precede an
        // expression start (open, sep, plus, op, or specific keywords).
        const lastTok = tokens[tokens.length - 1];
        const REGEX_CONTEXT_KEYWORDS = /^(return|typeof|void|delete|in|of|new|throw|await|yield|instanceof|case)$/;
        const canBeRegex = !lastTok ||
          lastTok.type === 'sep' || lastTok.type === 'open' ||
          lastTok.type === 'plus' || lastTok.type === 'op' ||
          (lastTok.type === 'other' && REGEX_CONTEXT_KEYWORDS.test(lastTok.text));
        if (canBeRegex) {
          const start = i;
          let j = i + 1;
          let inClass = false;
          while (j < n) {
            const ch = src[j];
            if (ch === '\n') { j = -1; break; }
            if (ch === '\\' && j + 1 < n) { j += 2; continue; }
            if (ch === '[') { inClass = true; j++; continue; }
            if (ch === ']') { inClass = false; j++; continue; }
            if (ch === '/' && !inClass) break;
            j++;
          }
          if (j > 0 && src[j] === '/') {
            j++;
            while (j < n && /[gimsuy]/.test(src[j])) j++;
            push({ type: 'regex', text: src.slice(start, j), start, end: j });
            i = j; continue;
          }
        }
        push({ type: 'op', text: '/', start: i, end: i + 1 }); i++; continue;
      }
      // Identifier/number/punctuation run — consumed until we hit a special char.
      const start = i;
      while (i < n) {
        const ch = src[i];
        if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') break;
        if (ch === "'" || ch === '"' || ch === '`') break;
        if (ch === '+') break;
        if (ch === ',' || ch === ';') break;
        if (ch === '=') break;
        if (ch === ':') break;
        if (ch === '?') break;
        if ('-*/%<>|&^!~'.indexOf(ch) !== -1) break;
        if (ch === '(' || ch === ')' || ch === '[' || ch === ']' || ch === '{' || ch === '}') break;
        i++;
      }
      if (i > start) push({ type: 'other', text: src.slice(start, i), start, end: i });
      else i++;
    }
    return tokens;
  }

  function decodeJsString(raw, quote) {
    // Decode common JS escapes. Template-literal ${...} passthrough.
    return raw.replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|[\s\S])/g, (_, esc) => {
      if (esc[0] === 'u') {
        if (esc[1] === '{') return String.fromCodePoint(parseInt(esc.slice(2, -1), 16));
        return String.fromCharCode(parseInt(esc.slice(1), 16));
      }
      if (esc[0] === 'x') return String.fromCharCode(parseInt(esc.slice(1), 16));
      if (/^[0-7]/.test(esc) && esc.length > 0 && esc !== '0') {
        return String.fromCharCode(parseInt(esc, 8));
      }
      const map = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', '0': '\0', "'": "'", '"': '"', '`': '`', '\\': '\\', '\n': '' };
      return map[esc] != null ? map[esc] : esc;
    });
  }

  function jsStr(s) {
    const esc = s
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t')
      .replace(/\u2028/g, '\\u2028')
      .replace(/\u2029/g, '\\u2029');
    return { code: "'" + esc + "'" };
  }

  // Make a safe, unique JS identifier from a tag name.
  function makeVar(tag, used) {
    let base = tag.toLowerCase().replace(/[^a-z0-9_$]/g, '') || 'el';
    if (/^[0-9]/.test(base)) base = 'el' + base;
    // Avoid JS reserved words by suffixing.
    const reserved = new Set(['class', 'const', 'let', 'var', 'for', 'if', 'do', 'in', 'of', 'new', 'return', 'this', 'void', 'with', 'yield', 'async', 'await', 'break', 'case', 'catch', 'default', 'delete', 'else', 'enum', 'export', 'extends', 'false', 'finally', 'function', 'import', 'instanceof', 'null', 'static', 'super', 'switch', 'throw', 'true', 'try', 'typeof', 'while']);
    if (reserved.has(base)) base = base + '_';
    let name = base;
    let n = 1;
    while (used.has(name)) { n++; name = base + n; }
    used.add(name);
    return name;
  }

  function isIdlProp(attrName) {
    if (FORCE_ATTR.has(attrName)) return null;
    if (ATTR_TO_PROP[attrName]) return ATTR_TO_PROP[attrName];
    if (IDL_PROPS.has(attrName)) return attrName;
    if (attrName.startsWith('data-') || attrName.startsWith('aria-')) return null;
    // Event-handler attributes (onclick, onload, ...) can't be
    // set as IDL string props — `el.onclick = "..."` doesn't
    // execute. Resolved via the TypeDB's attrSinks map which
    // names every attr whose value is a code sink, so this
    // check stays in sync with sink classification.
    var _attrSinkKind = DEFAULT_TYPE_DB.attrSinks && DEFAULT_TYPE_DB.attrSinks[attrName.toLowerCase()];
    if (_attrSinkKind === 'code') return null;
    if (attrName.includes(':') || attrName.includes('-')) return null;
    return null;
  }

  // Convert a style="..." attribute value into an array of style.* assignments.
  // Parse CSS declarations from a style attribute value.
  // Handles quoted strings, parens (url(), calc()), and !important.
  // Returns array of { prop, value, important }.
  function parseStyleDecls(styleVal) {
    // Split on ; respecting parens and quoted strings.
    const parts = [];
    let depth = 0, cur = '', quote = '';
    for (let i = 0; i < styleVal.length; i++) {
      const c = styleVal[i];
      if (quote) {
        cur += c;
        if (c === '\\' && i + 1 < styleVal.length) {
          i++;
          cur += styleVal[i];
        } else if (c === quote) {
          quote = '';
        }
        continue;
      }
      if (c === '"' || c === "'") {
        quote = c;
        cur += c;
        continue;
      }
      if (c === '(') depth++;
      else if (c === ')' && depth > 0) depth--;
      if (c === ';' && depth === 0) {
        if (cur.trim()) parts.push(cur.trim());
        cur = '';
      } else {
        cur += c;
      }
    }
    if (cur.trim()) parts.push(cur.trim());

    const result = [];
    for (const d of parts) {
      const colon = d.indexOf(':');
      if (colon < 0) continue;
      const prop = d.slice(0, colon).trim().toLowerCase();
      let val = d.slice(colon + 1).trim();
      let important = false;
      const impIdx = val.toLowerCase().lastIndexOf('!important');
      if (impIdx >= 0 && impIdx === val.length - '!important'.length) {
        val = val.slice(0, impIdx).trim();
        important = true;
      }
      result.push({ prop: prop, value: val, important: important });
    }
    return result;
  }


  // Pre-pass: find functions that build and return HTML via a build
  // variable (var html = ''; html += ...; return html;). Convert each
  // independently to return a DocumentFragment with DOM operations.
  // This avoids multi-level inlining which flattens scopes.
  // Uses the JS tokenizer for proper function detection and brace
  // matching (handles strings, comments, regex containing braces).
  // convertHtmlBuilderFunctions: moved to htmldom-convert.js

  // Core conversion: takes a raw input string, returns the converted output.
  // sourceName: optional filename for naming output files (e.g. 'index.html').
  // convertRaw: moved to htmldom-convert.js

  // UI wrapper: reads from editor, converts, writes to output.
  // convert: UI glue moved to monaco-init.js

  let lastOutput = '';
  // setOutput: UI glue moved to monaco-init.js

  // Summarize the DOM tree the script constructs via createElement /
  // appendChild / setAttribute as HTML comments. The script's own code
  // is already safe (no innerHTML), so there's nothing to rewrite; the
  // summary shows what the user ends up building.
  // summarizeDomConstruction: moved to htmldom-convert.js

  // ---------------------------------------------------------------------------
  // Direct chain-to-DOM converter: bypass DOMParser, work from chain tokens.
  // ---------------------------------------------------------------------------

  // Produce DOM-API code for a single innerHTML/outerHTML extraction.
  //
  // Two-phase approach:
  //   Phase 1: Parse chain tokens into a VNode tree using the stateful
  //            HTML parser. Each element has {tag, attrs, children}.
  //   Phase 2: Emit clean code from the tree. Each element gets a named
  //            variable. Children are appended directly to their parent
  //            variable. textContent shortcut for text-only elements.
  //            replaceChildren() for the root.
  //
  // For runtime-dependent structure (state machines with unbalanced
  // tags), falls back to a runtime parent pointer only where needed.
  // convertOne: moved to htmldom-convert.js

  // Copy is handled by monaco-init.js in the full UI.
  // Only attach here for standalone/test usage.
  // copy button handler: moved to monaco-init.js

  // Monaco editors are initialized by index.html before this script loads.
  if (typeof window !== 'undefined' && window._monacoIn) {
  // event listener for convert(): moved to monaco-init.js
  } else if ($('in')) {
  // event listener for convert(): moved to monaco-init.js
  }

  // await convert(): moved to monaco-init.js

  // --- Project-level API ---

  // resolveRelativePath: moved to htmldom-convert.js

  // findPageScripts: moved to htmldom-convert.js

  // Scan JS source for navigation sinks and wrap them with protocol filtering.
  // Returns the modified source, or null if no changes.
  // filterUnsafeSinks: moved to htmldom-convert.js

  // convertJsFile: moved to htmldom-convert.js

  // HTML tokenizer: produces a flat token stream from HTML source.
  // Token types:
  //   { type: 'text', text }          — text content
  //   { type: 'openTag', tag, tagRaw, attrs, selfClose, start, end }
  //   { type: 'closeTag', tag, start, end }
  //   { type: 'comment', text, start, end }
  //   { type: 'doctype', text, start, end }
  // Each attr: { name (lowercase), value, nameRaw, start, end }
  function tokenizeHtml(src) {
    const tokens = [];
    let i = 0;
    const n = src.length;
    let textStart = 0;

    function flushText() {
      if (i > textStart) {
        tokens.push({ type: 'text', text: src.slice(textStart, i), start: textStart, end: i });
      }
    }

    while (i < n) {
      if (src[i] === '<') {
        flushText();
        const tagStart = i;

        // Comment: <!-- ... -->
        if (i + 3 < n && src[i+1] === '!' && src[i+2] === '-' && src[i+3] === '-') {
          const endIdx = src.indexOf('-->', i + 4);
          const commentEnd = endIdx >= 0 ? endIdx + 3 : n;
          tokens.push({ type: 'comment', text: src.slice(i + 4, endIdx >= 0 ? endIdx : n), start: i, end: commentEnd });
          i = commentEnd;
          textStart = i;
          continue;
        }

        // DOCTYPE: <!DOCTYPE ...>
        if (i + 9 < n && src[i+1] === '!' && src.slice(i+2, i+9).toUpperCase() === 'DOCTYPE') {
          const endIdx = src.indexOf('>', i + 2);
          const dtEnd = endIdx >= 0 ? endIdx + 1 : n;
          tokens.push({ type: 'doctype', text: src.slice(i, dtEnd), start: i, end: dtEnd });
          i = dtEnd;
          textStart = i;
          continue;
        }

        // Closing tag: </tag>
        if (i + 1 < n && src[i+1] === '/') {
          let j = i + 2;
          let tag = '';
          while (j < n && src[j] !== '>' && src[j] !== ' ') { tag += src[j]; j++; }
          while (j < n && src[j] !== '>') j++;
          if (j < n) j++; // past >
          tokens.push({ type: 'closeTag', tag: tag.toLowerCase(), start: tagStart, end: j });
          i = j;
          textStart = i;
          continue;
        }

        // Opening tag: <tag attrs...> or <tag attrs.../>
        let j = i + 1;
        let tag = '';
        while (j < n && src[j] !== '>' && src[j] !== ' ' && src[j] !== '\t' && src[j] !== '\n' && src[j] !== '\r' && src[j] !== '/') {
          tag += src[j]; j++;
        }
        if (!tag) { i++; textStart = i; continue; } // bare < not a tag

        // Parse attributes.
        const attrs = [];
        while (j < n) {
          // Skip whitespace.
          while (j < n && (src[j] === ' ' || src[j] === '\t' || src[j] === '\n' || src[j] === '\r')) j++;
          if (j >= n || src[j] === '>' || (src[j] === '/' && j + 1 < n && src[j+1] === '>')) break;

          // Attribute name.
          const attrStart = j;
          let attrName = '';
          while (j < n && src[j] !== '=' && src[j] !== '>' && src[j] !== ' ' && src[j] !== '\t' && src[j] !== '\n' && src[j] !== '/') {
            attrName += src[j]; j++;
          }
          if (!attrName) { j++; continue; }

          // Skip whitespace around =.
          while (j < n && (src[j] === ' ' || src[j] === '\t')) j++;

          let attrValue = '';
          if (j < n && src[j] === '=') {
            j++; // past =
            while (j < n && (src[j] === ' ' || src[j] === '\t')) j++;
            if (j < n && (src[j] === '"' || src[j] === "'")) {
              const q = src[j]; j++;
              while (j < n && src[j] !== q) { attrValue += src[j]; j++; }
              if (j < n) j++; // past closing quote
            } else {
              // Unquoted value.
              while (j < n && src[j] !== ' ' && src[j] !== '>' && src[j] !== '\t' && src[j] !== '\n') {
                attrValue += src[j]; j++;
              }
            }
          }
          attrs.push({ name: attrName.toLowerCase(), value: attrValue, nameRaw: attrName, start: attrStart, end: j });
        }

        let selfClose = false;
        if (j < n && src[j] === '/') { selfClose = true; j++; }
        if (j < n && src[j] === '>') j++;

        const tagLower = tag.toLowerCase();
        tokens.push({ type: 'openTag', tag: tagLower, tagRaw: tag, attrs: attrs, selfClose: selfClose, start: tagStart, end: j });
        i = j;
        textStart = i;

        // Raw text elements (script, style, iframe, noscript) and escapable
        // raw text elements (textarea, title): content is NOT parsed for
        // HTML tags. Consume everything as text until the closing tag.
        if (!selfClose && (tagLower === 'script' || tagLower === 'style' ||
            tagLower === 'textarea' || tagLower === 'title' ||
            tagLower === 'iframe' || tagLower === 'noscript')) {
          const closePattern = '</' + tagLower;
          const rawStart = i;
          while (i < n) {
            if (src[i] === '<' && src[i + 1] === '/' &&
                src.slice(i, i + closePattern.length).toLowerCase() === closePattern) {
              let k = i + closePattern.length;
              while (k < n && (src[k] === ' ' || src[k] === '\t')) k++;
              if (k < n && src[k] === '>') break;
            }
            i++;
          }
          if (i > rawStart) {
            tokens.push({ type: 'text', text: src.slice(rawStart, i), start: rawStart, end: i });
          }
          textStart = i;
        }
        continue;
      }
      i++;
    }
    flushText();
    return tokens;
  }

  // Decode HTML entities in attribute values.
  // Handles named entities, decimal (&#123;), and hex (&#xA0;) numeric entities.
  var HTML_ENTITIES = {
    amp: '&', lt: '<', gt: '>', quot: '"', apos: "'",
    nbsp: '\u00A0', ensp: '\u2002', emsp: '\u2003', thinsp: '\u2009',
    mdash: '\u2014', ndash: '\u2013', lsquo: '\u2018', rsquo: '\u2019',
    ldquo: '\u201C', rdquo: '\u201D', bull: '\u2022', hellip: '\u2026',
    copy: '\u00A9', reg: '\u00AE', trade: '\u2122', deg: '\u00B0',
    plusmn: '\u00B1', times: '\u00D7', divide: '\u00F7', micro: '\u00B5',
    cent: '\u00A2', pound: '\u00A3', euro: '\u20AC', yen: '\u00A5',
    laquo: '\u00AB', raquo: '\u00BB', larr: '\u2190', rarr: '\u2192',
    uarr: '\u2191', darr: '\u2193', para: '\u00B6', sect: '\u00A7',
    iexcl: '\u00A1', iquest: '\u00BF', frac12: '\u00BD', frac14: '\u00BC',
    frac34: '\u00BE', sup1: '\u00B9', sup2: '\u00B2', sup3: '\u00B3',
    acute: '\u00B4', cedil: '\u00B8',
  };
  function decodeHtmlEntities(s) {
    return s.replace(/&(#x([0-9a-fA-F]+)|#([0-9]+)|([a-zA-Z]+));/g, function(match, _, hex, dec, named) {
      if (hex) return String.fromCodePoint(parseInt(hex, 16));
      if (dec) return String.fromCodePoint(parseInt(dec, 10));
      if (named && HTML_ENTITIES[named]) return HTML_ENTITIES[named];
      return match; // Unknown entity — preserve as-is.
    });
  }

  // Serialize HTML tokens back to a string.
  function serializeHtmlTokens(tokens) {
    let out = '';
    for (const tok of tokens) {
      if (tok.type === 'text') out += tok.text;
      else if (tok.type === 'comment') out += '<!--' + tok.text + '-->';
      else if (tok.type === 'doctype') out += tok.text;
      else if (tok.type === 'closeTag') out += '</' + tok.tag + '>';
      else if (tok.type === 'openTag') {
        out += '<' + tok.tagRaw;
        for (const attr of tok.attrs) {
          out += ' ' + attr.nameRaw + '="' + attr.value + '"';
        }
        if (tok.selfClose) out += '/';
        out += '>';
      }
    }
    return out;
  }

  // convertHtmlMarkup: moved to htmldom-convert.js

  // -----------------------------------------------------------------------
  // Taint Analysis API
  // -----------------------------------------------------------------------

  // Analyze a single JS source for taint flows. Returns an array of findings.
  // All detection happens inside the scope walker — no post-hoc regex scanning.
  async function traceTaintInJs(jsContent, precedingCode) {
    var src = (precedingCode ? precedingCode + '\n' : '') + jsContent;
    var tokens = tokenize(src.trim());
    if (!tokens.length) return [];
    // Run scope walker with taint enabled — it detects all sinks internally.
    var scope = await buildScopeState(tokens, tokens.length, null, null, { enabled: true });
    return scope.taintFindings || [];
  }

  // Count newlines before a position for line number calculation.
  function countLines(src, pos) {
    if (!src) return 0;
    var n = 1;
    for (var i = 0; i < pos && i < src.length; i++) {
      if (src[i] === '\n') n++;
    }
    return n;
  }

  // Analyze a multi-file project for taint flows.
  // Returns { findings: [...], summary: { ... } }.
  async function traceTaint(files) {
    var allFindings = [];
    // Find HTML pages and their referenced scripts.
    var htmlPages = Object.keys(files).filter(function(p) { return /\.html?$/i.test(p); });
    // Analyze JS files inline in HTML and standalone.
    for (var page of htmlPages) {
      var content = files[page];
      // Extract inline scripts from HTML.
      var htmlTokens = tokenizeHtml(content);
      for (var ti = 0; ti < htmlTokens.length; ti++) {
        if (htmlTokens[ti].type === 'openTag' && htmlTokens[ti].tag === 'script') {
          // Check if it has a src attribute (external) — skip inline scan.
          var hasSrc = false;
          for (var ai = 0; ai < (htmlTokens[ti].attrs || []).length; ai++) {
            if (htmlTokens[ti].attrs[ai].name === 'src') { hasSrc = true; break; }
          }
          if (hasSrc) continue;
          // Find matching </script> and extract content.
          var scriptStart = ti + 1;
          var scriptEnd = scriptStart;
          while (scriptEnd < htmlTokens.length && !(htmlTokens[scriptEnd].type === 'closeTag' && htmlTokens[scriptEnd].tag === 'script')) scriptEnd++;
          var scriptContent = '';
          for (var si = scriptStart; si < scriptEnd; si++) {
            if (htmlTokens[si].type === 'text') scriptContent += htmlTokens[si].text;
          }
          if (scriptContent.trim()) {
            // Compute the line offset: the script content's line 1 maps
            // to this line in the HTML file.
            var scriptLineOffset = 0;
            var scriptToken = htmlTokens[scriptStart];
            if (scriptToken && scriptToken.start !== undefined) {
              scriptLineOffset = countLines(content, scriptToken.start);
            }
            var inlineFindings = await traceTaintInJs(scriptContent);
            for (var f of inlineFindings) {
              f.file = page;
              f.inline = true;
              if (f.location && f.location.line) {
                f.location.line += scriptLineOffset;
              }
              allFindings.push(f);
            }
          }
        }
      }
      // Find external script references.
      var scriptRefs = [];
      for (var ti2 = 0; ti2 < htmlTokens.length; ti2++) {
        if (htmlTokens[ti2].type === 'openTag' && htmlTokens[ti2].tag === 'script') {
          for (var ai2 = 0; ai2 < (htmlTokens[ti2].attrs || []).length; ai2++) {
            if (htmlTokens[ti2].attrs[ai2].name === 'src') {
              scriptRefs.push(htmlTokens[ti2].attrs[ai2].value);
            }
          }
        }
      }
      // Analyze external scripts in order (preceding code accumulates).
      var precedingCode = '';
      for (var sr of scriptRefs) {
        if (files[sr]) {
          var extFindings = await traceTaintInJs(files[sr], precedingCode);
          for (var f2 of extFindings) {
            f2.file = sr;
            allFindings.push(f2);
          }
          precedingCode += (precedingCode ? '\n' : '') + files[sr];
        }
      }
    }
    // Also analyze standalone JS files not referenced by any HTML.
    var referencedJs = new Set();
    for (var page2 of htmlPages) {
      var ht2 = tokenizeHtml(files[page2]);
      for (var ti3 = 0; ti3 < ht2.length; ti3++) {
        if (ht2[ti3].type === 'openTag' && ht2[ti3].tag === 'script') {
          for (var ai3 = 0; ai3 < (ht2[ti3].attrs || []).length; ai3++) {
            if (ht2[ti3].attrs[ai3].name === 'src') referencedJs.add(ht2[ti3].attrs[ai3].value);
          }
        }
      }
    }
    var standaloneJs = Object.keys(files).filter(function(p) { return /\.js$/i.test(p) && !referencedJs.has(p); });
    for (var sj of standaloneJs) {
      var sjFindings = await traceTaintInJs(files[sj]);
      for (var f3 of sjFindings) {
        f3.file = sj;
        allFindings.push(f3);
      }
    }
    // No dedup — each finding is a distinct code path.
    var deduped = allFindings;
    return {
      findings: deduped,
      summary: {
        total: deduped.length,
        critical: deduped.filter(function(f) { return f.severity === 'critical'; }).length,
        high: deduped.filter(function(f) { return f.severity === 'high'; }).length,
        medium: deduped.filter(function(f) { return f.severity === 'medium'; }).length,
      }
    };
  }

  // convertProject: moved to htmldom-convert.js

  // ---------------------------------------------------------------
  // DEFAULT_TYPE_DB — the preset TypeDB shipped with the engine.
  //
  // This is pure data. Every source / sink / sanitizer / event-type
  // decision the walker makes is expressed as a TypeDescriptor on a
  // named type. The walker's lookup helpers (_lookupProp /
  // _lookupMethod / _resolveReturnType) apply the same generic
  // logic to every entry — there are no hardcoded name literals
  // in the walker itself, only the TypeDB.
  //
  // Consumers who want to add, remove, or replace types can pass a
  // custom db as options.taintConfig.typeDB to analyze(). The engine
  // treats it identically to this preset.
  //
  // Label vocabulary used below (sources and sink kinds):
  //   sources: 'url', 'cookie', 'referrer', 'window.name', 'storage',
  //            'network', 'postMessage', 'file', 'dragdrop', 'clipboard'
  //   sinks:   'html', 'code', 'url', 'navigation', 'css', 'text'
  //
  // Inheritance: every HTMLxElement extends HTMLElement which
  // extends Element which extends EventTarget. String methods live
  // on String. Event subtypes extend Event. Promise.then/.catch
  // live on Promise. And so on — the chain gives each subtype
  // access to its parent's props/methods automatically.
  const DEFAULT_TYPE_DB = {
    types: {
      // --- Base types ---
      EventTarget: {
        methods: {
          addEventListener: { args: [{}, {}] },
          removeEventListener: { args: [{}, {}] },
          dispatchEvent: { args: [{}] },
        },
      },
      Event: {
        extends: 'EventTarget',
        props: {
          // Generic Event has no taint-relevant props; subtypes override.
        },
      },
      MessageEvent: {
        extends: 'Event',
        props: {
          data:   { source: 'postMessage' },
          origin: { source: 'postMessage' },
        },
      },
      HashChangeEvent: {
        extends: 'Event',
        props: {
          newURL: { source: 'url' },
          oldURL: { source: 'url' },
        },
      },
      PopStateEvent: {
        extends: 'Event',
        props: {
          state: { source: 'url' },
        },
      },
      ErrorEvent: {
        extends: 'Event',
        props: {
          message:  { source: 'network' },
          filename: { source: 'url' },
        },
      },
      StorageEvent: {
        extends: 'Event',
        props: {
          newValue: { source: 'storage' },
          oldValue: { source: 'storage' },
          url:      { source: 'url' },
        },
      },
      DataTransfer: {
        props: {
          files: { source: 'file' },
        },
        methods: {
          getData: { source: 'dragdrop', returnType: 'String' },
        },
      },
      DragEvent: {
        extends: 'Event',
        props: {
          dataTransfer: { readType: 'DataTransfer' },
        },
      },
      ClipboardData: {
        methods: {
          getData: { source: 'clipboard', returnType: 'String' },
        },
      },
      ClipboardEvent: {
        extends: 'Event',
        props: {
          clipboardData: { readType: 'ClipboardData' },
        },
      },
      FileReader: {
        extends: 'EventTarget',
        props: {
          result:       { source: 'file' },
          response:     { source: 'network' },
          responseText: { source: 'network' },
        },
      },
      ProgressEvent: {
        extends: 'Event',
        props: {
          target: { readType: 'FileReader' },
        },
      },

      // --- DOM structural types ---
      Location: {
        // Reading a bare Location binding — e.g. `document.body.
        // innerHTML = window.location` — produces a URL string via
        // the implicit toString() the consumer performs, so the
        // binding itself carries the `url` label. Matches the
        // legacy behaviour of the `'window.location': 'url'` and
        // `'location': …` entries that over-tagged intermediate
        // Location references.
        selfSource: 'url',
        props: {
          search:   { source: 'url', readType: 'String' },
          hash:     { source: 'url', readType: 'String' },
          href:     { source: 'url', readType: 'String', sink: 'navigation' },
          pathname: { source: 'url', readType: 'String' },
          host:     { source: 'url', readType: 'String' },
          hostname: { source: 'url', readType: 'String' },
          origin:   { source: 'url', readType: 'String' },
          port:     { source: 'url', readType: 'String' },
          protocol: { source: 'url', readType: 'String' },
        },
        methods: {
          assign:   { args: [{ sink: 'navigation' }] },
          replace:  { args: [{ sink: 'navigation' }] },
          reload:   {},
          toString: { source: 'url', returnType: 'String' },
        },
      },
      History: {
        methods: {
          pushState:    {},
          replaceState: {},
          back:         {},
          forward:      {},
          go:           {},
        },
      },
      Navigation: {
        methods: {
          navigate: { args: [{ sink: 'navigation' }] },
        },
      },
      Storage: {
        // Reading a bare `localStorage` / `sessionStorage`
        // binding directly yields the `storage` label — matches
        // the legacy TAINT_SOURCES entries for those roots.
        selfSource: 'storage',
        methods: {
          getItem:    { source: 'storage', returnType: 'String' },
          setItem:    {},
          removeItem: {},
          clear:      {},
          key:        {},
        },
      },
      Document: {
        extends: 'EventTarget',
        props: {
          URL:         { source: 'url',      readType: 'String' },
          documentURI: { source: 'url',      readType: 'String' },
          baseURI:     { source: 'url',      readType: 'String' },
          cookie:      { source: 'cookie',   readType: 'String' },
          referrer:    { source: 'referrer', readType: 'String' },
          domain:      { source: 'referrer', readType: 'String', sink: 'origin' },
          location:    { readType: 'Location' },
          body:        { readType: 'HTMLElement' },
          documentElement: { readType: 'HTMLElement' },
        },
        methods: {
          createElement: {
            returnType: { fromArg: 0, map: {}, default: 'HTMLElement' },
          },
          createTextNode:    { returnType: 'Node' },
          createDocumentFragment: { returnType: 'DocumentFragment' },
          getElementById:    { returnType: 'HTMLElement' },
          getElementsByTagName: { returnType: 'HTMLCollection' },
          getElementsByClassName: { returnType: 'HTMLCollection' },
          querySelector:     { returnType: 'HTMLElement' },
          querySelectorAll:  { returnType: 'NodeList' },
          write:             { args: [{ sink: 'html' }] },
          writeln:           { args: [{ sink: 'html' }] },
        },
      },
      Window: {
        extends: 'EventTarget',
        props: {
          location:       { readType: 'Location' },
          name:           { source: 'window.name', readType: 'String' },
          document:       { readType: 'Document' },
          history:        { readType: 'History' },
          navigation:     { readType: 'Navigation' },
          localStorage:   { readType: 'Storage' },
          sessionStorage: { readType: 'Storage' },
          top:            { readType: 'Window' },
          parent:         { readType: 'Window' },
          opener:         { readType: 'Window' },
          self:           { readType: 'Window' },
          frames:         { readType: 'Window' },
        },
        methods: {
          open: { args: [{ sink: 'navigation', severity: 'medium' }] },
          postMessage: {},
          setTimeout:  { args: [{ sink: 'code' }] },
          setInterval: { args: [{ sink: 'code' }] },
          clearTimeout:  {},
          clearInterval: {},
        },
      },

      // --- Element hierarchy ---
      Node: {
        extends: 'EventTarget',
        props: {
          // Baseline safe read/write. Subtypes (HTMLScriptElement,
          // HTMLStyleElement) override with stronger sinks. Carrying
          // sink:'text' here means unknown-tag writes resolve to the
          // safe baseline rather than scanning every subtype.
          textContent: { sink: 'text', severity: 'safe' },
        },
        methods: {
          appendChild:  { args: [{}] },
          insertBefore: { args: [{}, {}] },
          removeChild:  { args: [{}] },
          replaceChild: { args: [{}, {}] },
        },
      },
      DocumentFragment: {
        extends: 'Node',
      },
      Element: {
        extends: 'Node',
        props: {
          innerHTML: { sink: 'html' },
          outerHTML: { sink: 'html' },
        },
        methods: {
          insertAdjacentHTML: { args: [{}, { sink: 'html' }] },
          setAttribute: {
            // arg[0] is the attribute name, arg[1] is its value. The
            // per-attr sink classification lives on db.attrSinks so
            // it's reusable from both the call-site sinkIfArgEquals
            // handler AND the checkSinkSetAttribute (direct attr
            // write) code path. The sinkIfArgEquals.values object is
            // wired to db.attrSinks at DB finalisation time below,
            // so there's one source of truth.
            args: [{ sinkIfArgEquals: { arg: 1, values: null } }, {}],
          },
          removeAttribute: { args: [{}] },
          getAttribute:    { args: [{}], returnType: 'String' },
        },
      },
      HTMLElement: { extends: 'Element' },
      HTMLIFrameElement: {
        extends: 'HTMLElement',
        props: {
          src:    { sink: 'url' },
          srcdoc: { sink: 'html' },
        },
      },
      HTMLScriptElement: {
        extends: 'HTMLElement',
        props: {
          src:         { sink: 'url' },
          textContent: { sink: 'code' },
          text:        { sink: 'code' },
          innerText:   { sink: 'code' },
        },
      },
      HTMLEmbedElement: {
        extends: 'HTMLElement',
        props: { src: { sink: 'url' } },
      },
      HTMLObjectElement: {
        extends: 'HTMLElement',
        props: { data: { sink: 'url' } },
      },
      HTMLFrameElement: {
        extends: 'HTMLElement',
        props: { src: { sink: 'url' } },
      },
      HTMLAnchorElement: {
        extends: 'HTMLElement',
        props: { href: { sink: 'url' } },
      },
      HTMLAreaElement: {
        extends: 'HTMLElement',
        props: { href: { sink: 'url' } },
      },
      HTMLBaseElement: {
        extends: 'HTMLElement',
        props: { href: { sink: 'url' } },
      },
      HTMLLinkElement: {
        extends: 'HTMLElement',
        props: { href: { sink: 'url' } },
      },
      HTMLFormElement: {
        extends: 'HTMLElement',
        props: { action: { sink: 'url' } },
      },
      HTMLInputElement: {
        extends: 'HTMLElement',
        props: { formAction: { sink: 'url', severity: 'medium' } },
      },
      HTMLButtonElement: {
        extends: 'HTMLElement',
        props: { formAction: { sink: 'url', severity: 'medium' } },
      },
      HTMLStyleElement: {
        extends: 'HTMLElement',
        props: {
          textContent: { sink: 'css' },
          innerText:   { sink: 'css' },
        },
      },
      HTMLImageElement: { extends: 'HTMLElement' },
      HTMLVideoElement: { extends: 'HTMLElement' },
      HTMLAudioElement: { extends: 'HTMLElement' },
      HTMLSourceElement: { extends: 'HTMLElement' },
      HTMLTrackElement: { extends: 'HTMLElement' },
      HTMLCollection: {},
      NodeList: {},

      // --- Network types ---
      Response: {
        methods: {
          json:      { source: 'network', returnType: 'Promise' },
          text:      { source: 'network', returnType: 'Promise' },
          blob:      { source: 'network', returnType: 'Promise' },
          arrayBuffer: { source: 'network', returnType: 'Promise' },
          formData:  { source: 'network', returnType: 'Promise' },
        },
      },
      Promise: {
        methods: {
          then:    { args: [{}, {}] },
          catch:   { args: [{}] },
          finally: { args: [{}] },
        },
      },
      XMLHttpRequest: {
        extends: 'EventTarget',
        props: {
          responseText: { source: 'network', readType: 'String' },
          response:     { source: 'network' },
          responseXML:  { source: 'network' },
          status:       {},
          statusText:   {},
        },
        methods: {
          open:            { args: [{}, {}] },
          send:            { args: [{}] },
          setRequestHeader:{ args: [{}, {}] },
          getResponseHeader: { args: [{}], returnType: 'String' },
          abort:           {},
        },
      },
      WebSocket: {
        extends: 'EventTarget',
        methods: {
          send:  { args: [{}] },
          close: {},
        },
      },
      EventSource: {
        extends: 'EventTarget',
        methods: {
          close: {},
        },
      },

      // --- String (for label-preserving string methods) ---
      String: {
        methods: {
          slice:       { returnType: 'String', preservesLabelsFromReceiver: true },
          substring:   { returnType: 'String', preservesLabelsFromReceiver: true },
          substr:      { returnType: 'String', preservesLabelsFromReceiver: true },
          toLowerCase: { returnType: 'String', preservesLabelsFromReceiver: true },
          toUpperCase: { returnType: 'String', preservesLabelsFromReceiver: true },
          trim:        { returnType: 'String', preservesLabelsFromReceiver: true },
          trimStart:   { returnType: 'String', preservesLabelsFromReceiver: true },
          trimEnd:     { returnType: 'String', preservesLabelsFromReceiver: true },
          charAt:      { returnType: 'String', preservesLabelsFromReceiver: true },
          concat:      { returnType: 'String', preservesLabelsFromReceiver: true },
          repeat:      { returnType: 'String', preservesLabelsFromReceiver: true },
          replace:     { returnType: 'String', preservesLabelsFromReceiver: true },
          replaceAll:  { returnType: 'String', preservesLabelsFromReceiver: true },
          padStart:    { returnType: 'String', preservesLabelsFromReceiver: true },
          padEnd:      { returnType: 'String', preservesLabelsFromReceiver: true },
          normalize:   { returnType: 'String', preservesLabelsFromReceiver: true },
          split:       { preservesLabelsFromReceiver: true },
          indexOf:     {},
          lastIndexOf: {},
          includes:    {},
          startsWith:  {},
          endsWith:    {},
          toString:    { returnType: 'String', preservesLabelsFromReceiver: true },
        },
        props: {
          length: {},
        },
      },

      // --- Global callables ---
      GlobalEval: {
        call: { args: [{ sink: 'code', severity: 'high' }] },
      },
      GlobalFunctionCtor: {
        construct: { args: [{ sink: 'code', severity: 'high' }, { sink: 'code', severity: 'high' }] },
        call:      { args: [{ sink: 'code', severity: 'high' }, { sink: 'code', severity: 'high' }] },
      },
      GlobalSetTimeout: {
        call: { args: [{ sink: 'code', severity: 'high' }, {}] },
      },
      GlobalSetInterval: {
        call: { args: [{ sink: 'code', severity: 'high' }, {}] },
      },
      GlobalFetch: {
        // `fetch(...)` is tagged as a network source at the call
        // site in addition to returning a Promise — matches the
        // legacy TAINT_SOURCE_CALLS behaviour that treats the
        // call result as attacker-influenced data.
        call: { source: 'network', returnType: 'Promise' },
      },
      GlobalXMLHttpRequestCtor: {
        construct: { source: 'network', returnType: 'XMLHttpRequest' },
      },
      // Constructor singletons for common instance types. These
      // let `new FileReader()` / `new WebSocket(url)` / etc.
      // resolve to their instance type at binding-tag time.
      GlobalFileReaderCtor: {
        construct: { returnType: 'FileReader' },
      },
      GlobalWebSocketCtor: {
        construct: { source: 'network', returnType: 'WebSocket' },
      },
      GlobalEventSourceCtor: {
        construct: { source: 'network', returnType: 'EventSource' },
      },
      GlobalURLCtor: {
        construct: { returnType: 'URL' },
      },
      // URL instances — props carry the `url` label because
      // constructing a URL from any string doesn't sanitize it.
      URL: {
        props: {
          href:     { source: 'url', readType: 'String' },
          hash:     { source: 'url', readType: 'String' },
          search:   { source: 'url', readType: 'String' },
          pathname: { source: 'url', readType: 'String' },
          host:     { source: 'url', readType: 'String' },
          hostname: { source: 'url', readType: 'String' },
          origin:   { source: 'url', readType: 'String' },
          port:     { source: 'url', readType: 'String' },
          protocol: { source: 'url', readType: 'String' },
          searchParams: { source: 'url' },
        },
      },
      IDBObjectStore: {
        methods: {
          get: { source: 'storage' },
          put: {},
          add: {},
          delete: {},
        },
      },
      CacheStorage: {
        methods: {
          match: { source: 'storage' },
          open: {},
          has: {},
          delete: {},
        },
      },
      GlobalDecodeURIComponent: {
        call: { source: 'url', returnType: 'String', preservesLabelsFromArg: 0 },
      },
      GlobalDecodeURI: {
        call: { source: 'url', returnType: 'String', preservesLabelsFromArg: 0 },
      },
      GlobalAtob: {
        call: { source: 'url', returnType: 'String', preservesLabelsFromArg: 0 },
      },
      // Sanitizers: functions whose return type has no
      // preservesLabelsFrom* field, so labels do not flow from
      // the argument to the return. The engine treats a function
      // without a preserve hint as label-stripping automatically.
      // Sanitizers: `sanitizer: true` on the call descriptor
      // marks the result as label-free regardless of arg taint.
      // The walker's opaque-call path consults this flag.
      GlobalEncodeURIComponent: { call: { returnType: 'String', sanitizer: true } },
      GlobalEncodeURI:          { call: { returnType: 'String', sanitizer: true } },
      GlobalEscape:             { call: { returnType: 'String', sanitizer: true } },
      GlobalBtoa:               { call: { returnType: 'String', sanitizer: true } },
      GlobalParseInt:           { call: { sanitizer: true } },
      GlobalParseFloat:         { call: { sanitizer: true } },
      GlobalNumber:             { call: { sanitizer: true } },
      GlobalBoolean:            { call: { sanitizer: true } },
      // DOMPurify is an object whose .sanitize() method neutralises
      // HTML taint labels, yielding a string safe for innerHTML.
      DOMPurify: {
        methods: {
          sanitize: { returnType: 'String', sanitizer: true },
        },
      },
    },

    // Root name → type. Applied when the name is not shadowed by an
    // in-scope user declaration.
    roots: {
      location:       'Location',
      window:         'Window',
      document:       'Document',
      navigator:      'Window',     // coarse; refine if needed
      history:        'History',
      navigation:     'Navigation',
      localStorage:   'Storage',
      sessionStorage: 'Storage',
      top:            'Window',
      parent:         'Window',
      opener:         'Window',
      self:           'Window',
      frames:         'Window',

      // Global callables modeled as singletons
      eval:        'GlobalEval',
      Function:    'GlobalFunctionCtor',
      setTimeout:  'GlobalSetTimeout',
      setInterval: 'GlobalSetInterval',
      fetch:          'GlobalFetch',
      XMLHttpRequest: 'GlobalXMLHttpRequestCtor',
      FileReader:     'GlobalFileReaderCtor',
      WebSocket:      'GlobalWebSocketCtor',
      EventSource:    'GlobalEventSourceCtor',
      URL:            'GlobalURLCtor',
      caches:         'CacheStorage',
      decodeURIComponent: 'GlobalDecodeURIComponent',
      decodeURI:          'GlobalDecodeURI',
      atob:               'GlobalAtob',
      encodeURIComponent: 'GlobalEncodeURIComponent',
      encodeURI:          'GlobalEncodeURI',
      escape:             'GlobalEscape',
      btoa:               'GlobalBtoa',
      parseInt:           'GlobalParseInt',
      parseFloat:         'GlobalParseFloat',
      Number:             'GlobalNumber',
      Boolean:            'GlobalBoolean',
      DOMPurify:          'DOMPurify',
    },

    // createElement(tag) and similar → specific HTMLxElement type.
    tagMap: {
      iframe: 'HTMLIFrameElement',
      script: 'HTMLScriptElement',
      embed:  'HTMLEmbedElement',
      object: 'HTMLObjectElement',
      frame:  'HTMLFrameElement',
      a:      'HTMLAnchorElement',
      area:   'HTMLAreaElement',
      base:   'HTMLBaseElement',
      link:   'HTMLLinkElement',
      form:   'HTMLFormElement',
      input:  'HTMLInputElement',
      button: 'HTMLButtonElement',
      style:  'HTMLStyleElement',
      img:    'HTMLImageElement',
      video:  'HTMLVideoElement',
      audio:  'HTMLAudioElement',
      source: 'HTMLSourceElement',
      track:  'HTMLTrackElement',
    },

    // Attribute-name sinks: writing these attributes (via
    // `setAttribute(attr, v)` OR a direct attribute-write path)
    // classifies the value under the named sink kind regardless
    // of the concrete element type.
    attrSinks: {
      onclick: 'code', onload: 'code', onerror: 'code',
      onmouseover: 'code', onfocus: 'code', onblur: 'code',
      onsubmit: 'code', onchange: 'code', oninput: 'code',
      onkeydown: 'code', onkeyup: 'code', onkeypress: 'code',
      onmousedown: 'code', onmouseup: 'code', onmousemove: 'code',
      ondblclick: 'code', oncontextmenu: 'code', ondrag: 'code',
      ondrop: 'code', onscroll: 'code', onwheel: 'code',
      ontouchstart: 'code', ontouchend: 'code', ontouchmove: 'code',
      onanimationend: 'code', ontransitionend: 'code',
      style: 'css',
    },

    // addEventListener(eventName, fn) → the fn's first param gets this type.
    eventMap: {
      message:      'MessageEvent',
      messageerror: 'MessageEvent',
      hashchange:   'HashChangeEvent',
      popstate:     'PopStateEvent',
      error:        'ErrorEvent',
      storage:      'StorageEvent',
      drop:         'DragEvent',
      dragover:     'DragEvent',
      dragenter:    'DragEvent',
      dragleave:    'DragEvent',
      dragstart:    'DragEvent',
      dragend:      'DragEvent',
      paste:        'ClipboardEvent',
      copy:         'ClipboardEvent',
      cut:          'ClipboardEvent',
      load:         'ProgressEvent',
      loadend:      'ProgressEvent',
      loadstart:    'ProgressEvent',
      progress:     'ProgressEvent',
    },
  };
  // Populate createElement's dynamic return-type map from tagMap
  // so the two stay in sync. Keyed here (not inline in the Document
  // descriptor above) so tagMap remains the single source of truth.
  (function () {
    var map = DEFAULT_TYPE_DB.types.Document.methods.createElement.returnType.map;
    for (var tag in DEFAULT_TYPE_DB.tagMap) {
      map[tag] = DEFAULT_TYPE_DB.tagMap[tag];
    }
    // Wire Element.setAttribute's sinkIfArgEquals.values to
    // db.attrSinks so attribute classification has exactly one
    // source of truth — the values object — shared by both the
    // call-site sinkIfArgEquals evaluator AND the direct
    // setAttribute(attr, v) sink checker.
    DEFAULT_TYPE_DB.types.Element.methods.setAttribute.args[0].sinkIfArgEquals.values = DEFAULT_TYPE_DB.attrSinks;
  })();

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------
  var api = {
    // Core analysis
    tokenize: tokenize,
    tokenizeHtml: tokenizeHtml,
    // Conversion entry points: Stage 4b.2 removed these from
    // jsanalyze.js. Consumers should use the HtmldomConvert facade
    // (globalThis.HtmldomConvert or require('./htmldom-convert.js')).
    // The keys are kept here as getter shims so legacy code that
    // reaches into jsanalyze.js's api.convertJsFile continues to
    // resolve after HtmldomConvert has loaded. The shims return
    // undefined until HtmldomConvert.js executes.
    get convertProject() {
      return (typeof globalThis !== 'undefined' && globalThis.HtmldomConvert) ? globalThis.HtmldomConvert.convertProject : undefined;
    },
    get convertJsFile() {
      return (typeof globalThis !== 'undefined' && globalThis.HtmldomConvert) ? globalThis.HtmldomConvert.convertJsFile : undefined;
    },
    get convertHtmlMarkup() {
      return (typeof globalThis !== 'undefined' && globalThis.HtmldomConvert) ? globalThis.HtmldomConvert.convertHtmlMarkup : undefined;
    },
    // Diagnostics / extraction still live in jsanalyze.js (they're
    // walker-level extractors, not converter-specific).
    extractHTML: extractHTML,
    extractAllHTML: extractAllHTML,
    extractAllDOM: extractAllDOM,
    // Taint analysis
    traceTaint: traceTaint,
    traceTaintInJs: traceTaintInJs,
    // Utilities
    decodeHtmlEntities: decodeHtmlEntities,
    parseStyleDecls: parseStyleDecls,
    serializeHtmlTokens: serializeHtmlTokens,
    makeVar: makeVar,
    // Classification data (for custom analysis). Sources, sinks,
    // event-handler taint AND sanitizers are all driven by the
    // DEFAULT_TYPE_DB exposed via _walkerInternals below; legacy
    // flat tables were removed in phases 2-5 of the type-db
    // refactor.
    // jsanalyze public surface (stage 1 — seam only, stable shape)
    jsanalyze: {
      bindingToValue: bindingToValue,
      // Allow tests + consumers to reach the walker for now.
      // Stage 2 will expose a proper `analyze()` entry point.
      buildScopeState: buildScopeState,
      scanMutations: scanMutations,
      tokenize: tokenize,
    },
    // Walker internals exposed for htmldom-convert.js's factory
    // (Stage 4b). Consumers OTHER than htmldom-convert should use
    // the jsanalyze query layer — these are walker-private and
    // will migrate to jsanalyze.js in Stage 5.
    _walkerInternals: {
      // Tokenizers & parsers
      tokenize: tokenize,
      tokenizeHtml: tokenizeHtml,
      decodeHtmlEntities: decodeHtmlEntities,
      decodeJsString: decodeJsString,
      serializeHtmlTokens: serializeHtmlTokens,
      parseStyleDecls: parseStyleDecls,
      scanMutations: scanMutations,
      // Walker
      buildScopeState: buildScopeState,
      extractHTML: extractHTML,
      extractAllHTML: extractAllHTML,
      extractAllDOM: extractAllDOM,
      traceTaint: traceTaint,
      traceTaintInJs: traceTaintInJs,
      bindingToValue: bindingToValue,
      // Binding primitives
      collectChainTaint: collectChainTaint,
      getElementTag: getElementTag,
      isSanitizer: isSanitizer,
      isNavSink: isNavSink,
      isIdlProp: isIdlProp,
      classifySink: classifySink,
      countLines: countLines,
      makeVar: makeVar,
      jsStr: jsStr,
      // Regex & classification tables
      IDENT_RE: IDENT_RE,
      PATH_RE: PATH_RE,
      ATTR_TO_PROP: ATTR_TO_PROP,
      BOOLEAN_ATTRS: BOOLEAN_ATTRS,
      VOID_ELEMENTS: VOID_ELEMENTS,
      SVG_TAGS: SVG_TAGS,
      NAV_SAFE_FILTER: NAV_SAFE_FILTER,
      // New declarative type database. See the big comment block
      // above DEFAULT_TYPE_DB for the shape.
      DEFAULT_TYPE_DB: DEFAULT_TYPE_DB,
      _lookupProp: _lookupProp,
      _lookupMethod: _lookupMethod,
      _resolveReturnType: _resolveReturnType,
      _walkPathInDB: _walkPathInDB,
      _resolveExprTypeViaDB: _resolveExprTypeViaDB,
      _classifySinkViaDB: _classifySinkViaDB,
      _classifySinkByTypeViaDB: _classifySinkByTypeViaDB,
      _classifyCallSinkViaDB: _classifyCallSinkViaDB,
      _classifyAttrSinkViaDB: _classifyAttrSinkViaDB,
      _propIsEverASink: _propIsEverASink,
      _collectEventSourceLabels: _collectEventSourceLabels,
      _isSanitizerCallViaDB: _isSanitizerCallViaDB,
      _isNavSinkViaDB: _isNavSinkViaDB,
    },
  };

  if (typeof globalThis !== 'undefined') {
    // Converter globals removed in Stage 4b.2 — use HtmldomConvert
    // (loaded from htmldom-convert.js) instead. The test harness
    // wires up __convertProject / __convertJsFile / __convertHtmlMarkup
    // / __convertRaw from HtmldomConvert for back-compat.
    globalThis.__traceTaint = traceTaint;
    globalThis.__htmldomApi = api;
    globalThis.__bindingToValue = bindingToValue;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})();
