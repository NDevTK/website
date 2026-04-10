// HTML to DOM API Converter
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

  // Known taint sources — expressions or patterns that introduce untrusted data.
  const TAINT_SOURCES = {
    // URL-derived
    'location.search':    'url',
    'location.hash':      'url',
    'location.href':      'url',
    'location.pathname':  'url',
    'document.URL':       'url',
    'document.documentURI': 'url',
    'document.baseURI':   'url',
    'window.location':    'url',
    'window.location.search': 'url',
    'window.location.hash':   'url',
    'window.location.href':   'url',
    // Document properties
    'document.cookie':    'cookie',
    'document.referrer':  'referrer',
    'document.domain':    'referrer',
    // Window properties
    'window.name':        'window.name',
    // Storage
    'localStorage':       'storage',
    'sessionStorage':     'storage',
  };
  // Patterns matched against full expressions (method calls, etc.).
  const TAINT_SOURCE_CALLS = {
    'localStorage.getItem':    'storage',
    'sessionStorage.getItem':  'storage',
    'location.toString':       'url',
    'decodeURIComponent':      'url', // preserves taint, not a sanitizer
    'decodeURI':               'url',
    'atob':                    'url', // often used to decode tainted base64
  };
  // Event handler parameter sources: addEventListener type → param.property → label.
  const EVENT_TAINT_SOURCES = {
    'message':    { 'data': 'postMessage', 'origin': 'postMessage' },
    'hashchange': { 'newURL': 'url', 'oldURL': 'url' },
    'popstate':   { 'state': 'url' },
  };

  // Sink classification: property → {type, severity, elementDependent}.
  // When elementDependent is true, the sink only applies to certain element types.
  const TAINT_SINKS = {
    'innerHTML':          { type: 'html',   severity: 'high',   elementDependent: false },
    'outerHTML':          { type: 'html',   severity: 'high',   elementDependent: false },
    'insertAdjacentHTML': { type: 'html',   severity: 'high',   elementDependent: false },
    'srcdoc':             { type: 'html',   severity: 'high',   elementDependent: true, elements: new Set(['iframe']) },
    'src':                { type: 'url',    severity: 'high',   elementDependent: true, elements: new Set(['iframe', 'script', 'embed', 'object', 'frame']) },
    'href':               { type: 'url',    severity: 'high',   elementDependent: true, elements: new Set(['a', 'base', 'area']) },
    'action':             { type: 'url',    severity: 'high',   elementDependent: true, elements: new Set(['form']) },
    'formAction':         { type: 'url',    severity: 'medium', elementDependent: true, elements: new Set(['input', 'button']) },
    'data':               { type: 'url',    severity: 'high',   elementDependent: true, elements: new Set(['object']) },
    'textContent':        { type: 'text',   severity: 'safe',   elementDependent: true, elements: new Set(['script', 'style']) },
    // Safe by default on non-script/style elements — only a sink on script/style
  };
  // Global call sinks (not property-based).
  const TAINT_CALL_SINKS = {
    'eval':                   { type: 'code', severity: 'high' },
    'Function':               { type: 'code', severity: 'high' },
    'setTimeout':             { type: 'code', severity: 'high' },
    'setInterval':            { type: 'code', severity: 'high' },
    'document.write':         { type: 'html', severity: 'high' },
    'document.writeln':       { type: 'html', severity: 'high' },
    'window.open':            { type: 'navigation', severity: 'medium' },
    'location.assign':        { type: 'navigation', severity: 'high' },
    'location.replace':       { type: 'navigation', severity: 'high' },
    'navigation.navigate':    { type: 'navigation', severity: 'high' },
  };
  // setAttribute sinks: attr name → classification.
  const ATTR_SINKS = {
    'onclick': 'code', 'onload': 'code', 'onerror': 'code',
    'onmouseover': 'code', 'onfocus': 'code', 'onblur': 'code',
    'onsubmit': 'code', 'onchange': 'code', 'oninput': 'code',
    'onkeydown': 'code', 'onkeyup': 'code', 'onkeypress': 'code',
    'onmousedown': 'code', 'onmouseup': 'code', 'onmousemove': 'code',
    'ondblclick': 'code', 'oncontextmenu': 'code', 'ondrag': 'code',
    'ondrop': 'code', 'onscroll': 'code', 'onwheel': 'code',
    'ontouchstart': 'code', 'ontouchend': 'code', 'ontouchmove': 'code',
    'onanimationend': 'code', 'ontransitionend': 'code',
    'style': 'css',
  };

  // Element type classification for property sinks.
  // Maps element tag → property → whether it's a sink.
  const ELEMENT_SINK_TYPES = {
    'iframe':  { src: 'url', srcdoc: 'html', sandbox: 'safe', allow: 'safe', name: 'safe' },
    'script':  { src: 'url', textContent: 'code', text: 'code', innerText: 'code' },
    'embed':   { src: 'url' },
    'object':  { data: 'url', type: 'safe' },
    'frame':   { src: 'url' },
    'a':       { href: 'url' },
    'area':    { href: 'url' },
    'base':    { href: 'url' },
    'form':    { action: 'url' },
    'input':   { formAction: 'url', value: 'safe' },
    'button':  { formAction: 'url' },
    'link':    { href: 'url' }, // rel=stylesheet, rel=import, etc.
    'style':   { textContent: 'css', innerText: 'css' },
    'img':     { src: 'safe', srcset: 'safe' },
    'video':   { src: 'safe' },
    'audio':   { src: 'safe' },
    'source':  { src: 'safe', srcset: 'safe' },
    'track':   { src: 'safe' },
  };

  // Known sanitizer functions that neutralize taint.
  const TAINT_SANITIZERS = new Set([
    'encodeURIComponent', 'encodeURI',
    'parseInt', 'parseFloat', 'Number', 'Boolean',
    'DOMPurify.sanitize',
    'escape',
    'btoa',
  ]);

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
      } else if (t.type === 'switch' && t.branches) {
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

  // Check if an expression text matches a known taint source. Returns label or null.
  // Matches exact, suffix (window.location.search), and prefix with method calls
  // (location.hash.slice(1) starts with taint source location.hash).
  function getTaintSource(expr) {
    if (TAINT_SOURCES[expr]) return TAINT_SOURCES[expr];
    for (var src in TAINT_SOURCES) {
      // Suffix match: "window.location.search" contains "location.search"
      if (expr.endsWith(src) && (expr.length === src.length || expr[expr.length - src.length - 1] === '.')) {
        return TAINT_SOURCES[src];
      }
      // Prefix match: "location.hash.slice(1)" starts with "location.hash"
      if (expr.startsWith(src) && expr.length > src.length && (expr[src.length] === '.' || expr[src.length] === '(')) {
        return TAINT_SOURCES[src];
      }
    }
    return null;
  }

  // Check if an expression is a known call-based taint source.
  function getTaintSourceCall(callExpr) {
    return TAINT_SOURCE_CALLS[callExpr] || null;
  }

  // Classify a property sink given the element type. Returns sink info or null.
  function classifySink(propName, elementTag) {
    // Direct sink lookup (non-element-dependent)
    var sink = TAINT_SINKS[propName];
    if (sink && !sink.elementDependent) {
      return { type: sink.type, severity: sink.severity, prop: propName };
    }
    // Element-dependent: check if this property is a sink on this element type
    if (elementTag) {
      var elSinks = ELEMENT_SINK_TYPES[elementTag.toLowerCase()];
      if (elSinks && elSinks[propName]) {
        var sinkType = elSinks[propName];
        if (sinkType === 'safe') return null;
        return { type: sinkType, severity: sinkType === 'code' ? 'critical' : 'high', prop: propName, elementTag: elementTag };
      }
      // If element type is known and property isn't listed, it's safe.
      if (sink && sink.elementDependent && !sink.elements.has(elementTag.toLowerCase())) {
        return null; // e.g. img.src is safe
      }
    }
    // Element-dependent sink but element type unknown — report as potential
    if (sink && sink.elementDependent) {
      return { type: sink.type, severity: sink.severity, prop: propName, elementTag: elementTag || 'unknown' };
    }
    return null;
  }

  // Check if a function name is a known sanitizer.
  function isSanitizer(name) {
    return TAINT_SANITIZERS.has(name);
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


  // Navigation sink patterns: property assignments or method calls that
  // cause navigation and are vulnerable to javascript: protocol XSS.
  // Each entry: { kind: 'assign'|'call', severity, check }.
  const NAV_SINKS = {
    // Direct location assignments
    'location.href':     { kind: 'assign', severity: 'high' },
    'location':          { kind: 'assign', severity: 'high' },  // location = url
    // Location methods
    'location.assign':   { kind: 'call', severity: 'high' },
    'location.replace':  { kind: 'call', severity: 'high' },
    // window.open
    'window.open':       { kind: 'call', severity: 'medium' },
    'open':              { kind: 'call', severity: 'medium' },
    // Navigation API
    'navigation.navigate': { kind: 'call', severity: 'high' },
  };

  // Properties on frame/iframe elements that are navigation sinks.
  const FRAME_NAV_PROPS = new Set(['src']);
  // Properties on opener/parent/top.location that are navigation sinks.
  const LOCATION_NAV_PROPS = new Set(['href', '']);  // '' = direct assignment

  // Check if an expression is a known global navigation object.
  // Returns the nav type or null. Only matches when the name isn't
  // shadowed by a local binding in the provided resolve function.
  // Check if an expression refers to a global navigation object.
  // Only returns a match when the root identifier is NOT declared
  // locally (var/let/const/function). Bare assignments to globals
  // (location = x) don't count as declarations.
  // declaredSet: a Set of names declared with var/let/const.
  // Navigation sink expressions: these are the ONLY patterns that cause
  // navigation and are vulnerable to javascript: protocol. Any other
  // property on location (location.hash, location.search) is a SOURCE
  // not a sink.
  const NAV_SINK_EXPRS = new Set([
    'location', 'location.href', 'location.assign', 'location.replace',
    'window.location', 'window.location.href', 'window.location.assign', 'window.location.replace',
    'document.location', 'document.location.href', 'document.location.assign', 'document.location.replace',
    'self.location', 'self.location.href',
    'opener', 'opener.location', 'opener.location.href',
    'window.opener', 'window.opener.location', 'window.opener.location.href',
    'parent', 'parent.location', 'parent.location.href',
    'window.parent', 'window.parent.location', 'window.parent.location.href',
    'top', 'top.location', 'top.location.href',
    'window.top', 'window.top.location', 'window.top.location.href',
    'navigation.navigate', 'window.navigation.navigate',
  ]);

  // Check if an expression is a navigation sink. Only matches actual
  // sink patterns, not reads like location.hash or location.search.
  function isNavSink(expr, declaredSet) {
    if (!NAV_SINK_EXPRS.has(expr)) return false;
    var root = expr.split('.')[0];
    if (root === 'window' || root === 'self' || root === 'globalThis' || root === 'document') return true;
    if (declaredSet && declaredSet.has(root)) return false;
    return true;
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
  function _mergeSorts(a, b) {
    var out = {};
    if (a) for (var k in a) out[k] = a[k];
    if (b) for (var k2 in b) {
      out[k2] = (out[k2] === 'String' || b[k2] === 'String') ? 'String' : (out[k2] || b[k2]);
    }
    return out;
  }
  // Coerce a value-typed expression to its boolean form (truthy check).
  function _toBool(o) {
    if (!o) return 'true';
    if (o.isBool) return o.expr;
    if (o.value) {
      if (o.value.kind === 'bool') return o.value.val ? 'true' : 'false';
      if (o.value.kind === 'int')  return o.value.val !== 0  ? 'true' : 'false';
      if (o.value.kind === 'str')  return o.value.val !== '' ? 'true' : 'false';
    }
    if (o.symName) {
      var sort = o.sorts[o.symName] || 'Int';
      if (sort === 'String') return '(not (= ' + o.expr + ' ""))';
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
      return { expr: _quoteSmtString(value), sorts: {}, isBool: false, value: { kind: 'str', val: value } };
    }
    return { expr: 'true', sorts: {}, isBool: true, value: { kind: 'bool', val: true } };
  }
  function smtNot(o) {
    if (!o) return null;
    if (o.value && o.value.kind === 'bool') return smtConst(!o.value.val);
    return { expr: '(not ' + _toBool(o) + ')', sorts: o.sorts, isBool: true };
  }
  function smtAnd(a, b) {
    if (!a) return b;
    if (!b) return a;
    if (a.value && a.value.kind === 'bool') return a.value.val ? b : a;
    if (b.value && b.value.kind === 'bool') return b.value.val ? a : b;
    return { expr: '(and ' + _toBool(a) + ' ' + _toBool(b) + ')',
             sorts: _mergeSorts(a.sorts, b.sorts), isBool: true };
  }
  function smtOr(a, b) {
    if (!a) return b;
    if (!b) return a;
    if (a.value && a.value.kind === 'bool') return a.value.val ? a : b;
    if (b.value && b.value.kind === 'bool') return b.value.val ? b : a;
    return { expr: '(or ' + _toBool(a) + ' ' + _toBool(b) + ')',
             sorts: _mergeSorts(a.sorts, b.sorts), isBool: true };
  }
  function smtCmp(op, l, r) {
    if (!l || !r) return null;
    // Compile-time fold for fully-concrete operands.
    if (l.value && r.value && l.value.kind === r.value.kind) {
      var lv = l.value.val, rv = r.value.val, ok;
      switch (op) {
        case '<':  ok = lv < rv; break;
        case '>':  ok = lv > rv; break;
        case '<=': ok = lv <= rv; break;
        case '>=': ok = lv >= rv; break;
        case '==': case '===': ok = lv === rv; break;
        case '!=': case '!==': ok = lv !== rv; break;
        default: ok = true;
      }
      return smtConst(ok);
    }
    // Sort upgrade: a sym compared with a string literal becomes String.
    var sorts = _mergeSorts(l.sorts, r.sorts);
    if (l.symName && r.value && r.value.kind === 'str') sorts[l.symName] = 'String';
    if (r.symName && l.value && l.value.kind === 'str') sorts[r.symName] = 'String';
    var smtOp;
    if (op === '<')  smtOp = '<';
    else if (op === '>')  smtOp = '>';
    else if (op === '<=') smtOp = '<=';
    else if (op === '>=') smtOp = '>=';
    else if (op === '==' || op === '===') smtOp = '=';
    else if (op === '!=' || op === '!==') {
      return { expr: '(not (= ' + l.expr + ' ' + r.expr + '))',
               sorts: sorts, isBool: true };
    } else return null;
    return { expr: '(' + smtOp + ' ' + l.expr + ' ' + r.expr + ')',
             sorts: sorts, isBool: true };
  }
  function smtArith(op, l, r) {
    if (!l || !r) return null;
    // String theory: x.length, x.indexOf(literal)
    if (op === 'length' && l.symName) {
      var sortsL = _mergeSorts(l.sorts, null);
      sortsL[l.symName] = 'String';
      return { expr: '(str.len ' + l.expr + ')', sorts: sortsL, isBool: false };
    }
    if (op === 'indexOf' && l.symName && r.value && r.value.kind === 'str') {
      var sortsI = _mergeSorts(l.sorts, null);
      sortsI[l.symName] = 'String';
      return { expr: '(str.indexof ' + l.expr + ' ' + r.expr + ' 0)',
               sorts: sortsI, isBool: false };
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
      var smtOp = op === '/' ? 'div' : op === '%' ? 'mod' : op;
      return { expr: '(' + smtOp + ' ' + l.expr + ' ' + r.expr + ')',
               sorts: _mergeSorts(l.sorts, r.sorts), isBool: false };
    }
    return null;
  }
  // String predicates: startsWith / endsWith / includes. `symObj` is a
  // smtSym() result; `value` is the literal substring.
  function smtStrProp(symObj, prop, value) {
    if (!symObj || !symObj.symName) return null;
    var sorts = _mergeSorts(symObj.sorts, null);
    sorts[symObj.symName] = 'String';
    var v = _quoteSmtString(value);
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
  // Browser pages either pre-load z3-solver and set globalThis.__htmldomZ3Init
  // to its init function, or htmldom.js will dynamically import the
  // ES module from a CDN. Node loads via require('z3-solver').
  var _z3 = null;
  var _z3Promise = null;
  function _initZ3() {
    if (_z3Promise) return _z3Promise;
    _z3Promise = (async function () {
      var initFn = null;
      if (typeof globalThis !== 'undefined' && typeof globalThis.__htmldomZ3Init === 'function') {
        initFn = globalThis.__htmldomZ3Init;
      } else if (typeof require === 'function') {
        // Node path.
        var mod = require('z3-solver');
        initFn = mod.init;
      } else {
        // Browser fallback: dynamic ESM import from jsDelivr. The host
        // page's CSP must allow https://cdn.jsdelivr.net.
        var mod = await import('https://cdn.jsdelivr.net/npm/z3-solver@4.16.0/+esm');
        initFn = mod.init;
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
  async function smtSat(formula) {
    if (!formula) return true;
    // Compile-time fold for fully-concrete results.
    if (formula.value && formula.value.kind === 'bool') return formula.value.val;
    var z3 = await _initZ3();
    var decls = '';
    for (var name in formula.sorts) {
      decls += '(declare-const ' + _quoteSmtName(name) + ' ' + (formula.sorts[name] || 'Int') + ')\n';
    }
    var smtlib = decls + '(assert ' + _toBool(formula) + ')\n';
    var solver = new z3.Solver();
    solver.fromString(smtlib);
    var result = await solver.check();
    return result !== 'unsat';
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
            var fv = fb.toks[0].text;
            if (fv === 'true') return smtConst(true);
            if (fv === 'false' || fv === 'null' || fv === 'undefined' || fv === '') return smtConst(false);
            var nv = Number(fv);
            if (!Number.isNaN(nv)) return smtConst(nv);
            return smtConst(fv);
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
          // Find the argument (single string literal).
          var _mArgTok = toks[start + 2];
          var _mArgVal = null;
          if (_mArgTok && _mArgTok.type === 'str' && toks[start + 3] && toks[start + 3].type === 'close') {
            _mArgVal = _mArgTok.text;
          }
          // Resolve aliases for consistent symbolic ID.
          var _mResolvedBase = _mBase;
          if (_mRb && _mRb.kind === 'chain' && _mRb.toks.length === 1 && _mRb.toks[0].type === 'other') _mResolvedBase = _mRb.toks[0].text;
          var _mSymObj = smtSym(_mResolvedBase);
          if (_mMethod === 'startsWith' && _mArgVal !== null) return smtStrProp(_mSymObj, 'startsWith', _mArgVal);
          if (_mMethod === 'endsWith' && _mArgVal !== null) return smtStrProp(_mSymObj, 'endsWith', _mArgVal);
          if (_mMethod === 'includes' && _mArgVal !== null) return smtStrProp(_mSymObj, 'includes', _mArgVal);
          if (_mMethod === 'indexOf' && _mArgVal !== null) return smtArith('indexOf', smtSym(_mResolvedBase), smtConst(_mArgVal));
          // .length is a property, not a method call.
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
  async function smtCheckCondition(condTokens, resolveFunc, resolvePathFunc, pathConstraintStack) {
    var formula = await smtParseExpr(condTokens, 0, condTokens.length, resolveFunc, resolvePathFunc);
    if (!formula) return null;
    // Combine with path constraints: the full context is
    // pathConstraint[0] ∧ pathConstraint[1] ∧ ... ∧ formula
    var context = formula;
    var negContext = smtNot(formula);
    if (pathConstraintStack && pathConstraintStack.length > 0) {
      // Build conjunction of all path constraints.
      var pathConj = pathConstraintStack[0];
      for (var i = 1; i < pathConstraintStack.length; i++) {
        pathConj = smtAnd(pathConj, pathConstraintStack[i]);
      }
      // The true branch is reachable iff pathConj ∧ formula is satisfiable.
      // The false branch is reachable iff pathConj ∧ ¬formula is satisfiable.
      context = smtAnd(pathConj, formula);
      negContext = smtAnd(pathConj, smtNot(formula));
    }
    var sat = await smtSat(context);
    var unsat = await smtSat(negContext);
    return { sat: sat, unsat: unsat };
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
  ]);

  const MATH_CONSTANTS = {
    'Math.PI': Math.PI, 'Math.E': Math.E, 'Math.LN2': Math.LN2, 'Math.LN10': Math.LN10,
    'Math.LOG2E': Math.LOG2E, 'Math.LOG10E': Math.LOG10E,
    'Math.SQRT2': Math.SQRT2, 'Math.SQRT1_2': Math.SQRT1_2,
  };

  // A chain binding wraps an array of operand/plus tokens. Object and array
  // bindings hold named or indexed child bindings (each itself a chain,
  // object, or array) so member access and destructuring can walk into them.
  const chainBinding = (toks) => ({ kind: 'chain', toks });
  const objectBinding = (props) => ({ kind: 'object', props });
  const arrayBinding = (elems) => ({ kind: 'array', elems });
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
      element: (origin) => ({
        kind: 'element',
        elementId: nextElementId++,
        origin,
        attrs: Object.create(null),
        props: Object.create(null),
        styles: Object.create(null),
        classList: [],
        children: [],
        text: null,
        html: null,
        attached: false,
      }),
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

  async function buildScopeState(tokens, stopAt, externallyMutable, trackBuildVarInit, taintConfig) {
    const stack = [{ bindings: Object.create(null), isFunction: true }];
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
    const chainStartsWith = (full, prefix) => {
      if (full.length < prefix.length) return false;
      for (let s = 0; s < prefix.length; s++) {
        if (JSON.stringify(full[s]) !== JSON.stringify(prefix[s])) return false;
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
    // Taint checking helpers (no-ops when taintEnabled is false).
    const checkTaintSource = (exprText) => {
      if (!taintEnabled) return null;
      // Don't flag as taint source if the root is a declared local variable.
      var root = exprText.split('.')[0];
      if (root !== 'window' && root !== 'self' && root !== 'globalThis' && declaredNames.has(root)) return null;
      var label = getTaintSource(exprText);
      if (label) return new Set([label]);
      return null;
    };
    const checkTaintSourceCall = (callExpr) => {
      if (!taintEnabled) return null;
      var root = callExpr.split('.')[0];
      if (root !== 'window' && root !== 'self' && root !== 'globalThis' && declaredNames.has(root)) return null;
      var label = getTaintSourceCall(callExpr);
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
    const checkSinkAssignment = (el, propName, valBinding, tok) => {
      if (!taintEnabled || !valBinding) return;
      var toks = valBinding.kind === 'chain' ? valBinding.toks : null;
      var taint = toks ? collectChainTaint(toks) : null;
      if (!taint || !taint.size) return;
      var tag = getElementTag(el);
      var sinkInfo = classifySink(propName, tag);
      if (sinkInfo && sinkInfo.severity !== 'safe') {
        var loc = tok && tok._src ? { expr: tok.text || propName, line: countLines(tok._src, tok.start) } : null;
        recordTaintFinding(sinkInfo.type, sinkInfo.severity, propName, tag, taint, taintCondStack, loc);
      }
    };
    const checkSinkSetAttribute = (el, attrName, valBinding) => {
      if (!taintEnabled || !valBinding || !attrName) return;
      var toks = valBinding.kind === 'chain' ? valBinding.toks : null;
      var taint = toks ? collectChainTaint(toks) : null;
      if (!taint || !taint.size) return;
      var sinkType = ATTR_SINKS[attrName.toLowerCase()];
      if (sinkType) {
        var sev = sinkType === 'code' ? 'critical' : sinkType === 'css' ? 'medium' : 'high';
        recordTaintFinding(sinkType, sev, attrName, getElementTag(el), taint, taintCondStack);
      }
      // Also check if it's a URL attribute on a sensitive element
      var tag = getElementTag(el);
      if (tag && (attrName === 'src' || attrName === 'href' || attrName === 'action')) {
        var sinkInfo = classifySink(attrName, tag);
        if (sinkInfo) {
          recordTaintFinding(sinkInfo.type, sinkInfo.severity, attrName, tag, taint, taintCondStack);
        }
      }
    };
    const checkSinkCall = (callExpr, argBindings, tok) => {
      if (!taintEnabled || !argBindings) return;
      var sinkInfo = TAINT_CALL_SINKS[callExpr];
      if (!sinkInfo) return;
      for (var ai = 0; ai < argBindings.length; ai++) {
        var ab = argBindings[ai];
        if (!ab) continue;
        var toks = ab.kind === 'chain' ? ab.toks : null;
        var taint = toks ? collectChainTaint(toks) : null;
        if (taint && taint.size) {
          var loc = tok && tok._src ? { expr: callExpr, line: countLines(tok._src, tok.start) } : null;
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
    const declBlock = (name, value) => { declaredNames.add(name); topBlock().bindings[name] = asRef(name, value); };
    const declFunction = (name, value) => {
      declaredNames.add(name);
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].isFunction) { stack[i].bindings[name] = asRef(name, value); return; }
      }
    };
    const assignName = (name, value) => {
      for (let i = stack.length - 1; i >= 0; i--) {
        if (name in stack[i].bindings) { stack[i].bindings[name] = asRef(name, value); return; }
      }
      stack[0].bindings[name] = asRef(name, value); // implicit global
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
          b = chainBinding([deriveExprRef(b.toks[0].text + '.' + parts.slice(i).join('.'), b.toks)]);
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

    // Bind names from `pattern` by walking into `source` (a binding).
    const applyPatternBindings = async (pattern, source, bind) => {
      if (pattern.kind === 'obj-pattern') {
        const props = source && source.kind === 'object' ? source.props : null;
        const seen = Object.create(null);
        for (const entry of pattern.entries) {
          seen[entry.key] = true;
          let val = props ? (props[entry.key] || null) : null;
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
            bind(pattern.rest, null);
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
          if (val === null && entry.dflt) val = await resolveDefault(entry.dflt);
          bind(entry.name, val);
        }
        if (pattern.rest) {
          if (elems) {
            bind(pattern.rest, arrayBinding(elems.slice(pattern.entries.length)));
          } else {
            bind(pattern.rest, null);
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
      const t = tks[k];
      if (!t) return null;
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
      if (!ft || ft.type !== 'other' || ft.text !== 'function') return null;
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
      return { binding: functionBinding(params, fj, bodyEnd, true), next: bodyEnd };
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
        return {
          binding: functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock),
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
            if (!r) break;
            bind = r.bind;
            next = r.next;
            continue;
          }
          // Object method call: cur is a function binding accessed via .prop,
          // followed by (args). Inline the function.
          if (isCall && cur && cur.kind === 'function') {
            var _omArgs = await readCallArgBindings(next + 1, stop);
            if (_omArgs) {
              // Pass the receiver object as 'this' for method calls.
              var _omResult = await instantiateFunction(cur, _omArgs.bindings, bind);
              if (_omResult && _omResult.kind) { bind = _omResult; next = _omArgs.next; continue; }
              if (_omResult) { bind = chainBinding(_omResult); next = _omArgs.next; continue; }
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
            if (body) { fn = functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock); fnNext = body.next; }
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
            if (body) { reduceFn = functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock); reduceFnNext = body.next; }
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
          var _et = chainAsExprText(baseResult.bind);
          if (_et === null) return null;
          baseResult = { bind: chainBinding([exprRef(_pf.text + ' ' + _et)]), next: baseResult.next };
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
            // Class instantiation: create instance with class methods.
            var _newJ = k + 2;
            if (tks[_newJ] && tks[_newJ].type === 'open' && tks[_newJ].char === '(') {
              var _nd = 1; _newJ++;
              while (_newJ < stop && _nd > 0) { if (tks[_newJ].type === 'open' && tks[_newJ].char === '(') _nd++; if (tks[_newJ].type === 'close' && tks[_newJ].char === ')') _nd--; _newJ++; }
            }
            // Create instance object with copies of all class methods.
            var _instProps = Object.create(null);
            for (var _ck in _newBind.props) _instProps[_ck] = _newBind.props[_ck];
            var _inst = objectBinding(_instProps);
            return { bind: _inst, next: _newJ };
          }
        }
        let j = k + 1;
        if (tks[j] && tks[j].type === 'other' && IDENT_OR_PATH_RE.test(tks[j].text)) j++;
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
        if (taintEnabled && isCall && TAINT_CALL_SINKS[t.text] && !declaredNames.has(t.text.split('.')[0])) {
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
          var _opaqueTaint = checkTaintSource(_opaqueText);
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
              if (taintEnabled && !isSanitizer(t.text)) {
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
            if (taintEnabled && isSanitizer(t.text)) {
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
    const instantiateFunction = async (fn, argBindings, thisBinding) => {
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
        const r = await readConcatExpr(fn.bodyStart, fn.bodyEnd, TERMS_NONE);
        if (r && r.next === fn.bodyEnd) result = r.toks;
      }
      tks = savedTks;
      taintFnDepth = savedTaintFnDepth;
      stack.pop();
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
      if (chain.toks.length !== 1) return null;
      const t = chain.toks[0];
      if (t.type === 'str') {
        // Quote literal strings; bare numbers flow as-is.
        const n = Number(t.text);
        if (!Number.isNaN(n) && String(n) === t.text) return t.text;
        return JSON.stringify(t.text);
      }
      if (t.type === 'other') return t.text;
      if (t.type === 'cond') {
        const tt = chainAsExprText(chainBinding(t.ifTrue));
        const ft = chainAsExprText(chainBinding(t.ifFalse));
        if (tt !== null && ft !== null) return '(' + t.condExpr + ' ? ' + tt + ' : ' + ft + ')';
      }
      return null;
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
    const _expandBindWithLVs = (bind, branchLVs) => {
      if (!bind || bind.kind !== 'chain') return bind ? bind.toks : [];
      const lvMap = Object.create(null);
      for (const lv of branchLVs) { if (!lvMap[lv.name]) lvMap[lv.name] = []; lvMap[lv.name].push(lv); }
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
    const _snapshotBindings = () => {
      const snap = Object.create(null);
      for (let si = stack.length - 1; si >= 0; si--)
        for (const name in stack[si].bindings)
          if (!(name in snap)) snap[name] = stack[si].bindings[name];
      return snap;
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
      'var':           'decl-block-scope(name); mutate B',
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
      // Expression statements are handled after the keyword dispatch.
      'expression':    'read LHS; if assign, mutate B; if call, side-effects',
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
      for (const name in _task.snapshot) assignName(name, _task.snapshot[name]);
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
      for (const name in ctx.ifBindings) {
        const ifB = ctx.ifBindings[name];
        const elB = elseBindings[name] || _task.snapshot[name];
        if (!ifB || ifB.kind !== 'chain' || !elB || elB.kind !== 'chain') continue;
        const ifFull = _expandBindWithLVs(ifB, ctx.ifLoopVars);
        const elFull = _expandBindWithLVs(elB, elseLoopVars);
        if (JSON.stringify(ifFull) === JSON.stringify(elFull)) continue;
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
        }
      }
      for (const name in ctx.ifBindings) {
        if (trackBuildVar && trackBuildVar.has(name)) continue;
        const ifB = ctx.ifBindings[name], elB = elseBindings[name] || _task.snapshot[name];
        if (ifB === elB || JSON.stringify(ifB) === JSON.stringify(elB)) continue;
        assignName(name, chainBinding([deriveExprRef(name, ifB && ifB.kind === 'chain' ? ifB.toks : null, elB && elB.kind === 'chain' ? elB.toks : null)]));
      }
      continue;
    }
    // --- Action: restore after try-body, queue catch ---
    if (_task.type === 'try_restore') {
      const tryLoopVars = loopVars.splice(_task.lvBefore);
      const tryBindings = _snapshotBindings();
      for (const name in _task.snapshot) assignName(name, _task.snapshot[name]);
      _task.ctx.tryBindings = tryBindings;
      _task.ctx.tryLoopVars = tryLoopVars;
      _task.ctx.lvBefore2 = loopVars.length;
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
        const tryFull = _expandBindWithLVs(tryB, ctx.tryLoopVars);
        const catchFull = _expandBindWithLVs(catchB, catchLoopVars);
        if (JSON.stringify(tryFull) === JSON.stringify(catchFull)) continue;
        const snapB = _task.snapshot[name];
        if (!snapB || snapB.kind !== 'chain') {
          assignName(name, chainBinding([deriveExprRef(name, tryB.toks, catchB.toks)]));
        } else if (trackBuildVar && trackBuildVar.has(name)) {
          const snapFull = snapB.toks;
          const tryAppended = chainStartsWith(tryFull, snapFull);
          const catchAppended = chainStartsWith(catchFull, snapFull);
          const tryExtra = tryAppended ? stripLeadingPlus(tryFull.slice(snapFull.length)) : tryFull;
          const catchExtra = catchAppended ? stripLeadingPlus(catchFull.slice(snapFull.length)) : catchFull;
          const tryCatchTok = { type: 'trycatch', tryBody: tryExtra, catchBody: catchExtra, catchParam: _task.catchParam };
          if (tryAppended && catchAppended) assignName(name, chainBinding([...snapB.toks, SYNTH_PLUS, tryCatchTok]));
          else assignName(name, chainBinding([tryCatchTok]));
        } else {
          assignName(name, chainBinding([deriveExprRef(name, tryB.toks, catchB.toks)]));
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
      for (const name in _task.snapshot) assignName(name, _task.snapshot[name]);
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
        if (b && (!snap || JSON.stringify(b) !== JSON.stringify(snap))) switchChanged.add(name);
      }
      for (const name of switchChanged) {
        var _swToks = [];
        for (var _cr of caseResults) if (_cr.bindings[name] && _cr.bindings[name].kind === 'chain') _swToks.push(_cr.bindings[name].toks);
        assignName(name, chainBinding([deriveExprRef.apply(null, [name].concat(_swToks))]));
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
            assignName(name, chainBinding([deriveExprRef(name, b.toks)]));
          }
        }
      }
      const t = tokens[i];

      if (t.type === 'open' && t.char === '{') {
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
            var _forInOfTaint = null;
            if (taintEnabled) {
              for (var _fi = i + 2; _fi < j; _fi++) {
                if (tokens[_fi].type === 'other' && (tokens[_fi].text === 'in' || tokens[_fi].text === 'of')) {
                  var _forInOf = tokens[_fi].text;
                  var _fiVarStart = i + 2;
                  if (tokens[_fiVarStart].type === 'other' && (tokens[_fiVarStart].text === 'var' || tokens[_fiVarStart].text === 'let' || tokens[_fiVarStart].text === 'const')) _fiVarStart++;
                  var _fiVarName = tokens[_fiVarStart] && IDENT_RE.test(tokens[_fiVarStart].text) ? tokens[_fiVarStart].text : null;
                  if (_fiVarName) {
                    var _fiExprVal = await readValue(_fi + 1, j, null);
                    var _fiIterBind = _fiExprVal ? _fiExprVal.binding : null;
                    var _fiTaintSources = [];
                    if (_fiIterBind && _fiIterBind.kind === 'array') {
                      for (var _fie = 0; _fie < _fiIterBind.elems.length; _fie++) {
                        if (_fiIterBind.elems[_fie] && _fiIterBind.elems[_fie].kind === 'chain') _fiTaintSources.push(_fiIterBind.elems[_fie].toks);
                      }
                    } else if (_fiIterBind && _fiIterBind.kind === 'object' && _forInOf === 'of') {
                      for (var _fip in _fiIterBind.props) {
                        if (_fiIterBind.props[_fip] && _fiIterBind.props[_fip].kind === 'chain') _fiTaintSources.push(_fiIterBind.props[_fip].toks);
                      }
                    } else if (_fiIterBind && _fiIterBind.kind === 'chain') {
                      _fiTaintSources.push(_fiIterBind.toks);
                    }
                    if (_fiTaintSources.length) _forInOfTaint = { varName: _fiVarName, sources: _fiTaintSources };
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
                for (var _uk = _sc2 + 1; _uk < j; _uk++) {
                  var _ut = tokens[_uk];
                  if (_ut.type === 'other' && _ut.text === _cName) {
                    var _un = tokens[_uk + 1];
                    if (_un && _un.type === 'op' && _un.text === '++') { _ascending = true; _step = 1; break; }
                    if (_un && _un.type === 'op' && _un.text === '--') { _ascending = false; _step = 1; break; }
                    if (_un && _un.type === 'op' && (_un.text === '+=' || _un.text === '-=')) {
                      var _sTok = tokens[_uk + 2];
                      if (_sTok && _sTok.type === 'other' && /^\d+$/.test(_sTok.text)) {
                        _ascending = _un.text === '+=';
                        _step = parseInt(_sTok.text, 10);
                        break;
                      }
                    }
                  }
                  if (_ut.type === 'op' && (_ut.text === '++' || _ut.text === '--')) {
                    var _un2 = tokens[_uk + 1];
                    if (_un2 && _un2.type === 'other' && _un2.text === _cName) {
                      _ascending = _ut.text === '++'; _step = 1;
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
                // BOUNDED UNROLLING as an SMT refinement: if the loop has
                // a concrete upper bound AND the iteration count is ≤
                // UNROLL_LIMIT, push a disjunction of concrete values
                // `i === init || i === init±step || ...` so the theory
                // solver can prove properties that depend on specific
                // iteration values, not just the range [init, bound).
                var UNROLL_LIMIT = 8;
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
                  var _bound = parseInt(_boundTok.text, 10);
                  var _iterCount;
                  if (_ascending) {
                    if (_boundOp === '<') _iterCount = Math.max(0, Math.ceil((_bound - _cInit) / _step));
                    else if (_boundOp === '<=') _iterCount = Math.max(0, Math.floor((_bound - _cInit) / _step) + 1);
                    else return;
                  } else {
                    if (_boundOp === '>') _iterCount = Math.max(0, Math.ceil((_cInit - _bound) / _step));
                    else if (_boundOp === '>=') _iterCount = Math.max(0, Math.floor((_cInit - _bound) / _step) + 1);
                    else return;
                  }
                  if (_iterCount > 0 && _iterCount <= UNROLL_LIMIT) {
                    // Build disjunction: i === v_0 OR i === v_1 OR ...
                    var _disj = null;
                    var _disjExprs = [];
                    for (var _it = 0; _it < _iterCount; _it++) {
                      var _val = _ascending ? (_cInit + _it * _step) : (_cInit - _it * _step);
                      var _atom = smtCmp('===', _cSym, smtConst(_val));
                      _disj = _disj ? smtOr(_disj, _atom) : _atom;
                      _disjExprs.push(_cName + ' === ' + _val);
                    }
                    _extraLoopFormulas.push(_disj);
                    _extraLoopExprs.push('unroll(' + _iterCount + '): ' + _disjExprs.join(' || '));
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
          // so extraction and inner declarations are processed.
          i = _clsIdx; // point to '{', the walker will push a scope frame
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
        if (taintEnabled && eqTok && eqTok.type === 'sep' && eqTok.char === '=' && isNavSink(t.text, declaredNames)) {
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
            }
            i = _timerArgs.next - 1;
            continue;
          }
        }
      }
      // Bare function call as a statement: `render(input);` or `obj.method(args);`.
      // Resolve the callee; if it's a function binding, inline it for side effects.
      if (t.type === 'other' && IDENT_OR_PATH_RE.test(t.text)) {
        const callParen = tokens[i + 1];
        if (callParen && callParen.type === 'open' && callParen.char === '(') {
          var calleeBind = await resolvePath(t.text);
          if (calleeBind && calleeBind.kind === 'function') {
            var callArgs = await readCallArgBindings(i + 1, stop);
            if (callArgs) {
              await instantiateFunction(calleeBind, callArgs.bindings);
              i = callArgs.next - 1;
              if (taintEnabled && TAINT_CALL_SINKS[t.text] && !declaredNames.has(t.text.split('.')[0])) {
                checkSinkCall(t.text, callArgs.bindings, t);
              }
              continue;
            }
          }
          // Taint: even if callee isn't inlinable, check if it's a call-based sink.
          if (taintEnabled && TAINT_CALL_SINKS[t.text] && !declaredNames.has(t.text.split('.')[0])) {
            var sinkArgs = await readCallArgBindings(i + 1, stop);
            if (sinkArgs) {
              checkSinkCall(t.text, sinkArgs.bindings, t);
              i = sinkArgs.next - 1;
              continue;
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
        var _navType = isNavSink(t.text, declaredNames);
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
          }
          i = i + 1;
          continue;
        }
        // Path compound assignment: obj.prop += value
        if (eqTok && eqTok.type === 'sep' && (eqTok.char === '=' || eqTok.char === '+=')) {
          const parts = t.text.split('.');
          const baseBind = resolve(parts[0]);
          // Object property assignment: obj.prop = value
          if (baseBind && baseBind.kind === 'object' && parts.length === 2) {
            const r = await readValue(i + 2, stop, TERMS_TOP);
            if (r && r.binding) {
              if (eqTok.char === '+=') {
                var prev = baseBind.props[parts[1]];
                if (prev && prev.kind === 'chain' && r.binding.kind === 'chain') {
                  baseBind.props[parts[1]] = chainBinding([...prev.toks, SYNTH_PLUS, ...r.binding.toks]);
                } else {
                  baseBind.props[parts[1]] = r.binding;
                }
              } else {
                baseBind.props[parts[1]] = r.binding;
              }
            }
            i = skipExpr(i + 2, stop) - 1;
            continue;
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
            if (TAINT_SINKS[sinkProp] || sinkProp === 'src' || sinkProp === 'href' || sinkProp === 'action' || sinkProp === 'srcdoc') {
              const r = await readValue(i + 2, stop, TERMS_TOP);
              const val = r ? r.binding : null;
              if (val && val.kind === 'chain') {
                var _taint = collectChainTaint(val.toks);
                if (_taint && _taint.size) {
                  // Try to resolve element type from the base binding.
                  var _elTag = baseBind ? getElementTag(baseBind) : null;
                  var _sinkInfo = classifySink(sinkProp, _elTag);
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
                  // Build tainted param binding if this event type has known sources.
                  var _evParamBindings = [];
                  if (_evTypeStr && EVENT_TAINT_SOURCES[_evTypeStr] && _evHandler.params && _evHandler.params.length > 0) {
                    var _evSources = EVENT_TAINT_SOURCES[_evTypeStr];
                    var _pn = _evHandler.params[0].name;
                    var _evRef = exprRef(_pn);
                    _evRef.taint = new Set(Object.values(_evSources));
                    _evParamBindings.push(chainBinding([_evRef]));
                  } else if (_evHandler.params && _evHandler.params.length > 0) {
                    // Unknown event type: param is opaque, no taint.
                    _evParamBindings.push(chainBinding([exprRef(_evHandler.params[0].name)]));
                  }
                  // Walk the handler body twice: event handlers fire
                  // multiple times. The first walk establishes mutations
                  // (state transitions). The second walk sees accumulated
                  // state and can reach branches guarded by it.
                  // Suppress findings during the first walk.
                  var _prevInEH = inEventHandler;
                  inEventHandler = true;
                  var _savedFindings = taintFindings ? taintFindings.length : 0;
                  await instantiateFunction(_evHandler, _evParamBindings);
                  if (taintFindings) taintFindings.length = _savedFindings; // discard first-walk findings
                  await instantiateFunction(_evHandler, _evParamBindings);
                  inEventHandler = _prevInEH;
                }
                i = _evArgs.next - 1;
                continue;
              }
            }
            // Taint: detect call-based sinks (eval, document.write, etc.).
            if (taintEnabled && TAINT_CALL_SINKS[t.text] && !declaredNames.has(t.text.split('.')[0])) {
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
    await walkRange(0, stop);

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
    if (/^on[a-z]+$/.test(attrName)) return null;
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
  async function convertHtmlBuilderFunctions(source) {
    const result = { source: source, converted: new Set() };
    const toks = tokenize(source);
    const replacements = []; // { start, end, replacement }

    for (let i = 0; i < toks.length; i++) {
      // Look for: function NAME ( params ) {
      if (toks[i].type !== 'other' || toks[i].text !== 'function') continue;
      const funcStart = toks[i].start;

      // Skip to name.
      let j = i + 1;
      while (j < toks.length && toks[j].type === 'sep' && toks[j].char === ';') j++;
      if (j >= toks.length || toks[j].type !== 'other') continue;
      const funcName = toks[j].text;
      j++;

      // Skip to (.
      if (j >= toks.length || toks[j].type !== 'open' || toks[j].char !== '(') continue;
      const paramsStart = toks[j].end;
      j++;

      // Find matching ).
      let parenDepth = 1;
      while (j < toks.length && parenDepth > 0) {
        if (toks[j].type === 'open' && toks[j].char === '(') parenDepth++;
        else if (toks[j].type === 'close' && toks[j].char === ')') parenDepth--;
        if (parenDepth > 0) j++;
      }
      if (parenDepth !== 0 || j >= toks.length) continue;
      const params = source.slice(paramsStart, toks[j].start);
      j++;

      // Skip to {.
      if (j >= toks.length || toks[j].type !== 'open' || toks[j].char !== '{') continue;
      const bodyStartPos = toks[j].end;
      j++;

      // Find matching } using the tokenizer's brace tracking.
      let braceDepth = 1;
      while (j < toks.length && braceDepth > 0) {
        if (toks[j].type === 'open' && toks[j].char === '{') braceDepth++;
        else if (toks[j].type === 'close' && toks[j].char === '}') braceDepth--;
        if (braceDepth > 0) j++;
      }
      if (braceDepth !== 0 || j >= toks.length) continue;
      const bodyEndPos = toks[j].start;
      const funcEnd = toks[j].end;
      const body = source.slice(bodyStartPos, bodyEndPos);

      // Check the build-and-return pattern using the tokenizer to
      // avoid matching inside strings or comments.
      let hasInnerHTML = false;
      // Tokenize the body to check for the build-and-return pattern.
      // Find any variable that: (1) is declared with var/let X = ...,
      // (2) has X += ..., and (3) has return X. The variable can have
      // any name, not just "html".
      const bodyToks = tokenize(body);
      const declaredVars = new Set();
      const concatVars = new Set();
      const returnedVars = new Set();
      for (let bi = 0; bi < bodyToks.length; bi++) {
        const bt = bodyToks[bi];
        if (bt.type === 'other' && /\.innerHTML$/.test(bt.text)) hasInnerHTML = true;
        if (bt.type === 'other' && (bt.text === 'var' || bt.text === 'let') &&
            bi + 1 < bodyToks.length && bodyToks[bi + 1].type === 'other' && IDENT_RE.test(bodyToks[bi + 1].text) &&
            bi + 2 < bodyToks.length && bodyToks[bi + 2].type === 'sep' && bodyToks[bi + 2].char === '=') {
          declaredVars.add(bodyToks[bi + 1].text);
        }
        if (bt.type === 'other' && IDENT_RE.test(bt.text) &&
            bi + 1 < bodyToks.length && bodyToks[bi + 1].type === 'sep' && bodyToks[bi + 1].char === '+=') {
          concatVars.add(bt.text);
        }
        if (bt.type === 'other' && bt.text === 'return' &&
            bi + 1 < bodyToks.length && bodyToks[bi + 1].type === 'other' && IDENT_RE.test(bodyToks[bi + 1].text)) {
          returnedVars.add(bodyToks[bi + 1].text);
        }
      }
      // Find the build variable: declared, concatenated, and returned.
      let buildVarName = null;
      for (const v of declaredVars) {
        if (concatVars.has(v) && returnedVars.has(v)) { buildVarName = v; break; }
      }
      if (hasInnerHTML || !buildVarName) continue;

      // Convert: replace `return html` with a synthetic innerHTML
      // assignment, run through the converter, wrap in fragment.
      // Find the return html token position in body to do the replacement.
      let syntheticBody = body;
      for (let bi = 0; bi < bodyToks.length; bi++) {
        if (bodyToks[bi].type === 'other' && bodyToks[bi].text === 'return' &&
            bi + 1 < bodyToks.length && bodyToks[bi + 1].type === 'other' && bodyToks[bi + 1].text === buildVarName) {
          const retStart = bodyToks[bi].start;
          let retEnd = bodyToks[bi + 1].end;
          if (bi + 2 < bodyToks.length && bodyToks[bi + 2].type === 'sep' && bodyToks[bi + 2].char === ';') {
            retEnd = bodyToks[bi + 2].end;
          }
          syntheticBody = body.slice(0, retStart) + '__frag.innerHTML = ' + buildVarName + ';' + body.slice(retEnd);
          break;
        }
      }

      const extractions = await extractAllHTML(syntheticBody);
      if (extractions.length > 0) {
        const ex = extractions[0];
        const used = new Set();
        const domBlock = await convertOne(syntheticBody, ex, false, false, used, '__frag', result.converted);
        if (domBlock) {
          let converted = domBlock
            .replace('__frag.replaceChildren();\n', '')
            .replace(/__frag/g, '__f');
          const indented = converted.split('\n').map(function(l) { return '  ' + l; }).join('\n');
          const newBody = '  var __f = document.createDocumentFragment();\n' + indented + '\n  return __f;\n';
          replacements.push({
            start: funcStart,
            end: funcEnd,
            replacement: 'function ' + funcName + '(' + params + ') {\n' + newBody + '}'
          });
          result.converted.add(funcName);
        }
      }
    }
    // Apply replacements in reverse order.
    if (replacements.length) {
      let s = source;
      replacements.sort(function(a, b) { return b.start - a.start; });
      for (const r of replacements) {
        s = s.slice(0, r.start) + r.replacement + s.slice(r.end);
      }
      result.source = s;
    }
    return result;
  }

  // Core conversion: takes a raw input string, returns the converted output.
  // sourceName: optional filename for naming output files (e.g. 'index.html').
  async function convertRaw(raw, sourceName, externalDomFunctions) {
    // Derive the handlers filename from the source.
    const baseName = sourceName ? sourceName.replace(/\.[^.]+$/, '') : 'index';
    const handlersFile = baseName + '.handlers.js';
    try {
      // If input starts with HTML, use the HTML tokenizer to split into
      // HTML portions and <script> blocks. Convert inline scripts for
      // innerHTML replacements, extract unsafe attributes (events, styles,
      // javascript: URLs) into a separate JS file.
      if (/^\s*</.test(raw)) {
        const markup = await convertHtmlMarkup(raw, sourceName || 'index.html');
        // Combine inline script blocks and process innerHTML assignments.
        const jsFileLines = [];
        const sharedUsed = new Set();
        if (markup.extractedScripts.length > 0) {
          const separator = '\n/*__BLOCK_SEP__*/\n';
          let combinedJs = markup.extractedScripts.map(function(s) { return s.content; }).join(separator);
          const prepass = await convertHtmlBuilderFunctions(combinedJs);
          combinedJs = prepass.source;
          const extractions = await extractAllHTML(combinedJs);
          if (extractions.length === 0) {
            for (const s of markup.extractedScripts) jsFileLines.push(s.content.trim());
          } else {
            const trimmed = combinedJs.trim();
            let scriptOutput = '';
            let cursor = 0;
            for (const ex of extractions) {
              if (ex.srcStart === undefined) continue;
              const domBlock = await convertOne(combinedJs, ex, false, false, sharedUsed, null, prepass.converted);
              let srcStart = ex.srcStart;
              let srcEnd = ex.srcEnd;
              if (ex.buildVarDeclStart >= 0) {
                srcStart = ex.buildVarDeclStart;
              }
              let pre = trimmed.slice(cursor, srcStart);
              pre = pre.replace(/\n\s*$/, '\n');
              scriptOutput += pre;
              if (domBlock) {
                let lineStart = srcStart;
                while (lineStart > 0 && trimmed[lineStart - 1] !== '\n') lineStart--;
                const indent = trimmed.slice(lineStart, srcStart).match(/^(\s*)/)[1];
                const indented = domBlock.split('\n').map(function(line) { return indent + line; }).join('\n');
                scriptOutput += indented;
                if (!indented.endsWith('\n')) scriptOutput += '\n';
              }
              cursor = srcEnd;
              while (cursor < trimmed.length && (trimmed[cursor] === ';' || trimmed[cursor] === ' ' || trimmed[cursor] === '\n')) cursor++;
            }
            scriptOutput += trimmed.slice(cursor);
            scriptOutput = scriptOutput.replace(/\n\/\*__BLOCK_SEP__\*\/\n/g, '\n');
            jsFileLines.push(scriptOutput.trim());
          }
        }
        // Build output: cleaned HTML + handlers JS + extracted script JS.
        const handlersContent = markup.handlers ? markup.handlers.content : '';
        const allJs = [handlersContent].concat(jsFileLines).filter(Boolean);
        const jsFile = allJs.length ? '// Generated by HTML to DOM API Converter\n// Extracted inline handlers, styles, and innerHTML conversions.\n\n' + allJs.join('\n\n') + '\n' : '';
        if (jsFile) {
          return ('// === ' + (sourceName || 'index.html') + ' ===\n' + markup.html + '\n\n// === ' + handlersFile + ' ===\n' + jsFile);
        } else {
          return (markup.html);
        }
      }

      // Pure JS input (no leading <).
      // The scope walker handles function inlining (including complex
      // builder functions with loops). External DOM function names
      // from cross-file pre-pass are passed via externalDomFunctions.
      const processedRaw = raw;
      const allDomFunctions = new Set();
      if (externalDomFunctions) {
        for (const fn of externalDomFunctions) allDomFunctions.add(fn);
      }
      const extractions = await extractAllHTML(processedRaw);
      if (extractions.length === 0) {
        const summary = await summarizeDomConstruction(processedRaw);
        if (summary) { return summary; }
        return (await convertOne(processedRaw, await extractHTML(processedRaw), false, false) || '');
        return;
      }
      // Inline rewriting: preserve original code, replace innerHTML sites.
      const trimmed = processedRaw.trim();
      let output = '';
      let cursor = 0;
      const sharedUsed = new Set();
      // Reserve all identifiers from the source code so generated
      // variable names don't collide with user variables.
      const srcToks = extractions[0] && extractions[0]._tokens ? extractions[0]._tokens : tokenize(trimmed);
      for (const st of srcToks) {
        if (st.type === 'other' && IDENT_RE.test(st.text)) sharedUsed.add(st.text);
      }
      // Also reserve target identifier roots.
      for (const ex of extractions) {
        if (ex.target) {
          const root = ex.target.match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
          if (root) sharedUsed.add(root[0]);
        }
      }
      for (const ex of extractions) {
        if (ex.srcStart === undefined) continue;
        const target = ex.target || 'document.body';
        const assignOp = ex.assignOp || '=';

        const domBlock = await convertOne(processedRaw, ex, false, false, sharedUsed, null, allDomFunctions);
        let srcStart = ex.srcStart;
        let srcEnd = ex.srcEnd;
        // When the chain carries preserve tokens, the region starts at
        // the build var declaration. No findBuildRegion needed.
        if (ex.buildVarDeclStart >= 0) {
          srcStart = ex.buildVarDeclStart;
        }
        let pre = trimmed.slice(cursor, srcStart);
        pre = pre.replace(/\n\s*$/, '\n');
        output += pre;
        if (domBlock) {
          let lineStart = srcStart;
          while (lineStart > 0 && trimmed[lineStart - 1] !== '\n') lineStart--;
          const indent = trimmed.slice(lineStart, srcStart).match(/^(\s*)/)[1];
          output += domBlock.split('\n').map((line) => indent + line).join('\n');
          if (!output.endsWith('\n')) output += '\n';
        }
        cursor = srcEnd;
        while (cursor < trimmed.length && (trimmed[cursor] === ';' || trimmed[cursor] === ' ' || trimmed[cursor] === '\n')) cursor++;
      }
      output += trimmed.slice(cursor);
      return output;
    } catch (err) {
      return ('// Error: ' + err.message);
    }
  }

  // UI wrapper: reads from editor, converts, writes to output.
  async function convert() {
    const raw = (typeof window !== 'undefined' && window._monacoIn) ? window._monacoIn.getValue() : ($('in') ? $('in').value : '');
    setOutput(await convertRaw(raw) || '');
  }

  let lastOutput = '';
  function setOutput(text) {
    lastOutput = text;
    if (typeof window !== 'undefined' && window._monacoOut) {
      window._monacoOut.setValue(text);
    } else if ($('out')) {
      $('out').value = text;
    }
  }

  // Summarize the DOM tree the script constructs via createElement /
  // appendChild / setAttribute as HTML comments. The script's own code
  // is already safe (no innerHTML), so there's nothing to rewrite; the
  // summary shows what the user ends up building.
  async function summarizeDomConstruction(raw) {
    const dom = await extractAllDOM(raw);
    if (!dom || !dom.roots || !dom.roots.length) return '';
    const hasCreate = dom.ops && dom.ops.some((o) => o.op === 'create' || o.op === 'createTextNode');
    if (!hasCreate) return '';
    const lines = ['// === DOM construction (already safe; summary only) ==='];
    for (const root of dom.roots) {
      if (root.kind === 'textNode') continue;
      if (!root.origin || root.origin.kind !== 'create') continue;
      lines.push('//   ' + (dom.html[root.id] || '').replace(/\n/g, ' '));
    }
    // Show what the attached children of looked-up elements become.
    for (const el of dom.elements) {
      if (el.kind !== 'element') continue;
      if (!el.origin || el.origin.kind !== 'lookup') continue;
      if (!el.children.length) continue;
      const where = '#' + el.origin.value + (el.origin.by === 'selector' ? ' (query)' : '');
      lines.push('//   ' + where + ' receives: ' + (dom.html[el.id] || '').replace(/\n/g, ' '));
    }
    return lines.length > 1 ? lines.join('\n') : '';
  }

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
  async function convertOne(raw, result, multi, emitTitle, sharedUsed, parentOverride, domFunctions) {
    const { target, assignProp, assignOp } = result;

    let parent = parentOverride || 'document.body';
    let parentFromAssignment = false;
    if (target) {
      parent = assignProp === 'outerHTML' ? target + '.parentNode' : target;
      parentFromAssignment = true;
    }

    const domFuncs = domFunctions || new Set();
    const lines = [];
    const used = sharedUsed || new Set();

    const parentRoot = parent.match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
    if (parentRoot) used.add(parentRoot[0]);
    const SVG_NS_STR = "'http://www.w3.org/2000/svg'";
    const MATHML_NS_STR = "'http://www.w3.org/1998/Math/MathML'";

    if (parentFromAssignment && assignOp === '=' && assignProp === 'innerHTML') {
      lines.push(target + '.replaceChildren();');
    }

    const chainTokens = result.chainTokens || [];
    if (chainTokens.length === 0 || (chainTokens.length === 1 && chainTokens[0].type === 'str' && chainTokens[0].text === '')) {
      return lines.length ? lines.join('\n') : '// (no nodes parsed)';
    }

    // Compile-time parent stack: tracks which variable is the current
    // parent at each nesting level. No runtime parent pointer needed.
    var parentStack = [parent]; // stack of variable names
    var runtimeParentVars = new Set(); // variables that are runtime parent pointers
    var inUnbalancedLoop = false; // true when inside a loop with unbalanced tags
    function curParent() { return parentStack[parentStack.length - 1]; }
    function isRuntimeVar(name) { return runtimeParentVars.has(name); }

    // Stateful HTML parser that persists across chain tokens.
    // States: TEXT, TAG_OPEN, ATTRS, ATTR_NAME, ATTR_EQ,
    //         ATTR_VAL_DQ, ATTR_VAL_SQ, ATTR_VAL_UQ, TAG_CLOSE, COMMENT
    const S_TEXT = 0, S_TAG_OPEN = 1, S_ATTRS = 2, S_ATTR_NAME = 3;
    const S_ATTR_EQ = 4, S_ATTR_VAL_DQ = 5, S_ATTR_VAL_SQ = 6;
    const S_ATTR_VAL_UQ = 7, S_TAG_CLOSE = 8, S_COMMENT = 9;
    let hState = S_TEXT;
    let hTag = '';
    let hAttrName = '';
    let hAttrVal = '';
    let hAttrExprs = []; // dynamic expressions embedded in attribute value
    let hAttrs = [];     // { name, value, dynamic:bool, exprs:[] }
    let hTagVar = '';     // variable name for current element being built
    let hCommentBuf = '';
    let hTextBuf = '';
    let hParentTags = []; // track parent tag names for auto-tbody
    let hTbodyVar = null; // variable for auto-inserted tbody

    // Infer the target element's tag from the chain content. If the
    // first HTML tag is <tr>, the target must be a table-like element.
    // Initialize hParentTags so auto-tbody works correctly.
    for (var ci = 0; ci < chainTokens.length; ci++) {
      if (chainTokens[ci].type === 'str' && chainTokens[ci].text.trim()) {
        var firstTag = chainTokens[ci].text.match(/<([a-zA-Z][a-zA-Z0-9]*)/);
        if (firstTag && firstTag[1].toLowerCase() === 'tr') {
          hParentTags = ['table'];
        }
        break;
      }
    }

    function hFlushText() {
      if (hTextBuf) {
        const decoded = decodeHtmlEntities(hTextBuf);
        lines.push(curParent() + '.appendChild(document.createTextNode(' + jsStr(decoded).code + '));');
        hTextBuf = '';
      }
    }

    function hFinishAttr() {
      if (hAttrName) {
        hAttrs.push({
          name: hAttrName.toLowerCase(),
          value: decodeHtmlEntities(hAttrVal),
          dynamic: hAttrExprs.length > 0,
          exprs: hAttrExprs.slice(),
        });
      }
      hAttrName = '';
      hAttrVal = '';
      hAttrExprs = [];
    }

    function hCommitTag(selfClose) {
      const tagLower = hTag.toLowerCase();
      if (VOID_ELEMENTS.has(tagLower)) selfClose = true;

      let nsExpr = null;
      if (tagLower === 'svg') nsExpr = SVG_NS_STR;
      else if (tagLower === 'math') nsExpr = MATHML_NS_STR;
      else if (SVG_TAGS.has(tagLower)) nsExpr = SVG_NS_STR;

      const v = makeVar(hTag, used);
      hTagVar = v;
      if (nsExpr) {
        lines.push('const ' + v + ' = document.createElementNS(' + nsExpr + ', ' + jsStr(tagLower).code + ');');
      } else {
        lines.push('const ' + v + ' = document.createElement(' + jsStr(tagLower).code + ');');
      }

      const eventAttrs = [];
      for (const attr of hAttrs) {
        // Compile-time conditional attribute: if (cond) el.setAttribute(...)
        if (attr.kind === 'cond_attr') {
          if (BOOLEAN_ATTRS.has(attr.name)) {
            lines.push('if (' + attr.condExpr + ') ' + v + '.' + attr.name + ' = true;');
          } else {
            lines.push('if (' + attr.condExpr + ') ' + v + '.setAttribute(' + jsStr(attr.name).code + ', ' + jsStr(attr.value).code + ');');
          }
          continue;
        }
        // All attribute expressions are resolved at compile time —
        // no dynamic_name kind exists. The scope walker resolves
        // opaque bracket access and property chains to symbolic
        // expressions, and ternaries are parsed by the JS tokenizer.
        const name = attr.name;
        // Extract inline event handlers and javascript: URLs.
        if (name.length > 2 && name.slice(0, 2) === 'on' && !attr.dynamic) {
          eventAttrs.push({ event: name.slice(2), handler: attr.value });
          continue;
        }
        if (name === 'href' && !attr.dynamic && attr.value.slice(0, 11).toLowerCase() === 'javascript:') {
          eventAttrs.push({ event: 'click', handler: attr.value.slice(11), preventDefault: true });
          continue;
        }
        if (attr.dynamic) {
          // Build expression from static parts + dynamic expressions.
          const parts = [];
          let cursor = 0;
          const sorted = attr.exprs.slice().sort(function(a, b) { return a.pos - b.pos; });
          for (const e of sorted) {
            if (e.pos > cursor) parts.push(jsStr(decodeHtmlEntities(attr.value.slice(cursor, e.pos))).code);
            parts.push(e.expr);
            cursor = e.pos;
          }
          if (cursor < attr.value.length) parts.push(jsStr(decodeHtmlEntities(attr.value.slice(cursor))).code);
          const valExpr = parts.length === 1 ? parts[0] : parts.join(' + ');

          if (name === 'style') {
            lines.push(v + '.setAttribute(' + jsStr(name).code + ', ' + valExpr + ');');
          } else if (name === 'class') {
            lines.push(v + '.className = ' + valExpr + ';');
          } else if (!nsExpr && isIdlProp(name)) {
            lines.push(v + '.' + (ATTR_TO_PROP[name] || name) + ' = ' + valExpr + ';');
          } else {
            lines.push(v + '.setAttribute(' + jsStr(name).code + ', ' + valExpr + ');');
          }
        } else {
          const val = attr.value;
          if (name === 'style') {
            const decls = parseStyleDecls(val);
            for (const d of decls) {
              lines.push(v + '.style.setProperty(' + jsStr(d.prop).code + ', ' + jsStr(d.value).code + (d.important ? ", 'important'" : '') + ');');
            }
          } else if (name === 'class') {
            const classes = val.split(/\s+/).filter(Boolean);
            if (classes.length === 1) lines.push(v + '.className = ' + jsStr(val).code + ';');
            else if (classes.length > 1) lines.push(v + '.classList.add(' + classes.map(function(c) { return jsStr(c).code; }).join(', ') + ');');
          } else if (!nsExpr && BOOLEAN_ATTRS.has(name) && (val === '' || val === name)) {
            lines.push(v + '.' + (ATTR_TO_PROP[name] || name) + ' = true;');
          } else if (!nsExpr && isIdlProp(name)) {
            lines.push(v + '.' + (ATTR_TO_PROP[name] || name) + ' = ' + jsStr(val).code + ';');
          } else {
            lines.push(v + '.setAttribute(' + jsStr(name).code + ', ' + jsStr(val).code + ');');
          }
        }
      }

      // Auto-insert <tbody> when <tr> is a direct child of <table>.
      // Skip if tbody was already pre-created by the loop pre-scan.
      if (tagLower === 'tr' && hParentTags.length > 0 && hParentTags[hParentTags.length - 1] === 'table') {
        if (!hTbodyVar) {
          hTbodyVar = makeVar('tbody', used);
          lines.push('const ' + hTbodyVar + ' = document.createElement(\'tbody\');');
          lines.push(curParent() + '.appendChild(' + hTbodyVar + ');');
        }
        parentStack.push(hTbodyVar);
        hParentTags.push('tbody');
      }
      // Auto-close implicit <tbody> when table section elements appear.
      if ((tagLower === 'tfoot' || tagLower === 'thead' || tagLower === 'caption') &&
          hParentTags.length > 0 && hParentTags[hParentTags.length - 1] === 'tbody') {
        parentStack.pop();
        hParentTags.pop();
      }

      // Emit event listeners for extracted on* attributes.
      for (const ev of eventAttrs) {
        if (ev.preventDefault) {
          lines.push(v + '.addEventListener(' + jsStr(ev.event).code + ', function(event) {');
          lines.push('  event.preventDefault();');
          lines.push('  ' + ev.handler);
          lines.push('});');
        } else {
          lines.push(v + '.addEventListener(' + jsStr(ev.event).code + ', function(event) { ' + ev.handler + ' });');
        }
      }

      var parentExpr = curParent();
      lines.push(parentExpr + '.appendChild(' + v + ');');
      if (!selfClose) {
        // In unbalanced loops, update the runtime parent variable
        // so the next iteration appends to the new element.
        if (inUnbalancedLoop && isRuntimeVar(parentExpr)) {
          lines.push(parentExpr + ' = ' + v + ';');
        }
        parentStack.push(v);
        hParentTags.push(tagLower);
      }
      hTag = '';
      hAttrs = [];
      hTagVar = '';
    }

    // Feed a character from a string literal through the HTML state machine.
    function hFeedStr(text) {
      for (let i = 0; i < text.length; i++) {
        const c = text[i];
        switch (hState) {
          case S_TEXT:
            if (c === '<') {
              hFlushText();
              if (text[i+1] === '/' && i+1 < text.length) { hState = S_TAG_CLOSE; hTag = ''; i++; }
              else if (text[i+1] === '!' && text[i+2] === '-' && text[i+3] === '-') { hState = S_COMMENT; hCommentBuf = ''; i += 3; }
              else { hState = S_TAG_OPEN; hTag = ''; }
            } else {
              hTextBuf += c;
            }
            break;
          case S_TAG_OPEN:
            if (c === ' ' || c === '\t' || c === '\n') { if (hTag) { hState = S_ATTRS; hAttrs = []; } }
            else if (c === '>') { hCommitTag(false); hState = S_TEXT; }
            else if (c === '/' && text[i+1] === '>') { hCommitTag(true); hState = S_TEXT; i++; }
            else hTag += c;
            break;
          case S_TAG_CLOSE:
            if (c === '>') {
              const closingTagLower = hTag.toLowerCase();
              // Auto-close implicit <tbody> when closing <table>.
              if (closingTagLower === 'table' && hParentTags.length > 0 && hParentTags[hParentTags.length - 1] === 'tbody') {
                parentStack.pop();
                hParentTags.pop();
              }
              // Pop the parent stack and, if the new current parent is a
              // runtime variable, emit a parentNode walk so it tracks correctly.
              parentStack.pop();
              if (parentStack.length > 0 && isRuntimeVar(curParent())) {
                lines.push(curParent() + ' = ' + curParent() + '.parentNode;');
              }
              if (hParentTags.length > 0) hParentTags.pop();
              hTag = '';
              hState = S_TEXT;
            } else {
              hTag += c;
            }
            break;
          case S_ATTRS:
            if (c === '>') { hFinishAttr(); hCommitTag(false); hState = S_TEXT; }
            else if (c === '/' && text[i+1] === '>') { hFinishAttr(); hCommitTag(true); hState = S_TEXT; i++; }
            else if (c !== ' ' && c !== '\t' && c !== '\n') { hAttrName = c; hAttrVal = ''; hAttrExprs = []; hState = S_ATTR_NAME; }
            break;
          case S_ATTR_NAME:
            if (c === '=') { hState = S_ATTR_EQ; }
            else if (c === ' ' || c === '\t') { hFinishAttr(); hState = S_ATTRS; }
            else if (c === '>') { hFinishAttr(); hCommitTag(false); hState = S_TEXT; }
            else if (c === '/' && text[i+1] === '>') { hFinishAttr(); hCommitTag(true); hState = S_TEXT; i++; }
            else hAttrName += c;
            break;
          case S_ATTR_EQ:
            if (c === '"') hState = S_ATTR_VAL_DQ;
            else if (c === "'") hState = S_ATTR_VAL_SQ;
            else if (c !== ' ' && c !== '\t') { hAttrVal = c; hState = S_ATTR_VAL_UQ; }
            break;
          case S_ATTR_VAL_DQ:
            if (c === '"') { hFinishAttr(); hState = S_ATTRS; }
            else hAttrVal += c;
            break;
          case S_ATTR_VAL_SQ:
            if (c === "'") { hFinishAttr(); hState = S_ATTRS; }
            else hAttrVal += c;
            break;
          case S_ATTR_VAL_UQ:
            if (c === ' ' || c === '\t') { hFinishAttr(); hState = S_ATTRS; }
            else if (c === '>') { hFinishAttr(); hCommitTag(false); hState = S_TEXT; }
            else hAttrVal += c;
            break;
          case S_COMMENT:
            if (c === '-' && text[i+1] === '-' && text[i+2] === '>') {
              lines.push(curParent() + '.appendChild(document.createComment(' + jsStr(hCommentBuf).code + '));');
              hState = S_TEXT; i += 2;
            } else hCommentBuf += c;
            break;
        }
      }
    }

    // Feed an expression token. If we're inside an attribute value,
    // the expression becomes a dynamic part of that attribute.
    // If we're in text context, it becomes a text node.
    function hFeedExpr(expr) {
      if (hState === S_ATTR_VAL_DQ || hState === S_ATTR_VAL_SQ || hState === S_ATTR_VAL_UQ) {
        // Dynamic expression in attribute value.
        hAttrExprs.push({ pos: hAttrVal.length, expr: expr });
      } else if (hState === S_ATTRS || hState === S_TAG_OPEN) {
        // Expression inside a tag (between attributes).
        // Parse the expression at compile time to extract attribute
        // name/value. Use the JS tokenizer to detect ternary patterns.
        hFinishAttr();
        var parsed = false;
        // Detect ternary: cond ? " attr" : "" or cond ? "" : " attr"
        var toks = tokenize(expr);
        var qIdx = -1;
        for (var ti = 0; ti < toks.length; ti++) {
          if (toks[ti].type === 'other' && toks[ti].text === '?') { qIdx = ti; break; }
        }
        if (qIdx > 0) {
          // Find the : separator (at depth 0)
          var colonIdx = -1;
          var depth = 0;
          for (var ti = qIdx + 1; ti < toks.length; ti++) {
            if (toks[ti].type === 'open') depth++;
            else if (toks[ti].type === 'close') depth--;
            else if (depth === 0 && toks[ti].type === 'other' && toks[ti].text === ':') { colonIdx = ti; break; }
          }
          if (colonIdx > 0) {
            // Extract condition, ifTrue, ifFalse as source text
            var condEnd = toks[qIdx].start;
            var trueStart = toks[qIdx].end;
            var trueEnd = toks[colonIdx].start;
            var falseStart = toks[colonIdx].end;
            var condExpr = expr.slice(0, condEnd).trim();
            var trueExpr = expr.slice(trueStart, trueEnd).trim();
            var falseExpr = expr.slice(falseStart).trim();
            // Check if one branch is a string and the other is empty
            var trueStr = null, falseStr = null;
            if (trueExpr.length >= 2 && (trueExpr[0] === '"' || trueExpr[0] === "'")) {
              trueStr = trueExpr.slice(1, -1).trim();
            }
            if (falseExpr.length >= 2 && (falseExpr[0] === '"' || falseExpr[0] === "'")) {
              falseStr = falseExpr.slice(1, -1).trim();
            }
            if (trueStr !== null && (falseStr === '' || falseExpr === '""' || falseExpr === "''")) {
              // cond ? " attr" : "" — conditional attribute
              var eqPos = trueStr.indexOf('=');
              if (eqPos >= 0) {
                hAttrs.push({ kind: 'cond_attr', condExpr: condExpr, name: trueStr.slice(0, eqPos), value: trueStr.slice(eqPos + 1).replace(/^['"]/, '').replace(/['"]$/, '') });
              } else if (trueStr) {
                hAttrs.push({ kind: 'cond_attr', condExpr: condExpr, name: trueStr, value: '' });
              }
              parsed = true;
            } else if (falseStr !== null && (trueStr === '' || trueExpr === '""' || trueExpr === "''")) {
              // cond ? "" : " attr" — inverted conditional
              var eqPos2 = falseStr.indexOf('=');
              if (eqPos2 >= 0) {
                hAttrs.push({ kind: 'cond_attr', condExpr: '!(' + condExpr + ')', name: falseStr.slice(0, eqPos2), value: falseStr.slice(eqPos2 + 1).replace(/^['"]/, '').replace(/['"]$/, '') });
              } else if (falseStr) {
                hAttrs.push({ kind: 'cond_attr', condExpr: '!(' + condExpr + ')', name: falseStr, value: '' });
              }
              parsed = true;
            }
          }
        }
        // If the expression wasn't parsed as a ternary, let it flow
        // through — the next string token will close the tag normally.
        // The expression was already processed by the scope walker;
        // if it resolved to a concrete string, it would be a str token
        // parsed by hFeedStr, not an other token reaching here.
      } else {
        // Text context — emit as text node or DOM call.
        hFlushText();
        const isDomCall = domFuncs.size > 0 &&
          [...domFuncs].some(function(fn) { return new RegExp('^' + fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(').test(expr); });
        if (isDomCall) {
          lines.push(curParent() + '.appendChild(' + expr + ');');
        } else {
          lines.push(curParent() + '.appendChild(document.createTextNode(' + expr + '));');
        }
      }
    }

    // Recursively process chain tokens.
    function emitChain(tokens) {
      for (let ti = 0; ti < tokens.length; ti++) {
        const t = tokens[ti];
        if (t.type === 'plus') continue;
        // Multi-target: switch the active __p to a different target element.
        if (t.type === '_targetPush') {
          hFlushText();
          parentStack.push(t.target);
          continue;
        }
        if (t.type === '_targetPop') {
          hFlushText();
          parentStack.pop();
          continue;
        }
        if (t.type === 'str') hFeedStr(t.text);
        else if (t.type === 'tmpl') {
          // Template literal: process each part — text portions through
          // the HTML parser, expression portions as dynamic values.
          for (const p of t.parts) {
            if (p.kind === 'text') {
              hFeedStr(decodeJsString(p.raw, '`'));
            } else if (p.kind === 'expr') {
              hFeedExpr(p.expr.trim());
            }
          }
        }
        else if (t.type === 'other') hFeedExpr(t.text);
        else if (t.type === 'preserve') { hFlushText(); lines.push(t.text); }
        else if (t.type === 'cond') {
          function condToExpr(ct) {
            if (ct.length === 1 && ct[0].type === 'str') return JSON.stringify(ct[0].text);
            if (ct.length === 1 && ct[0].type === 'other') return ct[0].text;
            return ct.filter(function(x){return x.type!=='plus';}).map(function(x) {
              return x.type === 'str' ? JSON.stringify(x.text) : x.text;
            }).join(' + ');
          }
          if (hState === S_ATTR_VAL_DQ || hState === S_ATTR_VAL_SQ || hState === S_ATTR_VAL_UQ) {
            // Inside an attribute value: emit as ternary expression.
            var ternaryExpr = '(' + t.condExpr + ' ? ' + condToExpr(t.ifTrue) + ' : ' + condToExpr(t.ifFalse) + ')';
            hAttrExprs.push({ pos: hAttrVal.length, expr: ternaryExpr });
          } else if (hState === S_ATTRS || hState === S_TAG_OPEN) {
            // Between tag attributes: conditional attribute addition.
            // Parse the branches at compile time to extract attribute
            // name/value and emit a static if/setAttribute.
            hFinishAttr();
            var trueStr = t.ifTrue.length === 1 && t.ifTrue[0].type === 'str' ? t.ifTrue[0].text.trim() : null;
            var falseStr = t.ifFalse.length === 1 && t.ifFalse[0].type === 'str' ? t.ifFalse[0].text.trim() : null;
            if (trueStr && !falseStr) {
              // Pattern: cond ? " selected" : "" — conditional boolean attr.
              var eqPos = trueStr.indexOf('=');
              if (eqPos >= 0) {
                var aName = trueStr.slice(0, eqPos);
                var aVal = trueStr.slice(eqPos + 1).replace(/^['"]/, '').replace(/['"]$/, '');
                hAttrs.push({ kind: 'cond_attr', condExpr: t.condExpr, name: aName, value: aVal });
              } else {
                hAttrs.push({ kind: 'cond_attr', condExpr: t.condExpr, name: trueStr, value: '' });
              }
            } else if (falseStr && !trueStr) {
              // Pattern: cond ? "" : " disabled" — inverted conditional.
              var eqPos2 = falseStr.indexOf('=');
              if (eqPos2 >= 0) {
                hAttrs.push({ kind: 'cond_attr', condExpr: '!(' + t.condExpr + ')', name: falseStr.slice(0, eqPos2), value: falseStr.slice(eqPos2 + 1).replace(/^['"]/, '').replace(/['"]$/, '') });
              } else {
                hAttrs.push({ kind: 'cond_attr', condExpr: '!(' + t.condExpr + ')', name: falseStr, value: '' });
              }
            } else if (trueStr !== null && falseStr !== null) {
              // Both branches produce attributes. Emit both as conditionals.
              var trueEq = trueStr.indexOf('=');
              var falseEq = falseStr.indexOf('=');
              if (trueStr) hAttrs.push({ kind: 'cond_attr', condExpr: t.condExpr, name: trueEq >= 0 ? trueStr.slice(0, trueEq) : trueStr, value: trueEq >= 0 ? trueStr.slice(trueEq + 1).replace(/^['"]/, '').replace(/['"]$/, '') : '' });
              if (falseStr) hAttrs.push({ kind: 'cond_attr', condExpr: '!(' + t.condExpr + ')', name: falseEq >= 0 ? falseStr.slice(0, falseEq) : falseStr, value: falseEq >= 0 ? falseStr.slice(falseEq + 1).replace(/^['"]/, '').replace(/['"]$/, '') : '' });
            }
          } else {
            // Text context: check for unbalanced tags in branches.
            // An unbalanced open tag (like <b> without </b>) means the
            // parent depends on runtime state after the cond.
            hFlushText();
            var savedStack = parentStack.slice();
            var savedHTags = hParentTags.slice();
            var savedHState = hState;

            // Process ifTrue branch, track stack changes.
            lines.push('if (' + t.condExpr + ') {');
            emitChain(t.ifTrue);
            hFlushText();
            var trueStack = parentStack.slice();
            var trueHTags = hParentTags.slice();

            // Restore and process ifFalse branch.
            parentStack.length = 0;
            for (var si = 0; si < savedStack.length; si++) parentStack.push(savedStack[si]);
            hParentTags = savedHTags.slice();
            hState = savedHState;
            lines.push('} else {');
            emitChain(t.ifFalse);
            hFlushText();
            var falseStack = parentStack.slice();
            lines.push('}');

            // If both branches end with the same parent stack, use it.
            if (JSON.stringify(trueStack) === JSON.stringify(falseStack)) {
              // Balanced: both branches end at the same nesting level.
              parentStack.length = 0;
              for (var si2 = 0; si2 < trueStack.length; si2++) parentStack.push(trueStack[si2]);
            } else {
              // Unbalanced: branches end at different nesting levels.
              // Introduce a runtime parent variable for subsequent code.
              // The variable is set in each branch to wherever that branch
              // left the parent.
              // Reuse existing runtime parent if the current parent is
              // already a runtime variable (from a previous cond).
              var existingRuntime = isRuntimeVar(curParent());
              var condParent = existingRuntime ? curParent() : makeVar('current', used);
              if (!existingRuntime) runtimeParentVars.add(condParent);
              // Insert assignment in branches that CHANGED the parent.
              // Branches that didn't change the stack (empty content)
              // should NOT set current — it preserves its previous value
              // (important for state machines where bold_on persists).
              function insertBeforeFlowControl(startIdx, endIdx, assignment) {
                var insertAt = endIdx;
                for (var li = endIdx - 1; li >= startIdx; li--) {
                  if (lines[li] === 'continue;' || lines[li] === 'break;') {
                    insertAt = li;
                  } else break;
                }
                lines.splice(insertAt, 0, assignment);
              }
              var trueChanged = JSON.stringify(trueStack) !== JSON.stringify(savedStack);
              var falseChanged = JSON.stringify(falseStack) !== JSON.stringify(savedStack);
              var elseIdx = lines.lastIndexOf('} else {');
              if (trueChanged && elseIdx >= 0) {
                insertBeforeFlowControl(0, elseIdx, condParent + ' = ' + trueStack[trueStack.length - 1] + ';');
              }
              if (falseChanged) {
                var closeIdx = lines.lastIndexOf('}');
                var elseIdx2 = lines.lastIndexOf('} else {');
                if (closeIdx >= 0 && elseIdx2 >= 0) {
                  insertBeforeFlowControl(elseIdx2 + 1, closeIdx, condParent + ' = ' + falseStack[falseStack.length - 1] + ';');
                }
              }
              // If only one branch changes, remove the empty else.
              if (!falseChanged) {
                var eIdx = lines.lastIndexOf('} else {');
                var cIdx = lines.lastIndexOf('}');
                if (eIdx >= 0 && cIdx > eIdx) {
                  // Check if else block is empty.
                  var elseContent = lines.slice(eIdx + 1, cIdx).filter(function(l) { return l.trim(); });
                  if (elseContent.length === 0) {
                    lines.splice(eIdx, cIdx - eIdx + 1, '}');
                  }
                }
              }
              // Add var declaration BEFORE any enclosing loop (so it
              // persists across iterations) or before the if if not in a loop.
              var ifIdx = -1;
              for (var li = lines.length - 1; li >= 0; li--) {
                if (lines[li] === 'if (' + t.condExpr + ') {') { ifIdx = li; break; }
              }
              // Look for an enclosing loop header before the if.
              var loopIdx = -1;
              if (ifIdx >= 0) {
                for (var li2 = ifIdx - 1; li2 >= 0; li2--) {
                  if (/^(for|while|do)\b/.test(lines[li2])) { loopIdx = li2; break; }
                  // Stop at function boundaries or other blocks.
                  if (lines[li2] === '}') break;
                }
              }
              if (!existingRuntime) {
                var insertIdx = loopIdx >= 0 ? loopIdx : ifIdx;
                if (insertIdx >= 0) {
                  lines.splice(insertIdx, 0, 'var ' + condParent + ' = ' + savedStack[savedStack.length - 1] + ';');
                }
              }
              // Replace parent stack with the runtime variable.
              parentStack.length = 0;
              var minLen = Math.min(trueStack.length, falseStack.length);
              for (var si3 = 0; si3 < minLen; si3++) parentStack.push(savedStack[si3] || condParent);
              parentStack.push(condParent);
            }
          }
        } else if (t.type === 'trycatch') {
          hFlushText();
          var savedState1 = hState, savedParents1 = hParentTags.slice();
          // Use a DocumentFragment for the try branch so partial DOM
          // from a failed try doesn't pollute the main tree.
          var tryFrag = makeVar('frag', used);
          lines.push('var ' + tryFrag + ' = document.createDocumentFragment();');
          var savedParent = curParent();
          parentStack.push(tryFrag);
          lines.push('try {');
          emitChain(t.tryBody);
          hFlushText();
          // Success: append fragment to parent.
          parentStack.pop();
          lines.push(savedParent + '.appendChild(' + tryFrag + ');');
          hState = savedState1; hParentTags = savedParents1.slice();
          lines.push('} catch(' + (t.catchParam || 'e') + ') {');
          // Failure: discard fragment, build catch content on parent directly.
          emitChain(t.catchBody);
          hFlushText();
          lines.push('}');
        } else if (t.type === 'switch') {
          hFlushText();
          lines.push('switch (' + t.discExpr + ') {');
          for (const br of t.branches) {
            if (br.label === 'default') lines.push('  default: {');
            else lines.push('  case ' + br.caseExpr + ': {');
            emitChain(br.chain);
            lines.push('    break;');
            lines.push('  }');
          }
          lines.push('}');
        } else if (t.type === 'iter') {
          hFlushText();
          lines.push(t.iterExpr + '.forEach(function(' + t.paramName + ') {');
          emitChain(t.perElemChain);
          lines.push('});');
        }
      }
    }

    // Emit chain tokens with proper nested loop wrappers.
    // Tokens carry loopId tags. When the loopId changes (increases),
    // we've entered an inner loop. When it reverts to a previous id
    // or null, we've exited. This handles arbitrary nesting depth.
    function emitWithLoops(tokens, loopInfoMap) {
      const toks = tokens.filter(function(t) { return t.type !== 'plus'; });
      const openLoops = []; // stack of { id, runtimeParent, preStack }


      function emitLoopHeader(id, upcomingTokens) {
        // Pre-scan: if the loop body has <tr> that needs auto-tbody,
        // create the tbody BEFORE the loop so it's not inside the loop.
        if (upcomingTokens && !hTbodyVar && hParentTags.length > 0 && hParentTags[hParentTags.length - 1] === 'table') {
          for (var ui = 0; ui < upcomingTokens.length; ui++) {
            if (upcomingTokens[ui].type === 'str' && /<tr[\s>]/i.test(upcomingTokens[ui].text)) {
              hTbodyVar = makeVar('tbody', used);
              lines.push('const ' + hTbodyVar + ' = document.createElement(\'tbody\');');
              lines.push(curParent() + '.appendChild(' + hTbodyVar + ');');
              parentStack.push(hTbodyVar);
              hParentTags.push('tbody');
              break;
            }
          }
        }
        const info = loopInfoMap ? loopInfoMap[id] : null;
        if (info) {
          if (info.kind === 'do') lines.push('do {');
          else lines.push((info.kind === 'while' ? 'while' : 'for') + ' (' + info.headerSrc + ') {');
        } else {
          lines.push('/* loop */ {');
        }
        openLoops.push({ id: id, runtimeParent: null, preStack: null });
      }

      function emitLoopFooter() {
        const entry = openLoops.pop();
        if (entry.runtimeParent) inUnbalancedLoop = false;
        if (entry.runtimeParent && entry.preStack) {
          parentStack.length = 0;
          for (var ri = 0; ri < entry.preStack.length; ri++) parentStack.push(entry.preStack[ri]);
          parentStack.push(entry.runtimeParent);
        }
        const id = entry.id;
        const info = loopInfoMap ? loopInfoMap[id] : null;
        if (info && info.kind === 'do') {
          lines.push('} while (' + info.headerSrc + ');');
        } else {
          lines.push('}');
        }
      }

      for (let i = 0; i < toks.length; i++) {
        const t = toks[i];
        // plus tokens don't carry loopId — inherit from surrounding context.
        if (t.type === 'plus') { emitChain([t]); continue; }
        const loopId = t.loopId != null ? t.loopId : null;
        const currentLoop = openLoops.length > 0 ? openLoops[openLoops.length - 1].id : null;

        if (loopId === currentLoop) {
          // Same loop (or both null) — just emit.
          emitChain([t]);
        } else if (loopId !== null && currentLoop === null) {
          // Entering a loop from non-loop context.
          var upcoming = toks.slice(i);
          var preLoopStack = parentStack.slice();
          emitLoopHeader(loopId, upcoming);
          // Check if loop body has unbalanced tags by pre-scanning
          // for open/close tag counts.
          var loopOpenTags = 0, loopCloseTags = 0;
          for (var si = i; si < toks.length; si++) {
            if (toks[si].type === 'plus') continue; // plus tokens don't carry loopId
            if (toks[si].loopId !== loopId) break;
            if (toks[si].type === 'str') {
              var s = toks[si].text;
              for (var ci = 0; ci < s.length; ci++) {
                if (s[ci] === '<' && s[ci+1] !== '/' && s[ci+1] !== '!') loopOpenTags++;
                if (s[ci] === '<' && s[ci+1] === '/') loopCloseTags++;
              }
            }
          }
          if (loopOpenTags !== loopCloseTags) {
            // Unbalanced loop body — use runtime parent variable.
            var loopParent = makeVar('current', used);
            var existingRT = isRuntimeVar(curParent());
            if (existingRT) {
              loopParent = curParent();
            } else {
              runtimeParentVars.add(loopParent);
              lines.splice(lines.length - 1, 0, 'var ' + loopParent + ' = ' + curParent() + ';');
              parentStack.push(loopParent);
            }
            // Record on the loop entry so emitLoopFooter can restore.
            openLoops[openLoops.length - 1].runtimeParent = loopParent;
            openLoops[openLoops.length - 1].preStack = preLoopStack;
            inUnbalancedLoop = true;
          }
          emitChain([t]);
        } else if (loopId === null && currentLoop !== null) {
          // Exiting all loops.
          while (openLoops.length > 0) emitLoopFooter();
          emitChain([t]);
        } else if (loopId !== null && currentLoop !== null && loopId !== currentLoop) {
          if (openLoops.some(function(e) { return e.id === loopId; })) {
            // Returning to an outer loop — close inner loops.
            while (openLoops.length > 0 && openLoops[openLoops.length - 1].id !== loopId) {
              emitLoopFooter();
            }
          } else {
            // Entering a deeper/sibling loop — open new loop (keep outer open).
            emitLoopHeader(loopId, toks.slice(i));
          }
          emitChain([t]);
        }
      }

      // Close any remaining open loops.
      while (openLoops.length > 0) emitLoopFooter();

      hFlushText();
    }

    // Emit all chain tokens.
    const loopInfoMap = result.loopInfoMap || null;
    emitWithLoops(chainTokens, loopInfoMap);

    let block = lines.join('\n');
    if (emitTitle) {
      block = '// === ' + target + '.' + assignProp + ' ' + assignOp + ' ... ===\n' + block;
    }
    return block;
  }

  // Copy is handled by monaco-init.js in the full UI.
  // Only attach here for standalone/test usage.
  if ($('copy') && !(typeof window !== 'undefined' && window._monacoIn)) {
    $('copy').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(lastOutput);
        $('copy').textContent = 'Copied!';
        setTimeout(() => { $('copy').textContent = 'Copy output'; }, 1200);
      } catch (_) {}
    });
  }

  // Monaco editors are initialized by index.html before this script loads.
  if (typeof window !== 'undefined' && window._monacoIn) {
    window._monacoIn.onDidChangeModelContent(convert);
  } else if ($('in')) {
    $('in').addEventListener('input', convert);
  }

  await convert();

  // --- Project-level API ---

  function resolveRelativePath(src, htmlPath) {
    const dir = htmlPath.indexOf('/') >= 0 ? htmlPath.slice(0, htmlPath.lastIndexOf('/') + 1) : '';
    const parts = (dir + src).split('/');
    const norm = [];
    for (let i = 0; i < parts.length; i++) {
      if (parts[i] === '..') norm.pop();
      else if (parts[i] !== '.') norm.push(parts[i]);
    }
    return norm.join('/');
  }

  function findPageScripts(htmlContent, htmlPath) {
    const scripts = [];
    const tokens = tokenizeHtml(htmlContent);
    for (const tok of tokens) {
      if (tok.type !== 'openTag' || tok.tag !== 'script') continue;
      for (const attr of tok.attrs) {
        if (attr.name === 'src' && attr.value) {
          scripts.push(resolveRelativePath(attr.value, htmlPath));
        }
      }
    }
    return scripts;
  }

  // Scan JS source for navigation sinks and wrap them with protocol filtering.
  // Returns the modified source, or null if no changes.
  async function filterUnsafeSinks(jsContent) {
    var tokens = tokenize(jsContent);
    if (!tokens.length) return null;
    // Build scope to resolve variable types and taint.
    var scope = await buildScopeState(tokens, tokens.length, null, null, { enabled: true });
    var replacements = []; // { start, end, replacement }
    for (var i = 0; i < tokens.length; i++) {
      var t = tokens[i];
      if (t.type !== 'other') continue;

      // --- Code execution sinks: eval, Function, setTimeout/setInterval ---
      // Helper: resolve an argument's source text to a known string if possible.
      // Checks literal strings, template literals, concat of literals, and
      // variables that resolve to literal strings through scope.
      var _resolveArgText = function(argStart, argEnd) {
        if (argStart >= argEnd) return null;
        // Single string token.
        if (argEnd === argStart + 1 && tokens[argStart].type === 'str') return tokens[argStart].text;
        // Single template literal with no expressions.
        if (argEnd === argStart + 1 && tokens[argStart].type === 'tmpl') {
          var parts = tokens[argStart].parts;
          if (parts && parts.every(function(p) { return p.kind === 'text'; })) {
            return parts.map(function(p) { return p.raw; }).join('');
          }
          return null;
        }
        // Single identifier: resolve through scope.
        if (argEnd === argStart + 1 && tokens[argStart].type === 'other' && IDENT_RE.test(tokens[argStart].text)) {
          var b = scope.resolve(tokens[argStart].text);
          if (b && b.kind === 'chain' && b.toks.length === 1 && b.toks[0].type === 'str') return b.toks[0].text;
          return null;
        }
        // Multi-token: try concat of string literals (e.g. "a" + "b").
        var result = '';
        for (var ai = argStart; ai < argEnd; ai++) {
          var at = tokens[ai];
          if (at.type === 'str') { result += at.text; continue; }
          if (at.type === 'plus') continue;
          if (at.type === 'other' && IDENT_RE.test(at.text)) {
            var ab = scope.resolve(at.text);
            if (ab && ab.kind === 'chain' && ab.toks.length === 1 && ab.toks[0].type === 'str') { result += ab.toks[0].text; continue; }
          }
          return null; // non-literal part
        }
        return result;
      };
      // Helper: split call args by commas at depth 0. Returns array of {start, end}.
      var _splitCallArgs = function(openIdx) {
        var args = [], argStart = openIdx + 1, d = 0;
        for (var ai = openIdx + 1; ai < tokens.length; ai++) {
          if (tokens[ai].type === 'open') d++;
          if (tokens[ai].type === 'close') { if (d === 0) { if (ai > argStart) args.push({ start: argStart, end: ai }); return { args: args, callEnd: ai + 1 }; } d--; }
          if (d === 0 && tokens[ai].type === 'sep' && tokens[ai].char === ',') { args.push({ start: argStart, end: ai }); argStart = ai + 1; }
        }
        return { args: args, callEnd: tokens.length };
      };

      // eval(expr) / Function(expr) — only real globals, not shadowed locals.
      if ((t.text === 'eval' || t.text === 'Function') && !scope.declaredNames.has(t.text)) {
        var paren = tokens[i + 1];
        if (paren && paren.type === 'open' && paren.char === '(') {
          var parsed = _splitCallArgs(i + 1);
          var fullEnd = tokens[parsed.callEnd - 1] ? tokens[parsed.callEnd - 1].end : t.end;
          if (parsed.args.length === 0) {
            // eval() with no args — leave as is (returns undefined).
            i = parsed.callEnd;
            continue;
          }
          if (t.text === 'eval') {
            // eval only uses first argument.
            var code = _resolveArgText(parsed.args[0].start, parsed.args[0].end);
            if (code !== null) {
              replacements.push({ start: t.start, end: fullEnd, replacement: code });
            } else {
              replacements.push({ start: t.start, end: fullEnd, replacement: '/* [blocked: eval with dynamic argument] */ void 0' });
            }
          } else {
            // Function(body) or Function(param1, param2, ..., body)
            var lastArg = parsed.args[parsed.args.length - 1];
            var bodyCode = _resolveArgText(lastArg.start, lastArg.end);
            if (bodyCode !== null) {
              var paramParts = [];
              for (var pi = 0; pi < parsed.args.length - 1; pi++) {
                var pText = _resolveArgText(parsed.args[pi].start, parsed.args[pi].end);
                if (pText !== null) paramParts.push(pText);
                else { bodyCode = null; break; }
              }
              if (bodyCode !== null) {
                replacements.push({ start: t.start, end: fullEnd, replacement: '(function(' + paramParts.join(', ') + ') { ' + bodyCode + ' })' });
              } else {
                replacements.push({ start: t.start, end: fullEnd, replacement: '/* [blocked: Function with dynamic argument] */ void 0' });
              }
            } else {
              replacements.push({ start: t.start, end: fullEnd, replacement: '/* [blocked: Function with dynamic argument] */ void 0' });
            }
          }
          i = parsed.callEnd;
          continue;
        }
      }
      // new Function(...)
      if (t.text === 'new' && tokens[i + 1] && tokens[i + 1].type === 'other' && tokens[i + 1].text === 'Function' && !scope.declaredNames.has('Function')) {
        var paren2 = tokens[i + 2];
        if (paren2 && paren2.type === 'open' && paren2.char === '(') {
          var parsed2 = _splitCallArgs(i + 2);
          var fullEnd2 = tokens[parsed2.callEnd - 1] ? tokens[parsed2.callEnd - 1].end : 0;
          if (parsed2.args.length === 0) {
            replacements.push({ start: t.start, end: fullEnd2, replacement: '(function() {})' });
          } else {
            var lastArg2 = parsed2.args[parsed2.args.length - 1];
            var bodyCode2 = _resolveArgText(lastArg2.start, lastArg2.end);
            if (bodyCode2 !== null) {
              var paramParts2 = [];
              for (var pi2 = 0; pi2 < parsed2.args.length - 1; pi2++) {
                var pText2 = _resolveArgText(parsed2.args[pi2].start, parsed2.args[pi2].end);
                if (pText2 !== null) paramParts2.push(pText2);
                else { bodyCode2 = null; break; }
              }
              if (bodyCode2 !== null) {
                replacements.push({ start: t.start, end: fullEnd2, replacement: '(function(' + paramParts2.join(', ') + ') { ' + bodyCode2 + ' })' });
              } else {
                replacements.push({ start: t.start, end: fullEnd2, replacement: '/* [blocked: new Function with dynamic argument] */ void 0' });
              }
            } else {
              replacements.push({ start: t.start, end: fullEnd2, replacement: '/* [blocked: new Function with dynamic argument] */ void 0' });
            }
          }
          i = parsed2.callEnd;
          continue;
        }
      }
      // setTimeout("code", delay) / setInterval("code", delay) — convert string to function
      if ((t.text === 'setTimeout' || t.text === 'setInterval') && !scope.declaredNames.has(t.text)) {
        var paren3 = tokens[i + 1];
        if (paren3 && paren3.type === 'open' && paren3.char === '(') {
          var firstArg = tokens[i + 2];
          if (firstArg) {
            var comma = null, commaIdx = -1;
            // Find the comma separating first arg from the rest.
            var d3 = 0;
            for (var ci = i + 2; ci < tokens.length; ci++) {
              if (tokens[ci].type === 'open') d3++;
              if (tokens[ci].type === 'close') d3--;
              if (d3 < 0) break;
              if (d3 === 0 && tokens[ci].type === 'sep' && tokens[ci].char === ',') { commaIdx = ci; break; }
            }
            if (firstArg.type === 'str' && commaIdx > 0) {
              // setTimeout("alert(1)", 100) → setTimeout(function() { alert(1) }, 100)
              replacements.push({ start: firstArg.start, end: tokens[commaIdx - 1].end, replacement: 'function() { ' + firstArg.text + ' }' });
              i = commaIdx;
              continue;
            }
            // Check if first arg is tainted/dynamic (not a function keyword or arrow).
            var resolved3 = firstArg.type === 'other' && IDENT_RE.test(firstArg.text) ? scope.resolve(firstArg.text) : null;
            var isFn = firstArg.text === 'function' || (resolved3 && resolved3.kind === 'function');
            var isArrow = false;
            // Check for arrow: look for => before comma
            if (!isFn && commaIdx > 0) {
              for (var ai = i + 2; ai < commaIdx; ai++) {
                if (tokens[ai].type === 'other' && tokens[ai].text === '=>') { isArrow = true; break; }
              }
            }
            if (!isFn && !isArrow && commaIdx > 0 && firstArg.type !== 'str') {
              // Dynamic string passed to setTimeout — check for taint.
              var hasTaint = false;
              if (resolved3 && resolved3.kind === 'chain') hasTaint = !!collectChainTaint(resolved3.toks);
              if (hasTaint || firstArg.type === 'other') {
                // Block it.
                var timerEnd = commaIdx;
                replacements.push({ start: firstArg.start, end: tokens[commaIdx - 1].end, replacement: '/* [blocked: ' + t.text + ' with dynamic string] */ function() {}' });
                i = commaIdx;
                continue;
              }
            }
          }
        }
      }

      // --- Navigation sinks ---
      if (PATH_RE.test(t.text) || IDENT_RE.test(t.text)) {
        var navType = isNavSink(t.text, scope.declaredNames);
        if (navType) {
          var eq = tokens[i + 1];
          // location.href = expr / location = expr
          if (eq && eq.type === 'sep' && eq.char === '=') {
            var stmtEnd = i + 2;
            while (stmtEnd < tokens.length && !(tokens[stmtEnd].type === 'sep' && tokens[stmtEnd].char === ';')) stmtEnd++;
            var rhsStart = tokens[i + 2].start;
            var rhsEnd = tokens[stmtEnd - 1].end;
            var rhsSrc = t._src.slice(rhsStart, rhsEnd);
            var fullStart = t.start;
            var fullEnd = tokens[stmtEnd] ? tokens[stmtEnd].end : rhsEnd;
            // Only wrap if the RHS isn't a plain string literal (string literals are safe).
            if (tokens[i + 2].type !== 'str' || stmtEnd > i + 3) {
              var safeExpr = '(function(){var __u=__safeNav(' + rhsSrc + ');if(__u!==undefined)' + t.text + '=__u}())';
              replacements.push({ start: fullStart, end: fullEnd, replacement: safeExpr });
            }
            i = stmtEnd;
            continue;
          }
          // location.assign(expr) / location.replace(expr) / navigation.navigate(expr)
          if (eq && eq.type === 'open' && eq.char === '(') {
            var callEnd = i + 2;
            var depth = 1;
            while (callEnd < tokens.length && depth > 0) {
              if (tokens[callEnd].type === 'open' && tokens[callEnd].char === '(') depth++;
              if (tokens[callEnd].type === 'close' && tokens[callEnd].char === ')') depth--;
              callEnd++;
            }
            // Extract the first argument.
            var argStart = tokens[i + 2] ? tokens[i + 2].start : null;
            var argEnd = tokens[callEnd - 2] ? tokens[callEnd - 2].end : null;
            if (argStart !== null && argEnd !== null) {
              var argSrc = t._src.slice(argStart, argEnd);
              if (tokens[i + 2].type !== 'str') {
                var safeCall = '(function(){var __u=__safeNav(' + argSrc + ');if(__u!==undefined)' + t.text + '(__u)}())';
                var cFullEnd = tokens[callEnd - 1] ? tokens[callEnd - 1].end : argEnd;
                replacements.push({ start: t.start, end: cFullEnd, replacement: safeCall });
              }
            }
            i = callEnd;
            continue;
          }
        }
        // frame.src = expr where frame is an iframe/frame element
        if (PATH_RE.test(t.text)) {
          var parts = t.text.split('.');
          var lastProp = parts[parts.length - 1];
          if (lastProp === 'src') {
            var baseBind = scope.resolve(parts[0]);
            var tag = getElementTag(baseBind);
            if (tag === 'iframe' || tag === 'frame') {
              var eq2 = tokens[i + 1];
              if (eq2 && eq2.type === 'sep' && eq2.char === '=') {
                var stmtEnd2 = i + 2;
                while (stmtEnd2 < tokens.length && !(tokens[stmtEnd2].type === 'sep' && tokens[stmtEnd2].char === ';')) stmtEnd2++;
                var rhsStart2 = tokens[i + 2].start;
                var rhsEnd2 = tokens[stmtEnd2 - 1].end;
                var rhsSrc2 = t._src.slice(rhsStart2, rhsEnd2);
                if (tokens[i + 2].type !== 'str' || stmtEnd2 > i + 3) {
                  var safeSrc = '(function(){var __u=__safeNav(' + rhsSrc2 + ');if(__u!==undefined)' + t.text + '=__u}())';
                  var fFullEnd = tokens[stmtEnd2] ? tokens[stmtEnd2].end : rhsEnd2;
                  replacements.push({ start: t.start, end: fFullEnd, replacement: safeSrc });
                }
                i = stmtEnd2;
                continue;
              }
            }
          }
        }
      }
    }
    if (!replacements.length) return null;
    // Apply replacements in reverse order to preserve positions.
    var result = jsContent;
    for (var ri = replacements.length - 1; ri >= 0; ri--) {
      var rep = replacements[ri];
      result = result.slice(0, rep.start) + rep.replacement + result.slice(rep.end);
    }
    // Prepend the safe navigation helper if not already present.
    if (result.indexOf('__safeNav') >= 0 && result.indexOf('function __safeNav') < 0) {
      result = NAV_SAFE_FILTER + '\n' + result;
    }
    return result;
  }

  async function convertJsFile(jsContent, precedingCode, knownDomFunctions) {
    // Use extractAllHTML to detect actual innerHTML/outerHTML assignments.
    // This uses the tokenizer (skipping comments/strings) AND verifies
    // the target is not a known non-element via scope resolution.
    const combined = precedingCode
      ? precedingCode + '\n/*__FILE_BOUNDARY__*/\n' + jsContent
      : jsContent;
    const extractions = await extractAllHTML(combined);
    // Also filter navigation sinks in the current file.
    var navFiltered = await filterUnsafeSinks(jsContent);
    if (extractions.length === 0 && !navFiltered) return navFiltered;
    var sourceToConvert = navFiltered || jsContent;
    var combinedSrc = precedingCode
      ? precedingCode + '\n/*__FILE_BOUNDARY__*/\n' + sourceToConvert
      : sourceToConvert;
    if (extractions.length === 0) return navFiltered;
    const converted = await convertRaw(combinedSrc, undefined, knownDomFunctions);
    if (!converted || converted === '// (no nodes parsed)') return navFiltered;
    if (precedingCode) {
      const idx = converted.indexOf('/*__FILE_BOUNDARY__*/');
      if (idx >= 0) {
        const result = converted.slice(idx + '/*__FILE_BOUNDARY__*/'.length).trim();
        if (result && result !== jsContent.trim()) return result;
        return navFiltered;
      }
    }
    if (converted.trim() === jsContent.trim()) return navFiltered;
    return converted;
  }

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

  async function convertHtmlMarkup(htmlContent, htmlPath, reservedIdents) {
    // Derive filenames from source path.
    let baseName = htmlPath;
    const slashIdx = baseName.lastIndexOf('/');
    if (slashIdx >= 0) baseName = baseName.slice(slashIdx + 1);
    const dotIdx = baseName.lastIndexOf('.');
    if (dotIdx >= 0) baseName = baseName.slice(0, dotIdx);
    const handlersFile = baseName + '.handlers.js';

    const htmlTokens = tokenizeHtml(htmlContent);
    let elemCounter = 0;
    const jsLines = [];
    const extractedScripts = [];
    const extractedStyles = [];
    let scriptIdx = 0;
    let styleIdx = 0;
    // Collect reserved identifiers from all inline scripts so generated
    // handler variable names don't collide with user code.
    const used = new Set(reservedIdents || []);
    for (let si = 0; si < htmlTokens.length; si++) {
      if (htmlTokens[si].type === 'openTag' && htmlTokens[si].tag === 'script') {
        const hasSrc = htmlTokens[si].attrs.some(function(a) { return a.name === 'src'; });
        if (!hasSrc) {
          let body = '';
          for (let sj = si + 1; sj < htmlTokens.length; sj++) {
            if (htmlTokens[sj].type === 'closeTag' && htmlTokens[sj].tag === 'script') break;
            if (htmlTokens[sj].type === 'text') body += htmlTokens[sj].text;
          }
          const toks = tokenize(body.trim());
          for (const t of toks) {
            if (t.type === 'other' && IDENT_RE.test(t.text)) used.add(t.text);
          }
        }
      }
    }

    // Walk tokens and process each opening tag.
    for (let ti = 0; ti < htmlTokens.length; ti++) {
      const tok = htmlTokens[ti];
      if (tok.type !== 'openTag') continue;

      // Handle <script> without src — extract to external file.
      if (tok.tag === 'script') {
        const hasSrc = tok.attrs.some(function(a) { return a.name === 'src'; });
        if (!hasSrc) {
          // Find the closing </script> and extract the body.
          let body = '';
          let closeIdx = ti + 1;
          while (closeIdx < htmlTokens.length) {
            if (htmlTokens[closeIdx].type === 'closeTag' && htmlTokens[closeIdx].tag === 'script') break;
            if (htmlTokens[closeIdx].type === 'text') body += htmlTokens[closeIdx].text;
            closeIdx++;
          }
          body = body.trim();
          if (body) {
            const name = scriptIdx === 0 ? baseName + '.js' : baseName + '.' + scriptIdx + '.js';
            scriptIdx++;
            extractedScripts.push({ name: name, content: body });
            // Add src attribute and remove text content.
            tok.attrs.push({ name: 'src', value: name, nameRaw: 'src', start: 0, end: 0 });
            for (let ri = ti + 1; ri < closeIdx; ri++) {
              htmlTokens[ri] = { type: 'text', text: '', start: 0, end: 0 };
            }
          }
        }
        continue;
      }

      // Handle <style> — extract to external CSS file.
      if (tok.tag === 'style') {
        let body = '';
        let closeIdx = ti + 1;
        while (closeIdx < htmlTokens.length) {
          if (htmlTokens[closeIdx].type === 'closeTag' && htmlTokens[closeIdx].tag === 'style') break;
          if (htmlTokens[closeIdx].type === 'text') body += htmlTokens[closeIdx].text;
          closeIdx++;
        }
        body = body.trim();
        if (body) {
          const name = styleIdx === 0 ? baseName + '.css' : baseName + '.' + styleIdx + '.css';
          styleIdx++;
          extractedStyles.push({ name: name, content: body });
          // Replace <style>content</style> with <link rel="stylesheet" href="name">
          htmlTokens[ti] = { type: 'openTag', tag: 'link', tagRaw: 'link', attrs: [
            { name: 'rel', value: 'stylesheet', nameRaw: 'rel', start: 0, end: 0 },
            { name: 'href', value: name, nameRaw: 'href', start: 0, end: 0 }
          ], selfClose: false, start: tok.start, end: tok.end };
          for (let ri = ti + 1; ri <= closeIdx && ri < htmlTokens.length; ri++) {
            htmlTokens[ri] = { type: 'text', text: '', start: 0, end: 0 };
          }
        }
        continue;
      }

      // Process all elements regardless of whether body will be replaced.
      // Elements exist during initial render and their handlers are active
      // until the script replaces body content.

      // Extract unsafe attributes from this element.
      const events = [];
      let styleVal = null;
      let jsHref = null;
      let existingId = null;
      const keepAttrs = [];

      for (const attr of tok.attrs) {
        if (attr.name.length > 2 && attr.name.slice(0, 2) === 'on') {
          events.push({ event: attr.name.slice(2), handler: decodeHtmlEntities(attr.value) });
          continue;
        }
        if (attr.name === 'href' && attr.value.slice(0, 11).toLowerCase() === 'javascript:') {
          jsHref = decodeHtmlEntities(attr.value.slice(11));
          continue;
        }
        if (attr.name === 'style') {
          styleVal = decodeHtmlEntities(attr.value);
          continue;
        }
        if (attr.name === 'id') existingId = attr.value;
        keepAttrs.push(attr);
      }

      if (events.length === 0 && !jsHref && !styleVal) continue;

      // Build selector.
      let sel;
      if (existingId) {
        sel = 'document.getElementById(\'' + existingId + '\')';
      } else {
        // Add a data-handler attribute to identify this element.
        // data-* attributes are standard HTML for machine-generated
        // metadata and won't collide with the id namespace.
        let handlerId;
        do {
          handlerId = String(elemCounter++);
        } while (htmlTokens.some(function(ht) {
          return ht.type === 'openTag' && ht.attrs && ht.attrs.some(function(a) { return a.name === 'data-handler' && a.value === handlerId; });
        }));
        sel = 'document.querySelector(\'[data-handler="' + handlerId + '"]\')';
        keepAttrs.push({ name: 'data-handler', value: handlerId, nameRaw: 'data-handler', start: 0, end: 0 });
      }

      // Count operations for grouping.
      let opCount = events.length + (jsHref ? 1 : 0);
      if (styleVal) {
        opCount += parseStyleDecls(styleVal).length;
      }
      const useVar = opCount > 1;
      // Variable is scoped inside an IIFE so no collision possible.
      const varName = useVar ? 'el' : null;
      const ref = useVar ? varName : sel;

      if (useVar) {
        jsLines.push('(function() {');
        jsLines.push('var ' + varName + ' = ' + sel + ';');
      }

      // Emit event listeners.
      for (const ev of events) {
        const body = ev.handler.trim();
        let hasReturn = false;
        const returnToks = tokenize(body);
        for (const rt of returnToks) {
          if (rt.type === 'other' && rt.text === 'return') { hasReturn = true; break; }
        }
        if (hasReturn) {
          jsLines.push(ref + '.addEventListener(\'' + ev.event + '\', function(event) {');
          jsLines.push('  var __r = (function() { ' + body + ' }).call(this);');
          jsLines.push('  if (__r === false) event.preventDefault();');
          jsLines.push('});');
        } else {
          jsLines.push(ref + '.addEventListener(\'' + ev.event + '\', function(event) { ' + body + ' });');
        }
      }

      if (jsHref) {
        jsLines.push(ref + '.addEventListener(\'click\', function(event) {');
        jsLines.push('  event.preventDefault();');
        jsLines.push('  ' + jsHref);
        jsLines.push('});');
      }

      if (styleVal) {
        const decls = parseStyleDecls(styleVal);
        for (const d of decls) {
          const escapedVal = d.value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
          jsLines.push(ref + '.style.setProperty(\'' + d.prop + '\', \'' + escapedVal + '\'' + (d.important ? ', \'important\'' : '') + ');');
        }
      }

      if (useVar) {
        jsLines.push('})();');
      }

      // Update the token's attributes to only keep safe ones.
      tok.attrs = keepAttrs;
    }

    // Insert handlers script reference. Place before </body> if it
    // exists, otherwise before the first <script> tag so handlers
    // run before any scripts that might modify the DOM.
    if (jsLines.length) {
      var handlerScriptTokens = [
        { type: 'openTag', tag: 'script', tagRaw: 'script',
          attrs: [{ name: 'src', value: handlersFile, nameRaw: 'src', start: 0, end: 0 }],
          selfClose: false, start: 0, end: 0 },
        { type: 'closeTag', tag: 'script', start: 0, end: 0 },
        { type: 'text', text: '\n', start: 0, end: 0 }
      ];
      var inserted = false;
      for (let ti = htmlTokens.length - 1; ti >= 0; ti--) {
        if (htmlTokens[ti].type === 'closeTag' && htmlTokens[ti].tag === 'body') {
          htmlTokens.splice(ti, 0, ...handlerScriptTokens);
          inserted = true;
          break;
        }
      }
      if (!inserted) {
        // No </body> — insert before the first <script> tag.
        for (let ti = 0; ti < htmlTokens.length; ti++) {
          if (htmlTokens[ti].type === 'openTag' && htmlTokens[ti].tag === 'script') {
            htmlTokens.splice(ti, 0, ...handlerScriptTokens);
            inserted = true;
            break;
          }
        }
      }
      if (!inserted) {
        // No </body> and no <script> — append at the end.
        htmlTokens.push(...handlerScriptTokens);
      }
    }

    return {
      html: serializeHtmlTokens(htmlTokens),
      handlers: jsLines.length ? { name: handlersFile, content: jsLines.join('\n') } : null,
      extractedScripts: extractedScripts,
      extractedStyles: extractedStyles,
    };
  }

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

  async function convertProject(files) {
    const output = {};
    const htmlPages = Object.keys(files).filter(function(p) { return /\.html?$/i.test(p); }).sort();
    const referencedJs = new Set();
    const pageScriptMap = {};
    for (const page of htmlPages) {
      const scripts = findPageScripts(files[page], page);
      pageScriptMap[page] = scripts;
      for (const s of scripts) referencedJs.add(s);
    }
    for (const page of htmlPages) {
      // Collect identifiers from ALL scripts on this page so generated
      // variable names in handlers don't collide with user code.
      const pageIdents = new Set();
      const pageScripts = pageScriptMap[page] || [];
      for (const sp of pageScripts) {
        if (!files[sp]) continue;
        const toks = tokenize(files[sp].trim());
        for (const t of toks) {
          if (t.type === 'other' && IDENT_RE.test(t.text)) pageIdents.add(t.text);
        }
      }
      const markup = await convertHtmlMarkup(files[page], page, pageIdents);
      const dir = page.indexOf('/') >= 0 ? page.slice(0, page.lastIndexOf('/') + 1) : '';
      // Only output HTML if it actually changed.
      if (markup.html !== files[page]) output[page] = markup.html;
      if (markup.handlers) {
        output[dir + markup.handlers.name] = markup.handlers.content;
      }
      // Output extracted CSS files.
      for (const style of markup.extractedStyles) {
        output[dir + style.name] = style.content;
      }
      // Convert external JS files referenced by this page.
      // Pass 1: convert builder functions across all files. A builder
      // function in an earlier file (e.g. util.js) needs to be converted
      // to return a DocumentFragment so later files can use it.
      const scripts = pageScriptMap[page] || [];
      const workingFiles = {};
      for (const sp of scripts) workingFiles[sp] = files[sp] || '';
      for (const script of markup.extractedScripts) workingFiles[dir + script.name] = script.content;
      // Pass 1: convert builder functions in PRECEDING files only.
      // Same-file functions are inlined by the scope walker and should
      // NOT be pre-converted (that would make them return DocumentFragment,
      // breaking string concatenation at call sites the walker can inline).
      // For each file, run the pre-pass on ONLY that file. Collect
      // converted function names. Output the converted file.
      // The scope walker inlines same-file builder functions properly
      // (including those with loops). For cross-file builders (function
      // defined in an earlier file), the pre-pass converts the function
      // to return a DocumentFragment and marks it as a DOM function so
      // call sites use appendChild instead of createTextNode.
      // Only pre-convert files that DON'T have innerHTML (pure utility files).
      const allConvertedFns = new Set();
      for (const sp of scripts) {
        if (!workingFiles[sp]) continue;
        // Check: does this file have innerHTML/outerHTML assignments?
        const fileToks = tokenize(workingFiles[sp].trim());
        let fileHasInnerHTML = false;
        for (let ti = 1; ti < fileToks.length; ti++) {
          if (fileToks[ti].type === 'sep' && (fileToks[ti].char === '=' || fileToks[ti].char === '+=') &&
              fileToks[ti-1].type === 'other' && /\.(innerHTML|outerHTML)$/.test(fileToks[ti-1].text)) {
            fileHasInnerHTML = true; break;
          }
        }
        // Skip pre-pass for files with innerHTML — scope walker handles them.
        if (fileHasInnerHTML) continue;
        const prepass = await convertHtmlBuilderFunctions(workingFiles[sp]);
        for (const fn of prepass.converted) allConvertedFns.add(fn);
        if (prepass.converted.size > 0 && prepass.source !== workingFiles[sp]) {
          workingFiles[sp] = prepass.source;
          output[sp] = prepass.source;
        }
      }
      // Pass 2: convert innerHTML/outerHTML/document.write/insertAdjacentHTML.
      // allConvertedFns collects builder function names from pass 1.
      let precedingCode = '';
      for (const sp of scripts) {
        if (!workingFiles[sp]) continue;
        const converted = await convertJsFile(workingFiles[sp], precedingCode, allConvertedFns);
        if (converted) output[sp] = converted;
        precedingCode += (precedingCode ? '\n' : '') + workingFiles[sp];
      }
      // Convert extracted inline scripts (now external files).
      for (const script of markup.extractedScripts) {
        const key = dir + script.name;
        const content = workingFiles[key] || script.content;
        const converted = await convertJsFile(content, precedingCode, allConvertedFns);
        output[key] = converted || content;
        precedingCode += (precedingCode ? '\n' : '') + content;
      }
    }
    const standaloneJs = Object.keys(files).filter(function(p) { return /\.js$/i.test(p) && !referencedJs.has(p); }).sort();
    for (const jp of standaloneJs) {
      const converted = await convertJsFile(files[jp], '');
      if (converted) output[jp] = converted;
    }
    return output;
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------
  var api = {
    // Core analysis
    tokenize: tokenize,
    tokenizeHtml: tokenizeHtml,
    // Conversion
    convertProject: convertProject,
    convertJsFile: convertJsFile,
    convertHtmlMarkup: convertHtmlMarkup,
    // Taint analysis
    traceTaint: traceTaint,
    traceTaintInJs: traceTaintInJs,
    // Utilities
    decodeHtmlEntities: decodeHtmlEntities,
    parseStyleDecls: parseStyleDecls,
    serializeHtmlTokens: serializeHtmlTokens,
    makeVar: makeVar,
    // Classification data (for custom analysis)
    TAINT_SOURCES: TAINT_SOURCES,
    TAINT_SINKS: TAINT_SINKS,
    TAINT_CALL_SINKS: TAINT_CALL_SINKS,
    ELEMENT_SINK_TYPES: ELEMENT_SINK_TYPES,
    TAINT_SANITIZERS: TAINT_SANITIZERS,
    EVENT_TAINT_SOURCES: EVENT_TAINT_SOURCES,
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.__convertProject = convertProject;
    globalThis.__convertHtmlMarkup = convertHtmlMarkup;
    globalThis.__convertJsFile = convertJsFile;
    globalThis.__traceTaint = traceTaint;
    globalThis.__htmldomApi = api;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})();
