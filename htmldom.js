// HTML to DOM API Converter
(function () {
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
    'filter', 'feblend', 'fecolormatrix', 'fecomposite', 'fegaussianblur',
    'femerge', 'femergenode', 'feoffset', 'foreignobject', 'marker', 'title',
    'desc', 'view', 'switch', 'a', 'animate', 'animatemotion', 'animatetransform'
  ]);

  function $(id) { return document.getElementById(id); }

  // Extract HTML from input. Returns { html, autoSubs, target } where autoSubs
  // is a list of [placeholder, originalExpression] pairs for JS expressions
  // embedded via string concatenation or template-literal interpolation, and
  // `target` is the detected parent element expression from an
  // `X.innerHTML = ...` (or outerHTML) assignment, or null if none was found.
  function extractHTML(input) {
    const trimmed = input.trim();
    if (!trimmed) return { html: '', autoSubs: [], target: null };
    if (trimmed.startsWith('<')) return { html: trimmed, autoSubs: [], target: null };

    const tokens = tokenize(trimmed);

    // If there's an `X.innerHTML = ...` / `X.outerHTML = ...` assignment,
    // restrict HTML extraction to the right-hand side and surface the target.
    const assign = findHtmlAssignment(tokens);
    let searchTokens = assign ? tokens.slice(assign.rhsStart, assign.rhsEnd) : tokens;
    // Resolve identifier references inside the RHS using the binding state at
    // the assignment site (honoring var/let/const scope, shadowing, and
    // reassignment order).
    if (assign) searchTokens = resolveIdentifiers(tokens, assign.rhsStart, assign.rhsEnd);
    const target = assign ? assign.target : null;
    const assignProp = assign ? assign.prop : null;
    const assignOp = assign ? assign.op : null;

    const chain = findBestConcatChain(searchTokens);
    if (chain) return Object.assign(chain, { target, assignProp, assignOp });

    // Fallback: pick the single string/template literal with the most HTML-ish
    // content.
    let best = null;
    for (const t of searchTokens) {
      if (t.type === 'str' || t.type === 'tmpl') {
        const { html, autoSubs } = materializeStringToken(t, 0);
        if (/</.test(html) && (!best || html.length > best.html.length)) {
          best = { html, autoSubs };
        }
      }
    }
    if (best) return Object.assign(best, { target, assignProp, assignOp });
    // If an assignment target was identified but its RHS held no HTML,
    // don't fall back to scanning the whole input — that would graft
    // unrelated HTML from elsewhere (e.g. `x='<iframe>'`) onto the target.
    if (assign) return { html: '', autoSubs: [], target, assignProp, assignOp };
    return { html: trimmed, autoSubs: [], target: null, assignProp: null, assignOp: null };
  }

  // Find the first top-level `<expr>.innerHTML = ...` / `.outerHTML = ...` /
  // `.innerHTML += ...` assignment in the token stream. Returns
  // { target, rhsStart, rhsEnd } or null. The tokenizer lumps identifier
  // chains like `document.body.innerHTML` into a single `other` token, but
  // calls/brackets like `document.getElementById('x').innerHTML` split the
  // target across several tokens; we reconstruct the full expression by
  // walking back through balanced parens/brackets.
  function findHtmlAssignment(tokens) {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.type !== 'sep') continue;
      if (t.char !== '=' && t.char !== '+=') continue;
      const prev = tokens[i - 1];
      if (!prev || prev.type !== 'other') continue;
      // The trailing accessor must look like `.innerHTML` / `.outerHTML` or
      // `<something>.innerHTML` (simple member chain lumped in one token).
      const trail = prev.text.match(/^(.*)\.(innerHTML|outerHTML)$/);
      if (!trail) continue;
      const prop = trail[2];
      let target = trail[1];
      let k = i - 2;
      // If the accessor stood alone (`.innerHTML`), walk back through a
      // balanced call/index expression to capture the real target.
      if (target === '') {
        const r = reconstructTarget(tokens, i - 1);
        if (!r) continue;
        target = r;
        k = i - 2; // unused; walk-back is already captured in r
      }
      // Find the end of the RHS: next top-level `;` or `,` separator, else EOF.
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
      return { target, prop, op: t.char, rhsStart: i + 1, rhsEnd };
      // (`k` is referenced only to silence lints if re-added later.)
      void k;
    }
    return null;
  }

  // Given the token index of the trailing `.innerHTML`/`.outerHTML` accessor,
  // walk backward collecting balanced `()` / `[]` groups and preceding
  // identifier/member tokens to reconstruct the full target source expression.
  // Returns the original source slice for the target, or null.
  function reconstructTarget(tokens, accessorIdx) {
    let j = accessorIdx - 1;
    let depth = 0;
    const startAccessor = tokens[accessorIdx];
    while (j >= 0) {
      const tk = tokens[j];
      if (tk.type === 'close') { depth++; j--; continue; }
      if (tk.type === 'open') {
        if (depth === 0) return null;
        depth--; j--; continue;
      }
      if (depth > 0) { j--; continue; }
      // At depth 0, accept identifier-like `other` tokens or `.propName`
      // accessors as continuing the member chain.
      if (tk.type === 'other') { j--; continue; }
      break;
    }
    const firstIdx = j + 1;
    if (firstIdx > accessorIdx - 1) return null;
    const first = tokens[firstIdx];
    // Exclude the trailing .innerHTML/.outerHTML from the target slice.
    return first._src.slice(first.start, startAccessor.start).trim() || null;
  }

  const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
  const PATH_RE = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$/;
  const IDENT_OR_PATH_RE = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$/;
  const TEMPLATE_EXPR_PATH_RE = /^\s*[A-Za-z_$][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*\s*$/;

  // A chain binding wraps an array of operand/plus tokens. Object and array
  // bindings hold named or indexed child bindings (each itself a chain,
  // object, or array) so member access and destructuring can walk into them.
  const chainBinding = (toks) => ({ kind: 'chain', toks });
  const objectBinding = (props) => ({ kind: 'object', props });
  const arrayBinding = (elems) => ({ kind: 'array', elems });

  const makeSynthStr = (text) => ({
    type: 'str', quote: "'", raw: text, text, start: 0, end: 0, _src: '',
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
  function buildScopeState(tokens, stopAt) {
    const stack = [{ bindings: Object.create(null), isFunction: true }];
    let pendingFunctionBrace = false;

    const topBlock = () => stack[stack.length - 1];
    const declBlock = (name, value) => { topBlock().bindings[name] = value; };
    const declFunction = (name, value) => {
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].isFunction) { stack[i].bindings[name] = value; return; }
      }
    };
    const assignName = (name, value) => {
      for (let i = stack.length - 1; i >= 0; i--) {
        if (name in stack[i].bindings) { stack[i].bindings[name] = value; return; }
      }
      stack[0].bindings[name] = value; // implicit global
    };
    const resolve = (name) => {
      for (let i = stack.length - 1; i >= 0; i--) {
        if (name in stack[i].bindings) return stack[i].bindings[name];
      }
      return null;
    };
    // Walk a dotted path ('obj.a.b') into an object binding tree.
    const resolvePath = (path) => {
      const parts = path.split('.');
      let b = resolve(parts[0]);
      for (let i = 1; i < parts.length && b; i++) {
        if (b.kind !== 'object') return null;
        b = b.props[parts[i]] || null;
      }
      return b;
    };
    // Flatten a binding to plain text if possible (all parts are string
    // literals or templates whose exprs all resolve). Returns null otherwise.
    const bindingToText = (b) => {
      if (!b) return null;
      if (b.kind !== 'chain') return null;
      let text = '';
      for (const t of b.toks) {
        if (t.type === 'plus') continue;
        if (t.type === 'str') { text += t.text; continue; }
        if (t.type === 'tmpl') {
          const rw = templateToText(t);
          if (rw === null) return null;
          text += rw;
          continue;
        }
        return null;
      }
      return text;
    };
    // Rewrite a template literal as plain text by resolving each ${expr} via
    // resolvePath. Returns null if any expr can't be resolved to plain text.
    const templateToText = (tok) => {
      let text = '';
      for (const p of tok.parts) {
        if (p.kind === 'text') { text += decodeJsString(p.raw, '`'); continue; }
        if (!TEMPLATE_EXPR_PATH_RE.test(p.expr)) return null;
        const path = p.expr.replace(/\s+/g, '');
        const b = resolvePath(path);
        if (!b) return null;
        const t = bindingToText(b);
        if (t === null) return null;
        text += t;
      }
      return text;
    };
    // Rewrite a tmpl token in place to inline every resolvable expr; falls
    // back to the original token if any expr can't be resolved.
    const rewriteTemplate = (tok) => {
      if (tok.type !== 'tmpl') return tok;
      // All-resolvable fast path: full text.
      const asText = templateToText(tok);
      if (asText !== null) return makeSynthStr(asText);
      // Partial rewrite: replace resolvable exprs with their plain text, keep
      // others. Coalesce adjacent text parts afterward.
      let changed = false;
      const parts = [];
      for (const p of tok.parts) {
        if (p.kind === 'text') { parts.push({ kind: 'text', raw: p.raw }); continue; }
        if (TEMPLATE_EXPR_PATH_RE.test(p.expr)) {
          const path = p.expr.replace(/\s+/g, '');
          const b = resolvePath(path);
          if (b) {
            const t = bindingToText(b);
            if (t !== null) {
              // Re-encode as template-raw (preserve backtick/backslash).
              const raw = t.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
              parts.push({ kind: 'text', raw });
              changed = true;
              continue;
            }
          }
        }
        parts.push({ kind: 'expr', expr: p.expr });
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
        const tk = tokens[k];
        if (tk.type === 'open') depth++;
        else if (tk.type === 'close') {
          if (depth === 0) break;
          depth--;
        } else if (depth === 0 && tk.type === 'sep' && (tk.char === ',' || tk.char === ';')) break;
        k++;
      }
      return k;
    };

    // Read a destructuring pattern starting at an opening `{` or `[`.
    // Supported:
    //   object: { a }, { a: b }, { a, b: c }
    //   array:  [ a, b ], [ a, , b ] (holes bind nothing)
    // Returns { pattern, next } or null. Pattern shapes:
    //   { kind:'obj-pattern', entries: [{key, name}] }
    //   { kind:'arr-pattern', entries: [name|null] }
    const readDestructurePattern = (k, stop) => {
      const open = tokens[k];
      if (!open || open.type !== 'open') return null;
      if (open.char === '{') {
        const entries = [];
        let i = k + 1;
        while (i < stop) {
          const tk = tokens[i];
          if (tk.type === 'close' && tk.char === '}') break;
          let key = null;
          let name = null;
          if (tk.type === 'other') {
            // `{ html }` shorthand: tk.text === 'html' and next token is ,/}
            // `{ html: h }`: tk.text === 'html' or 'html:' (attached colon)
            if (IDENT_RE.test(tk.text)) {
              key = tk.text;
              i++;
              // Check if next is `:` (rename) or comma/close (shorthand).
              const sep = tokens[i];
              if (sep && sep.type === 'other' && sep.text === ':') {
                i++;
                const alias = tokens[i];
                if (!alias || alias.type !== 'other' || !IDENT_RE.test(alias.text)) return null;
                name = alias.text;
                i++;
              } else {
                name = key;
              }
            } else if (tk.text.endsWith(':') && IDENT_RE.test(tk.text.slice(0, -1))) {
              key = tk.text.slice(0, -1);
              i++;
              const alias = tokens[i];
              if (!alias || alias.type !== 'other' || !IDENT_RE.test(alias.text)) return null;
              name = alias.text;
              i++;
            } else {
              return null;
            }
          } else {
            return null;
          }
          entries.push({ key, name });
          const comma = tokens[i];
          if (comma && comma.type === 'sep' && comma.char === ',') { i++; continue; }
          break;
        }
        const close = tokens[i];
        if (!close || close.type !== 'close' || close.char !== '}') return null;
        return { pattern: { kind: 'obj-pattern', entries }, next: i + 1 };
      }
      if (open.char === '[') {
        const entries = [];
        let i = k + 1;
        while (i < stop) {
          const tk = tokens[i];
          if (tk.type === 'close' && tk.char === ']') break;
          if (tk.type === 'sep' && tk.char === ',') { entries.push(null); i++; continue; }
          if (tk.type === 'other' && IDENT_RE.test(tk.text)) {
            entries.push(tk.text);
            i++;
            const comma = tokens[i];
            if (comma && comma.type === 'sep' && comma.char === ',') { i++; continue; }
            break;
          }
          return null;
        }
        const close = tokens[i];
        if (!close || close.type !== 'close' || close.char !== ']') return null;
        return { pattern: { kind: 'arr-pattern', entries }, next: i + 1 };
      }
      return null;
    };

    // Bind names from `pattern` by walking into `source` (a binding).
    const applyPatternBindings = (pattern, source, bind) => {
      if (pattern.kind === 'obj-pattern') {
        const props = source && source.kind === 'object' ? source.props : null;
        for (const { key, name } of pattern.entries) {
          bind(name, props ? (props[key] || null) : null);
        }
        return;
      }
      if (pattern.kind === 'arr-pattern') {
        const elems = source && source.kind === 'array' ? source.elems : null;
        for (let i = 0; i < pattern.entries.length; i++) {
          const name = pattern.entries[i];
          if (name === null) continue;
          bind(name, elems ? (elems[i] || null) : null);
        }
        return;
      }
    };

    // Read an object literal `{ key: value, ... }` starting at index `k`.
    // Keys are bare identifiers or quoted strings. Values are any readValue
    // (chain, nested object, or nested array). Returns { binding, next }.
    const readObjectLit = (k, stop) => {
      const open = tokens[k];
      if (!open || open.type !== 'open' || open.char !== '{') return null;
      const props = Object.create(null);
      let i = k + 1;
      while (i < stop) {
        const tk = tokens[i];
        if (tk.type === 'close' && tk.char === '}') break;
        // Key: either a str token or an 'other' identifier (possibly with
        // an attached trailing ':').
        let keyName = null;
        if (tk.type === 'str') {
          keyName = tk.text;
          i++;
        } else if (tk.type === 'other') {
          // Strip one optional trailing ':' that the tokenizer left attached.
          if (tk.text.endsWith(':') && IDENT_RE.test(tk.text.slice(0, -1))) {
            keyName = tk.text.slice(0, -1);
            i++;
            // The ':' was consumed as part of the token.
            // Value follows directly.
            const val = readValue(i, stop, TERMS_OBJ);
            if (!val) return null;
            props[keyName] = val.binding;
            i = val.next;
            const sep = tokens[i];
            if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
            break;
          }
          if (IDENT_RE.test(tk.text)) { keyName = tk.text; i++; }
          else return null;
        } else {
          return null;
        }
        // Expect a separate ':' delimiter — either an 'other' token of just ':'
        // or an 'other' token starting with ':' (rare).
        const colon = tokens[i];
        if (!colon) return null;
        if (colon.type === 'other' && colon.text === ':') { i++; }
        else if (colon.type === 'other' && colon.text.startsWith(':')) {
          // Split unusual cases: treat ':' as the separator, push rest back.
          // We don't support this cleanly; bail.
          return null;
        } else {
          return null;
        }
        const val = readValue(i, stop, TERMS_OBJ);
        if (!val) return null;
        props[keyName] = val.binding;
        i = val.next;
        const sep = tokens[i];
        if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
        break;
      }
      const close = tokens[i];
      if (!close || close.type !== 'close' || close.char !== '}') return null;
      return { binding: objectBinding(props), next: i + 1 };
    };

    // Read an array literal `[ v, v, ... ]`. Returns { binding, next } or null.
    const readArrayLit = (k, stop) => {
      const open = tokens[k];
      if (!open || open.type !== 'open' || open.char !== '[') return null;
      const elems = [];
      let i = k + 1;
      while (i < stop) {
        const tk = tokens[i];
        if (tk.type === 'close' && tk.char === ']') break;
        const val = readValue(i, stop, TERMS_ARR);
        if (!val) return null;
        elems.push(val.binding);
        i = val.next;
        const sep = tokens[i];
        if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
        break;
      }
      const close = tokens[i];
      if (!close || close.type !== 'close' || close.char !== ']') return null;
      return { binding: arrayBinding(elems), next: i + 1 };
    };

    // Read any value at index `k`: chain, object literal, or array literal.
    // `terms` defines the expression terminators for chain parsing.
    // Returns { binding, next } or null.
    const readValue = (k, stop, terms) => {
      const t = tokens[k];
      if (!t) return null;
      if (t.type === 'open' && t.char === '{') return readObjectLit(k, stop);
      if (t.type === 'open' && t.char === '[') {
        // Could be `[...].join(...)` (a concat operand) or a plain array.
        // Try concat first (it consumes the join suffix); fall back to
        // plain array literal.
        const saved = readChainFromHere(k, stop, terms);
        if (saved) return { binding: chainBinding(saved.toks), next: saved.next };
        return readArrayLit(k, stop);
      }
      const r = readChainFromHere(k, stop, terms);
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
    const applySuffixes = (bind, next, stop) => {
      while (next < stop && bind) {
        const t = tokens[next];
        if (!t) break;
        // Bracket subscript: [strLit] (object key) or [intLit] (array index).
        if (t.type === 'open' && t.char === '[') {
          const keyTok = tokens[next + 1];
          const close = tokens[next + 2];
          if (!keyTok || !close || close.type !== 'close' || close.char !== ']') break;
          if (keyTok.type === 'str') {
            if (bind.kind === 'object') {
              bind = bind.props[keyTok.text] || null;
            } else if (bind.kind === 'array' && /^\d+$/.test(keyTok.text)) {
              bind = bind.elems[parseInt(keyTok.text, 10)] || null;
            } else break;
            next = next + 3;
            continue;
          }
          if (keyTok.type === 'other' && /^-?\d+$/.test(keyTok.text)) {
            if (bind.kind === 'array') {
              bind = bind.elems[parseInt(keyTok.text, 10)] || null;
              next = next + 3;
              continue;
            }
            break;
          }
          break;
        }
        // Separate-token method call: `].join(sep)` or `'a'.concat(...)`.
        // Also handles `.prop.concat(...)` / `.prop.join(...)` when attached.
        if (t.type === 'other' && /^(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$/.test(t.text)) {
          const paren = tokens[next + 1];
          const isCall = paren && paren.type === 'open' && paren.char === '(';
          const segs = t.text.slice(1).split('.');
          const lastSeg = segs[segs.length - 1];
          const isMethodCall = isCall && (lastSeg === 'concat' || lastSeg === 'join');
          // Walk any leading property segments into an object binding.
          const propSegs = isMethodCall ? segs.slice(0, -1) : segs;
          let cur = bind;
          for (const p of propSegs) {
            if (!cur || cur.kind !== 'object') { cur = null; break; }
            cur = cur.props[p] || null;
          }
          if (isMethodCall) {
            const r = applyMethod(cur, lastSeg, next + 1, stop);
            if (!r) break;
            bind = chainBinding(r.toks);
            next = r.next;
            continue;
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
    const applyMethod = (bind, method, parenIdx, stop) => {
      if (method === 'concat') {
        if (!bind || bind.kind !== 'chain') return null;
        const args = readConcatArgs(parenIdx, stop);
        if (!args) return null;
        const toks = bind.toks.slice();
        for (const a of args.args) { toks.push(SYNTH_PLUS); for (const v of a) toks.push(v); }
        return { toks, next: args.next };
      }
      if (method === 'join') {
        if (!bind || bind.kind !== 'array') return null;
        const lp = tokens[parenIdx];
        if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
        const sepTok = tokens[parenIdx + 1];
        if (!sepTok || (sepTok.type !== 'str' && sepTok.type !== 'tmpl')) return null;
        const rp = tokens[parenIdx + 2];
        if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
        const elems = bind.elems;
        if (elems.length === 0) return { toks: [makeSynthStr('')], next: parenIdx + 3 };
        const out = [];
        for (let e = 0; e < elems.length; e++) {
          const eb = elems[e];
          if (!eb || eb.kind !== 'chain') return null;
          if (e > 0) { out.push(SYNTH_PLUS); out.push(rewriteTemplate(sepTok)); out.push(SYNTH_PLUS); }
          for (const vt of eb.toks) out.push(vt);
        }
        return { toks: out, next: parenIdx + 3 };
      }
      return null;
    };

    // Read a "base" value before any suffixes: literals, identifiers/paths
    // (with optional attached .concat/.join method), parenthesized
    // subexpressions, array literals, and object literals.
    const readBase = (k, stop) => {
      const t = tokens[k];
      if (!t) return null;
      if (t.type === 'str') return { bind: chainBinding([t]), next: k + 1 };
      if (t.type === 'tmpl') return { bind: chainBinding([rewriteTemplate(t)]), next: k + 1 };
      if (t.type === 'open' && t.char === '(') {
        const r = readConcatExpr(k + 1, stop, { sep: [], close: [')'] });
        if (!r) return null;
        const rp = tokens[r.next];
        if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
        return { bind: chainBinding(r.toks), next: r.next + 1 };
      }
      if (t.type === 'open' && t.char === '[') {
        const a = readArrayLit(k, stop);
        if (!a) return null;
        return { bind: a.binding, next: a.next };
      }
      if (t.type === 'open' && t.char === '{') {
        const o = readObjectLit(k, stop);
        if (!o) return null;
        return { bind: o.binding, next: o.next };
      }
      if (t.type !== 'other') return null;
      // Primitive literal.
      const lit = primitiveAsString(t.text);
      if (lit !== null) return { bind: chainBinding([makeSynthStr(lit)]), next: k + 1 };
      // Identifier/path, possibly with attached .concat/.join method call.
      if (IDENT_OR_PATH_RE.test(t.text)) {
        const paren = tokens[k + 1];
        const isCall = paren && paren.type === 'open' && paren.char === '(';
        if (isCall) {
          const dot = t.text.lastIndexOf('.');
          if (dot > 0) {
            const method = t.text.slice(dot + 1);
            if (method === 'concat' || method === 'join') {
              const prefix = t.text.slice(0, dot);
              const prefBind = resolvePath(prefix);
              if (prefBind) {
                const r = applyMethod(prefBind, method, k + 1, stop);
                if (r) return { bind: chainBinding(r.toks), next: r.next };
              }
              return null;
            }
          }
        }
        const b = resolvePath(t.text);
        if (b) return { bind: b, next: k + 1 };
      }
      return null;
    };

    // Read one operand of a concat chain. Returns { toks, next } where toks
    // is a flat concat sub-chain, or null. Combines readBase + applySuffixes
    // and requires the final binding to be a chain (strings/templates).
    const readOperand = (k, stop) => {
      const base = readBase(k, stop);
      if (!base) return null;
      const r = applySuffixes(base.bind, base.next, stop);
      if (!r.bind || r.bind.kind !== 'chain') return null;
      return { toks: r.bind.toks.slice(), next: r.next };
    };

    // Parse `( chain, chain, ... )` starting at the `(` token index. Returns
    // { args: [tokens[], ...], next } or null.
    const readConcatArgs = (k, stop) => {
      const lp = tokens[k];
      if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
      const args = [];
      let i = k + 1;
      const maybeRp = tokens[i];
      if (maybeRp && maybeRp.type === 'close' && maybeRp.char === ')') return { args, next: i + 1 };
      while (i < stop) {
        const arg = readChainFromHere(i, stop, TERMS_ARG);
        if (!arg) return null;
        args.push(arg.toks);
        i = arg.next;
        const sep = tokens[i];
        if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
        break;
      }
      const rp = tokens[i];
      if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
      return { args, next: i + 1 };
    };

    // Internal helper: same as readConcatExpr but always called with a fresh
    // starting point. (Separate name used to avoid confusion with exports.)
    const readChainFromHere = (k, stop, terms) => readConcatExpr(k, stop, terms);

    // Read a concat chain (operand [+ operand]*) starting at `k`, stopping at
    // the first top-level token matching any terminator in `terms`
    // (`{ sep: [...], close: [...] }`). Returns `{ toks, next }` or null.
    const readConcatExpr = (k, stop, terms) => {
      const out = [];
      const endAt = (tk) => {
        if (!tk) return true;
        if (tk.type === 'sep' && terms.sep.includes(tk.char)) return true;
        if (tk.type === 'close' && terms.close.includes(tk.char)) return true;
        return false;
      };
      let i = k;
      // Read first operand.
      if (endAt(tokens[i])) return null;
      let op = readOperand(i, stop);
      if (!op) return null;
      for (const t of op.toks) out.push(t);
      i = op.next;
      // Read subsequent (+ operand)* pairs.
      while (i < stop && !endAt(tokens[i])) {
        const plus = tokens[i];
        if (!plus || plus.type !== 'plus') return null;
        i++;
        op = readOperand(i, stop);
        if (!op) return null;
        out.push(plus);
        for (const t of op.toks) out.push(t);
        i = op.next;
      }
      return { toks: out, next: i };
    };

    // Top-level RHS reader: reads a concat chain up to `,`/`;`/stop.
    const readInit = (k, stop) => {
      const r = readConcatExpr(k, stop, TERMS_TOP);
      return r ? r.toks : null;
    };

    const stop = Math.min(stopAt, tokens.length);
    for (let i = 0; i < stop; i++) {
      const t = tokens[i];

      if (t.type === 'open' && t.char === '{') {
        stack.push({ bindings: Object.create(null), isFunction: pendingFunctionBrace });
        pendingFunctionBrace = false;
        continue;
      }
      if (t.type === 'close' && t.char === '}') {
        if (stack.length > 1) stack.pop();
        continue;
      }

      if (t.type !== 'other') continue;

      if (t.text === 'function') { pendingFunctionBrace = true; continue; }
      if (t.text === '=>') {
        // Only arrow bodies of the form `=> { ... }` open a function scope;
        // expression arrows (`x => x + 1`) don't.
        const next = tokens[i + 1];
        if (next && next.type === 'open' && next.char === '{') pendingFunctionBrace = true;
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
            const val = readValue(pat.next + 1, stop, TERMS_TOP);
            const srcBinding = val ? val.binding : null;
            applyPatternBindings(pat.pattern, srcBinding, declBind);
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
            const r = readValue(j + 2, stop, TERMS_TOP);
            value = r ? r.binding : null;
            k = skipExpr(j + 2, stop);
          }
          if (hasInit) {
            declBind(nameTok.text, value);
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
        i = j - 1;
        continue;
      }

      // Bare assignment: IDENT = <value>.
      if (IDENT_RE.test(t.text)) {
        const eqTok = tokens[i + 1];
        if (eqTok && eqTok.type === 'sep' && eqTok.char === '=') {
          const r = readValue(i + 2, stop, TERMS_TOP);
          assignName(t.text, r ? r.binding : null);
          i = skipExpr(i + 2, stop) - 1;
          continue;
        }
      }
    }

    // Parse tokens[start, end) as a concat chain, expanding identifier
    // references, member paths, `[...].join(sep)`, and `.concat(...)` calls.
    // Returns the flat chain tokens (alternating operand / plus) or null.
    const parseRange = (start, end) => {
      const r = readConcatExpr(start, end, TERMS_NONE);
      if (!r || r.next !== end) return null;
      return r.toks;
    };

    return { resolve, resolvePath, parseRange, rewriteTemplate };
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
  function resolveIdentifiers(tokens, startIdx, endIdx) {
    const state = buildScopeState(tokens, startIdx);
    const full = state.parseRange(startIdx, endIdx);
    if (full) return full;
    const out = [];
    for (let i = startIdx; i < endIdx; i++) {
      const t = tokens[i];
      if (t.type === 'tmpl') { out.push(state.rewriteTemplate(t)); continue; }
      if (t.type === 'other' && IDENT_OR_PATH_RE.test(t.text)) {
        const next = tokens[i + 1];
        const isLhs = next && next.type === 'sep' && next.char === '=';
        if (!isLhs) {
          const b = state.resolvePath(t.text);
          if (b && b.kind === 'chain') { for (const vt of b.toks) out.push(vt); continue; }
        }
      }
      out.push(t);
    }
    return out;
  }

  const EXPR_PREFIX = '__HDX';
  const EXPR_SUFFIX = '__';
  function makePlaceholder(n) { return EXPR_PREFIX + n + EXPR_SUFFIX; }

  // Build html/autoSubs from a single string or template literal token.
  // `startIdx` is the next placeholder index to use.
  function materializeStringToken(tok, startIdx) {
    const autoSubs = [];
    let idx = startIdx;
    if (tok.type === 'str') {
      return { html: tok.text, autoSubs, nextIdx: idx };
    }
    // template literal
    let html = '';
    for (const p of tok.parts) {
      if (p.kind === 'text') html += decodeJsString(p.raw, '`');
      else {
        const ph = makePlaceholder(idx++);
        autoSubs.push([ph, p.expr.trim()]);
        html += ph;
      }
    }
    return { html, autoSubs, nextIdx: idx };
  }

  // Walk tokens, maintaining a stack of bracket levels. At each level, split
  // the range into operand sub-ranges at every `+` at that level. Collect all
  // chains (operand-arrays) of length >= 2. Returns the chain producing the
  // most HTML-like output, or null.
  function findBestConcatChain(tokens) {
    const chains = [];
    const stack = [{ opStart: 0, operands: [] }];
    const addOperand = (ctx, fromIdx, toIdx) => {
      if (fromIdx > toIdx) return;
      // Trim whitespace (we don't emit whitespace tokens, so nothing to do).
      ctx.operands.push({ toks: tokens.slice(fromIdx, toIdx + 1) });
    };
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.type === 'open') {
        stack.push({ opStart: i + 1, operands: [] });
        continue;
      }
      if (t.type === 'close') {
        const top = stack.pop();
        addOperand(top, top.opStart, i - 1);
        if (top.operands.length > 1) chains.push(top.operands);
        continue;
      }
      if (t.type === 'plus') {
        const top = stack[stack.length - 1];
        addOperand(top, top.opStart, i - 1);
        top.opStart = i + 1;
        continue;
      }
      if (t.type === 'sep') {
        // Terminate and flush the current chain at this depth; start a fresh one.
        const top = stack[stack.length - 1];
        addOperand(top, top.opStart, i - 1);
        if (top.operands.length > 1) chains.push(top.operands);
        top.operands = [];
        top.opStart = i + 1;
      }
    }
    while (stack.length) {
      const top = stack.pop();
      addOperand(top, top.opStart, tokens.length - 1);
      if (top.operands.length > 1) chains.push(top.operands);
    }

    let best = null;
    let bestScore = -1;
    for (const chain of chains) {
      const m = materializeChain(chain);
      if (!m) continue;
      if (!/</.test(m.html)) continue;
      const score = m.html.length + m.autoSubs.length * 50;
      if (score > bestScore) { bestScore = score; best = m; }
    }
    return best;
  }

  function materializeChain(operands) {
    let html = '';
    const autoSubs = [];
    let idx = 0;
    let hasString = false;
    for (const op of operands) {
      // operand has { toks, start, end }
      if (op.toks.length === 1 && (op.toks[0].type === 'str' || op.toks[0].type === 'tmpl')) {
        const m = materializeStringToken(op.toks[0], idx);
        html += m.html;
        for (const s of m.autoSubs) autoSubs.push(s);
        idx = m.nextIdx;
        hasString = true;
      } else {
        const first = op.toks[0];
        const last = op.toks[op.toks.length - 1];
        const expr = first._src.slice(first.start, last.end).trim();
        const ph = makePlaceholder(idx++);
        autoSubs.push([ph, expr]);
        html += ph;
      }
    }
    if (!hasString) return null;
    return { html, autoSubs };
  }

  // --- Tokenizer ---
  function tokenize(src) {
    const tokens = [];
    let i = 0;
    const n = src.length;
    function push(tok) { tok._src = src; tokens.push(tok); }
    while (i < n) {
      const c = src[i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
      if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; continue; }
      if (c === '/' && src[i + 1] === '*') { i += 2; while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++; i += 2; continue; }
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
                i++;
                while (i < n && src[i] !== '`') {
                  if (src[i] === '\\') { i += 2; }
                  else if (src[i] === '$' && src[i + 1] === '{') { i += 2; let d = 1; while (i < n && d > 0) { if (src[i] === '{') d++; else if (src[i] === '}') d--; i++; } }
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
      // Comparison/equality operators starting with '=' — keep as opaque other.
      if (c === '=' && src[i + 1] === '=') {
        const len = src[i + 2] === '=' ? 3 : 2;
        push({ type: 'other', text: src.slice(i, i + len), start: i, end: i + len });
        i += len;
        continue;
      }
      if (c === '=' && src[i + 1] === '>') { push({ type: 'other', text: '=>', start: i, end: i + 2 }); i += 2; continue; }
      if (c === '(' || c === '[' || c === '{') { push({ type: 'open', char: c, start: i, end: i + 1 }); i++; continue; }
      if (c === ')' || c === ']' || c === '}') { push({ type: 'close', char: c, start: i, end: i + 1 }); i++; continue; }
      // Identifier/number/punctuation run — consumed until we hit a special char.
      const start = i;
      while (i < n) {
        const ch = src[i];
        if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') break;
        if (ch === "'" || ch === '"' || ch === '`') break;
        if (ch === '+' && src[i + 1] !== '+') break;
        if (ch === ',' || ch === ';') break;
        if (ch === '=') break;
        if (ch === '(' || ch === ')' || ch === '[' || ch === ']' || ch === '{' || ch === '}') break;
        if (ch === '/' && (src[i + 1] === '/' || src[i + 1] === '*')) break;
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

  // Produce a JS string literal (or variable/template) for `s`.
  function jsStr(s, substitutions) {
    if (substitutions && substitutions.length) {
      for (const [needle, varName] of substitutions) {
        if (needle && s === needle) return { code: varName, isVar: true };
      }
      for (const [needle, varName] of substitutions) {
        if (needle && s.includes(needle)) {
          const parts = s.split(needle);
          const pieces = [];
          for (let i = 0; i < parts.length; i++) {
            if (i > 0) pieces.push('${' + varName + '}');
            pieces.push(parts[i]
              .replace(/\\/g, '\\\\')
              .replace(/`/g, '\\`')
              .replace(/\$\{/g, '\\${'));
          }
          return { code: '`' + pieces.join('') + '`', isVar: true };
        }
      }
    }
    const esc = s
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t')
      .replace(/\u2028/g, '\\u2028')
      .replace(/\u2029/g, '\\u2029');
    return { code: "'" + esc + "'", isVar: false };
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

  function isValidIdent(s) { return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(s); }

  // Convert a style="..." attribute value into an array of style.* assignments.
  function parseStyle(val) {
    const out = [];
    // Split on ; that are not inside parens (e.g. url(a;b)).
    let depth = 0, cur = '';
    for (let i = 0; i < val.length; i++) {
      const c = val[i];
      if (c === '(') depth++;
      else if (c === ')') depth--;
      if (c === ';' && depth === 0) { if (cur.trim()) out.push(cur.trim()); cur = ''; }
      else cur += c;
    }
    if (cur.trim()) out.push(cur.trim());
    const decls = [];
    for (const d of out) {
      const idx = d.indexOf(':');
      if (idx === -1) continue;
      const prop = d.slice(0, idx).trim().toLowerCase();
      let value = d.slice(idx + 1).trim();
      let priority = '';
      const important = /!\s*important\s*$/i;
      if (important.test(value)) {
        value = value.replace(important, '').trim();
        priority = 'important';
      }
      decls.push({ prop, value, priority });
    }
    return decls;
  }

  function convertNode(node, parentVar, lines, used, opts, nsCtx) {
    // Text node.
    if (node.nodeType === 3) {
      const text = node.nodeValue;
      if (text === '') return;
      if (opts.skipWhitespaceText && /^\s*$/.test(text)) return;
      const v = makeVar('text', used);
      const lit = jsStr(text, opts.subs);
      lines.push('const ' + v + ' = document.createTextNode(' + lit.code + ');');
      lines.push(parentVar + '.appendChild(' + v + ');');
      return;
    }
    // Comment.
    if (node.nodeType === 8) {
      const v = makeVar('comment', used);
      const lit = jsStr(node.nodeValue, opts.subs);
      lines.push('const ' + v + ' = document.createComment(' + lit.code + ');');
      lines.push(parentVar + '.appendChild(' + v + ');');
      return;
    }
    // CDATA section (appears in foreign content, e.g. SVG).
    if (node.nodeType === 4) {
      const v = makeVar('cdata', used);
      const lit = jsStr(node.nodeValue, opts.subs);
      // HTML documents cannot create CDATA nodes; emit via an XML document.
      lines.push('const ' + v + " = document.implementation.createDocument(null, null).createCDATASection(" + lit.code + ');');
      lines.push(parentVar + '.appendChild(' + v + ');');
      return;
    }
    // Processing instruction.
    if (node.nodeType === 7) {
      const v = makeVar('pi', used);
      const target = jsStr(node.target, opts.subs).code;
      const data = jsStr(node.nodeValue, opts.subs).code;
      lines.push('const ' + v + ' = document.createProcessingInstruction(' + target + ', ' + data + ');');
      lines.push(parentVar + '.appendChild(' + v + ');');
      return;
    }
    if (node.nodeType !== 1) return;

    const tag = node.tagName.toLowerCase();
    const v = makeVar(tag, used);

    const attrs = Array.from(node.attributes || []);

    // Namespace detection. Elements in a parsed HTML document expose their
    // namespaceURI; prefer that when present, so fragments like
    // `<g xmlns="http://www.w3.org/2000/svg">` route through createElementNS
    // even without a wrapping <svg>. Fall back to tag-name heuristics for
    // elements lacking a namespaceURI.
    let ns = node.namespaceURI || nsCtx;
    if (ns === 'http://www.w3.org/1999/xhtml') ns = null;
    // Fallback tag-name heuristics for nodes without a namespaceURI.
    if (!node.namespaceURI) {
      if (tag === 'svg') ns = SVG_NS;
      else if (tag === 'math') ns = MATHML_NS;
    }
    // Note: <foreignObject> itself stays in SVG; its children revert to HTML
    // via `childNs` below.

    // Detect `is=` for customized built-ins (HTML namespace only).
    let isAttr = null;
    if (ns !== SVG_NS && ns !== MATHML_NS) {
      for (const a of attrs) {
        if (a.name === 'is') { isAttr = a.value; break; }
      }
    }

    if (ns === SVG_NS || ns === MATHML_NS) {
      lines.push('const ' + v + " = document.createElementNS('" + ns + "', '" + node.tagName + "');");
    } else if (isAttr !== null) {
      const isLit = jsStr(isAttr, opts.subs).code;
      lines.push('const ' + v + " = document.createElement('" + tag + "', { is: " + isLit + ' });');
    } else {
      lines.push('const ' + v + " = document.createElement('" + tag + "');");
    }

    for (const attr of attrs) {
      const name = attr.name;
      const val = attr.value;

      // Event handler -> addEventListener with the original code in a function body.
      const evMatch = /^on([a-z]+)$/.exec(name);
      if (evMatch && opts.eventsAsListeners) {
        const evName = evMatch[1];
        const body = val;
        // event/this/target are available in inline handler scope; emulate.
        lines.push(v + ".addEventListener('" + evName + "', function (event) {");
        for (const ln of body.split('\n')) lines.push('  ' + ln);
        lines.push('});');
        continue;
      }

      // Style attribute -> style.setProperty calls.
      if (name === 'style' && opts.splitStyle) {
        const decls = parseStyle(val);
        if (decls.length === 0) {
          lines.push(v + ".setAttribute('style', " + jsStr(val, opts.subs).code + ');');
        } else {
          for (const d of decls) {
            const p = jsStr(d.prop).code;
            const vv = jsStr(d.value, opts.subs).code;
            if (d.priority) {
              lines.push(v + '.style.setProperty(' + p + ', ' + vv + ", 'important');");
            } else {
              lines.push(v + '.style.setProperty(' + p + ', ' + vv + ');');
            }
          }
        }
        continue;
      }

      // Namespaced attributes -> setAttributeNS.
      if (name.startsWith('xlink:')) {
        lines.push(v + ".setAttributeNS('" + XLINK_NS + "', '" + name + "', " + jsStr(val, opts.subs).code + ');');
        continue;
      }
      if (name === 'xmlns' || name.startsWith('xmlns:')) {
        lines.push(v + ".setAttributeNS('" + XMLNS_NS + "', '" + name + "', " + jsStr(val, opts.subs).code + ');');
        continue;
      }
      if (name.startsWith('xml:')) {
        lines.push(v + ".setAttributeNS('" + XML_NS + "', '" + name + "', " + jsStr(val, opts.subs).code + ');');
        continue;
      }

      // Boolean attributes in HTML ns: empty value -> true, else setAttribute.
      if (ns !== SVG_NS && ns !== MATHML_NS && BOOLEAN_ATTRS.has(name)) {
        // attribute present implies true
        lines.push(v + '.' + (ATTR_TO_PROP[name] || name) + ' = true;');
        continue;
      }

      // Class attribute: use classList.add(...) for readability if multiple classes.
      if (name === 'class' && opts.useClassList && ns !== SVG_NS) {
        const classes = val.split(/\s+/).filter(Boolean);
        if (classes.length === 0) continue;
        if (classes.length === 1) {
          lines.push(v + '.className = ' + jsStr(classes[0], opts.subs).code + ';');
        } else {
          const parts = classes.map(c => jsStr(c, opts.subs).code).join(', ');
          lines.push(v + '.classList.add(' + parts + ');');
        }
        continue;
      }

      // IDL property (HTML ns only).
      const idl = (opts.useProps && ns !== SVG_NS && ns !== MATHML_NS) ? isIdlProp(name) : null;
      const lit = jsStr(val, opts.subs);
      if (idl) {
        lines.push(v + '.' + idl + ' = ' + lit.code + ';');
      } else {
        lines.push(v + ".setAttribute('" + name.replace(/'/g, "\\'") + "', " + lit.code + ');');
      }
    }

    // <noscript>: with scripting enabled, the HTML parser stores children as
    // raw text. DOMParser parses with scripting disabled, so children are real
    // nodes — serialize them back to text to match runtime semantics.
    if (tag === 'noscript' && ns !== SVG_NS && ns !== MATHML_NS) {
      const text = node.innerHTML;
      if (text !== '') {
        lines.push(v + '.textContent = ' + jsStr(text, opts.subs).code + ';');
      }
      lines.push(parentVar + '.appendChild(' + v + ');');
      return;
    }

    // <template> holds its parsed subtree on `.content` (a DocumentFragment),
    // not on childNodes. Recurse into that fragment instead.
    if (tag === 'template' && node.content) {
      const tplChildren = Array.from(node.content.childNodes);
      for (const child of tplChildren) {
        convertNode(child, v + '.content', lines, used, opts, null);
      }
      lines.push(parentVar + '.appendChild(' + v + ');');
      return;
    }

    let children = Array.from(node.childNodes);

    // Declarative Shadow DOM: if a direct child is <template shadowrootmode="…">,
    // attach a shadow root on this element and recurse the template content
    // into the shadow root instead. Only the first such template is honored,
    // matching the HTML parser.
    let shadowTpl = null;
    if (ns !== SVG_NS && ns !== MATHML_NS) {
      for (let i = 0; i < children.length; i++) {
        const c = children[i];
        if (c.nodeType !== 1) continue;
        if (c.tagName === 'TEMPLATE' && c.getAttribute && c.getAttribute('shadowrootmode')) {
          shadowTpl = c;
          children.splice(i, 1);
        }
        break;
      }
    }
    if (shadowTpl) {
      const mode = shadowTpl.getAttribute('shadowrootmode');
      const initParts = ['mode: ' + jsStr(mode).code];
      if (shadowTpl.hasAttribute('shadowrootdelegatesfocus')) initParts.push('delegatesFocus: true');
      if (shadowTpl.hasAttribute('shadowrootserializable')) initParts.push('serializable: true');
      if (shadowTpl.hasAttribute('shadowrootclonable')) initParts.push('clonable: true');
      const sv = makeVar('shadow', used);
      lines.push('const ' + sv + ' = ' + v + '.attachShadow({ ' + initParts.join(', ') + ' });');
      if (shadowTpl.content) {
        for (const c of shadowTpl.content.childNodes) {
          convertNode(c, sv, lines, used, opts, null);
        }
      }
    }

    // Children — use textContent shortcut when single text child and no substitution.
    if (!shadowTpl && opts.textContentShortcut &&
        children.length === 1 &&
        children[0].nodeType === 3 &&
        tag !== 'script' && tag !== 'style') {
      const text = children[0].nodeValue;
      const lit = jsStr(text, opts.subs);
      if (text !== '') {
        lines.push(v + '.textContent = ' + lit.code + ';');
      }
    } else {
      const childNs = (tag === 'foreignobject') ? null : ns;
      for (const child of children) {
        convertNode(child, v, lines, used, opts, childNs);
      }
    }

    lines.push(parentVar + '.appendChild(' + v + ');');
  }

  function convert() {
    const raw = $('in').value;
    const { html, autoSubs, target, assignProp, assignOp } = extractHTML(raw);
    const subStr = $('subStr').value;
    const subVar = $('subVar').value.trim();
    const subs = [];
    // Manual substitution first (so it wins on exact matches).
    if (subStr && subVar && isValidIdent(subVar)) {
      subs.push([subStr, subVar]);
    }
    // Auto subs extracted from JS concatenation / template interpolation.
    for (const s of autoSubs) subs.push(s);

    let parent = 'document.body';
    let parentFromAssignment = false;
    if ($('parentVar').checked) {
      const p = $('parentName').value.trim();
      if (p) parent = p;
    } else if (target) {
      // `el.outerHTML = ...` replaces `el` itself, so new nodes land in
      // `el.parentNode`. `el.innerHTML = ...` replaces `el`'s children.
      parent = assignProp === 'outerHTML' ? target + '.parentNode' : target;
      parentFromAssignment = true;
    }

    const opts = {
      useProps: $('useProps').checked,
      splitStyle: $('splitStyle').checked,
      eventsAsListeners: $('eventsAsListeners').checked,
      textContentShortcut: $('textShortcut').checked,
      useClassList: $('useClassList').checked,
      skipWhitespaceText: $('skipWS').checked,
      useFragment: $('useFragment').checked,
      subs
    };

    const doc = new DOMParser().parseFromString(html, 'text/html');
    const roots = [];
    if (doc.head) for (const n of doc.head.childNodes) roots.push(n);
    if (doc.body) {
      for (const n of doc.body.childNodes) roots.push(n);
    } else if (doc.documentElement) {
      // e.g. <frameset> replaces body in HTML5 parser output.
      for (const n of doc.documentElement.childNodes) {
        if (n !== doc.head) roots.push(n);
      }
    }

    // Filter whitespace-only text at the root level when requested.
    const useRoots = opts.skipWhitespaceText
      ? roots.filter(n => !(n.nodeType === 3 && /^\s*$/.test(n.nodeValue)))
      : roots;

    const lines = [];
    const used = new Set();

    // Reserve identifiers that appear in the user's substitution expressions
    // so we don't shadow them with element variable names.
    const idRe = /[A-Za-z_$][A-Za-z0-9_$]*/g;
    for (const [, expr] of subs) {
      let m;
      while ((m = idRe.exec(expr)) !== null) used.add(m[0]);
    }
    // Also reserve the parent target identifier root.
    const parentRoot = parent.match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
    if (parentRoot) used.add(parentRoot[0]);

    if (subStr && subVar && isValidIdent(subVar)) {
      lines.push('// Assumes: const ' + subVar + ' = ' + JSON.stringify(subStr) + ';');
    }
    if (autoSubs.length) {
      lines.push('// Auto-detected JS expressions from input:');
      for (const [ph, expr] of autoSubs) lines.push('//   ' + ph + ' -> ' + expr);
    }

    if (useRoots.length === 0) {
      $('out').value = '// (no nodes parsed)';
      return;
    }

    // Replicate `el.innerHTML = x` semantics (replace existing children) when
    // the input used `=` rather than `+=`, for innerHTML only. outerHTML is
    // emitted as a note since faithful replacement requires replaceWith().
    if (parentFromAssignment && assignOp === '=' && assignProp === 'innerHTML') {
      lines.push(target + '.replaceChildren();');
    } else if (parentFromAssignment && assignProp === 'outerHTML') {
      lines.push('// Note: ' + target + '.outerHTML = ... replaces ' + target + ' itself;');
      lines.push('//       call ' + target + '.replaceWith(...) or adjust as needed.');
    }

    let attachTarget = parent;
    let fragVar = null;
    if (opts.useFragment && useRoots.length > 1) {
      fragVar = makeVar('frag', used);
      lines.push('const ' + fragVar + ' = document.createDocumentFragment();');
      attachTarget = fragVar;
    }

    for (const n of useRoots) {
      convertNode(n, attachTarget, lines, used, opts, null);
    }

    if (fragVar) {
      lines.push(parent + '.appendChild(' + fragVar + ');');
    }

    $('out').value = lines.join('\n');
  }

  $('go').addEventListener('click', convert);
  $('copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('out').value);
      $('copy').textContent = 'Copied!';
      setTimeout(() => { $('copy').textContent = 'Copy output'; }, 1200);
    } catch (e) {
      $('out').select();
    }
  });

  // Live update on input changes.
  const inputs = ['in', 'subStr', 'subVar', 'parentName'];
  for (const id of inputs) $(id).addEventListener('input', convert);
  const toggles = ['useProps', 'splitStyle', 'eventsAsListeners', 'textShortcut', 'useClassList', 'skipWS', 'useFragment', 'parentVar'];
  for (const id of toggles) $(id).addEventListener('change', convert);

  convert();
})();
