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

  // Extract the virtual DOM constructed by the script: every
  // `document.createElement`/`getElementById`/`createTextNode` call
  // produces a tracked element, and subsequent `el.prop = ...`,
  // `el.setAttribute(...)`, `el.appendChild(...)` statements mutate it.
  // Returns { elements, ops, roots, html }, where:
  //   - elements: all tracked virtual elements/text nodes in creation order
  //   - ops:      the sequence of DOM operations the script performs
  //   - roots:    elements that weren't appended to another tracked element
  //   - html:     a per-element HTML serialization (best-effort)
  function extractAllDOM(input) {
    const trimmed = input.trim();
    if (!trimmed) return { elements: [], ops: [], roots: [], html: {} };
    const tokens = tokenize(trimmed);
    const state = buildScopeState(tokens, tokens.length, scanMutations(tokens));
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

  function extractAllHTML(input) {
    const trimmed = input.trim();
    if (!trimmed) return [];
    const tokens = tokenize(trimmed);
    const assigns = findAllHtmlAssignments(tokens);
    return assigns.map((assign) => {
      const result = extractOneAssignment(tokens, assign);
      if (!result) return null; // Target is a known non-element
      result.srcStart = assign.srcStart;
      result.srcEnd = assign.srcEnd;
      result._assign = assign;
      result._tokens = tokens;
      return result;
    }).filter(Boolean);
  }

  // Produce a { target, assignProp, assignOp, chainTokens, ... } record
  // for a single innerHTML/outerHTML assignment located in `tokens`.
  // Returns null if the target is known to NOT be a DOM element.
  function extractOneAssignment(tokens, assign) {
    const target = assign.target;
    const assignProp = assign.prop;
    const assignOp = assign.op;
    // Determine build variables from the RHS (single ident or concat of idents).
    const rhsToks = [];
    for (let j = assign.rhsStart; j < assign.rhsEnd; j++) rhsToks.push(tokens[j]);
    // Collect all identifiers in the RHS that could be build variables.
    const buildVars = [];
    for (const rt of rhsToks) {
      if (rt.type === 'other' && IDENT_RE.test(rt.text)) buildVars.push(rt.text);
    }
    const buildVar = buildVars.length === 1 ? buildVars[0] : null;
    const r = resolveIdentifiers(tokens, assign.rhsStart, assign.rhsEnd, buildVars.length ? buildVars : null);

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
        for (const lv of r.loopVars) {
          if (!lvByName[lv.name]) lvByName[lv.name] = [];
          lvByName[lv.name].push(lv);
        }
      }
      const expandChain = (toks) => {
        const out = [];
        for (const t of toks) {
          if (t.type === 'other' && IDENT_RE.test(t.text) && lvByName[t.text] && lvByName[t.text].length) {
            const lv = lvByName[t.text].pop();
            for (const vt of expandChain(lv.chain)) out.push(vt);
            lvByName[t.text].push(lv);
          } else if (t.type === 'cond') {
            out.push({ type: 'cond', condExpr: t.condExpr, ifTrue: expandChain(t.ifTrue), ifFalse: expandChain(t.ifFalse), loopId: t.loopId });
          } else if (t.type === 'trycatch') {
            out.push({ type: 'trycatch', tryBody: expandChain(t.tryBody), catchBody: expandChain(t.catchBody), catchParam: t.catchParam, loopId: t.loopId });
          } else if (t.type === 'switch') {
            out.push({ type: 'switch', discExpr: t.discExpr, branches: t.branches.map(br => ({ label: br.label, caseExpr: br.caseExpr, chain: expandChain(br.chain) })), loopId: t.loopId });
          } else {
            out.push(t);
          }
        }
        return out;
      };
      const mainTokens = expandChain(r.tokens);
      return { target, assignProp, assignOp, chainTokens: mainTokens, loopInfoMap: r.loopInfo, buildVarDeclStart: r.buildVarDeclStart };
    }
    // Resolver returned the RHS tokens with per-identifier substitution but
    // couldn't parse the full expression as a concat chain. Return the
    // resolved tokens directly — they'll go through parseChainToVNodes.
    return { target, assignProp, assignOp, chainTokens: r.tokens };
  }

  function extractHTML(input) {
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
      const result = extractOneAssignment(tokens, assign);
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
      const r = resolveIdentifiers(tokens, 0, tokens.length);
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
    if (!nm || nm.type !== 'other' || !IDENT_RE.test(nm.text)) return null;
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

  function buildScopeState(tokens, stopAt, externallyMutable, trackBuildVarInit) {
    const stack = [{ bindings: Object.create(null), isFunction: true }];
    let pendingFunctionBrace = false;
    let pendingFunctionParams = null;
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
    const applyElementSet = (el, path, val) => {
      if (!el || el.kind !== 'element') return;
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
        if (name !== null) el.attrs[name] = argBinds[1];
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
    const declBlock = (name, value) => { topBlock().bindings[name] = asRef(name, value); };
    const declFunction = (name, value) => {
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
    const resolvePath = (path) => {
      const parts = path.split('.');
      let b = resolve(parts[0]);
      for (let i = 1; i < parts.length && b; i++) {
        const p = parts[i];
        if (b.kind === 'object') {
          b = b.props[p] || null;
        } else if (b.kind === 'chain' && b.toks.length === 1 && b.toks[0].type === 'other') {
          // Opaque chain (e.g. parameter bound to exprRef) — extend the
          // path so `column.title` becomes `store.columns[i].title`.
          b = chainBinding([exprRef(b.toks[0].text + '.' + parts.slice(i).join('.'))]);
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
    // Re-tokenize an expression source string and parse it as a concat chain
    // using the in-scope bindings. Returns the chain token list or null.
    const evalExprSrc = (src) => {
      const exprTokens = tokenize(src);
      if (!exprTokens.length) return null;
      const saved = tks;
      tks = exprTokens;
      const r = readConcatExpr(0, exprTokens.length, TERMS_NONE);
      tks = saved;
      if (!r || r.next !== exprTokens.length) return null;
      return r.toks;
    };

    // Rewrite a template literal as plain text by resolving each ${expr}.
    // Returns null if any expr can't be resolved to plain text.
    const templateToText = (tok) => {
      let text = '';
      for (const p of tok.parts) {
        if (p.kind === 'text') { text += decodeJsString(p.raw, '`'); continue; }
        // Fast path: bare identifier/member path.
        if (TEMPLATE_EXPR_PATH_RE.test(p.expr)) {
          const path = p.expr.replace(/\s+/g, '');
          const b = resolvePath(path);
          if (!b) return null;
          const t2 = bindingToText(b);
          if (t2 === null) return null;
          text += t2;
          continue;
        }
        // General expression: re-tokenize and evaluate as a concat chain.
        const chain = evalExprSrc(p.expr);
        if (!chain) return null;
        const t2 = bindingToText(chainBinding(chain));
        if (t2 === null) return null;
        text += t2;
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
        let resolvedText = null;
        if (TEMPLATE_EXPR_PATH_RE.test(p.expr)) {
          const path = p.expr.replace(/\s+/g, '');
          const b = resolvePath(path);
          if (b) resolvedText = bindingToText(b);
        } else {
          const chain = evalExprSrc(p.expr);
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
            resolvedText = bindingToText(chainBinding(chain));
          }
        }
        if (resolvedText !== null) {
          const raw = resolvedText.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
          parts.push({ kind: 'text', raw });
          changed = true;
          continue;
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
    const resolveDefault = (dflt) => {
      if (!dflt) return null;
      const r = readValue(dflt.start, dflt.end, null);
      if (r && r.binding) return r.binding;
      const toks = [];
      for (let j = dflt.start; j < dflt.end; j++) toks.push(tks[j]);
      return chainBinding(toks.length ? toks : [exprRef('undefined')]);
    };

    // Bind names from `pattern` by walking into `source` (a binding).
    const applyPatternBindings = (pattern, source, bind) => {
      if (pattern.kind === 'obj-pattern') {
        const props = source && source.kind === 'object' ? source.props : null;
        const seen = Object.create(null);
        for (const { key, name, dflt } of pattern.entries) {
          seen[key] = true;
          let val = props ? (props[key] || null) : null;
          if (val === null && dflt) val = resolveDefault(dflt);
          bind(name, val);
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
          if (val === null && entry.dflt) val = resolveDefault(entry.dflt);
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

    // Read an object literal `{ key: value, ... }` starting at index `k`.
    // Keys are bare identifiers or quoted strings. Values are any readValue
    // (chain, nested object, or nested array). Returns { binding, next }.
    const readObjectLit = (k, stop) => {
      const open = tks[k];
      if (!open || open.type !== 'open' || open.char !== '{') return null;
      const props = Object.create(null);
      let i = k + 1;
      while (i < stop) {
        const tk = tks[i];
        if (tk.type === 'close' && tk.char === '}') break;
        // Spread: `...obj` merges a known object binding's props in.
        if (tk.type === 'other' && tk.text.startsWith('...')) {
          const name = tk.text.slice(3);
          if (IDENT_OR_PATH_RE.test(name)) {
            const b = resolvePath(name);
            if (b && b.kind === 'object') {
              for (const kk in b.props) props[kk] = b.props[kk];
              i++;
              const sep = tks[i];
              if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
              break;
            }
          }
          return null;
        }
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
            const sep = tks[i];
            if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
            break;
          }
          if (IDENT_RE.test(tk.text)) {
            // `get`/`set`/`async` prefix on a method definition — skip the
            // leading keyword and treat the following name as the key.
            if ((tk.text === 'get' || tk.text === 'set' || tk.text === 'async') &&
                tks[i + 1] && tks[i + 1].type === 'other' && IDENT_RE.test(tks[i + 1].text) &&
                tks[i + 2] && tks[i + 2].type === 'open' && tks[i + 2].char === '(') {
              i++; // skip prefix
              keyName = tks[i].text;
              i++;
            } else {
              keyName = tk.text;
              i++;
            }
          }
          else return null;
        } else if (tk.type === 'open' && tk.char === '[') {
          // Computed key `[expr]: value` — evaluate expr as a concat
          // chain, use its known string as the property name.
          let depth = 1, j = i + 1;
          while (j < stop && depth > 0) {
            const tkk = tks[j];
            if (tkk.type === 'open' && tkk.char === '[') depth++;
            else if (tkk.type === 'close' && tkk.char === ']') depth--;
            if (depth === 0) break;
            j++;
          }
          if (!tks[j] || tks[j].type !== 'close') return null;
          const inner = readConcatExpr(i + 1, j, TERMS_NONE);
          if (!inner || !inner.toks || inner.toks.length !== 1) return null;
          const keyTok = inner.toks[0];
          if (keyTok.type === 'str') keyName = keyTok.text;
          else return null;
          i = j + 1;
        } else {
          return null;
        }
        // Method shorthand: `key(...) { ... }` — skip over the method body
        // entirely and continue to the next property.
        if (tks[i] && tks[i].type === 'open' && tks[i].char === '(') {
          // Skip `(...)`
          let d = 1; i++;
          while (i < stop && d > 0) {
            const tkk = tks[i];
            if (tkk.type === 'open' && tkk.char === '(') d++;
            else if (tkk.type === 'close' && tkk.char === ')') d--;
            i++;
          }
          // Skip `{...}`
          if (tks[i] && tks[i].type === 'open' && tks[i].char === '{') {
            let bd = 1; i++;
            while (i < stop && bd > 0) {
              const tkk = tks[i];
              if (tkk.type === 'open' && tkk.char === '{') bd++;
              else if (tkk.type === 'close' && tkk.char === '}') bd--;
              i++;
            }
          }
          const sep = tks[i];
          if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
          break;
        }
        // Shorthand property `{ name }` → `{ name: name }` (name is a
        // reference to a binding in scope).
        if (tks[i] && (tks[i].type === 'sep' && (tks[i].char === ',' || tks[i].char === ';') ||
                       tks[i].type === 'close' && tks[i].char === '}')) {
          const b = resolve(keyName);
          props[keyName] = b || chainBinding([exprRef(keyName)]);
          if (tks[i].type === 'sep' && tks[i].char === ',') { i++; continue; }
          break;
        }
        // Expect a separate ':' delimiter — either an 'other' token of just ':'
        // or an 'other' token starting with ':' (rare).
        const colon = tks[i];
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
        const sep = tks[i];
        if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
        break;
      }
      const close = tks[i];
      if (!close || close.type !== 'close' || close.char !== '}') return null;
      return { binding: objectBinding(props), next: i + 1 };
    };

    // Read an array literal `[ v, v, ... ]`. Returns { binding, next } or null.
    const readArrayLit = (k, stop) => {
      const open = tks[k];
      if (!open || open.type !== 'open' || open.char !== '[') return null;
      const elems = [];
      let i = k + 1;
      while (i < stop) {
        const tk = tks[i];
        if (tk.type === 'close' && tk.char === ']') break;
        // Spread: `...arr` splices a known array binding's elements in.
        if (tk.type === 'other' && tk.text.startsWith('...')) {
          const name = tk.text.slice(3);
          if (IDENT_OR_PATH_RE.test(name)) {
            const b = resolvePath(name);
            if (b && b.kind === 'array') {
              for (const e of b.elems) elems.push(e);
              i++;
              const sep = tks[i];
              if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
              break;
            }
          }
          return null;
        }
        const val = readValue(i, stop, TERMS_ARR);
        if (!val) return null;
        elems.push(val.binding);
        i = val.next;
        const sep = tks[i];
        if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
        break;
      }
      const close = tks[i];
      if (!close || close.type !== 'close' || close.char !== ']') return null;
      return { binding: arrayBinding(elems), next: i + 1 };
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
    const readValue = (k, stop, terms) => {
      const t = tks[k];
      if (!t) return null;
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
      const arith = parseArithExpr(k, stop, 0);
      if (arith && arith.bind) {
        const nt = tks[arith.next];
        if (nt && nt.type === 'plus') {
          const r = readConcatExpr(k, stop, terms);
          if (r) return { binding: chainBinding(r.toks), next: r.next };
        }
        return { binding: arith.bind, next: arith.next };
      }
      // Fall back to readBase for typed bindings (array/object) that
      // parseArithExpr rejected because they're not chain results.
      const base = readBase(k, stop);
      if (base) {
        const s = applySuffixes(base.bind, base.next, stop);
        if (s.bind) {
          const nt = tks[s.next];
          if (nt && nt.type === 'plus') {
            const r = readConcatExpr(k, stop, terms);
            if (r) return { binding: chainBinding(r.toks), next: r.next };
          }
          return { binding: s.bind, next: s.next };
        }
      }
      // Fall through: chain parsing (with opaque-capture for unresolved).
      const r = readConcatExpr(k, stop, terms);
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
            const inner = parseArithExpr(next + 1, j, 0);
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
          if (!resolved) bind = null;
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
            } else {
              cur = null;
              break;
            }
          }
          if (isMethodCall) {
            const r = applyMethod(cur, lastSeg, next + 1, stop);
            if (!r) break;
            bind = r.bind;
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
          if (e > 0) { out.push(SYNTH_PLUS); out.push(rewriteTemplate(sepTok)); out.push(SYNTH_PLUS); }
          for (const vt of eb.toks) out.push(vt);
        }
        return { bind: chainBinding(out), next: parenIdx + 3 };
      }
      // Pure string methods on a known chain string: evaluate when all args
      // are concrete literals. Non-evaluatable cases return null.
      if (bind && bind.kind === 'chain') {
        const s = chainAsKnownString(bind);
        if (s !== null) {
          const args = readConcatArgs(parenIdx, stop);
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
          const arrow = peekArrow(parenIdx + 1, stop);
          if (!arrow) return null;
          const body = readArrowBody(arrow.arrowNext, stop);
          if (!body) return null;
          const rp = tks[body.next];
          if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
          const fn = functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock);
          if (method === 'forEach') {
            return { bind: chainBinding([makeSynthStr('undefined')]), next: body.next + 1 };
          }
          const results = [];
          for (const el of bind.elems) {
            if (!el) return null;
            const toks = instantiateFunction(fn, [el]);
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
            else if (!falsy) return null;
          }
          return { bind: arrayBinding(results), next: body.next + 1 };
        }
        // `.reduce(fn, init)` — two-arg reducer: invoke the callback
        // per element with (accumulator, element) and thread the
        // running result through.
        if (method === 'reduce') {
          const lp = tks[parenIdx];
          if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
          const arrow = peekArrow(parenIdx + 1, stop);
          if (!arrow || arrow.params.length !== 2) return null;
          const body = readArrowBody(arrow.arrowNext, stop);
          if (!body) return null;
          const sep = tks[body.next];
          if (!sep || sep.type !== 'sep' || sep.char !== ',') return null;
          const init = readConcatExpr(body.next + 1, stop, { sep: [], close: [')'] });
          if (!init) return null;
          const rp = tks[init.next];
          if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
          const fn = functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock);
          let accBind = chainBinding(init.toks);
          for (const el of bind.elems) {
            if (!el) return null;
            const toks = instantiateFunction(fn, [accBind, el]);
            if (!toks) return null;
            accBind = chainBinding(toks);
          }
          const acc = accBind.toks;
          return { bind: chainBinding(acc), next: init.next + 1 };
        }
        const args = readConcatArgs(parenIdx, stop);
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
      // parseChainToVNodes converts into a forEach loop.
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
          let k = parenIdx + 1;
          if (tks[k] && tks[k].type === 'other' && tks[k].text === 'function') {
            k++;
            // optional name
            if (tks[k] && tks[k].type === 'other' && IDENT_RE.test(tks[k].text) && tks[k].text !== 'function') k++;
            if (tks[k] && tks[k].type === 'open' && tks[k].char === '(') {
              const params = [];
              let j = k + 1;
              while (j < stop) {
                const pt = tks[j];
                if (pt && pt.type === 'close' && pt.char === ')') { j++; break; }
                if (pt && pt.type === 'other' && IDENT_RE.test(pt.text)) params.push({ name: pt.text });
                j++;
              }
              // Expect `{`
              if (tks[j] && tks[j].type === 'open' && tks[j].char === '{') {
                let depth = 1, bodyEnd = j + 1;
                while (bodyEnd < stop && depth > 0) {
                  if (tks[bodyEnd].type === 'open' && tks[bodyEnd].char === '{') depth++;
                  else if (tks[bodyEnd].type === 'close' && tks[bodyEnd].char === '}') depth--;
                  if (depth > 0) bodyEnd++;
                }
                fn = functionBinding(params, j, bodyEnd + 1, true);
                fnEnd = bodyEnd + 1;
              }
            }
          }
        }
        if (!fn) return null;
        const rp = tks[fnEnd];
        if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
        const paramBinds = fn.params.map((p) => chainBinding([exprRef(p.name)]));
        const toks = instantiateFunction(fn, paramBinds);
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
    const readBase = (k, stop) => {
      const t = tks[k];
      if (!t) return null;
      // `new X(args)` / `new X.Y` / `new X` — absorb the constructor call
      // and its arguments as a single opaque expression reference.
      if (t.type === 'other' && t.text === 'new') {
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
        return { bind: chainBinding([exprRef(first._src.slice(first.start, last.end))]), next: j };
      }
      // `await expr` / `yield expr` / `void expr` / `typeof expr` / `delete expr`:
      // evaluate the expression and surface a canonical symbolic form.
      if (t.type === 'other' && (t.text === 'await' || t.text === 'yield' || t.text === 'typeof' || t.text === 'void' || t.text === 'delete')) {
        const inner = readBase(k + 1, stop);
        if (!inner) return null;
        const et = chainAsExprText(inner.bind);
        if (et === null) return null;
        const text = t.text + ' ' + et;
        return { bind: chainBinding([exprRef(text)]), next: inner.next };
      }
      // Unary operators: `-`, `+`, `!`, `~`.
      if (t.type === 'op' && (t.text === '-' || t.text === '+' || t.text === '!' || t.text === '~')) {
        const inner = readBase(k + 1, stop);
        if (!inner) return null;
        const applied = applyUnary(t.text, inner.bind);
        if (!applied) return null;
        return { bind: applied, next: inner.next };
      }
      if (t.type === 'str') return { bind: chainBinding([t]), next: k + 1 };
      if (t.type === 'tmpl') {
        const rw = rewriteTemplate(t);
        if (rw.type === '_chain') return { bind: chainBinding(rw.toks), next: k + 1 };
        return { bind: chainBinding([rw]), next: k + 1 };
      }
      if (t.type === 'regex') return { bind: chainBinding([exprRef(t.text)]), next: k + 1 };
      if (t.type === 'open' && t.char === '(') {
        const r = readConcatExpr(k + 1, stop, { sep: [], close: [')'] });
        if (!r) return null;
        const rp = tks[r.next];
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
        const paren = tks[k + 1];
        const isCall = paren && paren.type === 'open' && paren.char === '(';
        // Known math/numeric constants like `Math.PI`.
        if (!isCall && MATH_CONSTANTS[t.text] !== undefined) {
          return { bind: chainBinding([makeSynthStr(String(MATH_CONSTANTS[t.text]))]), next: k + 1 };
        }
        // Known global builtin function call (numeric Math.*, parseInt...).
        if (isCall && BUILTINS[t.text]) {
          const args = readConcatArgs(k + 1, stop);
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
          const argRes = readCallArgBindings(k + 1, stop);
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
          const argRes = readCallArgBindings(k + 1, stop);
          if (argRes && argRes.bindings.length === 1) {
            const ob = argRes.bindings[0];
            const v = ob && ob.kind === 'array' ? 'true' : (ob && (ob.kind === 'object' || ob.kind === 'chain') ? 'false' : null);
            if (v !== null) return { bind: chainBinding([makeSynthStr(v)]), next: argRes.next };
          }
        }
        if (isCall && t.text === 'Array.of') {
          const argRes = readCallArgBindings(k + 1, stop);
          if (argRes) return { bind: arrayBinding(argRes.bindings.slice()), next: argRes.next };
        }
        if (isCall && t.text === 'Array.from') {
          const argRes = readCallArgBindings(k + 1, stop);
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
                  const toks = instantiateFunction(mapFn, [el, chainBinding([makeSynthStr(String(idx))])]);
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
                    const toks = instantiateFunction(mapFn, [
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
          const argRes = readCallArgBindings(k + 1, stop);
          if (argRes && argRes.bindings.length >= 1) {
            const val = bindingToJson(argRes.bindings[0]);
            if (val !== undefined) {
              if (t.text === 'JSON.stringify') {
                return { bind: chainBinding([makeSynthStr(JSON.stringify(val))]), next: argRes.next };
              }
              // parse: value is a string, parse it and reconstruct a binding.
              if (typeof val === 'string') {
                try {
                  const parsed = JSON.parse(val);
                  return { bind: jsonToBinding(parsed), next: argRes.next };
                } catch (_) { /* fall through */ }
              }
            }
          }
        }
        // DOM factories return a tracked virtual element.
        if (isCall && DOM_FACTORIES[t.text]) {
          const args = readConcatArgs(k + 1, stop);
          if (args) {
            const r = DOM_FACTORIES[t.text](args.args, k, args.next, t);
            if (r) return r;
          }
        }
        // `String(x)` coerces any literal to its string form.
        if (isCall && t.text === 'String') {
          const args = readConcatArgs(k + 1, stop);
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
              const prefBind = resolvePath(prefix) || chainBinding([exprRef(prefix)]);
              const r = applyMethod(prefBind, method, k + 1, stop);
              if (r) return { bind: r.bind, next: r.next };
            }
            // Fall through to the opaque-ident handling below for unknown
            // methods or unresolved prefixes.
          }
        }
        const b = resolvePath(t.text);
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
          return { bind: chainBinding([exprRef(first._src.slice(first.start, last.end))]), next: end };
        }
        if (b) {
          // Call syntax: `name(args)` where name resolves to a function binding.
          if (b.kind === 'function' && isCall) {
            const args = readConcatArgs(k + 1, stop);
            if (!args) return null;
            const toks = instantiateFunction(b, args.args.map((a) => chainBinding(a)));
            if (!toks) {
              // Function couldn't be inlined (e.g. pre-pass converted).
              // Produce an opaque call expression.
              const first = tks[k];
              const last = tks[args.next - 1];
              return { bind: chainBinding([exprRef(first._src.slice(first.start, last.end))]), next: args.next };
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
    const instantiateFunction = (fn, argBindings) => {
      stack.push({ bindings: Object.create(null), isFunction: true });
      const frame = stack[stack.length - 1];
      // Body indices are into the original `tokens` array; swap `tks` if we
      // happen to be evaluating a re-tokenized expression right now.
      const savedTks = tks;
      tks = tokens;
      for (let p = 0; p < fn.params.length; p++) {
        const pi = fn.params[p];
        const a = argBindings[p];
        if (a) {
          frame.bindings[pi.name] = a;
        } else if (pi.defaultStart != null) {
          // Evaluate the parameter's default expression in the current
          // (call-site) scope so enclosing bindings can be referenced.
          const r = readConcatExpr(pi.defaultStart, pi.defaultEnd, TERMS_NONE);
          frame.bindings[pi.name] = (r && r.next === pi.defaultEnd) ? chainBinding(r.toks) : null;
        } else {
          frame.bindings[pi.name] = null;
        }
      }
      let result = null;
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
        // Save and disable trackBuildVar inside inlined functions —
        // inner functions' variables are not build vars.
        const savedTrackBuildVar = trackBuildVar;
        const savedTrackDepth = trackBuildVarDepth;
        trackBuildVar = null;
        walkRange(bodyStart, bodyEnd);
        trackBuildVar = savedTrackBuildVar;
        trackBuildVarDepth = savedTrackDepth;
        // Find the return value: look for `return` at the top level of
        // the function body and resolve the returned expression.
        let ri = bodyStart;
        while (ri < bodyEnd) {
          const t = tks[ri];
          if (t && t.type === 'other' && t.text === 'return') {
            const r = readConcatExpr(ri + 1, bodyEnd, TERMS_TOP);
            if (r) result = r.toks;
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
        const r = readConcatExpr(fn.bodyStart, fn.bodyEnd, TERMS_NONE);
        if (r && r.next === fn.bodyEnd) result = r.toks;
      }
      tks = savedTks;
      stack.pop();
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
    const readOperand = (k, stop, terms) => {
      const parsed = parseArithExpr(k, stop);
      if (parsed) {
        const boundary = skipOperand(parsed.next, stop, terms);
        if (boundary === parsed.next) return { toks: parsed.bind.toks.slice(), next: parsed.next };
      }
      const end = skipOperand(k, stop, terms);
      if (end === k) return null;
      const first = tks[k];
      const last = tks[end - 1];
      return {
        toks: [exprRef(first._src.slice(first.start, last.end))],
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
    const parseArithExpr = (k, stop, minPrec) => {
      minPrec = minPrec || 0;
      const base = readBase(k, stop);
      if (!base) return null;
      const r = applySuffixes(base.bind, base.next, stop);
      let cur = r.bind;
      let next = r.next;
      while (next < stop) {
        const opTok = tks[next];
        let opText, prec;
        if (opTok && opTok.type === 'op' && BINOP_PREC[opTok.text] !== undefined) {
          opText = opTok.text; prec = BINOP_PREC[opText];
        } else if (opTok && opTok.type === 'plus') {
          // Treat `+` at precedence 12: numeric add when both operands are
          // number literals, otherwise leave it to the concat-chain parser.
          opText = '+'; prec = 12;
        } else if (opTok && opTok.type === 'other' && (opTok.text === 'in' || opTok.text === 'instanceof')) {
          // `in` / `instanceof` share relational precedence (10) and are
          // always runtime-opaque — they fold to `(lhs in rhs)` / similar.
          opText = opTok.text; prec = 10;
        } else break;
        if (prec < minPrec) break;
        const nextMinPrec = opText === '**' ? prec : prec + 1;
        const right = parseArithExpr(next + 1, stop, nextMinPrec);
        if (!right) break;
        const combined = combineArith(cur, opText, right.bind);
        if (!combined) break;
        cur = combined;
        next = right.next;
      }
      if (!cur || cur.kind !== 'chain') return null;
      // Ternary at the lowest precedence: `cond ? a : b`.
      const q = tks[next];
      if (minPrec === 0 && q && q.type === 'other' && q.text === '?') {
        const t = parseArithExpr(next + 1, stop, 0);
        if (!t) return { bind: cur, next };
        const colon = tks[t.next];
        if (!colon || colon.type !== 'other' || colon.text !== ':') return { bind: cur, next };
        const f = parseArithExpr(t.next + 1, stop, 0);
        if (!f) return { bind: cur, next };
        cur = combineTernary(cur, t.bind, f.bind);
        if (!cur) return null;
        next = f.next;
      }
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
        return chainBinding([exprRef('(' + lt + ' ' + op + ' ' + rt + ')')]);
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
      // `+` is overloaded in JS. When both operands aren't concrete numbers
      // we decline here and let the caller (concat-chain parser) handle it
      // as string concatenation.
      if (op === '+') return null;
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
      return chainBinding([exprRef(text)]);
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
      return chainBinding([exprRef(text)]);
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
      // Check boolean/null/undefined keywords first — these are synthetic
      // tokens from combineArith, not user string literals.
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
    const readCallArgBindings = (k, stop) => {
      const lp = tks[k];
      if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
      const bindings = [];
      let i = k + 1;
      const maybeRp = tks[i];
      if (maybeRp && maybeRp.type === 'close' && maybeRp.char === ')') return { bindings, next: i + 1 };
      while (i < stop) {
        const v = readValue(i, stop, TERMS_ARG);
        if (!v) return null;
        bindings.push(v.binding);
        i = v.next;
        const sep = tks[i];
        if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
        break;
      }
      const rp = tks[i];
      if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
      return { bindings, next: i + 1 };
    };

    const readConcatArgs = (k, stop) => {
      const lp = tks[k];
      if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
      const args = [];
      let i = k + 1;
      const maybeRp = tks[i];
      if (maybeRp && maybeRp.type === 'close' && maybeRp.char === ')') return { args, next: i + 1 };
      while (i < stop) {
        const arg = readConcatExpr(i, stop, TERMS_ARG);
        if (!arg) return null;
        args.push(arg.toks);
        i = arg.next;
        const sep = tks[i];
        if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
        break;
      }
      const rp = tks[i];
      if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
      return { args, next: i + 1 };
    };

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
      if (endAt(tks[i])) return null;
      let op = readOperand(i, stop, terms);
      if (!op) return null;
      for (const t of op.toks) out.push(t);
      i = op.next;
      // Read subsequent (+ operand)* pairs.
      while (i < stop && !endAt(tks[i])) {
        const plus = tks[i];
        if (!plus || plus.type !== 'plus') return null;
        i++;
        op = readOperand(i, stop, terms);
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

    let stop = Math.min(stopAt, tokens.length);
    const walkRange = (startI, endI) => {
    for (let i = startI; i < endI; i++) {
      // Pop any loops whose body we've walked past (and their shadow frames).
      // For each variable modified during the loop, capture its final chain
      // as a loopVar entry AND replace its binding with a single reference
      // token carrying the variable's name, so subsequent code reads it
      // as a named variable rather than inlining the one-iteration chain.
      while (loopStack.length > 0 && i >= loopStack[loopStack.length - 1].bodyEnd) {
        const entry = loopStack.pop();
        const topIdx = stack.indexOf(entry.frame);
        if (topIdx >= 0) stack.splice(topIdx, 1);
        for (const name of entry.modifiedVars) {
          const b = resolve(name);
          if (b && b.kind === 'chain') {
            // Store the chain UNSTRIPPED; strip the outer loop's tags only
            // at display time via loopVarHtml. The unstripped chain is
            // needed when unrolling references in a main-chain substitution.
            loopVars.push({
              name,
              loop: { id: entry.id, kind: entry.kind, headerSrc: entry.headerSrc },
              chain: b.toks,
            });
            assignName(name, chainBinding([exprRef(name)]));
          }
        }
      }
      const t = tokens[i];

      if (t.type === 'open' && t.char === '{') {
        const frame = { bindings: Object.create(null), isFunction: pendingFunctionBrace };
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
        if (stack.length > 1) stack.pop();
        continue;
      }

      if (t.type !== 'other') continue;

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
            // Evaluate the condition.
            const condVal = readValue(i + 2, j, null);
            const concrete = condVal ? evalTruthiness(condVal.binding) : null;
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
              // Walk only if-body; skip else chain.
              walkRange(j + 1, ifEnd);
              i = (elseEnd > 0 ? elseEnd : ifEnd) - 1;
              continue;
            } else if (concrete === false) {
              // Skip if-body; walk else-body (if present).
              if (elseStart > 0) {
                walkRange(elseStart, elseEnd);
              }
              i = (elseEnd > 0 ? elseEnd : ifEnd) - 1;
              continue;
            }
            // Opaque condition: snapshot bindings, walk both branches,
            // and merge. For build variables (chain kind), produce cond
            // tokens if the branches differ.
            const condExpr = condVal ? chainAsExprText(condVal.binding) : null;
            if (condExpr) {
              // Snapshot current bindings.
              const snapshot = Object.create(null);
              for (let si = stack.length - 1; si >= 0; si--) {
                for (const name in stack[si].bindings) {
                  if (!(name in snapshot)) snapshot[name] = stack[si].bindings[name];
                }
              }
              // Walk if-body using the full walker; capture loopVars created.
              const lvBefore = loopVars.length;
              walkRange(j + 1, ifEnd);
              const ifLoopVars = loopVars.splice(lvBefore);
              // Capture if-branch bindings.
              const ifBindings = Object.create(null);
              for (let si = stack.length - 1; si >= 0; si--) {
                for (const name in stack[si].bindings) {
                  if (!(name in ifBindings)) ifBindings[name] = stack[si].bindings[name];
                }
              }
              // Restore snapshot and walk else-body.
              for (const name in snapshot) {
                assignName(name, snapshot[name]);
              }
              const lvBefore2 = loopVars.length;
              if (elseStart > 0 && elseEnd > elseStart) {
                walkRange(elseStart, elseEnd);
              }
              const elseLoopVars = loopVars.splice(lvBefore2);
              // Merge: for any binding that differs between branches,
              // produce a cond token.
              const elseBindings = Object.create(null);
              for (let si = stack.length - 1; si >= 0; si--) {
                for (const name in stack[si].bindings) {
                  if (!(name in elseBindings)) elseBindings[name] = stack[si].bindings[name];
                }
              }
              // Helper: expand loopVars into a binding's chain to get
              // the full content including loop iterations.
              const expandWithLVs = (bind, branchLVs) => {
                if (!bind || bind.kind !== 'chain') return bind ? bind.toks : [];
                const lvMap = Object.create(null);
                for (const lv of branchLVs) {
                  if (!lvMap[lv.name]) lvMap[lv.name] = [];
                  lvMap[lv.name].push(lv);
                }
                const expand = (toks) => {
                  const out = [];
                  for (const t of toks) {
                    if (t.type === 'other' && IDENT_RE.test(t.text) && lvMap[t.text] && lvMap[t.text].length) {
                      const lv = lvMap[t.text].pop();
                      for (const vt of expand(lv.chain)) out.push(vt);
                      lvMap[t.text].push(lv);
                    } else {
                      out.push(t);
                    }
                  }
                  return out;
                };
                return expand(bind.toks);
              };
              for (const name in ifBindings) {
                const ifB = ifBindings[name];
                const elB = elseBindings[name] || snapshot[name];
                if (!ifB || ifB.kind !== 'chain') continue;
                if (!elB || elB.kind !== 'chain') continue;
                // Expand loopVars in each branch to get full content.
                const ifFull = expandWithLVs(ifB, ifLoopVars);
                const elFull = expandWithLVs(elB, elseLoopVars);
                if (JSON.stringify(ifFull) === JSON.stringify(elFull)) continue;
                const snapB = snapshot[name];
                if (snapB && snapB.kind === 'chain') {
                  const snapFull = snapB.toks;
                  const stripPlus = (arr) => (arr.length && arr[0].type === 'plus') ? arr.slice(1) : arr;
                  // Check if each branch starts with the snapshot prefix
                  // (appended via +=) or is a full replacement (via =).
                  const startsWithSnap = (full) => {
                    if (full.length < snapFull.length) return false;
                    for (let s = 0; s < snapFull.length; s++) {
                      if (JSON.stringify(full[s]) !== JSON.stringify(snapFull[s])) return false;
                    }
                    return true;
                  };
                  const ifAppended = startsWithSnap(ifFull);
                  const elAppended = startsWithSnap(elFull);
                  const ifExtra = ifAppended ? stripPlus(ifFull.slice(snapFull.length)) : ifFull;
                  const elExtra = elAppended ? stripPlus(elFull.slice(snapFull.length)) : elFull;
                  const currentLoopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
                  if (!ifAppended || !elAppended) {
                    // At least one branch did `html = ...` (full replacement).
                    // Emit as a ternary: the whole value depends on the condition.
                    const condTok = {
                      type: 'cond', condExpr,
                      ifTrue: ifFull,
                      ifFalse: elFull,
                    };
                    if (currentLoopId !== null) condTok.loopId = currentLoopId;
                    // The chain IS the cond — no snapshot prefix.
                    assignName(name, chainBinding([condTok]));
                  } else {
                    const condTok = {
                      type: 'cond', condExpr,
                      ifTrue: ifExtra,
                      ifFalse: elExtra,
                    };
                    if (currentLoopId !== null) condTok.loopId = currentLoopId;
                    assignName(name, chainBinding([...snapB.toks, SYNTH_PLUS, condTok]));
                  }
                  if (loopStack.length > 0) loopStack[loopStack.length - 1].modifiedVars.add(name);
                }
              }
              // Non-build vars that differ between branches become opaque
              // so subsequent code doesn't use a stale concrete value.
              for (const name in ifBindings) {
                if (trackBuildVar && trackBuildVar.has(name)) continue;
                const ifB = ifBindings[name];
                const elB = elseBindings[name] || snapshot[name];
                if (ifB === elB) continue;
                if (JSON.stringify(ifB) === JSON.stringify(elB)) continue;
                assignName(name, chainBinding([exprRef(name)]));
              }
              i = (elseEnd > 0 ? elseEnd : ifEnd) - 1;
              continue;
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
          // Snapshot, walk try body.
          const snapshot = Object.create(null);
          for (let si = stack.length - 1; si >= 0; si--) {
            for (const name in stack[si].bindings) {
              if (!(name in snapshot)) snapshot[name] = stack[si].bindings[name];
            }
          }
          const lvBefore = loopVars.length;
          walkRange(i + 1, tryEnd);
          const tryLoopVars = loopVars.splice(lvBefore);
          const tryBindings = Object.create(null);
          for (let si = stack.length - 1; si >= 0; si--) {
            for (const name in stack[si].bindings) {
              if (!(name in tryBindings)) tryBindings[name] = stack[si].bindings[name];
            }
          }
          // Restore and walk catch body.
          for (const name in snapshot) assignName(name, snapshot[name]);
          const lvBefore2 = loopVars.length;
          if (catchStart >= 0) walkRange(catchStart, catchEnd);
          const catchLoopVars = loopVars.splice(lvBefore2);
          const catchBindings = Object.create(null);
          for (let si = stack.length - 1; si >= 0; si--) {
            for (const name in stack[si].bindings) {
              if (!(name in catchBindings)) catchBindings[name] = stack[si].bindings[name];
            }
          }
          // Merge build var: try = one branch, catch = other.
          const expandWithLVs = (bind, branchLVs) => {
            if (!bind || bind.kind !== 'chain') return bind ? bind.toks : [];
            const lvMap = Object.create(null);
            for (const lv of branchLVs) {
              if (!lvMap[lv.name]) lvMap[lv.name] = [];
              lvMap[lv.name].push(lv);
            }
            const expand = (toks) => {
              const out = [];
              for (const ct of toks) {
                if (ct.type === 'other' && IDENT_RE.test(ct.text) && lvMap[ct.text] && lvMap[ct.text].length) {
                  const lv = lvMap[ct.text].pop();
                  for (const vt of expand(lv.chain)) out.push(vt);
                  lvMap[ct.text].push(lv);
                } else out.push(ct);
              }
              return out;
            };
            return expand(bind.toks);
          };
          for (const name in tryBindings) {
            if (!tryBindings[name] || tryBindings[name].kind !== 'chain') continue;
            const tryB = tryBindings[name];
            const catchB = catchBindings[name] || snapshot[name];
            if (!catchB || catchB.kind !== 'chain') continue;
            const tryFull = expandWithLVs(tryB, tryLoopVars);
            const catchFull = expandWithLVs(catchB, catchLoopVars);
            if (JSON.stringify(tryFull) === JSON.stringify(catchFull)) continue;
            const snapB = snapshot[name];
            if (snapB && snapB.kind === 'chain') {
              if (trackBuildVar && trackBuildVar.has(name)) {
                const tryExtra = tryFull.slice(snapB.toks.length);
                const catchExtra = catchFull.slice(snapB.toks.length);
                const stripPlus = (arr) => (arr.length && arr[0].type === 'plus') ? arr.slice(1) : arr;
                // Use a 'trycatch' token that the parser/emitter handles.
                const tryCatchTok = { type: 'trycatch', tryBody: stripPlus(tryExtra), catchBody: stripPlus(catchExtra), catchParam };
                assignName(name, chainBinding([...snapB.toks, SYNTH_PLUS, tryCatchTok]));
              } else {
                assignName(name, chainBinding([exprRef(name)]));
              }
            }
          }
          // Walk finally body unconditionally (it always runs).
          if (finallyStart >= 0) walkRange(finallyStart, finallyEnd);
          i = k - 1;
          continue;
        }
      }

      // `switch (expr) { case ...: ... }` — walk each case body with
      // snapshot/restore so build-var mutations become a 'switchcase' token.
      if (t.text === 'switch') {
        const lp = tokens[i + 1];
        if (lp && lp.type === 'open' && lp.char === '(') {
          const cp = findCloseParen(i + 1);
          // Read the discriminant expression.
          const discVal = readValue(i + 2, cp - 1, null);
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
                const caseExpr = tk.text === 'case' ? (function() {
                  const v = readValue(j + 1, colonIdx, null);
                  return v ? chainAsExprText(v.binding) : null;
                })() : null;
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
            for (const cs of cases) {
              // Restore snapshot.
              for (const name in snapshot) assignName(name, snapshot[name]);
              walkRange(cs.bodyStart, cs.bodyEnd);
              const bindings = Object.create(null);
              for (let si = stack.length - 1; si >= 0; si--) {
                for (const name in stack[si].bindings) {
                  if (!(name in bindings)) bindings[name] = stack[si].bindings[name];
                }
              }
              caseResults.push({ label: cs.label, caseExpr: cs.caseExpr, bindings });
            }
            // Merge: produce a switchcase token for the build var.
            if (trackBuildVar) {
              for (const bv of trackBuildVar) {
                const snapB = snapshot[bv];
                if (!snapB || snapB.kind !== 'chain') continue;
                const branches = [];
                for (const cr of caseResults) {
                  const b = cr.bindings[bv];
                  if (b && b.kind === 'chain') {
                    const extra = b.toks.slice(snapB.toks.length);
                    const stripPlus = (arr) => (arr.length && arr[0].type === 'plus') ? arr.slice(1) : arr;
                    branches.push({ label: cr.label, caseExpr: cr.caseExpr, chain: stripPlus(extra) });
                  }
                }
                if (branches.length) {
                  const switchTok = { type: 'switch', discExpr: discExpr || '/* switch */', branches };
                  assignName(bv, chainBinding([...snapB.toks, SYNTH_PLUS, switchTok]));
                }
              }
            }
            // Non-build vars: make opaque.
            for (const cr of caseResults) {
              for (const name in cr.bindings) {
                if (trackBuildVar && trackBuildVar.has(name)) continue;
                const b = cr.bindings[name];
                if (b && snapshot[name] && JSON.stringify(b) !== JSON.stringify(snapshot[name])) {
                  assignName(name, chainBinding([exprRef(name)]));
                }
              }
            }
            i = switchEnd - 1;
            continue;
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
              stack.push(loopFrame);
              loopStack.push({
                id, kind: 'do', headerSrc, bodyEnd: doEnd, frame: loopFrame,
                modifiedVars: new Set(),
              });
              walkRange(i + 1, bodyEnd);
              i = doEnd - 1;
              continue;
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
            const headerSrc = headerFirst._src.slice(headerFirst.start, headerLast.end);
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
            for (let h = i + 2; h < j; h++) {
              const hk = tokens[h];
              if (hk.type === 'other' && (hk.text === 'var' || hk.text === 'let' || hk.text === 'const')) {
                const nm = tokens[h + 1];
                if (nm && nm.type === 'other' && IDENT_RE.test(nm.text)) {
                  loopFrame.bindings[nm.text] = chainBinding([exprRef(nm.text)]);
                }
              }
            }
            stack.push(loopFrame);
            loopStack.push({
              id, kind: t.text, headerSrc, bodyEnd, frame: loopFrame,
              modifiedVars: new Set(),
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
            if (trackBuildVar && trackBuildVar.has(nameTok.text)) {
              // Always update — later declarations (closer to the innerHTML
              // assignment) take precedence over earlier ones in outer scopes.
              buildVarDeclStart = tokens[i].start;
              trackBuildVarDepth = funcDepth();
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
        if (eqTok && eqTok.type === 'sep' && eqTok.char === '=') {
          const stmtEndIdx = skipExpr(i + 2, stop);
          const r = readValue(i + 2, stop, TERMS_TOP);
          assignName(t.text, r ? r.binding : null);
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
          const r = readValue(i + 2, stop, TERMS_TOP);
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
          i = skipExpr(i + 2, stop) - 1;
          continue;
        }
        // Post-increment/decrement: IDENT++ or IDENT--.
        if (eqTok && eqTok.type === 'op' && (eqTok.text === '++' || eqTok.text === '--')) {
          const cur = resolve(t.text);
          const n = cur && cur.kind === 'chain' ? chainAsNumber(cur) : null;
          if (n !== null && loopStack.length === 0) {
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
      }

      // Path assignment on a tracked DOM element: `el.prop = value`,
      // `el.style.color = value`, etc. Records the mutation on the
      // element binding so subsequent DOM serialization sees it.
      if (t.type === 'other' && PATH_RE.test(t.text)) {
        const eqTok = tokens[i + 1];
        if (eqTok && eqTok.type === 'sep' && eqTok.char === '=') {
          const parts = t.text.split('.');
          const baseBind = resolve(parts[0]);
          if (baseBind && baseBind.kind === 'element') {
            const r = readValue(i + 2, stop, TERMS_TOP);
            const val = r ? r.binding : null;
            applyElementSet(baseBind, parts.slice(1), val);
            i = skipExpr(i + 2, stop) - 1;
            continue;
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
              const argResult = readCallArgBindings(i + 1, stop);
              if (argResult) {
                applyElementMethod(baseBind, method, argResult.bindings);
                i = argResult.next - 1;
                continue;
              }
            }
          }
        }
      }
    }
    };
    walkRange(0, stop);

    // Advance the scope walker to a new stop position, processing all
    // tokens between the current stop and the new one. This allows
    // the caller to incrementally build scope state for each statement
    // in a build region.
    const advanceTo = (newStop) => {
      const ns = Math.min(newStop, tokens.length);
      if (ns > stop) { walkRange(stop, ns); stop = ns; }
    };

    // Parse tokens[start, end) as a concat chain, expanding identifier
    // references, member paths, `[...].join(sep)`, and `.concat(...)` calls.
    // Returns the flat chain tokens (alternating operand / plus) or null.
    const parseRange = (start, end) => {
      const r = readConcatExpr(start, end, TERMS_NONE);
      if (!r || r.next !== end) return null;
      return r.toks;
    };

    const inScope = (name) => {
      for (let i = stack.length - 1; i >= 0; i--) if (name in stack[i].bindings) return true;
      return false;
    };
    const setTrackBuildVar = (name) => { trackBuildVar = name ? new Set(Array.isArray(name) ? name : [name]) : null; };
    const getBuildVarDeclStart = () => buildVarDeclStart;
    return { resolve, resolvePath, parseRange, rewriteTemplate, advanceTo, setTrackBuildVar, getBuildVarDeclStart, loopInfo, loopVars, inScope, domElements, domOps };
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
  function resolveIdentifiers(tokens, startIdx, endIdx, buildVarOrVars) {
    const externallyMutable = scanMutations(tokens);
    const state = buildScopeState(tokens, startIdx, externallyMutable, buildVarOrVars);
    const full = state.parseRange(startIdx, endIdx);
    if (full) return { tokens: full, parsed: true, loopInfo: state.loopInfo, loopVars: state.loopVars, buildVarDeclStart: state.getBuildVarDeclStart(), inScope: state.inScope, resolve: state.resolve };
    const out = [];
    for (let i = startIdx; i < endIdx; i++) {
      const t = tokens[i];
      if (t.type === 'tmpl') {
        const rw = state.rewriteTemplate(t);
        if (rw.type === '_chain') { for (const ct of rw.toks) out.push(ct); }
        else out.push(rw);
        continue;
      }
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
        // Multi-char tokens starting with '?': `??` (nullish coalescing)
        // and `?.` (optional chaining; ignore `?.<digit>` which is a
        // ternary followed by a decimal number).
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
  function convertHtmlBuilderFunctions(source) {
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
      let hasInnerHTML = false, hasVarHtml = false, hasHtmlConcat = false, hasReturnHtml = false;
      // Tokenize the body to check patterns properly.
      const bodyToks = tokenize(body);
      for (let bi = 0; bi < bodyToks.length; bi++) {
        const bt = bodyToks[bi];
        if (bt.type === 'other' && /\.innerHTML$/.test(bt.text)) hasInnerHTML = true;
        // var html = ... or let html = ...
        if (bt.type === 'other' && (bt.text === 'var' || bt.text === 'let') &&
            bi + 1 < bodyToks.length && bodyToks[bi + 1].type === 'other' && bodyToks[bi + 1].text === 'html' &&
            bi + 2 < bodyToks.length && bodyToks[bi + 2].type === 'sep' && bodyToks[bi + 2].char === '=') {
          hasVarHtml = true;
        }
        // html +=
        if (bt.type === 'other' && bt.text === 'html' &&
            bi + 1 < bodyToks.length && bodyToks[bi + 1].type === 'sep' && bodyToks[bi + 1].char === '+=') {
          hasHtmlConcat = true;
        }
        // return html
        if (bt.type === 'other' && bt.text === 'return' &&
            bi + 1 < bodyToks.length && bodyToks[bi + 1].type === 'other' && bodyToks[bi + 1].text === 'html') {
          hasReturnHtml = true;
        }
      }

      if (hasInnerHTML || !hasVarHtml || !hasHtmlConcat || !hasReturnHtml) continue;

      // Convert: replace `return html` with a synthetic innerHTML
      // assignment, run through the converter, wrap in fragment.
      // Find the return html token position in body to do the replacement.
      let syntheticBody = body;
      for (let bi = 0; bi < bodyToks.length; bi++) {
        if (bodyToks[bi].type === 'other' && bodyToks[bi].text === 'return' &&
            bi + 1 < bodyToks.length && bodyToks[bi + 1].type === 'other' && bodyToks[bi + 1].text === 'html') {
          const retStart = bodyToks[bi].start;
          // Find end: skip past 'html' and optional ;
          let retEnd = bodyToks[bi + 1].end;
          if (bi + 2 < bodyToks.length && bodyToks[bi + 2].type === 'sep' && bodyToks[bi + 2].char === ';') {
            retEnd = bodyToks[bi + 2].end;
          }
          syntheticBody = body.slice(0, retStart) + '__frag.innerHTML = html;' + body.slice(retEnd);
          break;
        }
      }

      const extractions = extractAllHTML(syntheticBody);
      if (extractions.length > 0) {
        const ex = extractions[0];
        const used = new Set();
        const domBlock = convertOne(syntheticBody, ex, false, false, used, '__frag', result.converted);
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
  function convertRaw(raw, sourceName) {
    // Derive the handlers filename from the source.
    const baseName = sourceName ? sourceName.replace(/\.[^.]+$/, '') : 'index';
    const handlersFile = baseName + '.handlers.js';
    try {
      // If input starts with HTML, use the HTML tokenizer to split into
      // HTML portions and <script> blocks. Convert inline scripts for
      // innerHTML replacements, extract unsafe attributes (events, styles,
      // javascript: URLs) into a separate JS file.
      if (/^\s*</.test(raw)) {
        const markup = convertHtmlMarkup(raw, sourceName || 'index.html');
        // Combine inline script blocks and process innerHTML assignments.
        const jsFileLines = [];
        const sharedUsed = new Set();
        if (markup.extractedScripts.length > 0) {
          const separator = '\n/*__BLOCK_SEP__*/\n';
          let combinedJs = markup.extractedScripts.map(function(s) { return s.content; }).join(separator);
          const prepass = convertHtmlBuilderFunctions(combinedJs);
          combinedJs = prepass.source;
          const extractions = extractAllHTML(combinedJs);
          if (extractions.length === 0) {
            for (const s of markup.extractedScripts) jsFileLines.push(s.content.trim());
          } else {
            const trimmed = combinedJs.trim();
            let scriptOutput = '';
            let cursor = 0;
            for (const ex of extractions) {
              if (ex.srcStart === undefined) continue;
              const domBlock = convertOne(combinedJs, ex, false, false, sharedUsed, null, prepass.converted);
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
      // Pre-pass: convert HTML-building helper functions.
      const prepass = convertHtmlBuilderFunctions(raw);
      const processedRaw = prepass.source;
      const extractions = extractAllHTML(processedRaw);
      if (extractions.length === 0) {
        const summary = summarizeDomConstruction(processedRaw);
        if (summary) { return summary; }
        return (convertOne(processedRaw, extractHTML(processedRaw), false, false) || '');
        return;
      }
      // Inline rewriting: preserve original code, replace innerHTML sites.
      const trimmed = processedRaw.trim();
      let output = '';
      let cursor = 0;
      const sharedUsed = new Set();
      // Reserve all target identifiers so generated variable names
      // don't shadow them.
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

        const domBlock = convertOne(processedRaw, ex, false, false, sharedUsed, null, prepass.converted);
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
  function convert() {
    const raw = (typeof window !== 'undefined' && window._monacoIn) ? window._monacoIn.getValue() : ($('in') ? $('in').value : '');
    setOutput(convertRaw(raw) || '');
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
  function summarizeDomConstruction(raw) {
    const dom = extractAllDOM(raw);
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

  // Parse chain tokens into a lightweight virtual DOM tree. Each str token
  // is fed character-by-character through an HTML state machine; each other
  // token (expression) is annotated with its HTML context (text content,
  // attribute value, attribute name, etc.).
  function parseChainToVNodes(chainTokens) {
    // Split chain at plus tokens into operands.
    const operands = [];
    let cur = [];
    for (const t of chainTokens) {
      if (t.type === 'plus') { if (cur.length) operands.push(cur); cur = []; }
      else cur.push(t);
    }
    if (cur.length) operands.push(cur);

    // Resolve an operand to { kind: 'str', text, loopId } or { kind: 'expr', expr, loopId }.
    const resolveOp = (toks) => {
      const loopId = toks[0].loopId != null ? toks[0].loopId : null;
      if (toks.length === 1 && toks[0].type === 'str') {
        return { kind: 'str', text: toks[0].text, loopId };
      }
      if (toks.length === 1 && toks[0].type === 'tmpl') {
        // Template literal — flatten parts into sub-operands.
        const parts = [];
        for (const p of toks[0].parts) {
          if (p.kind === 'text') parts.push({ kind: 'str', text: decodeJsString(p.raw, '`'), loopId });
          else parts.push({ kind: 'expr', expr: p.expr.trim(), loopId });
        }
        return { kind: 'tmpl', parts, loopId };
      }
      if (toks.length === 1 && toks[0].type === 'preserve') {
        return { kind: 'preserve', text: toks[0].text, loopId };
      }
      if (toks.length === 1 && toks[0].type === 'trycatch') {
        return { kind: 'trycatch', tryBody: toks[0].tryBody, catchBody: toks[0].catchBody, catchParam: toks[0].catchParam, loopId };
      }
      if (toks.length === 1 && toks[0].type === 'switch') {
        return { kind: 'switch', discExpr: toks[0].discExpr, branches: toks[0].branches, loopId };
      }
      if (toks.length === 1 && (toks[0].type === 'cond' || toks[0].type === 'iter')) {
        return Object.assign({ kind: toks[0].type, loopId }, toks[0]);
      }
      const first = toks[0];
      const last = toks[toks.length - 1];
      const expr = first._src.slice(first.start, last.end).trim();
      return { kind: 'expr', expr, loopId };
    };

    const resolved = [];
    for (const op of operands) {
      const r = resolveOp(op);
      if (r.kind === 'tmpl') {
        for (const p of r.parts) resolved.push(p);
      } else {
        resolved.push(r);
      }
    }

    // HTML state machine.
    const TEXT = 0, TAG_OPEN = 1, TAG_CLOSE = 2, ATTRS = 3;
    const ATTR_NAME = 4, ATTR_EQ = 5, ATTR_VALUE_DQ = 6, ATTR_VALUE_SQ = 7;
    const ATTR_VALUE_UQ = 8, COMMENT = 9;

    let state = TEXT;
    let tagName = '';
    let attrName = '';
    let attrValue = '';
    let attrExprs = [];  // {pos, expr} embedded in current attr value

    // Virtual DOM construction.
    const roots = [];
    const elStack = [];  // stack of { tag, attrs, children }
    const addChild = (node) => {
      if (elStack.length) elStack[elStack.length - 1].children.push(node);
      else roots.push(node);
    };
    let currentEl = null;  // element being built (receives attrs)
    const openTag = (tag, loopId) => {
      currentEl = { kind: 'element', tag, attrs: [], children: [], loopId };
    };
    // Called when `>` closes the opening tag — commit the element.
    const commitTag = () => {
      if (!currentEl) return;
      addChild(currentEl);
      if (!currentEl.tag || !VOID_ELEMENTS.has(currentEl.tag.toLowerCase())) elStack.push(currentEl);
      currentEl = null;
    };
    const commitAndSelfClose = () => {
      if (!currentEl) return;
      addChild(currentEl);
      // Don't push to stack — self-closing.
      currentEl = null;
    };
    const popEl = () => { if (elStack.length) elStack.pop(); };
    let textBuf = '';
    const flushText = () => {
      if (textBuf) { addChild({ kind: 'text', text: textBuf }); textBuf = ''; }
    };
    let currentTagLoopId = null;

    const finishAttr = () => {
      if (!attrName || !currentEl) { attrName = ''; attrValue = ''; attrExprs = []; return; }
      if (attrExprs.length) {
        currentEl.attrs.push({ kind: 'dynamic_value', name: attrName, value: attrValue, valueExprs: attrExprs.slice() });
      } else {
        currentEl.attrs.push({ kind: 'static', name: attrName, value: attrValue });
      }
      attrName = '';
      attrValue = '';
      attrExprs = [];
    };

    const startTag = (loopId) => {
      openTag(tagName, loopId);
      tagName = '';
    };

    // Feed a string through the state machine.
    const feedStr = (text, loopId) => {
      for (let i = 0; i < text.length; i++) {
        const c = text[i];
        switch (state) {
          case TEXT:
            if (c === '<') {
              flushText();
              if (text[i + 1] === '/') { state = TAG_CLOSE; i++; }
              else if (text[i + 1] === '!' && text[i + 2] === '-' && text[i + 3] === '-') {
                state = COMMENT; i += 3;
              }
              else { state = TAG_OPEN; tagName = ''; currentTagLoopId = loopId; }
            } else {
              textBuf += c;
            }
            break;
          case TAG_OPEN:
            if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
              if (tagName) { startTag(currentTagLoopId); state = ATTRS; }
            } else if (c === '>') {
              startTag(currentTagLoopId); commitTag(); state = TEXT;
            } else if (c === '/') {
              if (text[i + 1] === '>') { startTag(currentTagLoopId); commitAndSelfClose(); state = TEXT; i++; }
            } else {
              tagName += c;
            }
            break;
          case TAG_CLOSE:
            if (c === '>') { popEl(); state = TEXT; }
            break;
          case ATTRS:
            if (c === '>') {
              finishAttr(); commitTag();
              state = TEXT;
            } else if (c === '/') {
              if (text[i + 1] === '>') { finishAttr(); commitAndSelfClose(); state = TEXT; i++; }
            } else if (c !== ' ' && c !== '\t' && c !== '\n' && c !== '\r') {
              finishAttr();
              attrName = c;
              state = ATTR_NAME;
            }
            break;
          case ATTR_NAME:
            if (c === '=') { state = ATTR_EQ; }
            else if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
              // Boolean attribute or space before =
              // Peek ahead to see if = follows
              let j = i + 1;
              while (j < text.length && (text[j] === ' ' || text[j] === '\t')) j++;
              if (j < text.length && text[j] === '=') {
                i = j; state = ATTR_EQ;
              } else {
                // Boolean attribute
                finishAttr();
                state = ATTRS;
              }
            } else if (c === '>') {
              finishAttr(); commitTag(); state = TEXT;
            } else if (c === '/' && text[i + 1] === '>') {
              finishAttr(); commitAndSelfClose(); state = TEXT; i++;
            } else {
              attrName += c;
            }
            break;
          case ATTR_EQ:
            if (c === '"') { attrValue = ''; state = ATTR_VALUE_DQ; }
            else if (c === "'") { attrValue = ''; state = ATTR_VALUE_SQ; }
            else if (c !== ' ' && c !== '\t') {
              attrValue = c; state = ATTR_VALUE_UQ;
            }
            break;
          case ATTR_VALUE_DQ:
            if (c === '"') { finishAttr(); state = ATTRS; }
            else attrValue += c;
            break;
          case ATTR_VALUE_SQ:
            if (c === "'") { finishAttr(); state = ATTRS; }
            else attrValue += c;
            break;
          case ATTR_VALUE_UQ:
            if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { finishAttr(); state = ATTRS; }
            else if (c === '>') { finishAttr(); commitTag(); state = TEXT; }
            else if (c === '/' && text[i + 1] === '>') { finishAttr(); commitAndSelfClose(); state = TEXT; i++; }
            else attrValue += c;
            break;
          case COMMENT:
            if (c === '-' && text[i + 1] === '-' && text[i + 2] === '>') {
              i += 2; state = TEXT;
            }
            break;
        }
      }
    };

    // Feed an expression into the current state.
    const feedExpr = (expr, loopId) => {
      switch (state) {
        case TEXT:
          flushText();
          addChild({ kind: 'expr_text', expr, loopId });
          break;
        case TAG_OPEN:
          // Expression is the tag name (e.g. `"<" + tag + ">"`).
          tagName = null;
          openTag(null, loopId);
          currentEl.tagExpr = expr;
          state = ATTRS;
          break;
        case ATTRS:
          // Expression between attributes — conditional boolean attr.
          if (currentEl) {
            currentEl.attrs.push({ kind: 'dynamic_name', nameExpr: expr });
          }
          break;
        case ATTR_NAME:
          // Expression continues attribute name (unusual).
          attrName += '${' + expr + '}';
          break;
        case ATTR_VALUE_DQ:
        case ATTR_VALUE_SQ:
        case ATTR_VALUE_UQ:
          attrExprs.push({ pos: attrValue.length, expr });
          break;
        case ATTR_EQ:
          // Expression is the entire unquoted attribute value.
          attrExprs.push({ pos: 0, expr });
          finishAttr();
          state = ATTRS;
          break;
        default:
          break;
      }
    };

    // Convert chain tokens to a JS expression string (for attribute values
    // and other non-structural contexts where DOM nodes can't be emitted).
    const chainToksAsExpr = (toks) => {
      const parts = [];
      for (const t of toks) {
        if (t.type === 'plus') continue;
        if (t.type === 'str') parts.push(JSON.stringify(t.text));
        else if (t.type === 'other') parts.push(t.text);
        else if (t.type === 'cond') parts.push('(' + t.condExpr + ' ? ' + chainToksAsExpr(t.ifTrue) + ' : ' + chainToksAsExpr(t.ifFalse) + ')');
        else if (t.type === 'preserve' || t.type === 'trycatch' || t.type === 'switch') { /* skip — control flow tokens don't produce values */ }
      }
      return parts.join(' + ') || '""';
    };

    for (const op of resolved) {
      if (op.kind === 'str') feedStr(op.text, op.loopId);
      else if (op.kind === 'iter') {
        // Iteration: .map(fn).join('') — parse per-element chain and emit forEach loop.
        if (state === TEXT) {
          flushText();
          const elemNodes = parseChainToVNodes(op.perElemChain);
          addChild({ kind: 'iteration', iterExpr: op.iterExpr, paramName: op.paramName, children: elemNodes, loopId: op.loopId });
        } else {
          // Non-TEXT context — fall back to expression.
          feedExpr(op.iterExpr + '.map(function(' + op.paramName + ') { return ' + chainToksAsExpr(op.perElemChain) + '; }).join(\'\')', op.loopId);
        }
      }
      else if (op.kind === 'trycatch') {
        if (state === TEXT) {
          flushText();
          const tryNodes = parseChainToVNodes(op.tryBody);
          const catchNodes = parseChainToVNodes(op.catchBody);
          addChild({ kind: 'trycatch', tryBody: tryNodes, catchBody: catchNodes, catchParam: op.catchParam, loopId: op.loopId });
        }
      }
      else if (op.kind === 'switch') {
        if (state === TEXT) {
          flushText();
          const branches = op.branches.map(br => ({
            label: br.label, caseExpr: br.caseExpr,
            nodes: parseChainToVNodes(br.chain),
          }));
          addChild({ kind: 'switch', discExpr: op.discExpr, branches, loopId: op.loopId });
        }
      }
      else if (op.kind === 'preserve') {
        flushText();
        addChild({ kind: 'preserve', text: op.text, loopId: op.loopId });
      }
      else if (op.kind === 'cond') {
        // Conditional HTML: recursively parse both branches into vnodes
        // and emit a conditional vnode that the emitter renders as if/else.
        if (state === TEXT) {
          flushText();
          const trueNodes = parseChainToVNodes(op.ifTrue);
          const falseNodes = parseChainToVNodes(op.ifFalse);
          addChild({ kind: 'conditional', condExpr: op.condExpr, ifTrue: trueNodes, ifFalse: falseNodes, loopId: op.loopId });
        } else if (state === ATTR_VALUE_DQ || state === ATTR_VALUE_SQ || state === ATTR_VALUE_UQ) {
          // Conditional inside attribute value — fall back to expression.
          attrExprs.push({ pos: attrValue.length, expr: '(' + op.condExpr + ' ? ' + chainToksAsExpr(op.ifTrue) + ' : ' + chainToksAsExpr(op.ifFalse) + ')' });
        } else if (state === ATTRS && currentEl) {
          // Conditional in attribute-name position.
          currentEl.attrs.push({ kind: 'dynamic_name', nameExpr: '(' + op.condExpr + ' ? ' + chainToksAsExpr(op.ifTrue) + ' : ' + chainToksAsExpr(op.ifFalse) + ')' });
        } else {
          feedExpr('(' + op.condExpr + ' ? ' + chainToksAsExpr(op.ifTrue) + ' : ' + chainToksAsExpr(op.ifFalse) + ')', op.loopId);
        }
      }
      else feedExpr(op.expr, op.loopId);
    }
    flushText();

    return roots;
  }

  // Emit DOM API code from a virtual DOM tree produced by parseChainToVNodes.
  // Handles the same options as convertNode: useProps, classList, events, etc.
  function emitVNodes(vnodes, parentVar, lines, used, opts, loopInfoMap, loopIds, nsCtx) {
    // Reserve identifiers from preserve tokens so makeVar doesn't collide.
    const reservePreserveIdents = (nodes) => {
      for (const n of nodes) {
        if (n.kind === 'preserve' && n.text) {
          const ids = n.text.match(/[A-Za-z_$][A-Za-z0-9_$]*/g);
          if (ids) for (const id of ids) used.add(id);
        }
        if (n.kind === 'conditional') { reservePreserveIdents(n.ifTrue); reservePreserveIdents(n.ifFalse); }
        if (n.kind === 'iteration') reservePreserveIdents(n.children);
        if (n.kind === 'trycatch') { reservePreserveIdents(n.tryBody); reservePreserveIdents(n.catchBody); }
        if (n.kind === 'switch') for (const br of n.branches) reservePreserveIdents(br.nodes);
        if (n.kind === 'element') reservePreserveIdents(n.children);
      }
    };
    reservePreserveIdents(vnodes);

    // Group nodes by loopId to wrap loop segments.
    const groups = [];
    let curGroup = null;
    for (const node of vnodes) {
      const lid = node.loopId != null ? node.loopId : null;
      if (!curGroup || curGroup.loopId !== lid) {
        curGroup = { loopId: lid, nodes: [] };
        groups.push(curGroup);
      }
      curGroup.nodes.push(node);
    }

    for (const group of groups) {
      if (group.loopId != null && loopInfoMap && loopInfoMap[group.loopId] && !(loopIds && loopIds.has(group.loopId))) {
        const info = loopInfoMap[group.loopId];
        if (info.kind === 'do') {
          lines.push('do {');
        } else {
          const header = info.kind === 'while'
            ? 'while (' + info.headerSrc + ')'
            : 'for (' + info.headerSrc + ')';
          lines.push(header + ' {');
        }
        const loopUsed = new Set(used);
        const loopLines = [];
        const innerLoopIds = new Set(loopIds || []);
        innerLoopIds.add(group.loopId);
        for (const node of group.nodes) emitVNode(node, parentVar, loopLines, loopUsed, opts, loopInfoMap, innerLoopIds, nsCtx);
        for (const l of loopLines) lines.push('  ' + l);
        if (info.kind === 'do') {
          lines.push('} while (' + info.headerSrc + ');');
        } else {
          lines.push('}');
        }
      } else {
        for (const node of group.nodes) emitVNode(node, parentVar, lines, used, opts, loopInfoMap, loopIds, nsCtx);
      }
    }
  }

  function emitVNode(node, parentVar, lines, used, opts, loopInfoMap, loopIds, nsCtx) {
    if (node.kind === 'text') {
      const text = node.text;
      if (!text) return;
      if (opts.skipWhitespaceText && /^\s*$/.test(text)) return;
      const v = makeVar('text', used);
      lines.push('const ' + v + ' = document.createTextNode(' + jsStr(text).code + ');');
      lines.push(parentVar + '.appendChild(' + v + ');');
      return;
    }

    if (node.kind === 'trycatch') {
      const tryLines = [];
      const catchLines = [];
      const tryUsed = new Set(used);
      const catchUsed = new Set(used);
      emitVNodes(node.tryBody, parentVar, tryLines, tryUsed, opts, loopInfoMap, loopIds, nsCtx);
      emitVNodes(node.catchBody, parentVar, catchLines, catchUsed, opts, loopInfoMap, loopIds, nsCtx);
      lines.push('try {');
      for (const l of tryLines) lines.push('  ' + l);
      lines.push('} catch(' + (node.catchParam || 'e') + ') {');
      for (const l of catchLines) lines.push('  ' + l);
      lines.push('}');
      return;
    }

    if (node.kind === 'switch') {
      lines.push('switch (' + node.discExpr + ') {');
      for (const br of node.branches) {
        if (br.label === 'default') {
          lines.push('  default:');
        } else {
          lines.push('  case ' + br.caseExpr + ':');
        }
        const caseLines = [];
        const caseUsed = new Set(used);
        emitVNodes(br.nodes, parentVar, caseLines, caseUsed, opts, loopInfoMap, loopIds, nsCtx);
        for (const l of caseLines) lines.push('    ' + l);
        lines.push('    break;');
      }
      lines.push('}');
      return;
    }

    if (node.kind === 'preserve') {
      lines.push(node.text);
      return;
    }

    if (node.kind === 'iteration') {
      const iterLines = [];
      const iterUsed = new Set(used);
      emitVNodes(node.children, parentVar, iterLines, iterUsed, opts, loopInfoMap, loopIds, nsCtx);
      if (iterLines.length) {
        lines.push(node.iterExpr + '.forEach(function(' + node.paramName + ') {');
        for (const l of iterLines) lines.push('  ' + l);
        lines.push('});');
      }
      return;
    }

    if (node.kind === 'conditional') {
      const ifLines = [];
      const elseLines = [];
      const ifUsed = new Set(used);
      const elseUsed = new Set(used);
      emitVNodes(node.ifTrue, parentVar, ifLines, ifUsed, opts, loopInfoMap, loopIds, nsCtx);
      emitVNodes(node.ifFalse, parentVar, elseLines, elseUsed, opts, loopInfoMap, loopIds, nsCtx);
      if (ifLines.length || elseLines.length) {
        lines.push('if (' + node.condExpr + ') {');
        for (const l of ifLines) lines.push('  ' + l);
        if (elseLines.length) {
          lines.push('} else {');
          for (const l of elseLines) lines.push('  ' + l);
        }
        lines.push('}');
      }
      return;
    }

    if (node.kind === 'expr_text') {
      // Check if this expression is a call to a DOM-returning function
      // (converted by the pre-pass). If so, appendChild directly.
      const isDomCall = opts.domFunctions && opts.domFunctions.size > 0 &&
        [...opts.domFunctions].some(fn => new RegExp('^' + fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(').test(node.expr));
      if (isDomCall) {
        lines.push(parentVar + '.appendChild(' + node.expr + ');');
      } else {
        const v = makeVar('text', used);
        lines.push('const ' + v + ' = document.createTextNode(' + node.expr + ');');
        lines.push(parentVar + '.appendChild(' + v + ');');
      }
      return;
    }

    if (node.kind !== 'element') return;

    const tag = node.tag;
    const tagExpr = node.tagExpr || null;
    const v = makeVar(tag || 'el', used);
    const tagLower = tag ? tag.toLowerCase() : null;

    let ns = nsCtx || null;
    if (tagExpr) {
      lines.push('const ' + v + ' = document.createElement(' + tagExpr + ');');
    } else {
      if (tagLower === 'svg') ns = SVG_NS;
      else if (tagLower === 'math') ns = MATHML_NS;
      else if (tagLower === 'foreignobject') ns = null;
      else if (!ns && SVG_TAGS.has(tagLower)) ns = SVG_NS;

      if (ns) {
        lines.push('const ' + v + " = document.createElementNS('" + ns + "', '" + tag + "');");
      } else {
        lines.push('const ' + v + " = document.createElement('" + tagLower + "');");
      }
    }

    // Emit attributes.
    for (const attr of node.attrs) {
      if (attr.kind === 'dynamic_name') {
        // Conditional boolean attribute from expression in attr-name position.
        const expr = attr.nameExpr;
        const ternMatch = expr.match(/^\((.+?)\s*\?\s*"([^"]+)"\s*:\s*""\s*\)$/);
        if (ternMatch) {
          lines.push('if (' + ternMatch[1] + ') ' + v + ".setAttribute('" + ternMatch[2] + "', '');");
        } else {
          lines.push('{ const __a = ' + expr + '; if (__a) ' + v + ".setAttribute(__a, ''); }");
        }
        continue;
      }

      const name = attr.name;
      const hasDynamic = attr.kind === 'dynamic_value' && attr.valueExprs.length > 0;

      // Build the value expression.
      let valCode;
      if (hasDynamic) {
        valCode = spliceExprs(attr.value, attr.valueExprs, false);
      } else {
        valCode = null;  // use attr.value directly via jsStr
      }

      // Event handler -> addEventListener.
      const evMatch = /^on([a-z]+)$/i.exec(name);
      if (evMatch && opts.eventsAsListeners) {
        const evName = evMatch[1].toLowerCase();
        const body = hasDynamic ? spliceExprs(attr.value, attr.valueExprs, true) : attr.value;
        lines.push(v + ".addEventListener('" + evName + "', function (event) {");
        for (const ln of body.split('\n')) lines.push('  ' + ln);
        lines.push('});');
        continue;
      }

      // Style -> style.setProperty.
      if (name === 'style' && opts.splitStyle && !hasDynamic) {
        const decls = parseStyleDecls(attr.value);
        if (decls.length) {
          for (const d of decls) {
            lines.push(v + '.style.setProperty(' + jsStr(d.prop).code + ', ' + jsStr(d.value).code + (d.important ? ", 'important'" : '') + ');');
          }
          continue;
        }
      }

      // Boolean attributes.
      if (!ns && BOOLEAN_ATTRS.has(name.toLowerCase()) && !hasDynamic) {
        lines.push(v + '.' + (ATTR_TO_PROP[name.toLowerCase()] || name) + ' = true;');
        continue;
      }

      // Class attribute with classList.
      if (name === 'class' && opts.useClassList && !ns) {
        if (hasDynamic) {
          lines.push(v + '.className = ' + valCode + ';');
        } else {
          const classes = attr.value.split(/\s+/).filter(Boolean);
          if (classes.length === 0) continue;
          if (classes.length === 1) lines.push(v + '.className = ' + jsStr(classes[0]).code + ';');
          else lines.push(v + '.classList.add(' + classes.map(c => jsStr(c).code).join(', ') + ');');
        }
        continue;
      }

      // IDL property.
      const idl = (opts.useProps && !ns) ? isIdlProp(name) : null;
      if (hasDynamic) {
        if (idl) lines.push(v + '.' + idl + ' = ' + valCode + ';');
        else lines.push(v + ".setAttribute('" + name + "', " + valCode + ');');
      } else {
        const lit = jsStr(attr.value);
        if (idl) lines.push(v + '.' + idl + ' = ' + lit.code + ';');
        else lines.push(v + ".setAttribute('" + name + "', " + lit.code + ');');
      }
    }

    // Recurse into children.
    if (node.children.length) {
      // textContent shortcut: if all children are text or expr_text (no
      // nested elements), emit a single textContent assignment.
      const canShortcut = opts.textContentShortcut &&
        node.children.every(c => (c.kind === 'text' || c.kind === 'expr_text') && c.loopId == null) &&
        !node.children.some(c => c.kind === 'expr_text' && opts.domFunctions && opts.domFunctions.size > 0 && [...opts.domFunctions].some(fn => new RegExp('^' + fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(').test(c.expr)));
      if (canShortcut) {
        if (node.children.length === 1) {
          const child = node.children[0];
          if (child.kind === 'text') {
            lines.push(v + '.textContent = ' + jsStr(child.text).code + ';');
          } else {
            lines.push(v + '.textContent = ' + child.expr + ';');
          }
        } else {
          let tmpl = '';
          for (const child of node.children) {
            if (child.kind === 'text') tmpl += tmplEncode(child.text);
            else tmpl += '${' + child.expr + '}';
          }
          lines.push(v + '.textContent = `' + tmpl + '`;');
        }
        lines.push(parentVar + '.appendChild(' + v + ');');
        return;
      }
      // Children inherit namespace; <foreignObject> reverts to HTML.
      const childNs = (tagLower === 'foreignobject') ? null : ns;
      emitVNodes(node.children, v, lines, used, opts, loopInfoMap, loopIds, childNs);
    }

    lines.push(parentVar + '.appendChild(' + v + ');');
  }

  // Escape a string for embedding inside a template literal.
  const tmplEncode = (t) => t.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');

  // Splice expressions into a static value string. When `raw` is true,
  // expressions are inlined directly (for event handler bodies); otherwise
  // the result is wrapped as a JS template literal.
  function spliceExprs(value, valueExprs, raw) {
    if (valueExprs.length === 1 && valueExprs[0].pos === 0 && value === '') {
      return valueExprs[0].expr;
    }
    const sorted = valueExprs.slice().sort((a, b) => a.pos - b.pos);
    let out = '';
    let cursor = 0;
    for (const { pos, expr } of sorted) {
      out += raw ? value.slice(cursor, pos) : tmplEncode(value.slice(cursor, pos));
      out += raw ? expr : '${' + expr + '}';
      cursor = pos;
    }
    out += raw ? value.slice(cursor) : tmplEncode(value.slice(cursor));
    return raw ? out : '`' + out + '`';
  }

  // Produce the DOM-API code block for a single innerHTML/outerHTML
  // extraction. `multi` toggles the leading target-divider comment.
  function convertOne(raw, result, multi, emitTitle, sharedUsed, parentOverride, domFunctions) {
    const { target, assignProp, assignOp } = result;

    let parent = parentOverride || 'document.body';
    let parentFromAssignment = false;
    if (target) {
      parent = assignProp === 'outerHTML' ? target + '.parentNode' : target;
      parentFromAssignment = true;
    }

    const opts = {
      useProps: true,
      splitStyle: true,
      eventsAsListeners: true,
      textContentShortcut: true,
      useClassList: true,
      skipWhitespaceText: $('skipWS').checked,
      useFragment: $('useFragment').checked,
      emitComments: $('emitComments').checked,
      domFunctions: domFunctions || new Set(),
    };

    const lines = [];
    const used = sharedUsed || new Set();

    // Reserve the parent target identifier root.
    const parentRoot = parent.match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
    if (parentRoot) used.add(parentRoot[0]);

    if (parentFromAssignment && assignOp === '=' && assignProp === 'innerHTML') {
      lines.push(target + '.replaceChildren();');
    } else if (parentFromAssignment && assignProp === 'outerHTML' && opts.emitComments) {
      lines.push('// Note: ' + target + '.outerHTML = ... replaces ' + target + ' itself;');
      lines.push('//       call ' + target + '.replaceWith(...) or adjust as needed.');
    }

    const chainTokens = result.chainTokens || [];
    const vnodes = parseChainToVNodes(chainTokens);

    if (vnodes.length === 0) {
      return lines.length ? lines.join('\n') : '// (no nodes parsed)';
    }

    let attachTarget = parent;
    let fragVar = null;
    if (opts.useFragment && vnodes.length > 1) {
      fragVar = makeVar('frag', used);
      lines.push('const ' + fragVar + ' = document.createDocumentFragment();');
      attachTarget = fragVar;
    }

    emitVNodes(vnodes, attachTarget, lines, used, opts, result.loopInfoMap || null, null);

    if (fragVar) {
      lines.push(parent + '.appendChild(' + fragVar + ');');
    }

    let block = lines.join('\n');
    if (emitTitle && opts.emitComments) {
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

  const toggles = ['skipWS', 'useFragment', 'emitComments'];
  for (const id of toggles) $(id).addEventListener('change', convert);

  convert();

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

  function convertJsFile(jsContent, precedingCode) {
    // Use extractAllHTML to detect actual innerHTML/outerHTML assignments.
    // This uses the tokenizer (skipping comments/strings) AND verifies
    // the target is not a known non-element via scope resolution.
    const combined = precedingCode
      ? precedingCode + '\n/*__FILE_BOUNDARY__*/\n' + jsContent
      : jsContent;
    const extractions = extractAllHTML(combined);
    if (extractions.length === 0) return null;
    const converted = convertRaw(combined);
    if (!converted || converted === '// (no nodes parsed)') return null;
    if (precedingCode) {
      const idx = converted.indexOf('/*__FILE_BOUNDARY__*/');
      if (idx >= 0) {
        const result = converted.slice(idx + '/*__FILE_BOUNDARY__*/'.length).trim();
        if (result && result !== jsContent.trim()) return result;
        return null;
      }
    }
    if (converted.trim() === jsContent.trim()) return null;
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

  function convertHtmlMarkup(htmlContent, htmlPath) {
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
        const hdId = 'hd' + (elemCounter++);
        sel = 'document.querySelector(\'[data-hd="' + hdId + '"]\')';
        keepAttrs.push({ name: 'data-hd', value: hdId, nameRaw: 'data-hd', start: 0, end: 0 });
      }

      // Count operations for grouping.
      let opCount = events.length + (jsHref ? 1 : 0);
      if (styleVal) {
        opCount += parseStyleDecls(styleVal).length;
      }
      const useVar = opCount > 1;
      const varName = useVar ? ('__el' + (elemCounter - 1)) : null;
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

    // Insert handlers script reference before </body> if needed.
    if (jsLines.length) {
      for (let ti = htmlTokens.length - 1; ti >= 0; ti--) {
        if (htmlTokens[ti].type === 'closeTag' && htmlTokens[ti].tag === 'body') {
          htmlTokens.splice(ti, 0, {
            type: 'openTag', tag: 'script', tagRaw: 'script',
            attrs: [{ name: 'src', value: handlersFile, nameRaw: 'src', start: 0, end: 0 }],
            selfClose: false, start: 0, end: 0
          }, {
            type: 'closeTag', tag: 'script', start: 0, end: 0
          }, {
            type: 'text', text: '\n', start: 0, end: 0
          });
          break;
        }
      }
    }

    return {
      html: serializeHtmlTokens(htmlTokens),
      handlers: jsLines.length ? { name: handlersFile, content: jsLines.join('\n') } : null,
      extractedScripts: extractedScripts,
      extractedStyles: extractedStyles,
    };
  }

  function convertProject(files) {
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
      const markup = convertHtmlMarkup(files[page], page);
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
      const scripts = pageScriptMap[page] || [];
      let precedingCode = '';
      for (const sp of scripts) {
        if (!files[sp]) continue;
        const converted = convertJsFile(files[sp], precedingCode);
        if (converted) output[sp] = converted;
        precedingCode += (precedingCode ? '\n' : '') + files[sp];
      }
      // Convert extracted inline scripts (now external files).
      for (const script of markup.extractedScripts) {
        const converted = convertJsFile(script.content, precedingCode);
        output[dir + script.name] = converted || script.content;
        precedingCode += (precedingCode ? '\n' : '') + script.content;
      }
    }
    const standaloneJs = Object.keys(files).filter(function(p) { return /\.js$/i.test(p) && !referencedJs.has(p); }).sort();
    for (const jp of standaloneJs) {
      const converted = convertJsFile(files[jp], '');
      if (converted) output[jp] = converted;
    }
    return output;
  }

  if (typeof globalThis !== 'undefined') {
    globalThis.__convertProject = convertProject;
    globalThis.__convertHtmlMarkup = convertHtmlMarkup;
    globalThis.__convertJsFile = convertJsFile;
  }
})();
