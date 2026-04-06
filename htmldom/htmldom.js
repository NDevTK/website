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
  // Extract every `X.innerHTML`/`X.outerHTML` assignment in the input,
  // returning an array of extraction results in source order. Each result
  // has the same shape as `extractHTML`'s return value.
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
      result.srcStart = assign.srcStart;
      result.srcEnd = assign.srcEnd;
      result._assign = assign;
      result._tokens = tokens;
      return result;
    });
  }

  // Produce an { html, autoSubs, target, assignProp, assignOp, ... } record
  // for a single innerHTML/outerHTML assignment located in `tokens`.
  function extractOneAssignment(tokens, assign) {
    const target = assign.target;
    const assignProp = assign.prop;
    const assignOp = assign.op;
    const r = resolveIdentifiers(tokens, assign.rhsStart, assign.rhsEnd);
    if (r.parsed) {
      // Unroll ONE level of loopVar references: the walker replaces each
      // loop-built variable's binding with a single name-reference token
      // on loop exit, and here the main chain's references to those vars
      // get expanded back to their loopVar chains (which keep their
      // loop-body tags) so the materializer emits matching loop markers.
      // References to OTHER loop-built vars inside those expanded chains
      // stay as autoSubs placeholders; the caller can emit their
      // pre-computation loops separately via the loopVars output.
      const lvMap = Object.create(null);
      if (r.loopVars) for (const lv of r.loopVars) lvMap[lv.name] = lv;
      const mainTokens = [];
      for (const t of r.tokens) {
        if (t.type === 'other' && IDENT_RE.test(t.text) && lvMap[t.text]) {
          for (const vt of lvMap[t.text].chain) mainTokens.push(vt);
        } else {
          mainTokens.push(t);
        }
      }
      const m = materializeFlatChain(mainTokens, r.loopInfo);
      if (r.loopVars && r.loopVars.length && r.inScope) {
        const kept = r.loopVars.filter((lv) => r.inScope(lv.name));
        if (kept.length) {
          m.loopVars = kept.map((lv) => {
            const stripped = stripLoopTag(lv.chain, lv.loop.id);
            const mv = materializeFlatChain(stripped, r.loopInfo);
            return Object.assign({ name: lv.name, loop: lv.loop }, mv);
          });
        }
      }
      return Object.assign(m, { target, assignProp, assignOp });
    }
    const chain = findBestConcatChain(r.tokens);
    if (chain) return Object.assign(chain, { target, assignProp, assignOp });
    let best = null;
    for (const t of r.tokens) {
      if (t.type === 'str' || t.type === 'tmpl') {
        const { html, autoSubs } = materializeStringToken(t, 0);
        if (/</.test(html) && (!best || html.length > best.html.length)) {
          best = { html, autoSubs };
        }
      }
    }
    if (best) return Object.assign(best, { target, assignProp, assignOp });
    return { html: '', autoSubs: [], target, assignProp, assignOp };
  }

  function extractHTML(input) {
    const trimmed = input.trim();
    if (!trimmed) return { html: '', autoSubs: [], target: null };
    if (trimmed.startsWith('<')) return { html: trimmed, autoSubs: [], target: null };

    const tokens = tokenize(trimmed);

    // If there's an `X.innerHTML = ...` / `X.outerHTML = ...` assignment,
    // restrict HTML extraction to the right-hand side and surface the target.
    const assign = findHtmlAssignment(tokens);
    const target = assign ? assign.target : null;
    const assignProp = assign ? assign.prop : null;
    const assignOp = assign ? assign.op : null;

    // Resolve identifier references inside the RHS using the binding state at
    // the assignment site (honoring var/let/const scope, shadowing, and
    // reassignment order). When parsing succeeds we materialize the concat
    // chain directly so even single-operand results (including pure opaque
    // references) become a valid { html, autoSubs } pair.
    let searchTokens;
    if (assign) {
      return extractOneAssignment(tokens, assign);
    }
    searchTokens = tokens;

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
    const all = findAllHtmlAssignments(tokens);
    return all.length ? all[0] : null;
  }

  // Find every `X.innerHTML`/`X.outerHTML` `=` / `+=` assignment in the
  // token stream. Returns an array in source order.
  function findAllHtmlAssignments(tokens) {
    const out = [];
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.type !== 'sep') continue;
      if (t.char !== '=' && t.char !== '+=') continue;
      const prev = tokens[i - 1];
      if (!prev || prev.type !== 'other') continue;
      const trail = prev.text.match(/^(.*)\.(innerHTML|outerHTML)$/);
      if (!trail) continue;
      const prop = trail[2];
      let target = trail[1];
      let targetSrcStart = -1;
      if (target === '') {
        const r = reconstructTarget(tokens, i - 1);
        if (!r) continue;
        target = r.text;
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
      // Include trailing semicolon in the replaced range.
      if (rhsEnd < tokens.length && tokens[rhsEnd].type === 'sep' && tokens[rhsEnd].char === ';') {
        srcEnd = tokens[rhsEnd].end;
      }
      out.push({ target, prop, op: t.char, rhsStart: i + 1, rhsEnd, srcStart, srcEnd, eqIdx: i });
    }
    return out;
  }

  // Given an innerHTML assignment and the full token list, find the "build
  // region" — the contiguous span of source code that exists solely to
  // construct the value assigned to innerHTML. This includes:
  //   - The declaration of the build variable (`var html = ''`)
  //   - All `+=` / `=` mutations to it (`html += '<div>'`)
  //   - Loops whose body ONLY mutates the build variable
  //   - The innerHTML assignment itself
  // Returns { regionStart, regionEnd } (source char positions) or null.
  function findBuildRegion(tokens, assign, replacementCode) {
    // Variables referenced in the replacement output must NOT be removed.
    const referencedInReplacement = new Set();
    if (replacementCode) {
      const refTokens = replacementCode.match(/[A-Za-z_$][A-Za-z0-9_$]*/g);
      if (refTokens) for (const t of refTokens) referencedInReplacement.add(t);
    }
    const rhsToks = [];
    for (let j = assign.rhsStart; j < assign.rhsEnd; j++) rhsToks.push(tokens[j]);
    const hasBuildVar = rhsToks.length === 1 && rhsToks[0].type === 'other' && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(rhsToks[0].text);
    const buildVar = hasBuildVar ? rhsToks[0].text : null;

    const assignTokIdx = assign.eqIdx;
    const targetTokIdx = assignTokIdx - 1;

    // Find the enclosing block start: walk backwards from the innerHTML
    // site to find the `{` that opens the containing block (function body,
    // if-body, loop body, or file scope). Track depth so nested blocks
    // are skipped.
    let blockStart = 0;
    {
      let depth = 0;
      for (let j = targetTokIdx - 1; j >= 0; j--) {
        const tk = tokens[j];
        if (tk.type === 'close' && tk.char === '}') depth++;
        if (tk.type === 'open' && tk.char === '{') {
          if (depth === 0) { blockStart = j + 1; break; }
          depth--;
        }
      }
    }

    // Split tokens[blockStart..targetTokIdx] into statements within this
    // block. Respects brace depth (for nested blocks/loops) and paren
    // depth (for `for(;;)` headers).
    const allStmts = [];
    let stmtStart = blockStart;
    let braceDepth = 0;
    let parenDepth = 0;
    // Scan through rhsEnd (not just targetTokIdx) so the innerHTML
    // statement itself is included in allStmts.
    const scanEnd = assign.rhsEnd < tokens.length ? assign.rhsEnd : tokens.length - 1;
    for (let j = blockStart; j <= scanEnd; j++) {
      const tk = tokens[j];
      if (tk.type === 'open' && tk.char === '{') braceDepth++;
      if (tk.type === 'close' && tk.char === '}') {
        braceDepth--;
        if (braceDepth < 0) braceDepth = 0;
        if (braceDepth === 0 && parenDepth === 0) {
          allStmts.push({ tokStart: stmtStart, tokEnd: j + 1 });
          stmtStart = j + 1;
          continue;
        }
      }
      if (tk.type === 'open' && tk.char === '(') parenDepth++;
      if (tk.type === 'close' && tk.char === ')') {
        parenDepth--;
        if (parenDepth < 0) parenDepth = 0;
      }
      if (braceDepth === 0 && parenDepth === 0 && tk.type === 'sep' && tk.char === ';') {
        allStmts.push({ tokStart: stmtStart, tokEnd: j + 1 });
        stmtStart = j + 1;
      }
    }

    // Scan backwards to find the build region.
    let regionTokStart = -1;
    if (!buildVar) {
      // No build variable — still check for helper declarations
      // immediately before the innerHTML that are only used in the RHS
      // and not in the replacement output.
      regionTokStart = -1; // will be extended by transitive scan below
    }
    for (let s = allStmts.length - 1; s >= 0 && buildVar; s--) {
      const stmt = allStmts[s];
      // Skip the innerHTML statement itself — it's being replaced, not a build stmt.
      if (stmt.tokStart <= targetTokIdx && stmt.tokEnd > targetTokIdx) continue;
      const stmtTokens = tokens.slice(stmt.tokStart, stmt.tokEnd);
      let writesBuildVar = false;
      let isBuildVarDecl = false;

      for (let j = 0; j < stmtTokens.length; j++) {
        const tk = stmtTokens[j];
        if (tk.type === 'other' && tk.text === buildVar) {
          const next = stmtTokens[j + 1];
          if (next && next.type === 'sep' && (next.char === '=' || next.char === '+=')) {
            writesBuildVar = true;
          }
        }
        if (tk.type === 'other' && (tk.text === 'var' || tk.text === 'let' || tk.text === 'const')) {
          const nm = stmtTokens[j + 1];
          if (nm && nm.type === 'other' && nm.text === buildVar) {
            writesBuildVar = true;
            isBuildVarDecl = true;
          }
        }
        if (tk.type === 'other' && (tk.text === 'for' || tk.text === 'while' || tk.text === 'do')) {
          for (let k = j; k < stmtTokens.length; k++) {
            if (stmtTokens[k].type === 'other' && stmtTokens[k].text === buildVar) {
              const nx = stmtTokens[k + 1];
              if (nx && nx.type === 'sep' && (nx.char === '=' || nx.char === '+=')) {
                writesBuildVar = true;
              }
            }
          }
        }
      }

      if (!writesBuildVar) break;
      regionTokStart = stmt.tokStart;
      if (isBuildVarDecl) break;
    }

    if (regionTokStart < 0 && buildVar) return null;
    // For inline innerHTML expressions (no build var), set region to the
    // innerHTML statement itself so the transitive scanner can extend upward.
    if (regionTokStart < 0) {
      // Find the statement containing the innerHTML assignment.
      // Use srcStart to match by source position since the target
      // expression may span multiple tokens before .innerHTML.
      const assignCharStart = assign.srcStart;
      for (const stmt of allStmts) {
        if (tokens[stmt.tokStart].start <= assignCharStart && tokens[stmt.tokEnd - 1].end >= assignCharStart) {
          regionTokStart = stmt.tokStart;
          break;
        }
      }
      if (regionTokStart < 0) return null;
    }

    // Find enclosing block end for scope-limited checks.
    let blockEnd = tokens.length;
    {
      let depth = 0;
      for (let j = assign.rhsEnd; j < tokens.length; j++) {
        const tk = tokens[j];
        if (tk.type === 'open' && tk.char === '{') depth++;
        if (tk.type === 'close' && tk.char === '}') {
          if (depth === 0) { blockEnd = j; break; }
          depth--;
        }
      }
    }

    // Extend the region upward transitively: any statement immediately
    // before the region that declares or mutates a variable ONLY used
    // within the dead region is also dead. Repeat until no more
    // statements can be absorbed (handles chains like var url → var text
    // → while(text...) → for(...s+=...) → innerHTML = s).
    //
    // Collect all identifiers referenced within the current dead region.
    const collectIdents = (start, end) => {
      const ids = new Set();
      for (let j = start; j < end; j++) {
        if (tokens[j].type === 'other' && IDENT_RE.test(tokens[j].text)) ids.add(tokens[j].text);
      }
      return ids;
    };
    let changed = true;
    while (changed) {
      changed = false;
      const deadIdents = collectIdents(regionTokStart, assign.rhsEnd);
      for (let s = allStmts.length - 1; s >= 0; s--) {
        const stmt = allStmts[s];
        if (stmt.tokStart >= regionTokStart) continue;
        if (stmt.tokEnd !== regionTokStart) continue;
        // Find what this statement declares or primarily writes to.
        const stmtTokens = tokens.slice(stmt.tokStart, stmt.tokEnd);
        let declNames = [];
        for (let j = 0; j < stmtTokens.length; j++) {
          const tk = stmtTokens[j];
          if (tk.type === 'other' && (tk.text === 'var' || tk.text === 'let' || tk.text === 'const')) {
            const nm = stmtTokens[j + 1];
            if (nm && nm.type === 'other' && IDENT_RE.test(nm.text)) declNames.push(nm.text);
          }
        }
        // Also catch loops (for/while/do) that only mutate dead-region vars.
        let isLoop = stmtTokens.some(tk => tk.type === 'other' && (tk.text === 'for' || tk.text === 'while' || tk.text === 'do'));
        if (isLoop) {
          // All identifiers written in this loop.
          for (let j = 0; j < stmtTokens.length; j++) {
            const tk = stmtTokens[j];
            if (tk.type === 'other' && IDENT_RE.test(tk.text)) {
              const nx = stmtTokens[j + 1];
              if (nx && nx.type === 'sep' && (nx.char === '=' || nx.char === '+=')) declNames.push(tk.text);
            }
          }
        }
        if (declNames.length === 0) break;
        // Check: are ALL declared names only used within the dead region
        // (including this statement itself) and not after?
        let allDead = true;
        for (const name of declNames) {
          // Keep alive if the replacement code references this variable.
          if (referencedInReplacement.has(name)) { allDead = false; break; }
          if (!deadIdents.has(name) && name !== buildVar) { allDead = false; break; }
          for (let j = assign.rhsEnd + 1; j < blockEnd; j++) {
            if (tokens[j].type === 'other' && tokens[j].text === name) { allDead = false; break; }
          }
          if (!allDead) break;
        }
        if (!allDead) break;
        regionTokStart = stmt.tokStart;
        changed = true;
        break; // restart scan with extended region
      }
    }

    // Verify: is buildVar used AFTER the innerHTML assignment within the
    // same scope? If so, don't remove the build code.
    if (buildVar) {
      for (let j = assign.rhsEnd + 1; j < blockEnd; j++) {
        const tk = tokens[j];
        if (tk.type === 'other' && tk.text === buildVar) return null;
        if (tk.type === 'other' && tk.text.endsWith('.' + buildVar)) return null;
      }
    }

    // Only return a region if we actually extended beyond the innerHTML statement.
    const regionStart = tokens[regionTokStart].start;
    if (regionStart >= assign.srcStart) return null;
    return { regionStart, regionEnd: assign.srcEnd };
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
    // Exclude the trailing .innerHTML/.outerHTML from the target slice.
    const text = first._src.slice(first.start, startAccessor.start).trim() || null;
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
    'replaceChildren',
  ]);

  // Method names recognized on typed bindings (chain/array). Used by
  // applySuffixes and readBase's attached-method detection to route to
  // applyMethod for evaluation.
  const KNOWN_METHODS = new Set([
    'concat', 'join',
    'toUpperCase', 'toLowerCase', 'trim', 'trimStart', 'trimEnd', 'trimLeft', 'trimRight',
    'repeat', 'slice', 'substring', 'substr', 'charAt', 'at', 'indexOf', 'lastIndexOf',
    'includes', 'startsWith', 'endsWith', 'padStart', 'padEnd', 'toString',
    'split', 'reverse', 'map', 'filter', 'forEach', 'reduce',
    'replace', 'replaceAll', 'charCodeAt', 'codePointAt', 'match', 'search', 'test',
    'toFixed', 'toPrecision', 'toExponential', 'valueOf',
    'find', 'findIndex', 'some', 'every', 'flat', 'flatMap', 'fill', 'splice',
    'sort', 'keys', 'values', 'entries',
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
  const objectBinding = (props) => ({ kind: 'object', props, accessors: Object.create(null), classRef: null });
  const arrayBinding = (elems) => ({ kind: 'array', elems });
  const functionBinding = (params, bodyStart, bodyEnd, isBlock, closure) => ({
    kind: 'function', params, bodyStart, bodyEnd, isBlock, closure: closure || null,
  });
  // Class binding: tracks constructor (a functionBinding) and named methods.
  // `new ClassName(args)` invokes the constructor with `this` bound to a
  // fresh object; method calls on instances look up methods here.
  const classBinding = (name, ctor, methods, superClass) => ({
    kind: 'class', name, ctor, methods, superClass,
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
  // Like makeSynthStr but for numeric values — no quote wrapper, so
  // chainAsNumber recognises them as numeric rather than string.
  const makeSynthNum = (n) => ({
    type: 'str', quote: '', raw: String(n), text: String(n), start: 0, end: 0, _src: '', jsType: 'number',
  });
  // Boolean token — `jsType: 'boolean'` lets typeof fold correctly and
  // allows truthiness checks to work reliably.  JS coerces true→1,
  // false→0 in arithmetic, so chainAsNumber can fold these.
  const makeSynthBool = (v) => ({
    type: 'str', quote: '', raw: String(v), text: String(v), start: 0, end: 0, _src: '', jsType: 'boolean',
  });
  // null / undefined tokens.
  const makeSynthNull = () => ({
    type: 'str', quote: '', raw: 'null', text: 'null', start: 0, end: 0, _src: '', jsType: 'null',
  });
  const makeSynthUndef = () => ({
    type: 'str', quote: '', raw: 'undefined', text: 'undefined', start: 0, end: 0, _src: '', jsType: 'undefined',
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

  // Clone operand tokens, removing a specific `loopId` tag (e.g. when a
  // chain is captured as a loopVar and the outer loop is already implied
  // by the loopVar entry — we don't want double-wrapping markers).
  function stripLoopTag(toks, loopId) {
    return toks.map((t) => {
      if (t.type === 'plus') return t;
      if (t.loopId !== loopId) return t;
      const copy = Object.assign({}, t);
      delete copy.loopId;
      return copy;
    });
  }

  // Represent an unresolved subexpression as a single operand token whose
  // source slice equals `text`. It uses the same `other` token shape the
  // tokenizer emits for plain identifiers, so the downstream materializer
  // turns it into a `__HDX#__` placeholder and records the original source
  // in autoSubs — the same mechanism that already handles standalone
  // unresolved identifiers in a concat chain.
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
    // Rest parameter: `...name`
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
      if (t.type === 'other' && t.text === 'function') {
        // Don't increment depth for function callbacks inside array method
        // calls like `.forEach(function`, `.map(function` — these are
        // synchronous and their mutations are deterministic.
        const prev = tokens[i - 1];
        const prev2 = tokens[i - 2];
        const isSyncCallback = prev && prev.type === 'open' && prev.char === '(' &&
          prev2 && prev2.type === 'other' && /\.(forEach|map|filter|reduce|some|every|find|findIndex|flatMap)$/.test(prev2.text);
        if (!isSyncCallback) pendingFnBrace = true;
        continue;
      }
      if (t.type === 'other' && t.text === '=>') {
        const nt = tokens[i + 1];
        if (nt && nt.type === 'open' && nt.char === '{') {
          // Don't increment depth for arrow callbacks inside sync array
          // methods. Scan back past the arrow params to find the `(` from
          // the method call. Pattern: `.forEach(x => {` or `.map((a,b) => {`.
          let isSyncCb = false;
          let back = i - 1;
          // Skip past arrow params: either a single ident or `(params)`.
          if (tokens[back] && tokens[back].type === 'close' && tokens[back].char === ')') {
            let pd = 1; back--;
            while (back >= 0 && pd > 0) {
              if (tokens[back].type === 'close' && tokens[back].char === ')') pd++;
              else if (tokens[back].type === 'open' && tokens[back].char === '(') pd--;
              if (pd > 0) back--;
            }
            // back is at the `(` of params.
          }
          // back - 1 should be the `(` of the method call, back - 2 the method path.
          if (tokens[back - 1] && tokens[back - 1].type === 'open' && tokens[back - 1].char === '(' &&
              tokens[back - 2] && tokens[back - 2].type === 'other' &&
              /\.(forEach|map|filter|reduce|some|every|find|findIndex|flatMap)$/.test(tokens[back - 2].text)) {
            isSyncCb = true;
          }
          // Also single-param: `.forEach(x => {` — back is at x, back-1 is `(`, back-2 is method.
          if (!isSyncCb && tokens[back] && tokens[back].type === 'other' && IDENT_RE.test(tokens[back].text) &&
              tokens[back - 1] && tokens[back - 1].type === 'open' && tokens[back - 1].char === '(' &&
              tokens[back - 2] && tokens[back - 2].type === 'other' &&
              /\.(forEach|map|filter|reduce|some|every|find|findIndex|flatMap)$/.test(tokens[back - 2].text)) {
            isSyncCb = true;
          }
          if (!isSyncCb) pendingFnBrace = true;
        }
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
        // `arr[i] = ...` / `obj[k] = ...` mutates arr/obj.
        if (next && next.type === 'open' && next.char === '[') {
          let d = 1; let j = i + 2;
          while (j < tokens.length && d > 0) {
            const tk = tokens[j];
            if (tk.type === 'open' && tk.char === '[') d++;
            else if (tk.type === 'close' && tk.char === ']') d--;
            if (d > 0) j++;
          }
          const eq = tokens[j + 1];
          if (eq && eq.type === 'sep' && eq.char === '=') noteMut(t.text);
        }
      }
      // `arr.push(...)` / `obj.foo = ...` — the path token carries the base
      // name as its prefix. Flag mutation if followed by a mutating method or `=`.
      if (t.type === 'other' && PATH_RE.test(t.text)) {
        const dot = t.text.indexOf('.');
        const base = t.text.slice(0, dot);
        const rest = t.text.slice(dot + 1);
        const next = tokens[i + 1];
        if (next && next.type === 'sep' && /^[-+*/%]?=$/.test(next.char)) noteMut(base);
        if (next && next.type === 'open' && next.char === '(') {
          // Last segment is the method name.
          const lastDot = rest.lastIndexOf('.');
          const method = lastDot >= 0 ? rest.slice(lastDot + 1) : rest;
          if (method === 'push' || method === 'pop' || method === 'shift' || method === 'unshift' || method === 'splice' || method === 'sort' || method === 'reverse' || method === 'fill' || method === 'copyWithin') noteMut(base);
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

  function buildScopeState(tokens, stopAt, externallyMutable) {
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
    // Snapshot all bindings currently in scope (for closures).
    // Capture a closure: store references to the actual scope frames (not
    // copies) so multiple closures over the same variable share state.
    const captureScope = () => stack.slice();
    const asRef = (name, value) => value;
    const declBlock = (name, value) => { topBlock().bindings[name] = asRef(name, value); };
    const declFunction = (name, value) => {
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].isFunction) { stack[i].bindings[name] = asRef(name, value); return; }
      }
    };
    const assignName = (name, value) => {
      for (let i = stack.length - 1; i >= 0; i--) {
        if (name in stack[i].bindings) {
          // When side effects are off, don't modify bindings in frames
          // below the nearest function scope (outer variables).
          if (!sideEffects) {
            let inCurrentFunction = false;
            for (let j = stack.length - 1; j >= i; j--) {
              if (j === i) { inCurrentFunction = true; break; }
              if (stack[j].isFunction) break;
            }
            if (!inCurrentFunction) return;
          }
          stack[i].bindings[name] = asRef(name, value);
          return;
        }
      }
      if (sideEffects) stack[0].bindings[name] = asRef(name, value);
    };
    const resolve = (name) => {
      // `this` resolves to the nearest function scope's thisBinding.
      if (name === 'this') {
        for (let i = stack.length - 1; i >= 0; i--) {
          if (stack[i].isFunction && stack[i].thisBinding) return stack[i].thisBinding;
        }
        return null;
      }
      for (let i = stack.length - 1; i >= 0; i--) {
        if (name in stack[i].bindings) return stack[i].bindings[name];
      }
      return null;
    };
    // Check if a global builtin name (possibly dotted like 'Math.floor')
    // has been shadowed by a user-declared binding. Returns true when the
    // root identifier appears in ANY scope frame, meaning the user
    // redefined it and we must NOT apply builtin semantics.
    const isShadowed = (dottedName) => {
      const root = dottedName.includes('.') ? dottedName.slice(0, dottedName.indexOf('.')) : dottedName;
      return resolve(root) !== null;
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
          // Check for getter in accessors map.
          const accessor = b.accessors && b.accessors[p];
          if (accessor && accessor.get) {
            stack.push({ bindings: Object.create(null), isFunction: true, thisBinding: b });
            b = instantiateFunctionBinding(accessor.get, []);
            stack.pop();
          } else {
            // Missing property on a known object → undefined (not null).
            b = p in b.props ? b.props[p] : chainBinding([makeSynthUndef()]);
          }
        } else if (p === 'length' && b.kind === 'array') {
          b = chainBinding([makeSynthNum(b.elems.length)]);
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
          b = ok ? chainBinding([makeSynthNum(n)]) : null;
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
          if (chain) resolvedText = bindingToText(chainBinding(chain));
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
                // Value may be a nested destructuring pattern or a simple name.
                const nested = tks[i];
                if (nested && nested.type === 'open' && (nested.char === '{' || nested.char === '[')) {
                  const sub = readDestructurePattern(i, stop);
                  if (!sub) return null;
                  name = sub.pattern; // nested pattern stored as name
                  i = sub.next;
                } else if (nested && nested.type === 'other' && IDENT_RE.test(nested.text)) {
                  name = nested.text;
                  i++;
                } else {
                  return null;
                }
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
          // Nested destructuring: name is a pattern object, not a string.
          if (typeof name === 'object' && name !== null && name.kind) {
            applyPatternBindings(name, val, bind);
          } else {
            bind(name, val);
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
            if ((tk.text === 'get' || tk.text === 'set') &&
                tks[i + 1] && tks[i + 1].type === 'other' && IDENT_RE.test(tks[i + 1].text) &&
                tks[i + 2] && tks[i + 2].type === 'open' && tks[i + 2].char === '(') {
              const accessorKind = tk.text;
              i++; // skip get/set
              keyName = tks[i].text;
              i++;
              // Parse params and body into a functionBinding.
              const params = [];
              let p = i + 1;
              if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; }
              else {
                let ok = true;
                while (p < stop) {
                  const pt = parseParamWithDefault(tks, p, stop);
                  if (!pt) { ok = false; break; }
                  params.push(pt.param);
                  p = pt.next;
                  if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; break; }
                  if (tks[p] && tks[p].type === 'sep' && tks[p].char === ',') { p++; continue; }
                  ok = false; break;
                }
                if (!ok) { i = p; continue; }
              }
              if (tks[p] && tks[p].type === 'open' && tks[p].char === '{') {
                let bd = 1, bEnd = p + 1;
                while (bEnd < stop && bd > 0) {
                  if (tks[bEnd].type === 'open' && tks[bEnd].char === '{') bd++;
                  else if (tks[bEnd].type === 'close' && tks[bEnd].char === '}') bd--;
                  bEnd++;
                }
                const fn = functionBinding(params, p + 1, bEnd - 1, true);
                // Store accessor on the object's accessors map (not in props).
                // Getters are invoked on read; setters on write.
                if (!props.__pendingAccessors) props.__pendingAccessors = Object.create(null);
                if (!props.__pendingAccessors[keyName]) props.__pendingAccessors[keyName] = {};
                if (accessorKind === 'get') props.__pendingAccessors[keyName].get = fn;
                else props.__pendingAccessors[keyName].set = fn;
                i = bEnd;
                const sep = tks[i];
                if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
                break;
              }
              continue;
            }
            if (tk.text === 'async' &&
                tks[i + 1] && tks[i + 1].type === 'other' && IDENT_RE.test(tks[i + 1].text) &&
                tks[i + 2] && tks[i + 2].type === 'open' && tks[i + 2].char === '(') {
              i++; // skip async
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
        // Method shorthand: `key(...) { ... }` — parse as a functionBinding
        // so `obj.method()` can invoke it.
        if (tks[i] && tks[i].type === 'open' && tks[i].char === '(') {
          const params = [];
          let p = i + 1;
          if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; }
          else {
            let ok = true;
            while (p < stop) {
              const pt = parseParamWithDefault(tks, p, stop);
              if (!pt) { ok = false; break; }
              params.push(pt.param);
              p = pt.next;
              if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; break; }
              if (tks[p] && tks[p].type === 'sep' && tks[p].char === ',') { p++; continue; }
              ok = false; break;
            }
            if (!ok) {
              // Can't parse params — skip the method body.
              while (p < stop) {
                const tkk = tks[p];
                if (tkk.type === 'open') p++;
                else if (tkk.type === 'close') break;
                else p++;
              }
              i = p;
              const sep = tks[i];
              if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
              break;
            }
          }
          if (tks[p] && tks[p].type === 'open' && tks[p].char === '{') {
            let bd = 1, bEnd = p + 1;
            while (bEnd < stop && bd > 0) {
              if (tks[bEnd].type === 'open' && tks[bEnd].char === '{') bd++;
              else if (tks[bEnd].type === 'close' && tks[bEnd].char === '}') bd--;
              bEnd++;
            }
            props[keyName] = functionBinding(params, p + 1, bEnd - 1, true);
            i = bEnd;
            const sep = tks[i];
            if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
            break;
          }
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
      const obj = objectBinding(props);
      // Move pending accessors from props to the dedicated accessors map.
      if (props.__pendingAccessors) {
        for (const name of Object.keys(props.__pendingAccessors)) {
          obj.accessors[name] = props.__pendingAccessors[name];
        }
        delete props.__pendingAccessors;
      }
      return { binding: obj, next: i + 1 };
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
    // Parse a callback: either an arrow function OR `function(params) { body }`.
    // Returns { fn: functionBinding, next } or null.
    const peekCallback = (k, stop) => {
      // Try arrow first.
      const arrow = peekArrow(k, stop);
      if (arrow) {
        const body = readArrowBody(arrow.arrowNext, stop);
        if (body) return { fn: functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock), next: body.next };
      }
      // Try `function(params) { body }`.
      const t = tks[k];
      if (t && t.type === 'other' && t.text === 'function') {
        const lp = tks[k + 1];
        if (lp && lp.type === 'open' && lp.char === '(') {
          const params = [];
          let p = k + 2;
          if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; }
          else {
            let ok = true;
            while (p < stop) {
              const pt = parseParamWithDefault(tks, p, stop);
              if (!pt) { ok = false; break; }
              params.push(pt.param);
              p = pt.next;
              if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; break; }
              if (tks[p] && tks[p].type === 'sep' && tks[p].char === ',') { p++; continue; }
              ok = false; break;
            }
            if (!ok) return null;
          }
          if (tks[p] && tks[p].type === 'open' && tks[p].char === '{') {
            let d = 1, bEnd = p + 1;
            while (bEnd < stop && d > 0) {
              if (tks[bEnd].type === 'open' && tks[bEnd].char === '{') d++;
              else if (tks[bEnd].type === 'close' && tks[bEnd].char === '}') d--;
              bEnd++;
            }
            return { fn: functionBinding(params, p + 1, bEnd - 1, true), next: bEnd };
          }
        }
      }
      return null;
    };

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
          binding: functionBinding(arrow.params, body.bodyStart, body.bodyEnd, body.isBlock, stack.length > 1 ? captureScope() : null),
          next: body.next,
        };
      }
      // Assignment expression: `ident = expr` returns the assigned value.
      // Handles chained assignment: `a = b = "val"`.
      if (t.type === 'other' && IDENT_RE.test(t.text)) {
        const eqTok = tks[k + 1];
        if (eqTok && eqTok.type === 'sep' && eqTok.char === '=') {
          const rhs = readValue(k + 2, stop, terms);
          if (rhs) {
            assignName(t.text, rhs.binding);
            return rhs; // assignment expression returns the assigned value
          }
        }
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
      // Strip numeric separators: 1_000_000 → 1000000
      const stripped = text.indexOf('_') >= 0 ? text.replace(/_/g, '') : text;
      if (/^-?\d+$/.test(stripped)) return stripped.replace(/^-?0+(?=\d)/, (m) => m.startsWith('-') ? '-' : '');
      if (/^-?\d*\.\d+$/.test(stripped)) return stripped;
      // Hex (0x), octal (0o), binary (0b) literals.
      if (/^0[xX][0-9a-fA-F_]+$/.test(stripped)) return String(parseInt(stripped, 16));
      if (/^0[oO][0-7_]+$/.test(stripped)) return String(parseInt(stripped.slice(2), 8));
      if (/^0[bB][01_]+$/.test(stripped)) return String(parseInt(stripped.slice(2), 2));
      if (text === 'true' || text === 'false' || text === 'null' || text === 'undefined') return text;
      return null;
    };

    // Apply `[key]` subscripts and separate-token `.method(args)` calls as
    // postfix accessors on a typed binding. Returns { bind, next }.
    const applySuffixes = (bind, next, stop) => {
      let receiver = null; // tracks the object a method was accessed from
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
            else if (prop === 'length' && bind.kind === 'array') bind = chainBinding([makeSynthNum(bind.elems.length)]);
            else if (prop === 'length' && bind.kind === 'chain') {
              const s = chainAsKnownString(bind);
              bind = s === null ? null : chainBinding([makeSynthNum(s.length)]);
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
              const accessor = cur.accessors && cur.accessors[p];
              if (accessor && accessor.get) {
                stack.push({ bindings: Object.create(null), isFunction: true, thisBinding: cur });
                cur = instantiateFunctionBinding(accessor.get, []);
                stack.pop();
              } else {
                cur = cur.props[p] || null;
              }
            } else if (p === 'length' && cur.kind === 'array') {
              cur = chainBinding([makeSynthNum(cur.elems.length)]);
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
              cur = ok ? chainBinding([makeSynthNum(n)]) : null;
            } else {
              cur = null;
              break;
            }
          }
          if (isMethodCall) {
            const r = applyMethod(cur, lastSeg, next + 1, stop);
            if (r) {
              bind = r.bind;
              next = r.next;
              continue;
            }
            break;
          }
          // Track receiver for `this` binding in subsequent call.
          if (bind && (bind.kind === 'object' || bind.kind === 'element')) receiver = bind;
          bind = cur;
          next = next + 1;
          continue;
        }
        // Call on a function binding reached via property access:
        // `obj.method(args)` where method is a functionBinding in props.
        // Invoke with `this` bound to the receiver object.
        if (t.type === 'open' && t.char === '(' && bind && bind.kind === 'function') {
          const argRes = readCallArgBindings(next, stop);
          if (argRes) {
            // Set up this/super for method calls, then delegate to
            // instantiateFunctionBinding which handles closures.
            const recCls = receiver && receiver.classRef || null;
            const savedThis = bind.closure ? null : receiver;
            const result = instantiateFunctionBinding(bind, argRes.bindings, receiver || null, recCls && recCls.superClass || null);
            if (result) {
              receiver = null;
              bind = result;
              next = argRes.next;
              continue;
            }
          }
          break;
        }
        break;
      }
      // Tagged template: `func`a${x}b`` — invoke the function with
      // [strings, ...values] where strings is the static parts array
      // and values are the interpolated expressions.
      if (next < stop && bind && bind.kind === 'function' && tks[next] && tks[next].type === 'tmpl') {
        const tmpl = tks[next];
        const strings = [];
        const values = [];
        for (const part of tmpl.parts) {
          if (part.kind === 'text') {
            strings.push(chainBinding([makeSynthStr(decodeJsString(part.raw, '`'))]));
          } else if (part.kind === 'expr') {
            const exprSrc = part.expr || part.raw || '';
            const exprToks = tokenize(exprSrc);
            const savedTks = tks;
            tks = exprToks;
            const val = readValue(0, exprToks.length, TERMS_NONE);
            tks = savedTks;
            values.push(val ? val.binding : chainBinding([exprRef(exprSrc)]));
          }
        }
        // Build args: [stringsArray, ...values]
        const args = [arrayBinding(strings), ...values];
        const result = instantiateFunctionBinding(bind, args);
        if (result) {
          bind = result;
          next = next + 1;
        }
      }
      return { bind, next };
    };

    // Apply a method call: .concat on chain, or .join on array.
    const applyMethod = (bind, method, parenIdx, stop) => {
      if (method === 'concat' && bind && bind.kind === 'chain') {
        const args = readConcatArgs(parenIdx, stop);
        if (!args) return null;
        const toks = bind.toks.slice();
        for (const a of args.args) { toks.push(SYNTH_PLUS); for (const v of a) toks.push(v); }
        return { bind: chainBinding(toks), next: args.next };
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
      // Number methods on a known numeric chain: .toFixed, .toString(radix),
      // .toPrecision, .toExponential.
      if (bind && bind.kind === 'chain') {
        const num = chainAsNumber(bind);
        if (num !== null && (method === 'toFixed' || method === 'toString' || method === 'toPrecision' || method === 'toExponential' || method === 'valueOf')) {
          const args = readConcatArgs(parenIdx, stop);
          if (!args) return null;
          const argVals = [];
          let allConcrete = true;
          for (const a of args.args) {
            const ch = chainBinding(a);
            const n = chainAsNumber(ch);
            if (n !== null) { argVals.push(n); continue; }
            allConcrete = false; break;
          }
          if (allConcrete) {
            let result;
            try {
              switch (method) {
                case 'toFixed': result = num.toFixed(...argVals); break;
                case 'toString': result = num.toString(...argVals); break;
                case 'toPrecision': result = num.toPrecision(...argVals); break;
                case 'toExponential': result = num.toExponential(...argVals); break;
                case 'valueOf': result = String(num); break;
              }
            } catch (_) { return null; }
            if (result !== undefined) return { bind: chainBinding([makeSynthStr(result)]), next: args.next };
          }
        }
      }
      // Pure string methods on a known chain string: evaluate when all args
      // are concrete literals. Non-evaluatable cases return null.
      // Regex `.test(str)` — receiver is a regex, argument is a string.
      if (bind && bind.kind === 'chain' && method === 'test') {
        const re = chainAsRegex(bind);
        if (re) {
          const args = readConcatArgs(parenIdx, stop);
          if (args && args.args.length === 1) {
            const argStr = chainAsKnownString(chainBinding(args.args[0]));
            if (argStr !== null) {
              return { bind: chainBinding([makeSynthBool(re.test(argStr))]), next: args.next };
            }
          }
        }
      }
      if (bind && bind.kind === 'chain') {
        const s = chainAsKnownString(bind);
        if (s !== null) {
          const args = readConcatArgs(parenIdx, stop);
          if (!args) return null;
          // Check if any arg is a regex token (for replace/match/search/split).
          const firstArgChain = args.args.length >= 1 ? chainBinding(args.args[0]) : null;
          const firstArgRegex = firstArgChain ? chainAsRegex(firstArgChain) : null;
          // Regex-based string methods.
          if (firstArgRegex && (method === 'replace' || method === 'replaceAll' || method === 'match' || method === 'search' || method === 'split')) {
            try {
              if (method === 'replace' || method === 'replaceAll') {
                const replStr = args.args.length >= 2 ? chainAsKnownString(chainBinding(args.args[1])) : null;
                if (replStr !== null) {
                  const result = s.replace(firstArgRegex, replStr);
                  return { bind: chainBinding([makeSynthStr(result)]), next: args.next };
                }
              }
              if (method === 'match') {
                const m = s.match(firstArgRegex);
                if (m === null) return { bind: chainBinding([makeSynthNull()]), next: args.next };
                return { bind: arrayBinding(m.map((v) => chainBinding([makeSynthStr(v)]))), next: args.next };
              }
              if (method === 'search') {
                return { bind: chainBinding([makeSynthNum(s.search(firstArgRegex))]), next: args.next };
              }
              if (method === 'split') {
                const parts = s.split(firstArgRegex);
                return { bind: arrayBinding(parts.map((p) => chainBinding([makeSynthStr(p)]))), next: args.next };
              }
            } catch (_) { return null; }
          }
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
              case 'at': if (argVals.length === 1) result = s.at(argVals[0]); break;
              case 'replace': if (argVals.length === 2 && typeof argVals[0] === 'string') result = s.replace(argVals[0], argVals[1]); break;
              case 'replaceAll': if (argVals.length === 2 && typeof argVals[0] === 'string') result = s.replaceAll(argVals[0], argVals[1]); break;
              case 'charCodeAt': if (argVals.length === 1) result = String(s.charCodeAt(argVals[0])); break;
              case 'codePointAt': if (argVals.length === 1) result = String(s.codePointAt(argVals[0])); break;
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
          const cb = peekCallback(parenIdx + 1, stop);
          if (!cb) return null;
          const rp = tks[cb.next];
          if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
          const fn = cb.fn;
          if (method === 'forEach') {
            // Walk body per element for side effects (e.g. html += item).
            for (let idx = 0; idx < bind.elems.length; idx++) {
              const el = bind.elems[idx];
              if (!el) continue;
              const iterFrame = { bindings: Object.create(null), isFunction: true };
              if (fn.params[0]) iterFrame.bindings[fn.params[0].name] = el;
              if (fn.params[1]) iterFrame.bindings[fn.params[1].name] = chainBinding([makeSynthNum(idx)]);
              if (fn.params[2]) iterFrame.bindings[fn.params[2].name] = bind;
              stack.push(iterFrame);
              if (fn.isBlock) walkRangeWithEffects(fn.bodyStart, fn.bodyEnd);
              stack.pop();
            }
            return { bind: chainBinding([makeSynthStr('undefined')]), next: cb.next + 1 };
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
            const truth = evalTruthiness(chainBinding(toks));
            if (truth === true) results.push(el);
            else if (truth !== false) return null;
          }
          return { bind: arrayBinding(results), next: cb.next + 1 };
        }
        // Callback-based: find, findIndex, some, every, flatMap.
        if (method === 'find' || method === 'findIndex' || method === 'some' || method === 'every' || method === 'flatMap') {
          const lp = tks[parenIdx];
          if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
          const cb = peekCallback(parenIdx + 1, stop);
          if (!cb) return null;
          const rp = tks[cb.next];
          if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
          const fn = cb.fn;
          if (method === 'flatMap') {
            const out = [];
            for (const el of bind.elems) {
              if (!el) return null;
              const r = instantiateFunctionBinding(fn, [el]);
              if (!r) return null;
              if (r.kind === 'array') { for (const e of r.elems) out.push(e); }
              else out.push(r);
            }
            return { bind: arrayBinding(out), next: cb.next + 1 };
          }
          for (let idx = 0; idx < bind.elems.length; idx++) {
            const el = bind.elems[idx];
            if (!el) return null;
            const toks = instantiateFunction(fn, [el, chainBinding([makeSynthStr(String(idx))])]);
            if (!toks) return null;
            const truth = evalTruthiness(chainBinding(toks));
            if (method === 'find') {
              if (truth === true) return { bind: el, next: cb.next + 1 };
              if (truth === null) return null;
            } else if (method === 'findIndex') {
              if (truth === true) return { bind: chainBinding([makeSynthNum(idx)]), next: cb.next + 1 };
              if (truth === null) return null;
            } else if (method === 'some') {
              if (truth === true) return { bind: chainBinding([makeSynthBool(true)]), next: cb.next + 1 };
              if (truth === null) return null;
            } else if (method === 'every') {
              if (truth === false) return { bind: chainBinding([makeSynthBool(false)]), next: cb.next + 1 };
              if (truth === null) return null;
            }
          }
          if (method === 'find') return { bind: chainBinding([makeSynthStr('undefined')]), next: cb.next + 1 };
          if (method === 'findIndex') return { bind: chainBinding([makeSynthStr('-1')]), next: cb.next + 1 };
          if (method === 'some') return { bind: chainBinding([makeSynthStr('false')]), next: cb.next + 1 };
          if (method === 'every') return { bind: chainBinding([makeSynthStr('true')]), next: cb.next + 1 };
        }
        // `.reduce(fn, init)` — two-arg reducer: invoke the callback
        // per element with (accumulator, element) and thread the
        // running result through.
        if (method === 'reduce') {
          const lp = tks[parenIdx];
          if (!lp || lp.type !== 'open' || lp.char !== '(') return null;
          const cb = peekCallback(parenIdx + 1, stop);
          if (!cb || cb.fn.params.length !== 2) return null;
          const sep = tks[cb.next];
          if (!sep || sep.type !== 'sep' || sep.char !== ',') return null;
          const init = readConcatExpr(cb.next + 1, stop, { sep: [], close: [')'] });
          if (!init) return null;
          const rp = tks[init.next];
          if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
          const fn = cb.fn;
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
        // Methods that handle their own arg resolution (args may be arrays
        // or other non-scalar bindings).
        if (method === 'concat') {
          const argRes = readCallArgBindings(parenIdx, stop);
          if (!argRes) return null;
          const out = bind.elems.slice();
          for (const ab of argRes.bindings) {
            if (ab && ab.kind === 'array') { for (const e of ab.elems) out.push(e); }
            else out.push(ab);
          }
          return { bind: arrayBinding(out), next: argRes.next };
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
        if (method === 'concat') {
          // arr.concat(arr2, arr3, ...) — merges arrays/values.
          const out = bind.elems.slice();
          for (const a of args.args) {
            const ab = chainBinding(a);
            const resolved = ab.toks.length === 1 && ab.toks[0].type === 'other' ? resolve(ab.toks[0].text) : null;
            const src = resolved && resolved.kind === 'array' ? resolved : (ab.kind === 'array' ? ab : null);
            if (src && src.kind === 'array') { for (const e of src.elems) out.push(e); }
            else out.push(chainBinding(a));
          }
          return { bind: arrayBinding(out), next: args.next };
        }
        if (method === 'flat' && argVals.length <= 1) {
          const depth = argVals.length === 1 ? argVals[0] : 1;
          const flattenArr = (arr, d) => {
            const out = [];
            for (const el of arr) {
              if (d > 0 && el && el.kind === 'array') out.push(...flattenArr(el.elems, d - 1));
              else out.push(el);
            }
            return out;
          };
          return { bind: arrayBinding(flattenArr(bind.elems, depth)), next: args.next };
        }
        if (method === 'fill') {
          const out = bind.elems.slice();
          const val = args.args.length >= 1 ? chainBinding(args.args[0]) : null;
          const start = argVals.length >= 2 ? argVals[1] : 0;
          const end = argVals.length >= 3 ? argVals[2] : out.length;
          for (let k = start; k < end && k < out.length; k++) out[k] = val;
          return { bind: arrayBinding(out), next: args.next };
        }
        if (method === 'splice' && argVals.length >= 1) {
          const out = bind.elems.slice();
          const startIdx = argVals[0] < 0 ? Math.max(0, out.length + argVals[0]) : argVals[0];
          const delCount = argVals.length >= 2 ? argVals[1] : out.length - startIdx;
          const items = args.args.slice(2).map((a) => chainBinding(a));
          const removed = out.splice(startIdx, delCount, ...items);
          // Mutate the original binding AND return removed.
          bind.elems.length = 0;
          for (const e of out) bind.elems.push(e);
          return { bind: arrayBinding(removed), next: args.next };
        }
        if (method === 'at' && argVals.length === 1) {
          const idx = argVals[0] < 0 ? bind.elems.length + argVals[0] : argVals[0];
          const el = bind.elems[idx] || null;
          return el ? { bind: el, next: args.next } : null;
        }
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
      if (typeof v === 'number') return chainBinding([makeSynthNum(v)]);
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
      // Class expression: `class { ... }` or `class Name { ... }` in
      // expression position. Parse the same way as the statement-level
      // class handler but return the classBinding as a value.
      // Function expression: `function(params) { body }` or
      // `function name(params) { body }` in expression position.
      if (t.type === 'other' && t.text === 'function') {
        let j = k + 1;
        // Optional name.
        if (tks[j] && tks[j].type === 'other' && IDENT_RE.test(tks[j].text) &&
            tks[j + 1] && tks[j + 1].type === 'open' && tks[j + 1].char === '(') j++;
        if (tks[j] && tks[j].type === 'open' && tks[j].char === '(') {
          const params = [];
          let p = j + 1;
          if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; }
          else {
            let ok = true;
            while (p < stop) {
              const pt = parseParamWithDefault(tks, p, stop);
              if (!pt) { ok = false; break; }
              params.push(pt.param);
              p = pt.next;
              if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; break; }
              if (tks[p] && tks[p].type === 'sep' && tks[p].char === ',') { p++; continue; }
              ok = false; break;
            }
            if (!ok) return null;
          }
          if (tks[p] && tks[p].type === 'open' && tks[p].char === '{') {
            let d = 1, bEnd = p + 1;
            while (bEnd < stop && d > 0) {
              if (tks[bEnd].type === 'open' && tks[bEnd].char === '{') d++;
              else if (tks[bEnd].type === 'close' && tks[bEnd].char === '}') d--;
              bEnd++;
            }
            // Capture closure when created inside another function's scope.
            const closure = stack.length > 1 ? captureScope() : null;
            return { bind: functionBinding(params, p + 1, bEnd - 1, true, closure), next: bEnd };
          }
        }
      }
      if (t.type === 'other' && t.text === 'class') {
        let j = k + 1;
        let className = null;
        if (tks[j] && tks[j].type === 'other' && IDENT_RE.test(tks[j].text) &&
            !(tks[j].text === 'extends') /* don't consume extends as name */) {
          className = tks[j].text;
          j++;
        }
        let superClass = null;
        if (tks[j] && tks[j].type === 'other' && tks[j].text === 'extends') {
          j++;
          if (tks[j] && tks[j].type === 'other' && IDENT_OR_PATH_RE.test(tks[j].text)) {
            superClass = resolvePath(tks[j].text) || null;
            j++;
          }
        }
        if (tks[j] && tks[j].type === 'open' && tks[j].char === '{') {
          // Skip over the class body to find the closing `}`.
          let d = 1, bodyEnd = j + 1;
          while (bodyEnd < stop && d > 0) {
            const tk = tks[bodyEnd];
            if (tk.type === 'open' && tk.char === '{') d++;
            else if (tk.type === 'close' && tk.char === '}') d--;
            bodyEnd++;
          }
          // Reuse the statement-level class body parser by temporarily
          // switching to walk the class body (same as the walker does).
          // For simplicity, create a minimal classBinding from the body.
          let ctor = null;
          const methods = Object.create(null);
          let m = j + 1;
          while (m < bodyEnd - 1) {
            const mtk = tks[m];
            if (!mtk) break;
            if (mtk.type === 'sep' && mtk.char === ';') { m++; continue; }
            let isStatic = false;
            if (mtk.type === 'other' && mtk.text === 'static') { isStatic = true; m++; }
            if (tks[m] && tks[m].type === 'other' && tks[m].text === 'async') m++;
            if (tks[m] && tks[m].type === 'op' && tks[m].text === '*') m++;
            if (tks[m] && tks[m].type === 'other' && (tks[m].text === 'get' || tks[m].text === 'set')) {
              if (tks[m + 1] && tks[m + 1].type === 'other' && IDENT_RE.test(tks[m + 1].text) &&
                  tks[m + 2] && tks[m + 2].type === 'open' && tks[m + 2].char === '(') m++;
            }
            const nameTk = tks[m];
            if (!nameTk || nameTk.type !== 'other' || !IDENT_RE.test(nameTk.text)) {
              let sd = 0;
              while (m < bodyEnd - 1) {
                const sk = tks[m];
                if (sk.type === 'open') sd++;
                else if (sk.type === 'close') { if (sd === 0) break; sd--; }
                else if (sd === 0 && sk.type === 'sep' && sk.char === ';') break;
                m++;
              }
              if (tks[m] && (tks[m].type === 'close' || (tks[m].type === 'sep' && tks[m].char === ';'))) m++;
              continue;
            }
            const methodName = nameTk.text;
            m++;
            if (tks[m] && tks[m].type === 'open' && tks[m].char === '(') {
              const params = [];
              let p = m + 1;
              if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; }
              else {
                let ok = true;
                while (p < bodyEnd - 1) {
                  const pt = parseParamWithDefault(tokens, p, bodyEnd - 1);
                  if (!pt) { ok = false; break; }
                  params.push(pt.param);
                  p = pt.next;
                  if (tks[p] && tks[p].type === 'close' && tks[p].char === ')') { p++; break; }
                  if (tks[p] && tks[p].type === 'sep' && tks[p].char === ',') { p++; continue; }
                  ok = false; break;
                }
                if (!ok) { m = p; continue; }
              }
              if (tks[p] && tks[p].type === 'open' && tks[p].char === '{') {
                let md = 1, mEnd = p + 1;
                while (mEnd < bodyEnd && md > 0) {
                  if (tks[mEnd].type === 'open' && tks[mEnd].char === '{') md++;
                  else if (tks[mEnd].type === 'close' && tks[mEnd].char === '}') md--;
                  mEnd++;
                }
                const fn = functionBinding(params, p + 1, mEnd - 1, true);
                if (methodName === 'constructor' && !isStatic) ctor = fn;
                else if (!isStatic) methods[methodName] = fn;
                m = mEnd;
                continue;
              }
            }
            let sd = 0;
            while (m < bodyEnd - 1) {
              const sk = tks[m];
              if (sk.type === 'open') sd++;
              else if (sk.type === 'close') { if (sd === 0) break; sd--; }
              else if (sd === 0 && sk.type === 'sep' && sk.char === ';') break;
              m++;
            }
            if (tks[m] && (tks[m].type === 'close' || (tks[m].type === 'sep' && tks[m].char === ';'))) m++;
          }
          return { bind: classBinding(className, ctor, methods, superClass), next: bodyEnd };
        }
      }
      // `super.method(args)` in expression context — resolve via superClass.
      // `super.val` is tokenized as one PATH_RE token 'super.val'.
      if (t.type === 'other' && (t.text === 'super' || t.text.startsWith('super.'))) {
        const methodName = t.text.includes('.') ? t.text.slice(t.text.indexOf('.') + 1) : null;
        const dotTok = !methodName ? tks[k + 1] : null;
        const resolvedMethod = methodName || (dotTok && dotTok.type === 'other' && /^\.[A-Za-z_$]/.test(dotTok.text) ? dotTok.text.slice(1) : null);
        if (resolvedMethod) {
          let thisObj = null, superCls = null;
          for (let si = stack.length - 1; si >= 0; si--) {
            if (stack[si].isFunction && stack[si].thisBinding) {
              thisObj = stack[si].thisBinding;
              superCls = stack[si].superClass || null;
              break;
            }
          }
          if (superCls && superCls.kind === 'class' && superCls.methods[resolvedMethod]) {
            const fn = superCls.methods[resolvedMethod];
            // Paren is at k+1 when super.method is one token, k+2 when two.
            const parenOff = methodName ? k + 1 : k + 2;
            const parenTok = tks[parenOff];
            if (parenTok && parenTok.type === 'open' && parenTok.char === '(') {
              const argRes = readCallArgBindings(parenOff, stop);
              if (argRes) {
                const result = instantiateFunctionBinding(fn, argRes.bindings, thisObj, superCls.superClass || null);
                if (result) return { bind: result, next: argRes.next };
              }
            }
          }
        }
      }
      if (t.type === 'other' && t.text === 'new') {
        // Try to resolve `new ClassName(args)` when ClassName is a known
        // class binding. Creates a fresh object, runs the constructor
        // with `this` bound to it, and attaches class methods.
        const ctorTok = tks[k + 1];
        if (ctorTok && ctorTok.type === 'other' && IDENT_OR_PATH_RE.test(ctorTok.text)) {
          const cls = resolvePath(ctorTok.text);
          if (cls && cls.kind === 'class') {
            const argRes = readCallArgBindings(k + 2, stop);
            if (argRes) {
              // Create instance object. Copy super methods first, then own.
              const props = Object.create(null);
              if (cls.superClass && cls.superClass.kind === 'class') {
                for (const mn of Object.keys(cls.superClass.methods)) props[mn] = cls.superClass.methods[mn];
              }
              for (const mn of Object.keys(cls.methods)) props[mn] = cls.methods[mn];
              const instance = objectBinding(props);
              // Store class ref on instance for super method resolution.
              instance.classRef = cls;
              // Run constructor with `this` = instance.
              if (cls.ctor) {
                stack.push({ bindings: Object.create(null), isFunction: true, thisBinding: instance, superClass: cls.superClass || null });
                const frame = stack[stack.length - 1];
                for (let p = 0; p < cls.ctor.params.length; p++) {
                  const pi = cls.ctor.params[p];
                  frame.bindings[pi.name] = argRes.bindings[p] || null;
                }
                walkRangeWithEffects(cls.ctor.bodyStart, cls.ctor.bodyEnd);
                stack.pop();
              }
              return { bind: instance, next: argRes.next };
            }
          }
        }
        // Fall back: absorb as opaque `new X(...)`.
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
        // `typeof` folds to a concrete string when the operand has a known
        // binding kind or a concrete scalar value.
        if (t.text === 'typeof') {
          const b = inner.bind;
          if (b && b.kind === 'object') return { bind: chainBinding([makeSynthStr('object')]), next: inner.next };
          if (b && b.kind === 'array') return { bind: chainBinding([makeSynthStr('object')]), next: inner.next };
          if (b && b.kind === 'function') return { bind: chainBinding([makeSynthStr('function')]), next: inner.next };
          if (b && b.kind === 'element') return { bind: chainBinding([makeSynthStr('object')]), next: inner.next };
          if (b && b.kind === 'chain' && b.toks.length === 1 && b.toks[0].jsType) {
            const jt = b.toks[0].jsType;
            const mapped = jt === 'null' ? 'object' : jt;
            return { bind: chainBinding([makeSynthStr(mapped)]), next: inner.next };
          }
          if (b && b.kind === 'chain') {
            const n = chainAsNumber(b);
            if (n !== null) return { bind: chainBinding([makeSynthStr('number')]), next: inner.next };
            const s = chainAsKnownString(b);
            if (s !== null) return { bind: chainBinding([makeSynthStr('string')]), next: inner.next };
          }
        }
        // `void expr` is always `undefined`.
        if (t.text === 'void') {
          return { bind: chainBinding([makeSynthUndef()]), next: inner.next };
        }
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
      // Bare number literal: the tokenizer emits digits as type 'other'.
      // Recognise them here so arithmetic folding works.
      if (t.type === 'other' && /^[0-9]/.test(t.text) && !Number.isNaN(Number(t.text)) && String(Number(t.text)) === t.text) {
        return { bind: chainBinding([makeSynthNum(Number(t.text))]), next: k + 1 };
      }
      if (t.type === 'tmpl') return { bind: chainBinding([rewriteTemplate(t)]), next: k + 1 };
      // Regex literal: preserve the token type so applyMethod can construct
      // a real RegExp when used as an argument to .replace/.match/.test etc.
      if (t.type === 'regex') return { bind: chainBinding([t]), next: k + 1 };
      if (t.type === 'open' && t.char === '(') {
        // Try readValue first to preserve typed bindings (function, array,
        // object) that readConcatExpr would flatten to opaque tokens.
        const parenTerms = { sep: [','], close: [')'] };
        const rv = readValue(k + 1, stop, parenTerms);
        if (rv) {
          let lastBind = rv.binding;
          let pos = rv.next;
          // Comma operator: evaluate all sub-expressions, keep the last.
          while (tks[pos] && tks[pos].type === 'sep' && tks[pos].char === ',') {
            const sub = readValue(pos + 1, stop, parenTerms);
            if (!sub) break;
            lastBind = sub.binding;
            pos = sub.next;
          }
          const rp = tks[pos];
          if (rp && rp.type === 'close' && rp.char === ')') return { bind: lastBind, next: pos + 1 };
        }
        // Fallback to readConcatExpr for complex concat chains.
        const r = readConcatExpr(k + 1, stop, parenTerms);
        if (!r) return null;
        let lastToks = r.toks;
        let pos = r.next;
        while (tks[pos] && tks[pos].type === 'sep' && tks[pos].char === ',') {
          const sub = readConcatExpr(pos + 1, stop, parenTerms);
          if (!sub) break;
          lastToks = sub.toks;
          pos = sub.next;
        }
        const rp = tks[pos];
        if (!rp || rp.type !== 'close' || rp.char !== ')') return null;
        return { bind: chainBinding(lastToks), next: pos + 1 };
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
      if (t.text === 'true') return { bind: chainBinding([makeSynthBool(true)]), next: k + 1 };
      if (t.text === 'false') return { bind: chainBinding([makeSynthBool(false)]), next: k + 1 };
      if (t.text === 'null') return { bind: chainBinding([makeSynthNull()]), next: k + 1 };
      if (t.text === 'undefined') return { bind: chainBinding([makeSynthUndef()]), next: k + 1 };
      if (t.text === 'Infinity') return { bind: chainBinding([makeSynthNum(Infinity)]), next: k + 1 };
      if (t.text === 'NaN') return { bind: chainBinding([makeSynthNum(NaN)]), next: k + 1 };
      const lit = primitiveAsString(t.text);
      if (lit !== null) return { bind: chainBinding([makeSynthNum(Number(lit))]), next: k + 1 };
      // Identifier/path, possibly with attached .concat/.join method call.
      if (IDENT_OR_PATH_RE.test(t.text)) {
        const paren = tks[k + 1];
        const isCall = paren && paren.type === 'open' && paren.char === '(';
        // Known math/numeric constants like `Math.PI`.
        if (!isCall && MATH_CONSTANTS[t.text] !== undefined && !isShadowed(t.text)) {
          return { bind: chainBinding([makeSynthNum(MATH_CONSTANTS[t.text])]), next: k + 1 };
        }
        // Known global builtin function call (numeric Math.*, parseInt...).
        if (isCall && BUILTINS[t.text] && !isShadowed(t.text)) {
          const args = readConcatArgs(k + 1, stop);
          if (args) {
            // Collect args as numbers. parseInt/parseFloat/Number/Boolean
            // also accept string arguments, so try chainAsKnownString as
            // a fallback and coerce via Number() / parseInt() / parseFloat().
            const nums = [];
            let allResolved = true;
            const coerceFns = { 'parseInt': true, 'parseFloat': true, 'Number': true, 'Boolean': true, 'isNaN': true, 'isFinite': true };
            const acceptsStrings = coerceFns[t.text] || false;
            for (const a of args.args) {
              const ch = chainBinding(a);
              const n = chainAsNumber(ch);
              if (n !== null) { nums.push(n); continue; }
              if (acceptsStrings) {
                const s = chainAsKnownString(ch);
                if (s !== null) { nums.push(s); continue; }
              }
              allResolved = false; break;
            }
            if (allResolved) {
              const v = BUILTINS[t.text](...nums);
              if (typeof v === 'number' && !Number.isNaN(v)) {
                return { bind: chainBinding([makeSynthNum(v)]), next: args.next };
              }
              if (typeof v === 'boolean') {
                return { bind: chainBinding([makeSynthBool(v)]), next: args.next };
              }
              if (typeof v === 'number') {
                return { bind: chainBinding([makeSynthNum(v)]), next: args.next };
              }
            }
          }
        }
        // Object.keys/values/entries on known object bindings.
        if (isCall && (t.text === 'Object.keys' || t.text === 'Object.values' || t.text === 'Object.entries') && !isShadowed(t.text)) {
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
        // Object.assign / Object.fromEntries on known bindings.
        if (isCall && t.text === 'Object.assign' && !isShadowed(t.text)) {
          const argRes = readCallArgBindings(k + 1, stop);
          if (argRes && argRes.bindings.length >= 1) {
            const target = argRes.bindings[0];
            if (target && target.kind === 'object') {
              for (let a = 1; a < argRes.bindings.length; a++) {
                const src = argRes.bindings[a];
                if (src && src.kind === 'object') {
                  for (const key of Object.keys(src.props)) target.props[key] = src.props[key];
                }
              }
              return { bind: target, next: argRes.next };
            }
          }
        }
        if (isCall && t.text === 'Object.fromEntries' && !isShadowed(t.text)) {
          const argRes = readCallArgBindings(k + 1, stop);
          if (argRes && argRes.bindings.length === 1) {
            const src = argRes.bindings[0];
            if (src && src.kind === 'array') {
              const props = Object.create(null);
              let ok = true;
              for (const entry of src.elems) {
                if (!entry || entry.kind !== 'array' || entry.elems.length < 2) { ok = false; break; }
                const key = entry.elems[0] && entry.elems[0].kind === 'chain' ? chainAsKnownString(entry.elems[0]) : null;
                if (key === null) { ok = false; break; }
                props[key] = entry.elems[1];
              }
              if (ok) return { bind: objectBinding(props), next: argRes.next };
            }
          }
        }
        // Array.isArray / Array.from / Array.of on known bindings.
        if (isCall && t.text === 'Array.isArray' && !isShadowed(t.text)) {
          const argRes = readCallArgBindings(k + 1, stop);
          if (argRes && argRes.bindings.length === 1) {
            const ob = argRes.bindings[0];
            const v = ob && ob.kind === 'array' ? 'true' : (ob && (ob.kind === 'object' || ob.kind === 'chain') ? 'false' : null);
            if (v !== null) return { bind: chainBinding([makeSynthStr(v)]), next: argRes.next };
          }
        }
        if (isCall && t.text === 'Array.of' && !isShadowed(t.text)) {
          const argRes = readCallArgBindings(k + 1, stop);
          if (argRes) return { bind: arrayBinding(argRes.bindings.slice()), next: argRes.next };
        }
        if (isCall && t.text === 'Array.from' && !isShadowed(t.text)) {
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
            // Array.from('string') — iterate characters.
            if (src && src.kind === 'chain') {
              const s = chainAsKnownString(src);
              if (s !== null) {
                let out = Array.from(s).map((ch) => chainBinding([makeSynthStr(ch)]));
                if (mapFn && mapFn.kind === 'function') {
                  const mapped = [];
                  for (let idx = 0; idx < out.length; idx++) {
                    const el = out[idx];
                    const r = instantiateFunctionBinding(mapFn, [el, chainBinding([makeSynthNum(idx)])]);
                    if (!r) return null;
                    mapped.push(r);
                  }
                  out = mapped;
                }
                return { bind: arrayBinding(out), next: argRes.next };
              }
            }
            // Array.from({length: n}) with optional mapFn.
            if (src && src.kind === 'object') {
              const lenB = src.props.length;
              const lenN = lenB ? chainAsNumber(lenB) : null;
              if (lenN !== null && lenN >= 0) {
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
        if (isCall && (t.text === 'JSON.stringify' || t.text === 'JSON.parse') && !isShadowed(t.text)) {
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
        // `String.fromCharCode(n, ...)` / `String.fromCodePoint(n, ...)`
        if (isCall && (t.text === 'String.fromCharCode' || t.text === 'String.fromCodePoint') && !isShadowed(t.text)) {
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
              try {
                const result = t.text === 'String.fromCharCode'
                  ? String.fromCharCode(...nums)
                  : String.fromCodePoint(...nums);
                return { bind: chainBinding([makeSynthStr(result)]), next: args.next };
              } catch (_) { /* fall through */ }
            }
          }
        }
        // `String(x)` coerces any literal to its string form.
        if (isCall && t.text === 'String' && !isShadowed(t.text)) {
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
              const prefBind = resolvePath(prefix);
              if (prefBind) {
                const r = applyMethod(prefBind, method, k + 1, stop);
                if (r) return { bind: r.bind, next: r.next };
              }
            }
            // Method call on an object/instance: `obj.method(args)` where
            // method is a function binding stored in obj's props. Invoke
            // with `this` bound to the receiver object.
            if (!KNOWN_METHODS.has(method)) {
              const prefix = t.text.slice(0, dot);
              const receiver = resolvePath(prefix);
              if (receiver && receiver.kind === 'object') {
                const fn = receiver.props[method];
                if (fn && fn.kind === 'function') {
                  const argRes = readCallArgBindings(k + 1, stop);
                  if (argRes) {
                    const rcls = receiver && receiver.classRef || null;
                    const result = instantiateFunctionBinding(fn, argRes.bindings, receiver, rcls && rcls.superClass || null);
                    if (result) return { bind: result, next: argRes.next };
                  }
                }
              }
            }
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
          // Use instantiateFunctionBinding so typed returns (array, object)
          // are preserved — not flattened to a token chain.
          if (b.kind === 'function' && isCall) {
            const argRes = readCallArgBindings(k + 1, stop);
            if (!argRes) return null;
            const result = instantiateFunctionBinding(b, argRes.bindings);
            if (!result) return null;
            return { bind: result, next: argRes.next };
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
        if (pi.rest) {
          frame.bindings[pi.name] = arrayBinding(argBindings.slice(p));
          break;
        }
        const a = argBindings[p];
        if (a) {
          frame.bindings[pi.name] = a;
        } else if (pi.defaultStart != null) {
          const r = readConcatExpr(pi.defaultStart, pi.defaultEnd, TERMS_NONE);
          frame.bindings[pi.name] = (r && r.next === pi.defaultEnd) ? chainBinding(r.toks) : null;
        } else {
          frame.bindings[pi.name] = null;
        }
      }
      let result = null;
      if (fn.isBlock) {
        // Look for a top-level `return <expr>;` in the block.
        let i = fn.bodyStart;
        while (i < fn.bodyEnd) {
          const t = tks[i];
          if (t && t.type === 'other' && t.text === 'return') {
            const r = readConcatExpr(i + 1, fn.bodyEnd, TERMS_TOP);
            if (r) result = r.toks;
            break;
          }
          // Skip over nested blocks so `return` inside a nested function
          // doesn't match.
          if (t && t.type === 'open' && t.char === '{') {
            let depth = 1; i++;
            while (i < fn.bodyEnd && depth > 0) {
              const tk = tks[i];
              if (tk.type === 'open' && tk.char === '{') depth++;
              else if (tk.type === 'close' && tk.char === '}') depth--;
              i++;
            }
            continue;
          }
          i++;
        }
      } else {
        const r = readConcatExpr(fn.bodyStart, fn.bodyEnd, TERMS_NONE);
        if (r && r.next === fn.bodyEnd) result = r.toks;
      }
      tks = savedTks;
      stack.pop();
      return result;
    };

    // Like instantiateFunction but returns a typed binding (array/object/chain)
    // instead of raw tokens. Used by flatMap where the callback returns an
    // array literal that readConcatExpr can't represent as a token chain.
    // Unified function invocation: pushes closure + frame with this/super,
    // binds params (including rest), evaluates body, pops frames, returns result.
    const instantiateFunctionBinding = (fn, argBindings, thisObj, superClass) => {
      // Restore closure frames: push the ORIGINAL frames (by reference)
      // so modifications to closed-over variables are shared across all
      // closures that captured the same scope.
      const closureFrameCount = fn.closure ? fn.closure.length : 0;
      if (fn.closure) for (const frame of fn.closure) stack.push(frame);
      stack.push({ bindings: Object.create(null), isFunction: true, thisBinding: thisObj || null, superClass: superClass || null });
      const frame = stack[stack.length - 1];
      const savedTks = tks;
      tks = tokens;
      for (let p = 0; p < fn.params.length; p++) {
        const pi = fn.params[p];
        // Rest parameter: collect remaining args into an array.
        if (pi.rest) {
          frame.bindings[pi.name] = arrayBinding(argBindings.slice(p));
          break;
        }
        const a = argBindings[p];
        if (a) {
          frame.bindings[pi.name] = a;
        } else if (pi.defaultStart != null) {
          const r = readConcatExpr(pi.defaultStart, pi.defaultEnd, TERMS_NONE);
          frame.bindings[pi.name] = (r && r.next === pi.defaultEnd) ? chainBinding(r.toks) : null;
        } else {
          frame.bindings[pi.name] = null;
        }
      }
      let result = null;
      if (fn.isBlock) {
        // Walk the body via the statement walker so declarations (var,
        // function, class) are registered in the scope. Then scan for
        // the top-level `return` expression and evaluate it.
        walkRangeWithEffects(fn.bodyStart, fn.bodyEnd);
        // After walking, scan for `return expr` at the top level.
        let i = fn.bodyStart;
        while (i < fn.bodyEnd) {
          const ft = tks[i];
          if (ft && ft.type === 'other' && ft.text === 'return') {
            const r = readValue(i + 1, fn.bodyEnd, TERMS_TOP);
            if (r) result = r.binding;
            break;
          }
          if (ft && ft.type === 'open' && ft.char === '{') {
            let depth = 1; i++;
            while (i < fn.bodyEnd && depth > 0) {
              if (tks[i].type === 'open' && tks[i].char === '{') depth++;
              else if (tks[i].type === 'close' && tks[i].char === '}') depth--;
              i++;
            }
            continue;
          }
          i++;
        }
      } else {
        const r = readValue(fn.bodyStart, fn.bodyEnd, TERMS_NONE);
        if (r && r.next === fn.bodyEnd) result = r.binding;
      }
      tks = savedTks;
      stack.pop();
      for (let c = 0; c < closureFrameCount; c++) stack.pop();
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
    // known parts become text, unknown parts become placeholders.
    const readOperand = (k, stop, terms) => {
      const parsed = parseArithExpr(k, stop);
      if (parsed) {
        const boundary = skipOperand(parsed.next, stop, terms);
        if (boundary === parsed.next) return { toks: parsed.bind.toks.slice(), next: parsed.next };
        // parseArithExpr resolved partially (e.g. `items[i]` → `location.search`)
        // but there are trailing suffixes it couldn't consume (e.g. `.toLowerCase()`).
        // Use the resolved text + the raw remaining suffix source.
        const resolvedText = chainAsExprText(parsed.bind);
        if (resolvedText !== null && boundary > parsed.next) {
          const suffFirst = tks[parsed.next];
          const suffLast = tks[boundary - 1];
          const suffSrc = suffFirst._src.slice(suffFirst.start, suffLast.end);
          return { toks: [exprRef(resolvedText + suffSrc)], next: boundary };
        }
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
        } else if (opTok && opTok.type === 'other' && (opTok.text === '==' || opTok.text === '!=' || opTok.text === '===' || opTok.text === '!==')) {
          // Equality operators are emitted with type 'other' by the tokenizer.
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

    // Fold a ternary when the condition is a concrete value; otherwise emit
    // canonical symbolic text.
    // Evaluate a binding's truthiness: returns true, false, or null (opaque).
    // Parse a regex token's text (e.g. '/abc/gi') into a RegExp, or null.
    const tokenToRegex = (tok) => {
      if (!tok || tok.type !== 'regex') return null;
      const m = /^\/(.*)\/([gimsuy]*)$/.exec(tok.text);
      if (!m) return null;
      try { return new RegExp(m[1], m[2]); } catch (_) { return null; }
    };

    // Try to extract a regex from a chain binding's single token.
    const chainAsRegex = (chain) => {
      if (!chain || chain.kind !== 'chain' || chain.toks.length !== 1) return null;
      return tokenToRegex(chain.toks[0]);
    };

    const evalTruthiness = (b) => {
      if (!b) return null;
      if (b.kind !== 'chain') return true; // array/object/function/element always truthy
      const jt = b.toks && b.toks.length === 1 ? b.toks[0].jsType : null;
      if (jt === 'null' || jt === 'undefined') return false;
      if (jt === 'boolean') return b.toks[0].text === 'true';
      if (jt === 'number') { const cn = chainAsNumber(b); return cn !== null ? cn !== 0 && !Number.isNaN(cn) : null; }
      // Strings: only empty string is falsy. '0', 'false', 'NaN' are truthy.
      const cs = chainAsKnownString(b);
      if (cs !== null) return cs !== '';
      const cn = chainAsNumber(b);
      if (cn !== null) return cn !== 0 && !Number.isNaN(cn);
      return null;
    };

    const combineTernary = (cond, ifT, ifF) => {
      if (!cond || cond.kind !== 'chain') return null;
      if (!ifT || ifT.kind !== 'chain') return null;
      if (!ifF || ifF.kind !== 'chain') return null;
      const truth = evalTruthiness(cond);
      if (truth === true) return ifT;
      if (truth === false) return ifF;
      const ct = chainAsExprText(cond);
      const tt = chainAsExprText(ifT);
      const ft = chainAsExprText(ifF);
      if (ct === null || tt === null || ft === null) return null;
      const text = '(' + ct + ' ? ' + tt + ' : ' + ft + ')';
      return chainBinding([exprRef(text)]);
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
        if (typeof v === 'boolean') return chainBinding([makeSynthBool(v)]);
        return chainBinding([typeof v === 'number' ? makeSynthNum(v) : makeSynthStr(String(v))]);
      }
      // String comparison folding: when both operands are known strings,
      // fold `== != === !== < > <= >=` to a boolean literal.
      if (op === '==' || op === '!=' || op === '===' || op === '!==' ||
          op === '<' || op === '>' || op === '<=' || op === '>=') {
        const lS = chainAsKnownString(left);
        const rS = chainAsKnownString(right);
        if (lS !== null && rS !== null) {
          let v;
          switch (op) {
            case '==': v = lS == rS; break;
            case '!=': v = lS != rS; break;
            case '===': v = lS === rS; break;
            case '!==': v = lS !== rS; break;
            case '<': v = lS < rS; break;
            case '>': v = lS > rS; break;
            case '<=': v = lS <= rS; break;
            case '>=': v = lS >= rS; break;
          }
          return chainBinding([makeSynthBool(v)]);
        }
      }
      // `+` is overloaded in JS. When both operands aren't concrete numbers
      // we decline here and let the caller (concat-chain parser) handle it
      // as string concatenation.
      if (op === '+') return null;
      // Short-circuit logical/nullish operators using whichever concrete
      // value (number or string) the left-hand side has.
      const lTruth = evalTruthiness(left);
      const lJsType = left.toks.length === 1 ? left.toks[0].jsType : null;
      const lNullish = lJsType === 'null' || lJsType === 'undefined';
      if (op === '&&') { if (lTruth === false) return left; if (lTruth === true) return right; }
      else if (op === '||') { if (lTruth === true) return left; if (lTruth === false) return right; }
      else if (op === '??') { if (lNullish) return right; if (!lNullish && lTruth !== null) return left; }
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
        if (typeof v === 'boolean') return chainBinding([makeSynthBool(v)]);
        return chainBinding([typeof v === 'number' ? makeSynthNum(v) : makeSynthStr(String(v))]);
      }
      const et = chainAsExprText(operand);
      if (et === null) return null;
      const text = op + et;
      return chainBinding([exprRef(text)]);
    };

    const chainAsNumber = (chain) => {
      if (chain.toks.length !== 1) return null;
      const t = chain.toks[0];
      // Quoted strings (`'1'`, `"2"`) are string values even when they look
      // numeric. Only bare number-literal tokens (type 'other' from the
      // tokenizer, or type 'str' with empty/missing quote from makeSynthNum
      // or arithmetic results) fold to numbers.
      if (t.type === 'str' && t.quote && t.quote !== '') return null;
      if (t.type !== 'str' && t.type !== 'other') return null;
      // Booleans coerce: true→1, false→0 (JS semantics).
      if (t.jsType === 'boolean') return t.text === 'true' ? 1 : 0;
      // null coerces to 0; undefined to NaN (not numeric).
      if (t.jsType === 'null') return 0;
      if (t.jsType === 'undefined') return null;
      const n = Number(t.text);
      if (Number.isNaN(n)) return null;
      if (String(n) !== t.text) return null;
      return n;
    };

    const chainAsExprText = (chain) => {
      if (!chain || !chain.toks || chain.toks.length !== 1) return null;
      const t = chain.toks[0];
      if (t.type === 'str') {
        // Quote literal strings; bare numbers flow as-is.
        const n = Number(t.text);
        if (!Number.isNaN(n) && String(n) === t.text) return t.text;
        return JSON.stringify(t.text);
      }
      if (t.type === 'other') return t.text;
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
        // Spread argument: `...expr` — resolve expr and splice array elements.
        const spreadTok = tks[i];
        if (spreadTok && spreadTok.type === 'other' && spreadTok.text.startsWith('...')) {
          const name = spreadTok.text.slice(3);
          const resolved = IDENT_RE.test(name) ? resolve(name) : null;
          if (resolved && resolved.kind === 'array') {
            for (const el of resolved.elems) bindings.push(el);
            i++;
            const sep = tks[i];
            if (sep && sep.type === 'sep' && sep.char === ',') { i++; continue; }
            break;
          }
          // Can't resolve spread — bail.
          return null;
        }
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
    // When false, assignments to outer-scope variables and bare function
    // calls are skipped. This separates scope resolution (declarations,
    // local bindings) from side-effect execution (mutations to outer vars).
    // The initial pass runs with sideEffects OFF. Explicit invocations
    // (instantiateFunctionBinding, loop simulation, forEach) turn it ON.
    let sideEffects = false;
    const walkRange = (startI, endI) => {
      const savedStop = stop;
      stop = endI;
      const signal = walkRangeImpl(startI, endI);
      stop = savedStop;
      return signal;
    };
    // walkRange with side effects enabled — used by function calls,
    // loop simulation, forEach, etc.
    const walkRangeWithEffects = (startI, endI) => {
      const saved = sideEffects;
      sideEffects = true;
      const signal = walkRange(startI, endI);
      sideEffects = saved;
      return signal;
    };
    const walkRangeImpl = (startI, endI) => {
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
            // (Static for-of/for-in unrolling is handled above by walking the
            // body multiple times with the loop var bound per element.)
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
        const enteringFunction = pendingFunctionBrace;
        const frame = { bindings: Object.create(null), isFunction: enteringFunction };
        if (enteringFunction && pendingFunctionParams) {
          for (const p of pendingFunctionParams) {
            frame.bindings[p.name] = chainBinding([exprRef(p.name)]);
          }
        }
        // When entering a function body via the walker (not via an explicit
        // call), disable side effects — this is scope resolution only.
        if (enteringFunction) {
          frame._savedSideEffects = sideEffects;
          sideEffects = false;
        }
        stack.push(frame);
        pendingFunctionBrace = false;
        pendingFunctionParams = null;
        continue;
      }
      if (t.type === 'close' && t.char === '}') {
        if (stack.length > 1) {
          const popped = stack.pop();
          // Restore side effects state when leaving a function scope
          // that was entered via the walker (not an explicit call).
          if (popped.isFunction && '_savedSideEffects' in popped) {
            sideEffects = popped._savedSideEffects;
          }
        }
        continue;
      }

      // Bare function call at statement level: `fn()`, `fn(args)`,
      // `obj.method()`. Invoke for side effects (e.g. modifying outer vars).
      if (sideEffects && t.type === 'other' && IDENT_RE.test(t.text)) {
        const callParen = tokens[i + 1];
        if (callParen && callParen.type === 'open' && callParen.char === '(') {
          const fn = resolve(t.text);
          if (fn && fn.kind === 'function') {
            const argRes = readCallArgBindings(i + 1, stop);
            if (argRes) {
              instantiateFunctionBinding(fn, argRes.bindings);
              i = argRes.next - 1;
              continue;
            }
          }
        }
      }
      // Bare method call: `obj.method()` at statement level.
      if (sideEffects && t.type === 'other' && PATH_RE.test(t.text)) {
        const callParen = tokens[i + 1];
        if (callParen && callParen.type === 'open' && callParen.char === '(') {
          const dot = t.text.lastIndexOf('.');
          const base = t.text.slice(0, dot);
          const method = t.text.slice(dot + 1);
          const baseBind = resolvePath(base);
          if (baseBind && baseBind.kind === 'object') {
            const fn = baseBind.props[method];
            if (fn && fn.kind === 'function') {
              const argRes = readCallArgBindings(i + 1, stop);
              if (argRes) {
                instantiateFunctionBinding(fn, argRes.bindings, baseBind, baseBind.classRef && baseBind.classRef.superClass || null);
                i = argRes.next - 1;
                continue;
              }
            }
          }
        }
      }

      // Destructuring assignment at statement level: `[a,b] = expr`.
      if (t.type === 'open' && t.char === '[') {
        const pat = readDestructurePattern(i, stop);
        if (pat) {
          const eqTok = tokens[pat.next];
          if (eqTok && eqTok.type === 'sep' && eqTok.char === '=') {
            const val = readValue(pat.next + 1, stop, TERMS_TOP);
            const srcBinding = val ? val.binding : null;
            applyPatternBindings(pat.pattern, srcBinding, (name, v) => assignName(name, v));
            i = val ? val.next - 1 : skipExpr(pat.next + 1, stop) - 1;
            continue;
          }
        }
      }

      if (t.type !== 'other') continue;

      // `do { ... } while (cond);` — treat identically to a while loop for
      // loop-marker purposes. The body is always a `{ ... }` block. We push
      // a loop frame, walk the body via the normal block handling, and set
      // bodyEnd past the `while(cond);` trailer so the loop-pop pops at the
      // right position.
      if (t.text === 'do') {
        const bodyOpen = tokens[i + 1];
        if (bodyOpen && bodyOpen.type === 'open' && bodyOpen.char === '{') {
          let d = 1, k = i + 2;
          while (k < stop && d > 0) {
            const tk = tokens[k];
            if (tk.type === 'open' && tk.char === '{') d++;
            else if (tk.type === 'close' && tk.char === '}') d--;
            k++;
          }
          // k is now past the `}`. Expect `while (cond) ;`.
          const whTok = tokens[k];
          if (whTok && whTok.type === 'other' && whTok.text === 'while') {
            const wp = tokens[k + 1];
            if (wp && wp.type === 'open' && wp.char === '(') {
              let dp = 1, j = k + 2;
              while (j < stop && dp > 0) {
                const tk = tokens[j];
                if (tk.type === 'open' && tk.char === '(') dp++;
                else if (tk.type === 'close' && tk.char === ')') dp--;
                j++;
              }
              // j past `)`. Skip optional `;`.
              if (tokens[j] && tokens[j].type === 'sep' && tokens[j].char === ';') j++;
              const headerFirst = tokens[k + 2];
              const headerLast = tokens[j - 2]; // before `)` and optional `;`
              const headerSrc = headerFirst ? headerFirst._src.slice(headerFirst.start, headerLast.end) : '/* do-while */';
              const id = nextLoopId++;
              loopInfo[id] = { kind: 'do', headerSrc };
              const loopFrame = { bindings: Object.create(null), isFunction: false };
              stack.push(loopFrame);
              loopStack.push({
                id, kind: 'do', headerSrc, bodyEnd: j, frame: loopFrame,
                modifiedVars: new Set(), unrollVar: null, unrollElems: null,
              });
              // Let the walker enter the `{` naturally on the next iteration.
              continue;
            }
          }
        }
      }

      if (t.text === 'for' || t.text === 'while') {
        // Check for a label: `label: for(...)` — the previous two tokens
        // would be `ident` `:` before the `for`/`while`.
        let loopLabel = '';
        if (i >= 2 && tokens[i - 1] && tokens[i - 1].type === 'other' && tokens[i - 1].text === ':' &&
            tokens[i - 2] && tokens[i - 2].type === 'other' && IDENT_RE.test(tokens[i - 2].text)) {
          loopLabel = tokens[i - 2].text;
        }
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
            // Detect for-of / for-in with a static iterable: header shape
            // `[var|let|const] NAME (of|in) EXPR`. When EXPR is a known
            // array/object binding, re-walk the body once per element with
            // NAME bound to that element — a full static unroll with no
            // loop markers in the output.
            let unrollVar = null;     // simple ident loop var
            let unrollPattern = null; // destructuring pattern
            let unrollElems = null;
            {
              let h = i + 2;
              if (tokens[h] && tokens[h].type === 'other' && (tokens[h].text === 'var' || tokens[h].text === 'let' || tokens[h].text === 'const')) h++;
              // Check for destructuring pattern: `[k, v] of ...` or `{a, b} of ...`
              const maybeDestructure = tokens[h] && tokens[h].type === 'open' && (tokens[h].char === '[' || tokens[h].char === '{');
              if (maybeDestructure) {
                const pat = readDestructurePattern(h, j);
                if (pat) {
                  const kwTok = tokens[pat.next];
                  if (kwTok && kwTok.type === 'other' && (kwTok.text === 'of' || kwTok.text === 'in')) {
                    const iterRes = readValue(pat.next + 1, j, null);
                    if (iterRes && iterRes.binding) {
                      const b = iterRes.binding;
                      if (kwTok.text === 'of' && b.kind === 'array') {
                        unrollPattern = pat.pattern;
                        unrollElems = b.elems.slice();
                      } else if (kwTok.text === 'in' && b.kind === 'object') {
                        unrollPattern = pat.pattern;
                        unrollElems = Object.keys(b.props).map((k) => chainBinding([makeSynthStr(k)]));
                      }
                    }
                  }
                }
              }
              // Simple identifier: `x of ...`
              if (!unrollPattern) {
                const nameTok = tokens[h];
                const kwTok = tokens[h + 1];
                if (nameTok && nameTok.type === 'other' && IDENT_RE.test(nameTok.text) &&
                    kwTok && kwTok.type === 'other' && (kwTok.text === 'of' || kwTok.text === 'in')) {
                  const iterRes = readValue(h + 2, j, null);
                  if (iterRes && iterRes.binding) {
                    const b = iterRes.binding;
                    if (kwTok.text === 'of' && b.kind === 'array') {
                      unrollVar = nameTok.text;
                      unrollElems = b.elems.slice();
                    } else if (kwTok.text === 'in' && b.kind === 'object') {
                      unrollVar = nameTok.text;
                      unrollElems = Object.keys(b.props).map((k) => chainBinding([makeSynthStr(k)]));
                    }
                  }
                }
              }
            }
            if ((unrollVar || unrollPattern) && unrollElems) {
              const bodyIsBlock = tokens[j + 1] && tokens[j + 1].type === 'open' && tokens[j + 1].char === '{';
              const bodyStart = bodyIsBlock ? j + 1 : j + 1;
              for (const elem of unrollElems) {
                if (elem === null) { i = bodyEnd - 1; break; }
                const iterFrame = { bindings: Object.create(null), isFunction: false };
                if (unrollVar) {
                  iterFrame.bindings[unrollVar] = elem;
                } else {
                  applyPatternBindings(unrollPattern, elem, (name, val) => {
                    iterFrame.bindings[name] = val;
                  });
                }
                stack.push(iterFrame);
                const sig = walkRangeWithEffects(bodyStart, bodyEnd);
                const idx = stack.indexOf(iterFrame);
                if (idx >= 0) stack.splice(idx, 1);
                // Handle signal with label awareness.
                if (sig === 'break' || (sig === 'break:' + loopLabel && loopLabel)) break;
                if (sig === 'continue' || (sig === 'continue:' + loopLabel && loopLabel)) continue;
                if (sig && (sig.startsWith('break:') || sig.startsWith('continue:'))) return sig;
              }
              i = bodyEnd - 1;
              continue;
            }
            // Bounded C-style for-loop or while-loop simulation.
            // Split the header at top-level `;` to get init/cond/update
            // ranges for `for`, or use the whole header as the condition
            // for `while`. Then simulate: evaluate cond → if concrete
            // true, walk body (+ update for `for`), repeat. Bail to
            // loop markers if the condition ever becomes opaque.
            {
              let simulated = false;
              if (t.text === 'for') {
                // Split header tokens[i+2..j) at top-level `;` separators.
                const semis = [];
                let sd = 0;
                for (let h = i + 2; h < j; h++) {
                  const tk = tokens[h];
                  if (tk.type === 'open') sd++;
                  else if (tk.type === 'close') sd--;
                  else if (sd === 0 && tk.type === 'sep' && tk.char === ';') semis.push(h);
                }
                if (semis.length === 2) {
                  const initStart = i + 2, initEnd = semis[0];
                  const condStart = semis[0] + 1, condEnd = semis[1];
                  const updateStart = semis[1] + 1, updateEnd = j;
                  // Pre-check: evaluate init to set up counter, then test if
                  // the condition is concrete. If not, skip simulation entirely
                  // (don't dirty scope state).
                  if (initEnd > initStart) walkRangeWithEffects(initStart, initEnd);
                  const bodyStart = (tokens[j + 1] && tokens[j + 1].type === 'open' && tokens[j + 1].char === '{') ? j + 1 : j + 1;
                  // First condition check — if opaque, bail before any body walk.
                  const firstCond = condEnd > condStart ? readValue(condStart, condEnd, null) : null;
                  const firstTruth = firstCond ? evalTruthiness(firstCond.binding) : null;
                  if (firstTruth !== null) {
                    // Condition is concrete — simulate.
                    simulated = true;
                    // Helper: interpret a signal in this loop's context.
                    const handleSig = (sig) => {
                      if (!sig) return 'ok';
                      if (sig === 'break') return 'break';
                      if (sig === 'continue') return 'continue';
                      // Labeled: match against this loop's label.
                      if (sig === 'break:' + loopLabel && loopLabel) return 'break';
                      if (sig === 'continue:' + loopLabel && loopLabel) return 'continue';
                      return sig; // propagate unmatched label
                    };
                    if (firstTruth === true) {
                      let brk = false;
                      let action = handleSig(walkRangeWithEffects(bodyStart, bodyEnd));
                      if (action === 'break') brk = true;
                      else if (action !== 'ok' && action !== 'continue') return action; // propagate
                      if (!brk) {
                        if (action !== 'continue' && updateEnd > updateStart) walkRangeWithEffects(updateStart, updateEnd);
                        if (action === 'continue' && updateEnd > updateStart) walkRangeWithEffects(updateStart, updateEnd);
                        while (!brk) {
                          if (condEnd <= condStart) break;
                          const condVal = readValue(condStart, condEnd, null);
                          const concrete = evalTruthiness(condVal ? condVal.binding : null);
                          if (concrete !== true) break;
                          action = handleSig(walkRangeWithEffects(bodyStart, bodyEnd));
                          if (action === 'break') { brk = true; break; }
                          if (action !== 'ok' && action !== 'continue') return action;
                          if (updateEnd > updateStart) walkRangeWithEffects(updateStart, updateEnd);
                        }
                      }
                    }
                    // else: firstTruth === false, zero iterations.
                  }
                  // If firstTruth === null (opaque), simulated stays false → fall to markers.
                }
              } else if (t.text === 'while') {
                const condStart = i + 2, condEnd = j;
                const bodyStart = (tokens[j + 1] && tokens[j + 1].type === 'open' && tokens[j + 1].char === '{') ? j + 1 : j + 1;
                const firstCond = readValue(condStart, condEnd, null);
                const firstTruth = firstCond ? evalTruthiness(firstCond.binding) : null;
                if (firstTruth !== null) {
                  simulated = true;
                  if (firstTruth === true) {
                    const handleSig2 = (sig) => {
                      if (!sig) return 'ok';
                      if (sig === 'break') return 'break';
                      if (sig === 'continue') return 'continue';
                      if (sig === 'break:' + loopLabel && loopLabel) return 'break';
                      if (sig === 'continue:' + loopLabel && loopLabel) return 'continue';
                      return sig;
                    };
                    let brk = false;
                    let action = handleSig2(walkRangeWithEffects(bodyStart, bodyEnd));
                    if (action === 'break') brk = true;
                    else if (action !== 'ok' && action !== 'continue') return action;
                    while (!brk) {
                      const condVal = readValue(condStart, condEnd, null);
                      const concrete = evalTruthiness(condVal ? condVal.binding : null);
                      if (concrete !== true) break;
                      action = handleSig2(walkRangeWithEffects(bodyStart, bodyEnd));
                      if (action === 'break') { brk = true; break; }
                      if (action !== 'ok' && action !== 'continue') return action;
                    }
                  }
                }
              }
              if (simulated) {
                i = bodyEnd - 1;
                continue;
              }
            }
            const id = nextLoopId++;
            loopInfo[id] = { kind: t.text, headerSrc };
            // Extract loop variables from the init clause (`var/let/const X`)
            // and push a shadow block scope for the loop body — the walker
            // processes the init clause with this frame on top, but `var`
            // bindings still hoist to the enclosing function scope. Loop
            // counters resolve through this frame to reference tokens so
            // per-iteration values surface as autoSubs placeholders. This
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
              unrollVar: null, unrollElems: null,
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
      // `switch (expr) { case ... }` — when the discriminant is a concrete
      // value, walk only the matching case's body. Otherwise walk the entire
      // switch body and let the variable-tracking accumulate normally.
      // `if (cond) { ... } else if (...) { ... } else { ... }` — when the
      // condition is a concrete truthy/falsy value, walk only the matching
      // branch. When opaque, walk all branches so every binding mutation
      // is visible (existing implicit behavior via block scope handling).
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
              // Single-statement body.
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
            const elseTok = tokens[ifEnd];
            if (elseTok && elseTok.type === 'other' && elseTok.text === 'else') {
              const afterElse = tokens[ifEnd + 1];
              if (afterElse && afterElse.type === 'other' && afterElse.text === 'if') {
                // `else if (...)` — the else body is the entire if-chain
                // from here; let it be walked naturally when we resume at
                // elseStart (which points at the `if` keyword).
                elseStart = ifEnd + 1;
                // Scan to find the end of the else-if chain.
                let k = ifEnd + 1;
                // We need to skip the if(...){...} [else ...] recursively.
                // Simplest: just set elseEnd = stop and let walkRange handle it.
                // Actually, for concrete=true we skip the else entirely, for
                // concrete=false we resume at `if` and let the walker process it.
                elseEnd = -1; // Will be determined by the inner `if` handling.
              } else if (afterElse && afterElse.type === 'open' && afterElse.char === '{') {
                elseStart = ifEnd + 1;
                let d = 1, k = ifEnd + 2;
                while (k < stop && d > 0) {
                  const tk = tokens[k];
                  if (tk.type === 'open' && tk.char === '{') d++;
                  else if (tk.type === 'close' && tk.char === '}') d--;
                  k++;
                }
                elseEnd = k;
              } else {
                // Single-statement else.
                elseStart = ifEnd + 1;
                let sd = 0, k = ifEnd + 1;
                while (k < stop) {
                  const tk = tokens[k];
                  if (tk.type === 'open') sd++;
                  else if (tk.type === 'close') sd--;
                  else if (sd === 0 && tk.type === 'sep' && tk.char === ';') { k++; break; }
                  k++;
                }
                elseEnd = k;
              }
            }

            if (concrete === true) {
              const sig = walkRange(j + 1, ifEnd);
              if (sig) return sig; // propagate break/continue
              i = (elseEnd > 0 ? elseEnd : ifEnd) - 1;
              continue;
            }
            if (concrete === false) {
              if (elseStart >= 0) {
                if (elseEnd < 0) {
                  i = elseStart - 1;
                  continue;
                }
                const sig = walkRange(elseStart, elseEnd);
                if (sig) return sig;
                i = elseEnd - 1;
              } else {
                i = ifEnd - 1;
              }
              continue;
            }
            // Unknown condition: walk both branches so all mutations are
            // visible. This is the default behavior — just let the walker
            // continue into the if-body naturally, and after the if-body
            // it'll hit `else` and process that too.
          }
        }
      }

      if (t.text === 'switch') {
        const lp = tokens[i + 1];
        if (lp && lp.type === 'open' && lp.char === '(') {
          let depth = 1, j = i + 2;
          while (j < stop && depth > 0) {
            const tk = tokens[j];
            if (tk.type === 'open' && tk.char === '(') depth++;
            else if (tk.type === 'close' && tk.char === ')') depth--;
            if (depth === 0) break;
            j++;
          }
          // j is at closing `)`.
          const exprVal = readValue(i + 2, j, null);
          const bodyOpen = tokens[j + 1];
          if (bodyOpen && bodyOpen.type === 'open' && bodyOpen.char === '{') {
            let d = 1, k = j + 2;
            while (k < stop && d > 0) {
              const tk = tokens[k];
              if (tk.type === 'open' && tk.char === '{') d++;
              else if (tk.type === 'close' && tk.char === '}') d--;
              k++;
            }
            const switchEnd = k;
            // Try concrete match: find the matching case and walk from there.
            const exprStr = exprVal ? chainAsKnownString(exprVal.binding) : null;
            const exprNum = exprVal ? chainAsNumber(exprVal.binding) : null;
            if (exprStr !== null || exprNum !== null) {
              // Scan for matching case/default.
              let matchStart = -1;
              let defaultStart = -1;
              let ci = j + 2;
              while (ci < switchEnd - 1) {
                const ctk = tokens[ci];
                if (ctk.type === 'other' && ctk.text === 'case') {
                  const cv = readValue(ci + 1, switchEnd, null);
                  if (cv) {
                    const cs = chainAsKnownString(cv.binding);
                    const cn = chainAsNumber(cv.binding);
                    if ((exprStr !== null && cs === exprStr) || (exprNum !== null && cn === exprNum)) {
                      // Skip past the `:` after the case expression.
                      let cj = cv.next;
                      if (tokens[cj] && tokens[cj].type === 'other' && tokens[cj].text === ':') cj++;
                      matchStart = cj;
                      break;
                    }
                  }
                } else if (ctk.type === 'other' && ctk.text === 'default') {
                  let cj = ci + 1;
                  if (tokens[cj] && tokens[cj].type === 'other' && tokens[cj].text === ':') cj++;
                  defaultStart = cj;
                }
                ci++;
              }
              const caseStart = matchStart >= 0 ? matchStart : defaultStart;
              if (caseStart >= 0) {
                { const sig = walkRange(caseStart, switchEnd - 1); if (sig) return sig; }
              }
            } else {
              // Unknown discriminant: walk entire switch body.
              { const sig = walkRange(j + 2, switchEnd - 1); if (sig) return sig; }
            }
            i = switchEnd - 1;
            continue;
          }
        }
      }

      // `try { ... } catch (e) { ... } finally { ... }` — walk each block
      // sequentially. For the catch block, bind the error parameter as opaque.
      if (t.text === 'try') {
        const openTry = tokens[i + 1];
        if (openTry && openTry.type === 'open' && openTry.char === '{') {
          let d = 1, k = i + 2;
          while (k < stop && d > 0) {
            const tk = tokens[k];
            if (tk.type === 'open' && tk.char === '{') d++;
            else if (tk.type === 'close' && tk.char === '}') d--;
            k++;
          }
          { const sig = walkRange(i + 1, k); if (sig) return sig; }
          let j = k;
          // catch block?
          if (tokens[j] && tokens[j].type === 'other' && tokens[j].text === 'catch') {
            j++;
            // Optional `(e)` param.
            if (tokens[j] && tokens[j].type === 'open' && tokens[j].char === '(') {
              let dp = 1; j++;
              while (j < stop && dp > 0) {
                const tk = tokens[j];
                if (tk.type === 'open' && tk.char === '(') dp++;
                else if (tk.type === 'close' && tk.char === ')') dp--;
                j++;
              }
            }
            if (tokens[j] && tokens[j].type === 'open' && tokens[j].char === '{') {
              let d2 = 1, k2 = j + 1;
              while (k2 < stop && d2 > 0) {
                const tk = tokens[k2];
                if (tk.type === 'open' && tk.char === '{') d2++;
                else if (tk.type === 'close' && tk.char === '}') d2--;
                k2++;
              }
              walkRange(j, k2);
              j = k2;
            }
          }
          // finally block?
          if (tokens[j] && tokens[j].type === 'other' && tokens[j].text === 'finally') {
            j++;
            if (tokens[j] && tokens[j].type === 'open' && tokens[j].char === '{') {
              let d3 = 1, k3 = j + 1;
              while (k3 < stop && d3 > 0) {
                const tk = tokens[k3];
                if (tk.type === 'open' && tk.char === '{') d3++;
                else if (tk.type === 'close' && tk.char === '}') d3--;
                k3++;
              }
              walkRange(j, k3);
              j = k3;
            }
          }
          i = j - 1;
          continue;
        }
      }

      // `with (expr) { body }` — skip the body entirely since `with`
      // makes scope resolution unpredictable.
      if (t.text === 'with') {
        const wp = tokens[i + 1];
        if (wp && wp.type === 'open' && wp.char === '(') {
          let dp = 1, j = i + 2;
          while (j < stop && dp > 0) {
            const tk = tokens[j];
            if (tk.type === 'open' && tk.char === '(') dp++;
            else if (tk.type === 'close' && tk.char === ')') dp--;
            j++;
          }
          const bodyTok = tokens[j];
          if (bodyTok && bodyTok.type === 'open' && bodyTok.char === '{') {
            let d = 1, k = j + 1;
            while (k < stop && d > 0) {
              const tk = tokens[k];
              if (tk.type === 'open' && tk.char === '{') d++;
              else if (tk.type === 'close' && tk.char === '}') d--;
              k++;
            }
            i = k - 1;
            continue;
          }
        }
      }
      // `debugger;` — skip.
      if (t.text === 'debugger') continue;

      // `break` / `continue` with optional label — return a signal so
      // the enclosing loop simulation can act on it.
      if (t.text === 'break' || t.text === 'continue') {
        const next = tokens[i + 1];
        const label = (next && next.type === 'other' && IDENT_RE.test(next.text) &&
                       next.text !== 'case' && next.text !== 'default') ? next.text : '';
        return label ? t.text + ':' + label : t.text;
      }

      // `class Name { constructor() {} method() {} }` — parse into a
      // classBinding with constructor and methods as functionBindings.
      if (t.text === 'class') {
        let j = i + 1;
        let className = null;
        // Optional name.
        if (tokens[j] && tokens[j].type === 'other' && IDENT_RE.test(tokens[j].text)) {
          className = tokens[j].text;
          j++;
        }
        // Optional `extends SuperClass`.
        let superClass = null;
        if (tokens[j] && tokens[j].type === 'other' && tokens[j].text === 'extends') {
          j++;
          if (tokens[j] && tokens[j].type === 'other' && IDENT_OR_PATH_RE.test(tokens[j].text)) {
            superClass = resolve(tokens[j].text) || null;
            j++;
          }
        }
        // Class body `{ ... }`.
        if (tokens[j] && tokens[j].type === 'open' && tokens[j].char === '{') {
          let d = 1, bodyEnd = j + 1;
          while (bodyEnd < stop && d > 0) {
            const tk = tokens[bodyEnd];
            if (tk.type === 'open' && tk.char === '{') d++;
            else if (tk.type === 'close' && tk.char === '}') d--;
            bodyEnd++;
          }
          // Parse methods inside the class body.
          let ctor = null;
          const methods = Object.create(null);
          let m = j + 1;
          while (m < bodyEnd - 1) {
            const tk = tokens[m];
            if (!tk) break;
            // Skip semicolons between members.
            if (tk.type === 'sep' && tk.char === ';') { m++; continue; }
            // Skip prefixes: static, async, get, set, *.
            let isStatic = false;
            if (tk.type === 'other' && tk.text === 'static') { isStatic = true; m++; }
            if (tokens[m] && tokens[m].type === 'other' && tokens[m].text === 'async') m++;
            if (tokens[m] && tokens[m].type === 'op' && tokens[m].text === '*') m++;
            if (tokens[m] && tokens[m].type === 'other' && (tokens[m].text === 'get' || tokens[m].text === 'set')) {
              // Only treat as prefix if followed by ident + `(`, not just ident.
              if (tokens[m + 1] && tokens[m + 1].type === 'other' && IDENT_RE.test(tokens[m + 1].text) &&
                  tokens[m + 2] && tokens[m + 2].type === 'open' && tokens[m + 2].char === '(') {
                m++; // skip get/set prefix
              }
            }
            // Method name.
            const nameTk = tokens[m];
            if (!nameTk || nameTk.type !== 'other' || !IDENT_RE.test(nameTk.text)) {
              // Skip to next `}` at depth 0 or `;`.
              let sd = 0;
              while (m < bodyEnd - 1) {
                const sk = tokens[m];
                if (sk.type === 'open') sd++;
                else if (sk.type === 'close') { if (sd === 0) break; sd--; }
                else if (sd === 0 && sk.type === 'sep' && sk.char === ';') break;
                m++;
              }
              if (tokens[m] && (tokens[m].type === 'close' || (tokens[m].type === 'sep' && tokens[m].char === ';'))) m++;
              continue;
            }
            const methodName = nameTk.text;
            m++;
            // Expect `(params) { body }`.
            if (tokens[m] && tokens[m].type === 'open' && tokens[m].char === '(') {
              const params = [];
              let p = m + 1;
              if (tokens[p] && tokens[p].type === 'close' && tokens[p].char === ')') { p++; }
              else {
                let ok = true;
                while (p < bodyEnd - 1) {
                  const pt = parseParamWithDefault(tokens, p, bodyEnd - 1);
                  if (!pt) { ok = false; break; }
                  params.push(pt.param);
                  p = pt.next;
                  const sep = tokens[p];
                  if (sep && sep.type === 'close' && sep.char === ')') { p++; break; }
                  if (sep && sep.type === 'sep' && sep.char === ',') { p++; continue; }
                  ok = false; break;
                }
                if (!ok) { m = p; continue; }
              }
              if (tokens[p] && tokens[p].type === 'open' && tokens[p].char === '{') {
                let md = 1, mEnd = p + 1;
                while (mEnd < bodyEnd && md > 0) {
                  const mk = tokens[mEnd];
                  if (mk.type === 'open' && mk.char === '{') md++;
                  else if (mk.type === 'close' && mk.char === '}') md--;
                  mEnd++;
                }
                const fn = functionBinding(params, p + 1, mEnd - 1, true);
                if (methodName === 'constructor' && !isStatic) ctor = fn;
                else if (!isStatic) methods[methodName] = fn;
                m = mEnd;
                continue;
              }
            }
            // Property assignment or unrecognised — skip to next member.
            let sd = 0;
            while (m < bodyEnd - 1) {
              const sk = tokens[m];
              if (sk.type === 'open') sd++;
              else if (sk.type === 'close') { if (sd === 0) break; sd--; }
              else if (sd === 0 && sk.type === 'sep' && sk.char === ';') break;
              m++;
            }
            if (tokens[m] && (tokens[m].type === 'close' || (tokens[m].type === 'sep' && tokens[m].char === ';'))) m++;
          }
          const cls = classBinding(className, ctor, methods, superClass);
          if (className) declFunction(className, cls);
          // Walk the class body so innerHTML assignments inside methods
          // are still detected (the walker processes method bodies via
          // the normal function-scope handling).
          walkRange(j, bodyEnd);
          i = bodyEnd - 1;
          continue;
        }
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
              declFunction(nameTok.text, functionBinding(params, j + 1, k - 1, true, stack.length > 1 ? captureScope() : null));
              // Let the `{` handler decide whether to walk or skip the body
              // based on whether it contains our target range.
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
        const next = tokens[i + 1];
        if (next && next.type === 'open' && next.char === '{') pendingFunctionBrace = true;
        continue;
      }

      // `super(args)` — invoke parent constructor with same `this`.
      // `super.method(args)` — call parent method with same `this`.
      if (t.text === 'super') {
        // Find the nearest constructor frame with thisBinding + superClass.
        let thisObj = null, superCls = null;
        for (let si = stack.length - 1; si >= 0; si--) {
          if (stack[si].isFunction && stack[si].thisBinding) {
            thisObj = stack[si].thisBinding;
            superCls = stack[si].superClass || null;
            break;
          }
        }
        const paren = tokens[i + 1];
        if (paren && paren.type === 'open' && paren.char === '(' && thisObj && superCls && superCls.kind === 'class' && superCls.ctor) {
          const argRes = readCallArgBindings(i + 1, stop);
          if (argRes) {
            stack.push({ bindings: Object.create(null), isFunction: true, thisBinding: thisObj, superClass: superCls.superClass || null });
            const frame = stack[stack.length - 1];
            for (let p = 0; p < superCls.ctor.params.length; p++) {
              frame.bindings[superCls.ctor.params[p].name] = argRes.bindings[p] || null;
            }
            walkRangeWithEffects(superCls.ctor.bodyStart, superCls.ctor.bodyEnd);
            stack.pop();
            i = argRes.next - 1;
            continue;
          }
        }
      }

      // Skip ES-module `import` statements entirely — their bindings are
      // opaque to us and the `from`/`{}` syntax would otherwise confuse the
      // walker. `export` is stripped: if it fronts a declaration we let the
      // walker see the underlying `const`/`let`/`var`/`function`, otherwise
      // skip to the statement terminator.
      // `delete obj.prop` — remove the property from a known object binding.
      if (t.text === 'delete') {
        const target = tokens[i + 1];
        if (target && target.type === 'other' && PATH_RE.test(target.text)) {
          const dot = target.text.lastIndexOf('.');
          const basePath = target.text.slice(0, dot);
          const prop = target.text.slice(dot + 1);
          const baseBind = resolvePath(basePath);
          if (baseBind && baseBind.kind === 'object' && prop in baseBind.props) {
            delete baseBind.props[prop];
          }
          i++;
          continue;
        }
      }

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

      // Bare assignment: IDENT = <value>, or compound `IDENT += <value>`
      // (which translates to `IDENT = IDENT + <value>`).
      if (IDENT_RE.test(t.text)) {
        const eqTok = tokens[i + 1];
        if (eqTok && eqTok.type === 'sep' && eqTok.char === '=') {
          const r = readValue(i + 2, stop, TERMS_TOP);
          assignName(t.text, r ? r.binding : null);
          i = skipExpr(i + 2, stop) - 1;
          continue;
        }
        if (eqTok && eqTok.type === 'sep' && eqTok.char === '+=') {
          const r = readValue(i + 2, stop, TERMS_TOP);
          const rhs = r ? r.binding : null;
          const cur = resolve(t.text);
          let combined = null;
          if (cur && cur.kind === 'chain' && rhs && rhs.kind === 'chain') {
            // Numeric fold: if both sides are numbers, add instead of concat.
            const ln = chainAsNumber(cur);
            const rn = chainAsNumber(rhs);
            if (ln !== null && rn !== null) {
              combined = chainBinding([makeSynthNum(ln + rn)]);
            } else {
              const loopId = loopStack.length > 0 ? loopStack[loopStack.length - 1].id : null;
              const tagged = loopId !== null ? tagWithLoop(rhs.toks, loopId) : rhs.toks;
              combined = chainBinding([...cur.toks, SYNTH_PLUS, ...tagged]);
            }
          }
          assignName(t.text, combined);
          if (loopStack.length > 0) loopStack[loopStack.length - 1].modifiedVars.add(t.text);
          i = skipExpr(i + 2, stop) - 1;
          continue;
        }
        // Logical/nullish compound assignment: `||=`, `&&=`, `??=`.
        if (eqTok && eqTok.type === 'sep' && (eqTok.char === '||=' || eqTok.char === '&&=' || eqTok.char === '??=')) {
          const r = readValue(i + 2, stop, TERMS_TOP);
          const rhs = r ? r.binding : null;
          const cur = resolve(t.text);
          if (eqTok.char === '||=') {
            const truth = evalTruthiness(cur);
            if (truth === false) assignName(t.text, rhs);
            else if (truth === null) assignName(t.text, null);
          } else if (eqTok.char === '&&=') {
            const truth = evalTruthiness(cur);
            if (truth === true) assignName(t.text, rhs);
          } else if (eqTok.char === '??=') {
            const jt = cur && cur.kind === 'chain' && cur.toks.length === 1 ? cur.toks[0].jsType : null;
            const nullish = jt === 'null' || jt === 'undefined' || !cur;
            if (nullish) assignName(t.text, rhs);
          }
          i = skipExpr(i + 2, stop) - 1;
          continue;
        }
        // Arithmetic compound assignments: `-=`, `*=`, `/=`, `%=`, `**=`.
        const ARITH_COMPOUND = new Set(['-=', '*=', '/=', '%=', '**=', '|=', '&=', '^=', '<<=', '>>=', '>>>=']);
        if (eqTok && eqTok.type === 'sep' && ARITH_COMPOUND.has(eqTok.char)) {
          const r = readValue(i + 2, stop, TERMS_TOP);
          const rhs = r ? r.binding : null;
          const cur = resolve(t.text);
          const ln = cur && cur.kind === 'chain' ? chainAsNumber(cur) : null;
          const rn = rhs && rhs.kind === 'chain' ? chainAsNumber(rhs) : null;
          if (ln !== null && rn !== null) {
            let v;
            switch (eqTok.char) {
              case '-=': v = ln - rn; break;
              case '*=': v = ln * rn; break;
              case '/=': v = ln / rn; break;
              case '%=': v = ln % rn; break;
              case '**=': v = ln ** rn; break;
              case '|=': v = ln | rn; break;
              case '&=': v = ln & rn; break;
              case '^=': v = ln ^ rn; break;
              case '<<=': v = ln << rn; break;
              case '>>=': v = ln >> rn; break;
              case '>>>=': v = ln >>> rn; break;
              default: v = null;
            }
            if (v !== null) assignName(t.text, chainBinding([makeSynthNum(v)]));
            else assignName(t.text, null);
          } else {
            assignName(t.text, null);
          }
          if (loopStack.length > 0) loopStack[loopStack.length - 1].modifiedVars.add(t.text);
          i = skipExpr(i + 2, stop) - 1;
          continue;
        }
        // Post-increment/decrement: IDENT++ or IDENT--.
        if (eqTok && eqTok.type === 'op' && (eqTok.text === '++' || eqTok.text === '--')) {
          const cur = resolve(t.text);
          const n = cur && cur.kind === 'chain' ? chainAsNumber(cur) : null;
          if (n !== null) {
            const delta = eqTok.text === '++' ? 1 : -1;
            assignName(t.text, chainBinding([makeSynthNum(n + delta)]));
          } else {
            assignName(t.text, null);
          }
          if (loopStack.length > 0) loopStack[loopStack.length - 1].modifiedVars.add(t.text);
          i = i + 1;
          continue;
        }
      }

      // All remaining handlers below perform mutations (path assignment,
      // path increment, method calls, delete). Skip when side effects off.
      if (!sideEffects) continue;

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
          // Object-path assignment: `obj.a = v`, `obj.a.b = v`. Walks into
          // the known object binding and installs the new value at the
          // terminal key. Bails if any intermediate step isn't an object.
          if (baseBind && baseBind.kind === 'object' && parts.length >= 2) {
            const r = readValue(i + 2, stop, TERMS_TOP);
            const val = r ? r.binding : null;
            let cur = baseBind;
            let ok = true;
            for (let p = 1; p < parts.length - 1; p++) {
              const nxt = cur.props[parts[p]];
              if (!nxt || nxt.kind !== 'object') { ok = false; break; }
              cur = nxt;
            }
            if (ok) {
              const termKey = parts[parts.length - 1];
              // Check for setter in accessors map.
              const accessor = cur.accessors && cur.accessors[termKey];
              if (accessor && accessor.set && accessor.set.kind === 'function') {
                stack.push({ bindings: Object.create(null), isFunction: true, thisBinding: cur });
                const setFrame = stack[stack.length - 1];
                if (accessor.set.params[0]) setFrame.bindings[accessor.set.params[0].name] = val;
                walkRange(accessor.set.bodyStart, accessor.set.bodyEnd);
                stack.pop();
              } else {
                cur.props[termKey] = val;
              }
            }
            i = skipExpr(i + 2, stop) - 1;
            continue;
          }
        }
        // Path increment/decrement: `obj.n++`, `this.count--`.
        if (eqTok && eqTok.type === 'op' && (eqTok.text === '++' || eqTok.text === '--')) {
          const parts = t.text.split('.');
          const baseBind = resolve(parts[0]);
          if (baseBind && baseBind.kind === 'object') {
            let cur = baseBind;
            let ok = true;
            for (let p = 1; p < parts.length - 1; p++) {
              const nxt = cur.props[parts[p]];
              if (!nxt || nxt.kind !== 'object') { ok = false; break; }
              cur = nxt;
            }
            if (ok) {
              const key = parts[parts.length - 1];
              const val = cur.props[key];
              const n = val && val.kind === 'chain' ? chainAsNumber(val) : null;
              if (n !== null) {
                const delta = eqTok.text === '++' ? 1 : -1;
                cur.props[key] = chainBinding([makeSynthNum(n + delta)]);
              }
              i++;
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
              const argResult = readCallArgBindings(i + 1, stop);
              if (argResult) {
                applyElementMethod(baseBind, method, argResult.bindings);
                i = argResult.next - 1;
                continue;
              }
            }
            // Array mutation methods on a known array binding.
            // `arr.push(v)`, `arr.pop()`, `arr.shift()`, `arr.unshift(v,...)`.
            if (baseBind && baseBind.kind === 'array' && (method === 'push' || method === 'pop' || method === 'shift' || method === 'unshift' || method === 'splice' || method === 'fill' || method === 'reverse' || method === 'sort')) {
              const argResult = readCallArgBindings(i + 1, stop);
              if (argResult) {
                if (method === 'push') {
                  for (const b of argResult.bindings) baseBind.elems.push(b);
                } else if (method === 'pop') {
                  baseBind.elems.pop();
                } else if (method === 'shift') {
                  baseBind.elems.shift();
                } else if (method === 'unshift') {
                  baseBind.elems.unshift(...argResult.bindings);
                } else if (method === 'splice') {
                  const startN = argResult.bindings[0] ? chainAsNumber(argResult.bindings[0]) : null;
                  const delN = argResult.bindings[1] ? chainAsNumber(argResult.bindings[1]) : null;
                  if (startN !== null) {
                    const start = startN < 0 ? Math.max(0, baseBind.elems.length + startN) : startN;
                    const del = delN !== null ? delN : baseBind.elems.length - start;
                    const items = argResult.bindings.slice(2);
                    baseBind.elems.splice(start, del, ...items);
                  }
                } else if (method === 'fill') {
                  const val = argResult.bindings[0] || null;
                  const startN = argResult.bindings[1] ? chainAsNumber(argResult.bindings[1]) : 0;
                  const endN = argResult.bindings[2] ? chainAsNumber(argResult.bindings[2]) : baseBind.elems.length;
                  for (let k = (startN || 0); k < (endN || baseBind.elems.length); k++) baseBind.elems[k] = val;
                } else if (method === 'reverse') {
                  baseBind.elems.reverse();
                } else if (method === 'sort') {
                  // No comparator support at statement level; just reverse-sort strings.
                  baseBind.elems.sort((a, b) => {
                    const sa = a && a.kind === 'chain' ? chainAsKnownString(a) : null;
                    const sb = b && b.kind === 'chain' ? chainAsKnownString(b) : null;
                    if (sa === null || sb === null) return 0;
                    return sa < sb ? -1 : sa > sb ? 1 : 0;
                  });
                }
                i = argResult.next - 1;
                continue;
              }
            }
            // forEach at statement level: walk callback body per element
            // for side effects (e.g. `arr.forEach(function(x) { html += x; })`).
            if (baseBind && baseBind.kind === 'array' && method === 'forEach') {
              const lp = tokens[i + 1];
              if (lp && lp.type === 'open' && lp.char === '(') {
                const cb = peekCallback(i + 2, stop);
                if (cb) {
                  const rp = tks[cb.next];
                  if (rp && rp.type === 'close' && rp.char === ')') {
                    for (let idx = 0; idx < baseBind.elems.length; idx++) {
                      const el = baseBind.elems[idx];
                      if (!el) continue;
                      const iterFrame = { bindings: Object.create(null), isFunction: false };
                      if (cb.fn.params[0]) iterFrame.bindings[cb.fn.params[0].name] = el;
                      if (cb.fn.params[1]) iterFrame.bindings[cb.fn.params[1].name] = chainBinding([makeSynthNum(idx)]);
                      if (cb.fn.params[2]) iterFrame.bindings[cb.fn.params[2].name] = baseBind;
                      stack.push(iterFrame);
                      if (cb.fn.isBlock) walkRangeWithEffects(cb.fn.bodyStart, cb.fn.bodyEnd);
                      stack.pop();
                    }
                    i = cb.next; // past `)`
                    continue;
                  }
                }
              }
            }
          }
        }
      }

      // Bracket-indexed assignment: `arr[i] = v`, `obj['key'] = v`.
      // Walks into the array/object binding and sets the slot when the
      // key is a concrete number/string.
      if (t.type === 'other' && IDENT_RE.test(t.text)) {
        const openTok = tokens[i + 1];
        if (openTok && openTok.type === 'open' && openTok.char === '[') {
          // Scan to matching `]`.
          let d = 1; let j = i + 2;
          while (j < stop && d > 0) {
            const tk = tokens[j];
            if (tk.type === 'open' && tk.char === '[') d++;
            else if (tk.type === 'close' && tk.char === ']') d--;
            if (d > 0) j++;
          }
          const eqTok = tokens[j + 1];
          if (j < stop && eqTok && eqTok.type === 'sep' && eqTok.char === '=') {
            const keyRes = readValue(i + 2, j, null);
            const valRes = readValue(j + 2, stop, TERMS_TOP);
            const baseBind = resolve(t.text);
            const keyN = keyRes ? chainAsNumber(keyRes.binding) : null;
            const keyS = keyRes && keyN === null ? chainAsKnownString(keyRes.binding) : null;
            if (baseBind && baseBind.kind === 'array' && keyN !== null && Number.isInteger(keyN) && keyN >= 0) {
              while (baseBind.elems.length <= keyN) baseBind.elems.push(null);
              baseBind.elems[keyN] = valRes ? valRes.binding : null;
              i = skipExpr(j + 2, stop) - 1;
              continue;
            }
            if (baseBind && baseBind.kind === 'object' && keyS !== null) {
              baseBind.props[keyS] = valRes ? valRes.binding : null;
              i = skipExpr(j + 2, stop) - 1;
              continue;
            }
          }
        }
      }
    }
    };
    walkRangeWithEffects(0, stop);

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
    return { resolve, resolvePath, parseRange, rewriteTemplate, loopInfo, loopVars, inScope, domElements, domOps };
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
    const externallyMutable = scanMutations(tokens);
    const state = buildScopeState(tokens, startIdx, externallyMutable);
    const full = state.parseRange(startIdx, endIdx);
    if (full) return { tokens: full, parsed: true, loopInfo: state.loopInfo, loopVars: state.loopVars, inScope: state.inScope };
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
    return { tokens: out, parsed: false, loopInfo: state.loopInfo, loopVars: state.loopVars, inScope: state.inScope };
  }

  // Materialize a flat concat chain (tokens alternating operand/plus) into
  // { html, autoSubs, loops }. Unlike materializeChain, doesn't require at
  // least one string operand — a lone opaque operand yields a placeholder.
  // Operands tagged with `loopId` emit `__HDLOOP#S__` / `__HDLOOP#E__`
  // boundary markers and populate the `loops` array.
  function materializeFlatChain(chainTokens, loopInfoMap) {
    const operands = [];
    let cur = [];
    for (const t of chainTokens) {
      if (t.type === 'plus') { if (cur.length) operands.push({ toks: cur }); cur = []; }
      else cur.push(t);
    }
    if (cur.length) operands.push({ toks: cur });
    const loopsSeen = Object.create(null);
    let html = '';
    const autoSubs = [];
    let idx = 0;
    let activeLoop = null;
    const closeActive = () => {
      if (activeLoop !== null) {
        html += '__HDLOOP' + activeLoop + 'E__';
        activeLoop = null;
      }
    };
    for (const op of operands) {
      const opLoop = op.toks[0].loopId != null ? op.toks[0].loopId : null;
      if (opLoop !== activeLoop) {
        closeActive();
        if (opLoop !== null) {
          html += '__HDLOOP' + opLoop + 'S__';
          activeLoop = opLoop;
          if (loopInfoMap && loopInfoMap[opLoop]) loopsSeen[opLoop] = loopInfoMap[opLoop];
        }
      }
      if (op.toks.length === 1 && (op.toks[0].type === 'str' || op.toks[0].type === 'tmpl')) {
        const m = materializeStringToken(op.toks[0], idx);
        html += m.html;
        for (const s of m.autoSubs) autoSubs.push(s);
        idx = m.nextIdx;
      } else {
        const first = op.toks[0];
        const last = op.toks[op.toks.length - 1];
        const expr = first._src.slice(first.start, last.end).trim();
        const ph = makePlaceholder(idx++);
        autoSubs.push([ph, expr]);
        html += ph;
      }
    }
    closeActive();
    const loops = Object.keys(loopsSeen).map((id) => ({
      id: Number(id), kind: loopsSeen[id].kind, headerSrc: loopsSeen[id].headerSrc,
    }));
    return loops.length ? { html, autoSubs, loops } : { html, autoSubs };
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
      if (c === ':') { push({ type: 'other', text: ':', start: i, end: i + 1 }); i++; continue; }
      if (c === '?') {
        // Multi-char tokens starting with '?': `??=` (nullish assign),
        // `??` (nullish coalescing), `?.` (optional chaining; ignore
        // `?.<digit>` which is a ternary followed by a decimal number).
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

  // Produce a JS string literal (or variable/template) for `s`.
  function jsStr(s, substitutions) {
    if (substitutions && substitutions.length) {
      for (const [needle, varName] of substitutions) {
        if (needle && s === needle) return { code: varName, isVar: true };
      }
      // Check if ANY needle appears in s.
      const needles = substitutions.filter(([n]) => n).map(([n, v]) => ({ n, v }));
      const present = needles.filter((x) => s.includes(x.n));
      if (present.length) {
        // Sort by length descending so longer needles win over substring
        // overlap in the regex alternation.
        present.sort((a, b) => b.n.length - a.n.length);
        const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp(present.map((x) => esc(x.n)).join('|'), 'g');
        const encode = (t) => t.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
        let out = '';
        let last = 0;
        let match;
        while ((match = re.exec(s)) !== null) {
          out += encode(s.slice(last, match.index));
          const hit = present.find((x) => x.n === match[0]);
          out += '${' + hit.v + '}';
          last = match.index + match[0].length;
        }
        out += encode(s.slice(last));
        return { code: '`' + out + '`', isVar: true };
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
    // Split on ; that are not inside parens or quoted strings.
    let depth = 0, cur = '', inQ = '';
    for (let i = 0; i < val.length; i++) {
      const c = val[i];
      if (inQ) {
        cur += c;
        if (c === '\\' && i + 1 < val.length) { cur += val[++i]; continue; }
        if (c === inQ) inQ = '';
        continue;
      }
      if (c === '"' || c === "'") { inQ = c; cur += c; continue; }
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

      // Style attribute -> always use style.setProperty to prevent CSS injection.
      // Never use setAttribute('style', ...) which could inject via crafted values.
      if (name === 'style') {
        const decls = parseStyle(val);
        for (const d of decls) {
          const p = jsStr(d.prop).code;
          const vv = jsStr(d.value, opts.subs).code;
          if (d.priority) {
            lines.push(v + '.style.setProperty(' + p + ', ' + vv + ", 'important');");
          } else {
            lines.push(v + '.style.setProperty(' + p + ', ' + vv + ');');
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

  // Split an HTML string containing `__HDLOOP#S__` / `__HDLOOP#E__` markers
  // into segments: `{ kind: 'static'|'loop', html, id? }`. Only top-level
  // (non-nested) loop markers create segment boundaries — nested loops stay
  // as markers inside the segment html.
  function splitLoopSegments(html) {
    const segments = [];
    const re = /__HDLOOP(\d+)([SE])__/g;
    let depth = 0;
    let segStart = 0;
    let loopId = null;
    let loopInnerStart = 0;
    let match;
    while ((match = re.exec(html)) !== null) {
      const id = Number(match[1]);
      const isStart = match[2] === 'S';
      if (isStart) {
        if (depth === 0) {
          if (match.index > segStart) {
            segments.push({ kind: 'static', html: html.slice(segStart, match.index) });
          }
          loopId = id;
          loopInnerStart = re.lastIndex;
        }
        depth++;
      } else {
        depth--;
        if (depth === 0) {
          segments.push({ kind: 'loop', id: loopId, html: html.slice(loopInnerStart, match.index) });
          segStart = re.lastIndex;
        }
      }
    }
    if (segStart < html.length) segments.push({ kind: 'static', html: html.slice(segStart) });
    return segments;
  }

  function convert() {
    try {
      const raw = $('inCode') ? $('inCode').textContent : ($('in') ? $('in').value : '');

      // If input is HTML (starts with <), split into HTML portions and
      // <script> blocks. Convert HTML to DOM API, process script blocks
      // for innerHTML replacements.
      if (/^\s*</.test(raw)) {
        const scriptRe = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
        let lastIdx = 0;
        const parts = [];
        let m;
        while ((m = scriptRe.exec(raw)) !== null) {
          // HTML before this script tag.
          if (m.index > lastIdx) {
            parts.push({ kind: 'html', text: raw.slice(lastIdx, m.index) });
          }
          parts.push({ kind: 'script', text: m[1], fullMatch: m[0], tagStart: m.index, tagEnd: m.index + m[0].length });
          lastIdx = scriptRe.lastIndex;
        }
        // Trailing HTML after last script.
        if (lastIdx < raw.length) {
          parts.push({ kind: 'html', text: raw.slice(lastIdx) });
        }
        // If no script tags found, treat entire input as HTML.
        if (parts.length === 0) parts.push({ kind: 'html', text: raw });

        const outputParts = [];
        for (const part of parts) {
          if (part.kind === 'html') {
            const htmlTrimmed = part.text.trim();
            if (!htmlTrimmed) continue;
            const result = extractHTML(htmlTrimmed);
            const block = convertOne(htmlTrimmed, result, false, false);
            if (block) outputParts.push(block);
          } else {
            // Process script content for innerHTML replacements.
            const jsCode = part.text;
            const extractions = extractAllHTML(jsCode);
            if (extractions.length === 0) {
              // No innerHTML in this script — keep as-is.
              outputParts.push(jsCode);
            } else {
              // Inline replacement within the script.
              const trimmed = jsCode;
              let scriptOutput = '';
              let cursor = 0;
              for (const ex of extractions) {
                if (ex.srcStart === undefined) continue;
                const domBlock = convertOne(jsCode, ex, false, false);
                let srcStart = ex.srcStart;
                let srcEnd = ex.srcEnd;
                if (ex._assign && ex._tokens) {
                  const region = findBuildRegion(ex._tokens, ex._assign, domBlock || '');
                  if (region) {
                    srcStart = region.regionStart;
                    srcEnd = region.regionEnd;
                  }
                }
                scriptOutput += trimmed.slice(cursor, srcStart);
                if (domBlock) {
                  let lineStart = srcStart;
                  while (lineStart > 0 && trimmed[lineStart - 1] !== '\n') lineStart--;
                  const indent = trimmed.slice(lineStart, srcStart).match(/^(\s*)/)[1];
                  const indented = domBlock.split('\n').map((line, i) => i === 0 ? line : indent + line).join('\n');
                  scriptOutput += indented;
                }
                cursor = srcEnd;
                // Skip trailing semicolons/whitespace to avoid doubled `;`.
                while (cursor < trimmed.length && (trimmed[cursor] === ';' || trimmed[cursor] === ' ')) cursor++;
              }
              scriptOutput += trimmed.slice(cursor);
              outputParts.push(scriptOutput);
            }
          }
        }
        setOutput(outputParts.join('\n'));
        return;
      }

      const extractions = extractAllHTML(raw);
      if (extractions.length === 0) {
        const summary = summarizeDomConstruction(raw);
        if (summary) { setOutput(summary); return; }
        setOutput(convertOne(raw, extractHTML(raw), false, false) || '');
        return;
      }
      // Build the full rewritten script: original code with innerHTML
      // assignments replaced inline by safe DOM API equivalents.
      const trimmed = raw.trim();
      let output = '';
      let cursor = 0;
      for (const ex of extractions) {
        if (ex.srcStart === undefined) continue;
        // Generate the DOM replacement block first.
        const domBlock = convertOne(raw, ex, false, false);
        // Now compute the build region, passing the replacement output
        // so variables it references aren't removed as dead code.
        let srcStart = ex.srcStart;
        let srcEnd = ex.srcEnd;
        if (ex._assign && ex._tokens) {
          const region = findBuildRegion(ex._tokens, ex._assign, domBlock || '');
          if (region) {
            srcStart = region.regionStart;
            srcEnd = region.regionEnd;
          }
        }
        // Copy original source up to this site.
        output += trimmed.slice(cursor, srcStart);
        if (domBlock) {
          let lineStart = srcStart;
          while (lineStart > 0 && trimmed[lineStart - 1] !== '\n') lineStart--;
          const indent = trimmed.slice(lineStart, srcStart).match(/^(\s*)/)[1];
          // Indent the replacement block to match.
          const indented = domBlock.split('\n').map((line, i) => i === 0 ? line : indent + line).join('\n');
          output += indented;
        }
        cursor = srcEnd;
        while (cursor < trimmed.length && (trimmed[cursor] === ';' || trimmed[cursor] === ' ')) cursor++;
      }
      // Append remaining original source after the last innerHTML site.
      output += trimmed.slice(cursor);
      setOutput(output);
    } catch (err) {
      setOutput('// Error: ' + err.message);
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

  // Produce the DOM-API code block for a single innerHTML/outerHTML
  // extraction. `multi` toggles the leading target-divider comment.
  function convertOne(raw, result, multi, emitTitle) {
    const { html, autoSubs, target, assignProp, assignOp } = result;
    const loops = result.loops || [];
    const subs = [];
    // Auto subs extracted from JS concatenation / template interpolation.
    for (const s of autoSubs) subs.push(s);

    let parent = 'document.body';
    let parentFromAssignment = false;
    if (target) {
      // `el.outerHTML = ...` replaces `el` itself, so new nodes land in
      // `el.parentNode`. `el.innerHTML = ...` replaces `el`'s children.
      parent = assignProp === 'outerHTML' ? target + '.parentNode' : target;
      parentFromAssignment = true;
    }

    const opts = {
      useProps: true,
      eventsAsListeners: true,
      textContentShortcut: true,
      useClassList: true,
      skipWhitespaceText: $('skipWS').checked,
      useFragment: $('useFragment').checked,
      emitComments: $('emitComments').checked,
      subs
    };

    // Table-context elements (<tr>, <td>, <th>, <thead>, etc.) are invalid
    // outside a <table> and get stripped by DOMParser. Wrap them so they parse
    // correctly, then extract the inner nodes.
    let tableWrap = null;
    const trimmed = html.trimStart();
    if (/^<(tr|td|th|thead|tbody|tfoot|caption|colgroup|col)\b/i.test(trimmed)) {
      tableWrap = 'table';
    } else if (/^<(li)\b/i.test(trimmed)) {
      tableWrap = 'ul';
    } else if (/^<(dt|dd)\b/i.test(trimmed)) {
      tableWrap = 'dl';
    } else if (/^<(option|optgroup)\b/i.test(trimmed)) {
      tableWrap = 'select';
    }
    const parseHtml = tableWrap ? '<' + tableWrap + '>' + html + '</' + tableWrap + '>' : html;
    const doc = new DOMParser().parseFromString(parseHtml, 'text/html');
    const roots = [];
    if (tableWrap) {
      // Extract from the wrapper element.
      const wrapper = doc.body ? doc.body.querySelector(tableWrap) : null;
      if (wrapper) for (const n of wrapper.childNodes) roots.push(n);
    } else if (doc.head) {
      for (const n of doc.head.childNodes) roots.push(n);
    }
    if (!tableWrap && doc.body) {
      for (const n of doc.body.childNodes) roots.push(n);
    } else if (!tableWrap && doc.documentElement) {
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

    if (opts.emitComments && autoSubs.length) {
      lines.push('// Auto-detected JS expressions from input:');
      for (const [ph, expr] of autoSubs) lines.push('//   ' + ph + ' -> ' + expr);
    }

    if (useRoots.length === 0) {
      return '// (no nodes parsed)';
    }

    // Replicate `el.innerHTML = x` semantics (replace existing children) when
    // the input used `=` rather than `+=`, for innerHTML only. outerHTML is
    // emitted as a note since faithful replacement requires replaceWith().
    if (parentFromAssignment && assignOp === '=' && assignProp === 'innerHTML') {
      lines.push(target + '.replaceChildren();');
    } else if (parentFromAssignment && assignProp === 'outerHTML') {
      if (opts.emitComments) {
        lines.push('// Note: ' + target + '.outerHTML = ... replaces ' + target + ' itself;');
        lines.push('//       call ' + target + '.replaceWith(...) or adjust as needed.');
      }
    }

    let attachTarget = parent;
    let fragVar = null;
    if (opts.useFragment && useRoots.length > 1) {
      fragVar = makeVar('frag', used);
      lines.push('const ' + fragVar + ' = document.createDocumentFragment();');
      attachTarget = fragVar;
    }

    // If the extracted html contains loop markers, emit each segment with
    // a matching for-loop wrapper so the generated DOM code mirrors the
    // source's iteration structure.
    const segments = loops.length ? splitLoopSegments(html) : null;
    if (segments && segments.length) {
      for (const seg of segments) {
        const segTrimmed = seg.html.trimStart();
        let segWrap = null;
        if (/^<(tr|td|th|thead|tbody|tfoot|caption|colgroup|col)\b/i.test(segTrimmed)) segWrap = 'table';
        else if (/^<(li)\b/i.test(segTrimmed)) segWrap = 'ul';
        else if (/^<(dt|dd)\b/i.test(segTrimmed)) segWrap = 'dl';
        else if (/^<(option|optgroup)\b/i.test(segTrimmed)) segWrap = 'select';
        const segParseHtml = segWrap ? '<' + segWrap + '>' + seg.html + '</' + segWrap + '>' : seg.html;
        const segDoc = new DOMParser().parseFromString(segParseHtml, 'text/html');
        const segNodes = [];
        if (segWrap) {
          const w = segDoc.body ? segDoc.body.querySelector(segWrap) : null;
          if (w) for (const n of w.childNodes) segNodes.push(n);
        } else if (segDoc.body) {
          for (const n of segDoc.body.childNodes) segNodes.push(n);
        }
        const segRoots = opts.skipWhitespaceText
          ? segNodes.filter((n) => !(n.nodeType === 3 && /^\s*$/.test(n.nodeValue)))
          : segNodes;
        if (seg.kind === 'loop') {
          const info = loops.find((l) => l.id === seg.id) || { kind: 'for', headerSrc: '/* loop */' };
          const header = info.kind === 'while'
            ? 'while (' + info.headerSrc + ')'
            : 'for (' + info.headerSrc + ')';
          lines.push(header + ' {');
          const loopUsed = new Set(used);
          const loopLines = [];
          for (const n of segRoots) convertNode(n, attachTarget, loopLines, loopUsed, opts, null);
          for (const l of loopLines) lines.push('  ' + l);
          lines.push('}');
        } else {
          for (const n of segRoots) convertNode(n, attachTarget, lines, used, opts, null);
        }
      }
    } else {
      for (const n of useRoots) {
        convertNode(n, attachTarget, lines, used, opts, null);
      }
    }

    if (fragVar) {
      lines.push(parent + '.appendChild(' + fragVar + ');');
    }

    let block = lines.join('\n');
    if (emitTitle) {
      block = '// === ' + target + '.' + assignProp + ' ' + assignOp + ' ... ===\n' + block;
    }
    return block;
  }

  function setOutput(text) {
    $('out').value = text;
    const codeEl = $('outCode');
    if (codeEl) {
      codeEl.textContent = text;
      if (typeof Prism !== 'undefined') Prism.highlightElement(codeEl);
    }
  }

  $('copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('out').value);
      $('copy').textContent = 'Copied!';
      setTimeout(() => { $('copy').textContent = 'Copy output'; }, 1200);
    } catch (e) {
      $('out').select();
    }
  });

  // Save and restore cursor position in contenteditable.
  function saveCursor(el) {
    const sel = window.getSelection();
    if (!sel.rangeCount) return null;
    const range = sel.getRangeAt(0);
    const pre = range.cloneRange();
    pre.selectNodeContents(el);
    pre.setEnd(range.startContainer, range.startOffset);
    return pre.toString().length;
  }
  function restoreCursor(el, pos) {
    if (pos === null) return;
    const sel = window.getSelection();
    const range = document.createRange();
    let current = 0;
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      const len = node.textContent.length;
      if (current + len >= pos) {
        range.setStart(node, pos - current);
        range.collapse(true);
        sel.removeAllRanges();
        sel.addRange(range);
        return;
      }
      current += len;
    }
  }

  function highlightInput() {
    const codeEl = $('inCode');
    if (!codeEl || typeof Prism === 'undefined') return;
    const pre = $('inPre');
    const pos = saveCursor(pre);
    const text = codeEl.textContent;
    const isMarkup = /^\s*</.test(text);
    codeEl.className = isMarkup ? 'language-markup' : 'language-javascript';
    Prism.highlightElement(codeEl);
    restoreCursor(pre, pos);
  }

  // Live update on input changes.
  const inputEl = $('inPre') || $('in');
  let highlightTimer = null;
  inputEl.addEventListener('input', () => {
    convert();
    // Debounce highlighting to avoid cursor jank on fast typing.
    clearTimeout(highlightTimer);
    highlightTimer = setTimeout(highlightInput, 300);
  });
  // Paste as plain text to avoid HTML formatting.
  if ($('inPre')) {
    $('inPre').addEventListener('paste', (e) => {
      e.preventDefault();
      const text = e.clipboardData.getData('text/plain');
      document.execCommand('insertText', false, text);
    });
  }
  const toggles = ['skipWS', 'useFragment', 'emitComments'];
  for (const id of toggles) $(id).addEventListener('change', convert);

  highlightInput();
  convert();
})();
