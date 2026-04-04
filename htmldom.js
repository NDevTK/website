// HTML to DOM API Converter
(function () {
  'use strict';

  // Properties that reflect as IDL properties on common elements.
  // Keep conservative; fall back to setAttribute otherwise.
  const IDL_PROPS = new Set([
    'id', 'className', 'title', 'lang', 'dir', 'hidden', 'tabIndex',
    'src', 'href', 'alt', 'name', 'type', 'value', 'placeholder',
    'width', 'height', 'rel', 'target', 'download',
    'loading', 'referrerPolicy', 'crossOrigin', 'integrity',
    'allow', 'allowFullscreen', 'srcdoc', 'srcset', 'sizes',
    'disabled', 'checked', 'readOnly', 'required', 'multiple', 'selected',
    'min', 'max', 'step', 'pattern', 'autocomplete', 'autofocus',
    'cols', 'rows', 'wrap', 'maxLength', 'minLength',
    'action', 'method', 'enctype', 'noValidate',
    'content', 'httpEquiv', 'charset',
    'media', 'as', 'rel'
  ]);

  // attribute name -> IDL property name
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
    'enctype': 'enctype',
    'formaction': 'formAction',
    'formenctype': 'formEnctype',
    'formmethod': 'formMethod',
    'formnovalidate': 'formNoValidate',
    'formtarget': 'formTarget'
  };

  // Attributes with no IDL reflection (or safer via setAttribute).
  // These are boolean-ish HTML attributes from older HTML where the
  // attribute name includes a hyphen or is not a standard IDL property.
  const FORCE_ATTR = new Set([
    'credentialless', 'sandbox', 'frameborder', 'marginwidth', 'marginheight',
    'scrolling', 'allowpaymentrequest', 'allowtransparency',
    'aria-label', 'aria-hidden', 'aria-describedby', 'aria-labelledby',
    'role', 'is', 'slot', 'part', 'exportparts',
    'contenteditable', 'spellcheck', 'translate', 'inputmode',
    'enterkeyhint', 'itemscope', 'itemtype', 'itemprop', 'itemid', 'itemref'
  ]);

  function $(id) { return document.getElementById(id); }

  // Extract HTML from input. If it looks like JS (contains innerHTML=, etc.),
  // try to extract the string literal(s). Otherwise treat as raw HTML.
  function extractHTML(input) {
    const trimmed = input.trim();
    // If first non-space char is '<' assume raw HTML.
    if (trimmed.startsWith('<')) return trimmed;

    // Try to find a string literal in the JS input.
    // Match single, double, or backtick quoted strings.
    const re = /(['"`])((?:\\.|(?!\1).)*)\1/g;
    const parts = [];
    let m;
    while ((m = re.exec(trimmed)) !== null) {
      // Decode escape sequences commonly found in JS strings.
      let s = m[2]
        .replace(/\\n/g, '\n')
        .replace(/\\r/g, '\r')
        .replace(/\\t/g, '\t')
        .replace(/\\'/g, "'")
        .replace(/\\"/g, '"')
        .replace(/\\`/g, '`')
        .replace(/\\\\/g, '\\');
      parts.push(s);
    }
    if (parts.length === 0) return trimmed;
    // Join all extracted strings — handles concatenated literals.
    return parts.join('');
  }

  // Escape a string as a JS single-quoted string literal.
  function jsStr(s, substitutions) {
    if (substitutions) {
      for (const [needle, varName] of substitutions) {
        if (needle && s === needle) {
          return { code: varName, isVar: true };
        }
      }
      // Also try substring replace -> template literal.
      for (const [needle, varName] of substitutions) {
        if (needle && s.includes(needle)) {
          const parts = s.split(needle);
          const pieces = [];
          for (let i = 0; i < parts.length; i++) {
            if (i > 0) pieces.push('${' + varName + '}');
            pieces.push(parts[i].replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${'));
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
      .replace(/\t/g, '\\t');
    return { code: "'" + esc + "'", isVar: false };
  }

  // Make a safe JS identifier from a tag name.
  function varName(tag, used) {
    let base = tag.toLowerCase().replace(/[^a-z0-9]/g, '') || 'el';
    if (/^[0-9]/.test(base)) base = 'el' + base;
    let name = base;
    let n = 1;
    while (used.has(name)) {
      n++;
      name = base + n;
    }
    used.add(name);
    return name;
  }

  function isIdlProp(attrName, useProps) {
    if (!useProps) return null;
    if (FORCE_ATTR.has(attrName)) return null;
    if (ATTR_TO_PROP[attrName]) return ATTR_TO_PROP[attrName];
    if (IDL_PROPS.has(attrName)) return attrName;
    // Event handlers
    if (/^on[a-z]+$/.test(attrName)) return null; // prefer addEventListener; leave to setAttribute
    // data-* / aria-* -> setAttribute
    if (attrName.startsWith('data-') || attrName.startsWith('aria-')) return null;
    return null;
  }

  function convertNode(node, parentVar, lines, used, opts) {
    if (node.nodeType === 3) {
      // text node
      const text = node.nodeValue;
      if (text === '') return;
      const v = varName('text', used);
      const lit = jsStr(text, opts.subs);
      lines.push('const ' + v + ' = document.createTextNode(' + lit.code + ');');
      lines.push(parentVar + '.appendChild(' + v + ');');
      return;
    }
    if (node.nodeType === 8) {
      const v = varName('comment', used);
      const lit = jsStr(node.nodeValue, opts.subs);
      lines.push('const ' + v + ' = document.createComment(' + lit.code + ');');
      lines.push(parentVar + '.appendChild(' + v + ');');
      return;
    }
    if (node.nodeType !== 1) return;

    const tag = node.tagName.toLowerCase();
    const v = varName(tag, used);
    lines.push('const ' + v + " = document.createElement('" + tag + "');");

    for (const attr of node.attributes) {
      const name = attr.name;
      const val = attr.value;
      const idl = isIdlProp(name, opts.useProps);
      const lit = jsStr(val, opts.subs);
      if (idl) {
        // Boolean attributes: empty value is common; use true if attribute present and value is "" for known booleans.
        lines.push(v + '.' + idl + ' = ' + lit.code + ';');
      } else {
        // valid attribute name? use setAttribute with string.
        lines.push(v + ".setAttribute('" + name.replace(/'/g, "\\'") + "', " + lit.code + ');');
      }
    }

    // Children
    for (const child of node.childNodes) {
      convertNode(child, v, lines, used, opts);
    }

    lines.push(parentVar + '.appendChild(' + v + ');');
  }

  function convert() {
    const raw = $('in').value;
    const html = extractHTML(raw);
    const useProps = $('useProps').checked;
    const subStr = $('subStr').value;
    const subVar = $('subVar').value.trim();
    const subs = [];
    if (subStr && subVar) subs.push([subStr, subVar]);

    let parent = 'document.body';
    if ($('parentVar').checked) {
      const p = $('parentName').value.trim();
      if (p) parent = p;
    }

    const doc = new DOMParser().parseFromString(html, 'text/html');
    // Gather nodes in body, plus anything the parser put in head (e.g. <meta>, <title>).
    const roots = [];
    for (const n of doc.head.childNodes) roots.push(n);
    for (const n of doc.body.childNodes) roots.push(n);

    const lines = [];
    const used = new Set();
    const opts = { useProps, subs };

    if (subs.length && subStr) {
      // Emit a hint comment.
      lines.push('// Assumes: const ' + subVar + ' = ' + JSON.stringify(subStr) + ';');
    }

    for (const n of roots) {
      convertNode(n, parent, lines, used, opts);
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

  // Run once on load with the default example.
  convert();
})();
