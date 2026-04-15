// dom-convert.js — DOM-conversion consumer (Wave 12 / Phase E, D1 + D11)
//
// Converts unsafe HTML + JS inputs into safer equivalents:
//
//   HTML-side (this file):
//     * inline event handlers (onclick, onload, …) → external
//       `<page>.handlers.js` with addEventListener calls,
//       referenced by a `data-handler="N"` attribute on the
//       element.
//     * inline `style="…"` attributes → `el.style.setProperty`
//       calls in the same handlers file, again keyed by
//       `data-handler="N"`.
//     * `href="javascript:…"` → `addEventListener('click', …)`
//       in the handlers file, with preventDefault().
//     * inline `<script>…</script>` blocks → external
//       `<page>.js` / `<page>.N.js` files, referenced by
//       `<script src="…">`.
//     * inline `<style>…</style>` blocks → external
//       `<page>.css` / `<page>.N.css` files, referenced by
//       `<link rel="stylesheet" href="…">`.
//
//   JS-side (next commit):
//     * `el.innerHTML = concrete string` → `createElement` /
//       `appendChild` tree (parsed via the vendored HTML
//       parser and re-emitted as imperative DOM calls).
//     * tainted navigation (`location.href = user`,
//       `frame.src = user`) → wrapped in a `__safeNav`
//       protocol filter.
//     * `eval(dynamicArg)` → `/* [blocked: eval with dynamic
//       argument] */ void 0`.
//     * `document.write(literal)` →
//       `document.body.appendChild(document.createTextNode(literal))`.
//
// Public API:
//
//   const dc = require('jsanalyze/consumers/dom-convert');
//   const out = await dc.convertProject(files, options?);
//     // files: { 'page.html': '<html>…', 'app.js': '…' }
//     // returns: { 'page.html': '…rewritten…',
//     //            'page.handlers.js': '…',
//     //            'page.js': '…',
//     //            'page.css': '…' }
//     // Only files that actually changed appear in the output.
//
//   const out = dc.convertHtmlMarkup(html, pagePath, reserved?);
//     // pure HTML-side conversion. Returns { html, handlers,
//     //   extractedScripts, extractedStyles }.
//
// Design notes
// ------------
//
//   * Zero coupling to engine internals. The consumer uses the
//     vendored HTML parser (src/html.js) directly and, for the
//     JS-side step (next commit), the public Trace from
//     `analyze()`. No walker or transfer-function access.
//
//   * Source-preserving. HTML rewrites mutate the flat token
//     stream in place and re-emit via `html.serializeTokens`,
//     so unchanged regions keep their original byte sequence.
//     Only the attributes / tag names / nested content we
//     explicitly rewrite change.
//
//   * Idempotent. Running the converter twice on the same
//     input produces the same output (modulo collisions
//     between existing handler files and newly generated ones,
//     which are avoided by using page-scoped file names).

'use strict';

const html = require('../src/html.js');
const HtmlTemplates = require('../src/html-templates.js');

// Per D11.1 the consumer does NOT parse JS source itself.
// Every piece of structured knowledge about JS accumulator
// patterns comes from the engine's html-templates.js pass
// and lands on the trace's innerHtmlAssignment.template
// field. This consumer only EMITS code from the template.

// --- Runtime helper injected into rewritten JS ---------------------------
//
// Any JS file
// whose rewritten form references `__safeNav` gets this helper
// prepended. It's idempotent: if the input already defines
// `function __safeNav` we don't add a second copy.
const NAV_SAFE_FILTER =
  'function __safeNav(url){try{var u=new URL(url,location.href);' +
  'if(u.protocol==="https:"||u.protocol==="http:")return url}' +
  'catch(e){}return undefined}';

// --- CSS declaration parser ---------------------------------------------
//
// Port of the legacy `parseStyleDecls`. Splits a style
// attribute value like `color: red; background: url(a.png);
// margin: 0 !important` into
// `[{prop, value, important}, …]`, respecting quoted strings
// and parenthesised function calls.
function parseStyleDecls(styleVal) {
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
    result.push({ prop, value: val, important });
  }
  return result;
}

// --- Filename derivation -------------------------------------------------

function baseNameOf(pagePath) {
  let b = pagePath;
  const slashIdx = b.lastIndexOf('/');
  if (slashIdx >= 0) b = b.slice(slashIdx + 1);
  const dotIdx = b.lastIndexOf('.');
  if (dotIdx >= 0) b = b.slice(0, dotIdx);
  return b;
}

// --- HTML-side conversion -----------------------------------------------
//
// convertHtmlMarkup(htmlContent, pagePath, reservedIdents?) →
//   { html, handlers, extractedScripts, extractedStyles }
//
// Walks the HTML token stream and applies every HTML-side
// rewrite listed in the file header. Returns:
//
//   html              — the rewritten HTML source
//   handlers          — { name, content } for the generated
//                       handlers file, or null if there are
//                       no inline events/styles/javascript: hrefs
//   extractedScripts  — Array<{ name, content }> for each
//                       inline <script> that was lifted out
//   extractedStyles   — Array<{ name, content }> for each
//                       inline <style> that was lifted out
//
// `pagePath` is used to derive output filenames (`page.js`,
// `page.handlers.js`, `page.css`). `reservedIdents` is an
// optional Set<string> of identifier names to avoid when
// generating handler variable names (unused in the current
// implementation but preserved for compatibility with the
// legacy signature).
function convertHtmlMarkup(htmlContent, pagePath, reservedIdents) {  // eslint-disable-line no-unused-vars
  const baseName = baseNameOf(pagePath || 'page.html');
  const handlersFile = baseName + '.handlers.js';

  const tokens = html.tokenize(htmlContent);
  let elemCounter = 0;
  const jsLines = [];
  const extractedScripts = [];
  const extractedStyles = [];
  let scriptIdx = 0;
  let styleIdx = 0;

  // Helper: find the closing tag for a raw-text element
  // starting at token index `startIdx` (inclusive, pointing
  // at the TOK_START). Returns the index of the matching
  // TOK_END, or -1 if none found.
  function findRawClose(startIdx, tagName) {
    for (let j = startIdx + 1; j < tokens.length; j++) {
      if (tokens[j].type === 'end' && tokens[j].tagName === tagName) return j;
    }
    return -1;
  }

  // First walk: extract inline <script> and <style> blocks
  // into external files. We replace the token stream in place
  // so the second walk sees the rewritten elements.
  for (let ti = 0; ti < tokens.length; ti++) {
    const tok = tokens[ti];
    if (tok.type !== 'start') continue;

    if (tok.tagName === 'script') {
      const hasSrc = tok.attrs.some(a => a.name === 'src');
      if (hasSrc) continue;
      const closeIdx = findRawClose(ti, 'script');
      if (closeIdx < 0) continue;
      // Collect inner TEXT token values — the tokenizer
      // reuses the TOK_START.end/TOK_END.start range for raw
      // text, so grab anything between.
      let body = '';
      for (let k = ti + 1; k < closeIdx; k++) {
        if (tokens[k].type === 'text') body += tokens[k].value;
      }
      body = body.trim();
      if (!body) continue;
      const name = scriptIdx === 0 ? baseName + '.js' : baseName + '.' + scriptIdx + '.js';
      scriptIdx++;
      extractedScripts.push({ name, content: body });
      // Rewrite: add src attribute, blank the inner text, drop the close.
      tok.attrs.push({ name: 'src', nameRaw: 'src', value: name, quoted: '"' });
      for (let k = ti + 1; k < closeIdx; k++) {
        tokens[k] = { type: 'text', value: '', start: 0, end: 0 };
      }
      ti = closeIdx;
      continue;
    }

    if (tok.tagName === 'style') {
      const closeIdx = findRawClose(ti, 'style');
      if (closeIdx < 0) continue;
      let body = '';
      for (let k = ti + 1; k < closeIdx; k++) {
        if (tokens[k].type === 'text') body += tokens[k].value;
      }
      body = body.trim();
      if (!body) continue;
      const name = styleIdx === 0 ? baseName + '.css' : baseName + '.' + styleIdx + '.css';
      styleIdx++;
      extractedStyles.push({ name, content: body });
      // Rewrite the <style> token into a <link> self-close.
      tokens[ti] = {
        type: 'self',
        tagName: 'link',
        tagRaw: 'link',
        attrs: [
          { name: 'rel', nameRaw: 'rel', value: 'stylesheet', quoted: '"' },
          { name: 'href', nameRaw: 'href', value: name, quoted: '"' },
        ],
      };
      // Blank everything through the closing </style>.
      for (let k = ti + 1; k <= closeIdx; k++) {
        tokens[k] = { type: 'text', value: '', start: 0, end: 0 };
      }
      ti = closeIdx;
      continue;
    }
  }

  // Second walk: for each start/self tag, extract inline
  // event handlers + style attributes + javascript: hrefs.
  for (let ti = 0; ti < tokens.length; ti++) {
    const tok = tokens[ti];
    if (tok.type !== 'start' && tok.type !== 'self') continue;

    const events = [];
    let styleVal = null;
    let jsHref = null;
    let existingId = null;
    const keepAttrs = [];

    for (const attr of tok.attrs) {
      if (attr.name.length > 2 && attr.name.slice(0, 2) === 'on') {
        events.push({ event: attr.name.slice(2), handler: attr.value });
        continue;
      }
      if (attr.name === 'href' &&
          attr.value.slice(0, 11).toLowerCase() === 'javascript:') {
        jsHref = attr.value.slice(11);
        continue;
      }
      if (attr.name === 'style') {
        styleVal = attr.value;
        continue;
      }
      if (attr.name === 'id') existingId = attr.value;
      keepAttrs.push(attr);
    }

    if (events.length === 0 && !jsHref && !styleVal) continue;

    // Build the selector expression.
    let sel;
    if (existingId) {
      sel = 'document.getElementById(\'' + existingId + '\')';
    } else {
      const handlerId = String(elemCounter++);
      sel = 'document.querySelector(\'[data-handler="' + handlerId + '"]\')';
      keepAttrs.push({
        name: 'data-handler',
        nameRaw: 'data-handler',
        value: handlerId,
        quoted: '"',
      });
    }

    // Group operations into an IIFE when there's more than
    // one, so we don't repeat the selector.
    let opCount = events.length + (jsHref ? 1 : 0);
    if (styleVal) opCount += parseStyleDecls(styleVal).length;
    const useVar = opCount > 1;
    const ref = useVar ? 'el' : sel;

    if (useVar) {
      jsLines.push('(function() {');
      jsLines.push('var ' + ref + ' = ' + sel + ';');
    }

    for (const ev of events) {
      const body = ev.handler.trim();
      // If the handler body contains `return`, wrap it in an
      // IIFE and check the return value for preventDefault
      // (classic onfoo="return false" pattern).
      const returnsSomething = /\breturn\b/.test(body);
      if (returnsSomething) {
        jsLines.push(ref + '.addEventListener(\'' + ev.event + '\', function(event) {');
        jsLines.push('  var __r = (function() { ' + body + ' }).call(this);');
        jsLines.push('  if (__r === false) event.preventDefault();');
        jsLines.push('});');
      } else {
        jsLines.push(ref + '.addEventListener(\'' + ev.event +
          '\', function(event) { ' + body + ' });');
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
        const escaped = d.value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        jsLines.push(ref + '.style.setProperty(\'' + d.prop + '\', \'' + escaped + '\'' +
          (d.important ? ', \'important\'' : '') + ');');
      }
    }

    if (useVar) {
      jsLines.push('})();');
    }

    tok.attrs = keepAttrs;
  }

  // Insert the handlers script reference right before
  // </body>, or before the first existing <script> if there's
  // no body close tag (so the handlers file runs before any
  // user scripts that might replace body content).
  if (jsLines.length) {
    const handlerStart = {
      type: 'start',
      tagName: 'script',
      tagRaw: 'script',
      attrs: [{ name: 'src', nameRaw: 'src', value: handlersFile, quoted: '"' }],
    };
    const handlerEnd = { type: 'end', tagName: 'script', tagRaw: 'script' };
    const newline = { type: 'text', value: '\n' };
    const handlerTokens = [handlerStart, handlerEnd, newline];

    let inserted = false;
    for (let ti = tokens.length - 1; ti >= 0; ti--) {
      if (tokens[ti].type === 'end' && tokens[ti].tagName === 'body') {
        tokens.splice(ti, 0, ...handlerTokens);
        inserted = true;
        break;
      }
    }
    if (!inserted) {
      for (let ti = 0; ti < tokens.length; ti++) {
        if (tokens[ti].type === 'start' && tokens[ti].tagName === 'script') {
          tokens.splice(ti, 0, ...handlerTokens);
          inserted = true;
          break;
        }
      }
    }
    if (!inserted) {
      tokens.push(...handlerTokens);
    }
  }

  return {
    html: html.serializeTokens(tokens),
    handlers: jsLines.length ? { name: handlersFile, content: jsLines.join('\n') } : null,
    extractedScripts,
    extractedStyles,
  };
}

// --- JS-side conversion -------------------------------------------------
//
// emitDomCalls(node, receiverExpr, depth?, varPool?)
//
// Recursive DOM-call emitter. Given an HtmlNode (fragment or
// element) and a JavaScript expression referring to the
// receiver element (e.g. `document.body`), returns a
// multi-line string of imperative DOM calls that produce the
// same subtree. Void elements emit a single createElement +
// setAttribute chain; container elements push the created
// child and recursively emit their own children against it.
//
// Variable allocation: each non-text child becomes a
// locally-scoped `__n` variable so setAttribute / appendChild
// references resolve unambiguously. `depth` threads the
// nesting level so inner variables don't collide.
function emitDomCalls(node, receiverExpr, depth, varCounter) {
  if (depth == null) depth = 0;
  if (!varCounter) varCounter = { n: 0 };
  const lines = [];
  for (const child of node.children) {
    if (child.type === 'text') {
      // Only emit non-empty text nodes. Whitespace-only text
      // between siblings is preserved as a text node so the
      // rendered layout matches the original.
      if (child.value === '') continue;
      lines.push(receiverExpr + '.appendChild(document.createTextNode(' +
        JSON.stringify(child.value) + '));');
      continue;
    }
    if (child.type === 'comment') {
      lines.push(receiverExpr + '.appendChild(document.createComment(' +
        JSON.stringify(child.value) + '));');
      continue;
    }
    if (child.type !== 'element') continue;
    const varName = '__n' + (varCounter.n++);
    lines.push('var ' + varName + ' = document.createElement(' +
      JSON.stringify(child.tag) + ');');
    // setAttribute for every attr in source order so the
    // emitted code preserves the original ordering.
    for (const attr of child.attrList || []) {
      lines.push(varName + '.setAttribute(' + JSON.stringify(attr.name) +
        ', ' + JSON.stringify(attr.value) + ');');
    }
    lines.push(receiverExpr + '.appendChild(' + varName + ');');
    if (child.children && child.children.length > 0) {
      const inner = emitDomCalls(child, varName, depth + 1, varCounter);
      if (inner) lines.push(inner);
    }
  }
  return lines.join('\n');
}

// sliceStatement(source, loc) → string. Extracts the source
// text for a Location record using pos / endPos.
function sliceStatement(source, loc) {
  if (!loc || loc.pos == null || loc.endPos == null) return '';
  return source.slice(loc.pos, loc.endPos);
}

// detectLineIndent(source, pos) — return the whitespace
// prefix of the line containing `pos`. Used by the loop
// emitter to align the emitted child-block with the
// accumulator-append statement's original indentation.
function detectLineIndent(source, pos) {
  let lineStart = pos;
  while (lineStart > 0 && source[lineStart - 1] !== '\n') lineStart--;
  let end = lineStart;
  while (end < source.length) {
    const ch = source[end];
    if (ch === ' ' || ch === '\t') end++;
    else break;
  }
  return source.slice(lineStart, end);
}

// findOpenStmtEnd(source, openStart, loopStart) — walk
// forward from the open-accum var declaration's start
// position and return the position just past the `;`
// terminator. The open-accum is always the FIRST statement
// in the replacement range, and it ends before any
// bookkeeping statements (which we want to re-emit
// between `pre` and the rewritten loop).
function findOpenStmtEnd(source, openStart, loopStart) {
  // Scan for the first `;` after openStart that isn't
  // inside a string literal. We use a tiny state machine
  // because the open literal itself contains HTML with `;`
  // characters that shouldn't count.
  let i = openStart;
  let state = 'code';
  let quote = null;
  while (i < loopStart) {
    const ch = source[i];
    if (state === 'code') {
      if (ch === '"' || ch === "'" || ch === '`') {
        quote = ch;
        state = 'string';
        i++;
        continue;
      }
      if (ch === ';') return i + 1;
      i++;
      continue;
    }
    if (state === 'string') {
      if (ch === '\\') { i += 2; continue; }
      if (ch === quote) { state = 'code'; i++; continue; }
      i++;
      continue;
    }
  }
  return loopStart;
}

// emitChildBlock(child, parentRef, jsSource) — return the
// list of source lines that re-create one accumulator-append
// site's child element (a `var __c = …; parent.appendChild
// (__c); __c.appendChild(textNode);` sequence). The caller
// joins the lines with its chosen indent and splices the
// result into the surrounding loop-body source.
//
// Factored out so the loop emitter can call it once per
// accumSite — multiple sites arise when the loop body
// contains branching `H += …` appends (one per branch).
function emitChildBlock(child, parentRef, jsSource) {
  const lines = [];
  lines.push('var __c = document.createElement(' + JSON.stringify(child.tag) + ');');
  for (const attr of child.attrs) {
    if (attr.parts.length === 1 && attr.parts[0].kind === 'literal') {
      lines.push('__c.setAttribute(' + JSON.stringify(attr.name) + ', ' +
        JSON.stringify(attr.parts[0].value) + ');');
      continue;
    }
    const pieces = attr.parts.map(p => {
      if (p.kind === 'literal') return JSON.stringify(p.value);
      return '(' + jsSource.slice(p.start, p.end) + ')';
    });
    lines.push('__c.setAttribute(' + JSON.stringify(attr.name) + ', ' +
      pieces.join(' + ') + ');');
  }
  lines.push(parentRef + '.appendChild(__c);');
  if (child.textExpr) {
    const textSrc = jsSource.slice(child.textExpr.start, child.textExpr.end);
    lines.push('__c.appendChild(document.createTextNode(' + textSrc + '));');
  }
  return lines;
}

// emitBranchBody — emit DOM calls for a nested template
// inside a caller-provided receiver expression. Used by the
// `branch` emitter to recursively lower each if/else
// branch. Returns null when the nested template can't be
// emitted (opaque / unknown kind).
function emitBranchBody(tmpl, receiver, jsSource) {
  if (!tmpl) return null;
  if (tmpl.kind === 'concrete' && tmpl.nodes) {
    return emitDomCalls(tmpl.nodes, receiver);
  }
  // Nested branch (else-if chain, nested ternary). Emit an
  // inner if/else whose each arm recursively emits its own
  // template. The nested emission does NOT prepend
  // replaceChildren — only the outermost branch clears the
  // receiver; inner arms just emit their own createElement
  // calls inside the inherited control flow.
  if (tmpl.kind === 'branch') {
    const testSrc = jsSource.slice(tmpl.testExpr.start, tmpl.testExpr.end);
    const lines = [];
    lines.push('if (' + testSrc + ') {');
    const conseqBody = emitBranchBody(tmpl.consequent, receiver, jsSource);
    if (conseqBody) {
      for (const l of conseqBody.split('\n')) lines.push('  ' + l);
    }
    lines.push('} else {');
    const altBody = emitBranchBody(tmpl.alternate, receiver, jsSource);
    if (altBody) {
      for (const l of altBody.split('\n')) lines.push('  ' + l);
    }
    lines.push('}');
    return lines.join('\n');
  }
  // Loop inside a branch arm. The `block-loop` template
  // carries the extracted loop shape (outer wrapper, loop
  // header, accumSites) without the top-level replaceChildren
  // concerns that apply to the primary loop emitter. We
  // emit into the outer branch's receiver: a
  // document.createElement for the wrapper, append it, then
  // the original loop source with each accumSite replaced
  // by its child block keyed to the wrapper parent.
  if (tmpl.kind === 'block-loop') {
    const sh = tmpl.loopShape;
    const lines = [];
    let parentRef;
    if (tmpl.outer) {
      lines.push('var __p = document.createElement(' +
        JSON.stringify(tmpl.outer.tag) + ');');
      for (const a of tmpl.outer.attrList) {
        lines.push('__p.setAttribute(' + JSON.stringify(a.name) + ', ' +
          JSON.stringify(a.value) + ');');
      }
      lines.push(receiver + '.appendChild(__p);');
      parentRef = '__p';
    } else {
      parentRef = receiver;
    }
    const sites = (tmpl.accumSites || []).slice().sort((a, b) => a.start - b.start);
    let loopSrc = jsSource.slice(sh.loopStart, sh.headerEnd);
    let cursor = sh.headerEnd;
    for (const site of sites) {
      loopSrc += jsSource.slice(cursor, site.start);
      const indent = detectLineIndent(jsSource, site.start);
      const childLines = emitChildBlock(site.child, parentRef, jsSource);
      loopSrc += childLines.join('\n' + indent);
      cursor = site.end;
    }
    loopSrc += jsSource.slice(cursor, sh.bodyEnd);
    loopSrc += jsSource.slice(sh.bodyEnd, sh.loopEnd);
    lines.push(loopSrc);
    return lines.join('\n');
  }
  return null;
}

// --- Emit code from a structured HtmlTemplate ---------------------------
//
// The engine's src/html-templates.js attaches a template to
// every innerHtmlAssignment on the trace. This function
// consumes the template and returns a source-range
// replacement record `{start, end, replacement}` that the
// convertJsFile replacement applier splices into the file.
//
// Supported template kinds:
//
//   * 'concrete' — fully static HTML. Emit createElement /
//                  setAttribute / appendChild calls via
//                  emitDomCalls on the parsed tree.
//   * 'loop'     — accumulator loop. Emit replaceChildren()
//                  + optional outer wrapper element + a for
//                  loop that creates the per-iteration child
//                  from the template's shape.
//   * 'opaque'   — template extractor couldn't match the
//                  site; return null and let convertJsFile
//                  leave the source alone.
function emitFromTemplate(jsSource, ih) {
  const tmpl = ih.template;
  if (!tmpl) return null;

  if (tmpl.kind === 'concrete' && ih.parsedHtml) {
    const stmtText = sliceStatement(jsSource, ih.location);
    const m = stmtText.match(/^(.+?)\.(innerHTML|outerHTML|insertAdjacentHTML)\b/);
    if (!m) return null;
    const receiver = m[1];

    // outerHTML replaces the element itself, not its
    // contents. We build a DocumentFragment holding the new
    // nodes and call `receiver.parentNode.replaceChild
    // (__f, receiver)` so the fragment's children take
    // receiver's position in the tree and receiver is
    // removed.
    if (ih.kind === 'outerHTML') {
      const body = emitDomCalls(ih.parsedHtml, '__f');
      const lines = [];
      lines.push('var __f = document.createDocumentFragment();');
      if (body) lines.push(body);
      lines.push(receiver + '.parentNode.replaceChild(__f, ' + receiver + ');');
      return {
        start: ih.location.pos,
        end: ih.location.endPos,
        replacement: lines.join('\n'),
      };
    }

    const body = emitDomCalls(ih.parsedHtml, receiver);
    return {
      start: ih.location.pos,
      end: ih.location.endPos,
      replacement: receiver + '.replaceChildren();\n' + body,
    };
  }

  if (tmpl.kind === 'append') {
    // innerHTML `=` or `+=` assignment whose RHS is a
    // string-shaped expression (literal, concat chain, or
    // TemplateLiteral). The template carries either a
    // parsed node list (for static content) or a single-
    // child descriptor (for one-element RHS). The emitter
    // prepends `receiver.replaceChildren();` when the
    // operator is '=' so existing children are cleared
    // before the new nodes go in; for '+=' the existing
    // children stay in place and only the new nodes are
    // appended.
    const receiver = jsSource.slice(tmpl.receiver.start, tmpl.receiver.end);
    let body;
    if (tmpl.nodes) {
      body = emitDomCalls(tmpl.nodes, receiver);
    } else if (tmpl.child) {
      body = emitChildBlock(tmpl.child, receiver, jsSource).join('\n');
    } else {
      return null;
    }
    const pre = tmpl.operator === '=' ? receiver + '.replaceChildren();\n' : '';
    return {
      start: tmpl.rangeStart,
      end: tmpl.rangeEnd,
      replacement: pre + body,
    };
  }

  if (tmpl.kind === 'switch') {
    const receiver = jsSource.slice(tmpl.receiver.start, tmpl.receiver.end);
    const discSrc = jsSource.slice(tmpl.discriminant.start, tmpl.discriminant.end);
    const lines = [];
    lines.push(receiver + '.replaceChildren();');
    lines.push('switch (' + discSrc + ') {');
    for (const c of tmpl.cases) {
      if (c.testExpr) {
        const testSrc = jsSource.slice(c.testExpr.start, c.testExpr.end);
        lines.push('  case ' + testSrc + ': {');
      } else {
        lines.push('  default: {');
      }
      const body = emitBranchBody(c.template, receiver, jsSource);
      if (body) {
        for (const l of body.split('\n')) lines.push('    ' + l);
      }
      lines.push('    break;');
      lines.push('  }');
    }
    lines.push('}');
    return {
      start: tmpl.rangeStart,
      end: tmpl.rangeEnd,
      replacement: lines.join('\n'),
    };
  }

  if (tmpl.kind === 'branch') {
    const receiver = jsSource.slice(tmpl.receiver.start, tmpl.receiver.end);
    const testSrc = jsSource.slice(tmpl.testExpr.start, tmpl.testExpr.end);
    const lines = [];
    lines.push(receiver + '.replaceChildren();');
    lines.push('if (' + testSrc + ') {');
    const conseqBody = emitBranchBody(tmpl.consequent, receiver, jsSource);
    if (conseqBody) {
      for (const l of conseqBody.split('\n')) lines.push('  ' + l);
    }
    lines.push('} else {');
    const altBody = emitBranchBody(tmpl.alternate, receiver, jsSource);
    if (altBody) {
      for (const l of altBody.split('\n')) lines.push('  ' + l);
    }
    lines.push('}');
    return {
      start: tmpl.rangeStart,
      end: tmpl.rangeEnd,
      replacement: lines.join('\n'),
    };
  }

  if (tmpl.kind === 'loop') {
    const receiver = jsSource.slice(tmpl.receiver.start, tmpl.receiver.end);
    const pre = [];
    pre.push(receiver + '.replaceChildren();');
    let parentRef;
    if (tmpl.outer) {
      pre.push('var __p = document.createElement(' + JSON.stringify(tmpl.outer.tag) + ');');
      for (const a of tmpl.outer.attrList) {
        pre.push('__p.setAttribute(' + JSON.stringify(a.name) + ', ' +
          JSON.stringify(a.value) + ');');
      }
      pre.push(receiver + '.appendChild(__p);');
      parentRef = '__p';
    } else {
      parentRef = receiver;
    }

    // Emit the per-iteration child element creation. The
    // library's template gives us one `accumSite` per
    // accumulator-append statement found anywhere in the
    // loop body (including inside nested IfStatement
    // branches). We walk the original loop-body source from
    // `headerEnd` to `bodyEnd`, splicing each site's child
    // block in place of its statement and re-emitting
    // everything else verbatim. The surrounding loop header
    // and closing brace are sliced verbatim from the source
    // so while / do-while / for-in / for-of all work without
    // per-type handling.
    const sh = tmpl.loopShape;
    const sites = (tmpl.accumSites || []).slice().sort((a, b) => a.start - b.start);

    let loopSrc = jsSource.slice(sh.loopStart, sh.headerEnd);
    let cursor = sh.headerEnd;
    for (const site of sites) {
      loopSrc += jsSource.slice(cursor, site.start);
      // Match the indentation of the accumulator-append
      // statement at this site so the spliced-in child-
      // block aligns with its neighbours. The first line's
      // indent is already supplied by the verbatim slice
      // ending at `site.start`; subsequent lines need the
      // indent prefix.
      const indent = detectLineIndent(jsSource, site.start);
      const childLines = emitChildBlock(site.child, parentRef, jsSource);
      loopSrc += childLines.join('\n' + indent);
      cursor = site.end;
    }
    loopSrc += jsSource.slice(cursor, sh.bodyEnd);
    loopSrc += jsSource.slice(sh.bodyEnd, sh.loopEnd);

    // Preserve bookkeeping statements that live BETWEEN
    // the openStmt and the loopStmt (e.g. `var i = 0;`
    // before a while-loop). They sit inside the replacement
    // range so we re-emit them verbatim between pre and
    // the rewritten loop.
    //
    // We slice from the end of openStmt to the start of
    // the loop, stripping the open-accum's own text, to
    // recover the original bookkeeping region.
    const openStmtEnd = findOpenStmtEnd(jsSource, tmpl.rangeStart, sh.loopStart);
    const bookkeeping = jsSource.slice(openStmtEnd, sh.loopStart);

    return {
      start: tmpl.rangeStart,
      end: tmpl.rangeEnd,
      replacement: pre.join('\n') + '\n' + bookkeeping.trimStart() + loopSrc,
    };
  }

  return null;
}


// convertJsFile(jsSource, trace, filename?) → string
//
// Applies every JS-side rewrite to `jsSource` based on what
// the trace observed for `filename` (or the first file in the
// trace if only one was analysed):
//
//   * innerHTML / outerHTML assignments whose value is a
//     concrete string become a sequence of createElement /
//     setAttribute / appendChild calls.
//   * Tainted navigation — assignments to `location.href`,
//     `location` itself, and `<iframe|frame>.src` whose RHS
//     is tainted — get wrapped in a `__safeNav(rhs)` protocol
//     filter, matching the legacy engine's wrapper form.
//   * `eval(dynamic)` calls become `/* [blocked: eval with
//     dynamic argument] */ void 0`. Constant-string eval is
//     left alone.
//   * `document.write(literal)` becomes
//     `document.body.appendChild(document.createTextNode(literal))`.
//     Non-literal document.write is currently left alone (the
//     legacy engine has a sanitizer pass for it, out of scope
//     for this commit).
//
// Rewrites are applied in REVERSE source order so earlier
// positions are still valid while we edit later ones. A final
// pass prepends the `__safeNav` helper if any rewrite
// introduced a reference to it.
function convertJsFile(jsSource, trace, filename) {
  const replacements = [];

  // Build a per-file filter. The trace may span multiple
  // files; a rewrite is only applicable to `jsSource` if its
  // location.file matches.
  const matchesFile = loc => {
    if (!loc) return false;
    if (filename == null) return true;
    return loc.file === filename;
  };

  // --- 1. innerHTML / outerHTML → DOM calls -----------------------------
  //
  // Completeness principle (DESIGN-DECISIONS.md §D19):
  // DOM conversion must rewrite EVERY syntactic sink,
  // regardless of whether the engine's reachability analysis
  // walked the block that contains it. The rewrite preserves
  // runtime semantics, and leaving an unreachable-per-analysis
  // sink un-rewritten would become a security hole the
  // moment the runtime takes a path the analysis ruled out
  // (refutation is sound w.r.t. the model, not the world).
  //
  // We therefore get the site list from the AST via
  // html-templates.findAllAssignments — not from
  // trace.innerHtmlAssignments, which is filtered to walked
  // blocks. The trace entries are still consulted
  // opportunistically: when a trace entry matches a site,
  // its pre-built template is used; otherwise we re-run the
  // template extractor on the AST, which works identically
  // on dead code because it's pure source-level.
  const traceByPos = Object.create(null);
  for (const ih of trace.innerHtmlAssignments || []) {
    if (!matchesFile(ih.location)) continue;
    const k = ih.location.pos + ':' + ih.location.endPos;
    if (!traceByPos[k]) traceByPos[k] = ih;
  }
  // Positions the walker executed but whose receiver was
  // NOT a DOM element (plain-object `.innerHTML = …` field
  // writes). These are in `trace.walkedHtmlSites` but NOT
  // in `trace.innerHtmlAssignments`, so the set difference
  // is our "walked non-DOM" signal. Rewriting such sites
  // would break programs that intentionally use `innerHTML`
  // as a field name on their own data objects.
  const walkedNonDom = new Set();
  for (const w of trace.walkedHtmlSites || []) {
    if (!matchesFile(w)) continue;
    const k = w.pos + ':' + w.endPos;
    if (!traceByPos[k]) walkedNonDom.add(k);
  }
  // Enumerate every syntactic innerHTML / outerHTML site.
  const siteList = HtmlTemplates.findAllAssignments(
    jsSource, filename || '<input>.js');
  const stmtOffsets = new Set();
  const astCache = Object.create(null);
  for (const site of siteList) {
    if (site.kind !== 'innerHTML' && site.kind !== 'outerHTML') continue;
    const key = site.pos + ':' + site.endPos;
    if (stmtOffsets.has(key)) continue;
    stmtOffsets.add(key);
    // Case A: walked, plain-object receiver — skip. The
    // rewrite would turn a harmless field write into a
    // broken createElement call on a non-DOM object.
    if (walkedNonDom.has(key)) continue;
    // Case B: walked, DOM receiver — use the trace record.
    // It carries the full lattice-derived value plus the
    // (usually richer) template built during analyse().
    // Case C: not walked — dead branch or uncalled
    // function. Per the completeness principle, we still
    // rewrite based on whatever the AST template extractor
    // can see structurally. This is safe because
    // html-templates operates purely on source and never
    // consults the lattice.
    let ih = traceByPos[key];
    if (!ih) {
      const tmpl = HtmlTemplates.extractTemplate(
        jsSource, site.pos, filename || '<input>.js', astCache);
      ih = {
        kind: site.kind,
        location: {
          file: site.file, line: site.line, col: site.col,
          pos: site.pos, endPos: site.endPos,
        },
        value: null,
        labels: [],
        concrete: tmpl && tmpl.kind === 'concrete' ? tmpl.html : null,
        parsedHtml: tmpl && tmpl.kind === 'concrete' ? tmpl.nodes : null,
        template: tmpl,
      };
    }
    const rewrite = emitFromTemplate(jsSource, ih);
    if (rewrite) replacements.push(rewrite);
  }

  // --- 2. Tainted navigation → __safeNav wrap ---------------------------
  for (const flow of trace.taintFlows || []) {
    if (!matchesFile(flow.sink && flow.sink.location)) continue;
    if (!flow.sink) continue;
    const sinkKind = flow.sink.kind;
    const sinkProp = flow.sink.prop;
    // Navigation sinks per the default TypeDB: 'navigation'
    // kind on Location.href / Location.assign / etc., plus
    // `url` kind on HTMLIFrameElement.src / .srcdoc.
    const isNav = sinkKind === 'navigation' ||
      (sinkKind === 'url' && (sinkProp === 'src' || sinkProp === 'href'));
    if (!isNav) continue;
    const stmtText = sliceStatement(jsSource, flow.sink.location);
    if (!stmtText) continue;
    // Match `target = rhs;` or `target = rhs`.
    const assign = stmtText.match(/^([^=]+?)\s*=\s*([\s\S]+?);?$/);
    if (!assign) continue;
    const target = assign[1].trim();
    const rhs = assign[2].trim();
    // Skip if the RHS is a string literal — string literals
    // are safe at compile time.
    if (/^(["']).*\1$/.test(rhs)) continue;
    const wrapped = '(function(){var __u=__safeNav(' + rhs +
      ');if(__u!==undefined)' + target + '=__u}())';
    replacements.push({
      start: flow.sink.location.pos,
      end: flow.sink.location.endPos,
      replacement: wrapped,
    });
  }

  // --- 3. eval(dynamic) → blocked ---------------------------------------
  // --- 4. document.write(literal) → createTextNode ---------------------
  for (const c of trace.calls || []) {
    if (!matchesFile(c.site)) continue;
    const text = c.callee.text;
    const isEval = text === 'eval' ||
      (c.callee.calleeName === 'eval' && !c.callee.typeName);
    const isDocWrite =
      text === 'Document.write' || text === 'document.write' ||
      text === 'Document.writeln' || text === 'document.writeln';
    if (!isEval && !isDocWrite) continue;
    const arg0 = c.args[0];
    if (isEval) {
      // Only block dynamic eval. If the arg is a concrete
      // string, leave it alone (or ideally inline-walk it —
      // out of scope for this commit).
      if (arg0 && arg0.kind === 'concrete' && typeof arg0.value === 'string') continue;
      replacements.push({
        start: c.site.pos,
        end: c.site.endPos,
        replacement: '/* [blocked: eval with dynamic argument] */ void 0',
      });
      continue;
    }
    if (isDocWrite) {
      // Only rewrite concrete-literal document.write — dynamic
      // document.write is a bigger sanitization problem that
      // needs a runtime guard, out of scope for this commit.
      if (!arg0 || arg0.kind !== 'concrete' || typeof arg0.value !== 'string') continue;
      replacements.push({
        start: c.site.pos,
        end: c.site.endPos,
        replacement: 'document.body.appendChild(document.createTextNode(' +
          JSON.stringify(arg0.value) + '))',
      });
      continue;
    }
  }

  // --- 5. insertAdjacentHTML → createElement + insertBefore/appendChild -
  //
  // `el.insertAdjacentHTML(position, html)` is a DOM-sink
  // method call — the engine records it in trace.calls with
  // methodName === 'insertAdjacentHTML'. For concrete-literal
  // html values we parse the HTML via the library's
  // html.parse and emit DOM construction targeted at the
  // position-correct parent.
  //
  //   * 'beforebegin' → parent.insertBefore(new, el)
  //   * 'afterbegin'  → el.insertBefore(new, el.firstChild)
  //   * 'beforeend'   → el.appendChild(new)
  //   * 'afterend'    → parent.insertBefore(new, el.nextSibling)
  //
  // We build into a DocumentFragment so the same emitDomCalls
  // path works for every position and a single DOM operation
  // at the end places all new nodes. Non-concrete positions /
  // non-concrete html / unknown positions fall through.
  for (const c of trace.calls || []) {
    if (!matchesFile(c.site)) continue;
    if (!c.callee || c.callee.methodName !== 'insertAdjacentHTML') continue;
    const pos = c.args[0];
    const htmlArg = c.args[1];
    if (!pos || pos.kind !== 'concrete' || typeof pos.value !== 'string') continue;
    if (!htmlArg || htmlArg.kind !== 'concrete' ||
        typeof htmlArg.value !== 'string') continue;
    const position = pos.value;
    const known = ['beforebegin', 'afterbegin', 'beforeend', 'afterend'];
    if (known.indexOf(position) < 0) continue;

    // Recover the receiver text from the call site's source
    // slice: `recv.insertAdjacentHTML(…)`. The IR hasn't
    // preserved the receiver's source range, but the call
    // site's pos / endPos covers the whole expression and
    // the call shape is unambiguous.
    const stmtText = jsSource.slice(c.site.pos, c.site.endPos);
    const m = stmtText.match(/^(.+?)\.insertAdjacentHTML\s*\(/);
    if (!m) continue;
    const recv = m[1];
    const parsed = html.parse(htmlArg.value);
    const body = emitDomCalls(parsed, '__f');
    const lines = [];
    lines.push('var __f = document.createDocumentFragment();');
    if (body) lines.push(body);
    if (position === 'beforeend') {
      lines.push(recv + '.appendChild(__f);');
    } else if (position === 'afterbegin') {
      lines.push(recv + '.insertBefore(__f, ' + recv + '.firstChild);');
    } else if (position === 'beforebegin') {
      lines.push(recv + '.parentNode.insertBefore(__f, ' + recv + ');');
    } else if (position === 'afterend') {
      lines.push(recv + '.parentNode.insertBefore(__f, ' + recv + '.nextSibling);');
    }
    replacements.push({
      start: c.site.pos,
      end: c.site.endPos,
      replacement: lines.join('\n'),
    });
  }

  // --- Apply replacements in reverse order ------------------------------
  replacements.sort((a, b) => b.start - a.start);
  // Drop overlapping replacements (keep the earlier / outer one).
  const pruned = [];
  let lastStart = Infinity;
  for (const r of replacements) {
    if (r.end > lastStart) continue;
    pruned.push(r);
    lastStart = r.start;
  }

  let result = jsSource;
  for (const r of pruned) {
    result = result.slice(0, r.start) + r.replacement + result.slice(r.end);
  }

  // --- Prepend __safeNav helper if referenced -----------------------
  if (result.indexOf('__safeNav') >= 0 &&
      result.indexOf('function __safeNav') < 0) {
    result = NAV_SAFE_FILTER + '\n' + result;
  }

  return result;
}

// --- Project-level entry point ------------------------------------------
//
// convertProject(files, options?) → { filename: content }
//
// For each HTML file in `files`, runs convertHtmlMarkup and
// merges the extracted JS/CSS into the output map. The
// consumer's caller gets back only files that CHANGED — if an
// HTML file had no inline events/styles/scripts, it's not in
// the output.
//
// For each JS file (including inline scripts extracted from
// HTML), we run the engine via `analyze()` to get a Trace and
// then call `convertJsFile` to apply the source-range
// rewrites. Only files that actually changed appear in the
// output.
async function convertProject(files, options) {
  options = options || {};
  const output = {};
  const keys = Object.keys(files);
  const htmlPaths = keys.filter(p => /\.html?$/i.test(p)).sort();

  // --- Stage 1: HTML-side conversion ------------------------------------
  //
  // For each HTML page we extract inline <script>, inline
  // <style>, and per-element inline events + styles into
  // separate files. The extracted scripts are remembered in
  // per-page script-src order so Stage 2 knows which files
  // are siblings (analyzed together with shared scope).
  const pageScripts = Object.create(null);  // page → [jsPath, ...] in source order
  const pendingJs = Object.create(null);    // filename → source
  for (const page of htmlPaths) {
    const result = convertHtmlMarkup(files[page], page);
    let anyChange = false;
    if (result.handlers) {
      output[result.handlers.name] = result.handlers.content;
      anyChange = true;
    }
    // Walk the rewritten HTML's tokens and record every
    // <script src="..."> in source order so Stage 2 can
    // analyze the page's scripts as siblings.
    const pageScriptList = [];
    const orderedTokens = html.tokenize(result.html);
    for (const tok of orderedTokens) {
      if (tok.type !== 'start' || tok.tagName !== 'script') continue;
      const srcAttr = (tok.attrs || []).find(a => a.name === 'src');
      if (!srcAttr) continue;
      pageScriptList.push(srcAttr.value);
    }
    pageScripts[page] = pageScriptList;

    for (const s of result.extractedScripts) {
      output[s.name] = s.content;
      pendingJs[s.name] = s.content;
      anyChange = true;
    }
    for (const s of result.extractedStyles) {
      output[s.name] = s.content;
      anyChange = true;
    }
    if (anyChange || result.html !== files[page]) {
      output[page] = result.html;
    }
  }

  // --- Stage 2: JS-side conversion with project-level scope ------------
  //
  // Each HTML page's scripts are siblings — declarations in
  // one are visible in later ones because the runtime evaluates
  // them in order into the same global scope. The new engine
  // supports this via `analyze(files, {project: [...ordered
  // filenames...]})`: the files in `project` are parsed
  // individually but joined into ONE top-function whose
  // body is the concatenation of their top-level
  // statements, preserving per-instruction file+pos
  // locations for trace projection.
  //
  // Files not referenced by any HTML page are analyzed
  // standalone, one per analyze() call.
  const jsPaths = keys.filter(p => /\.m?js$/.test(p));
  for (const p of jsPaths) pendingJs[p] = files[p];

  const { analyze } = require('../src/index.js');
  const TDB = options.typeDB || require('../src/default-typedb.js');

  // Which JS file is loaded by which HTML page (if any).
  // A JS file that's not loaded by any HTML page analyses
  // as a standalone single-file project.
  const pageOfJs = Object.create(null);
  for (const page of htmlPaths) {
    for (const sp of (pageScripts[page] || [])) {
      if (pageOfJs[sp] == null) pageOfJs[sp] = page;
    }
  }

  // Group JS files by their owning HTML page (or null for
  // standalone). The project order for each group is the
  // page's script-src order; standalone files each form a
  // single-element group.
  const projects = [];    // Array<{ order: string[], files: {name: src} }>
  const seen = new Set();
  for (const page of htmlPaths) {
    const order = pageScripts[page] || [];
    if (order.length === 0) continue;
    const projFiles = Object.create(null);
    for (const p of order) {
      if (pendingJs[p] != null) {
        projFiles[p] = pendingJs[p];
        seen.add(p);
      }
    }
    if (Object.keys(projFiles).length > 0) {
      projects.push({ order, files: projFiles });
    }
  }
  for (const p of Object.keys(pendingJs)) {
    if (seen.has(p)) continue;
    projects.push({ order: [p], files: { [p]: pendingJs[p] } });
  }

  // Analyse each project and rewrite every file in it. The
  // new engine's `project: [...]` option tells it to treat
  // the files as ordered siblings sharing the top-level
  // scope, so `app.js` sees `var items` declared in
  // `store.js` without needing a precedingCode hack.
  for (const project of projects) {
    const trace = await analyze(project.files, {
      typeDB: TDB,
      
      project: project.order,
    });
    for (const jsPath of project.order) {
      const src = project.files[jsPath];
      if (src == null) continue;
      const rewritten = convertJsFile(src, trace, jsPath);
      if (rewritten !== src) {
        output[jsPath] = rewritten;
      }
    }
  }

  return output;
}

module.exports = {
  convertProject,
  convertHtmlMarkup,
  convertJsFile,
  parseStyleDecls,
  emitDomCalls,
};
