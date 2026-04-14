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
// We use acorn directly (not via the engine's parse.js) for
// consumer-side pattern matching on source AST. The engine's
// parse.js wraps acorn with a tokenizer + hand-rolled parser;
// here we just want the AST.
function getAcorn() {
  if (typeof globalThis !== 'undefined' && globalThis.acorn &&
      typeof globalThis.acorn.parse === 'function') {
    return globalThis.acorn;
  }
  const path = require('path');
  // eslint-disable-next-line no-undef
  const vendoredPath = path.join(__dirname, '..', 'vendor', 'acorn.js');
  return require(vendoredPath);
}

// --- Runtime helper injected into rewritten JS ---------------------------
//
// Ported verbatim from the legacy htmldom engine. Any JS file
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

// --- Loop-built innerHTML pattern matcher -------------------------------
//
// Detects the common pattern:
//
//   var H = '<tag0>';
//   for (var i = 0; i < A.length; i++) {
//     H += '<child>' + A[i] + '</child>';
//   }
//   H += '</tag0>';
//   elem.innerHTML = H;
//
// and rewrites it as:
//
//   elem.replaceChildren();
//   var __n0 = document.createElement('tag0');
//   elem.appendChild(__n0);
//   for (var i = 0; i < A.length; i++) {
//     var __n1 = document.createElement('child');
//     __n0.appendChild(__n1);
//     __n1.appendChild(document.createTextNode(A[i]));
//   }
//
// The detector works directly on the JS AST (via vendored
// acorn). It matches a specific shape — any variation (two
// loops, conditional append, nested templates) falls through
// to the non-concrete "left alone" path. The goal is to
// handle the user's navigation-builder example without
// trying to solve the general string-to-DOM problem.
//
// Pattern match pieces:
//
//   [A] var H = <string literal containing an open tag>;
//   [B] for (var i = <n>; i < <array>.length; i++) { ... }
//       where the body is `H += <expr>` with expr being
//       a string concatenation that includes a literal
//       `<child>` start tag, an expression hole (the
//       array-indexed value), and a literal `</child>` end
//       tag (plus optional attribute fragments).
//   [C] H += <string literal containing the matching close tag>;
//   [D] <elem>.innerHTML = H;
//
// The matcher returns a replacement source range + the
// imperative DOM-call replacement text when all four pieces
// are found and correlated (same H variable, same close tag
// matches the opening tag). On any mismatch it returns null.
function detectLoopBuiltInnerHtml(jsSource, assignStmtPos) {
  let ast;
  // eslint-disable-next-line no-restricted-syntax
  try {
    ast = getAcorn().parse(jsSource, {
      ecmaVersion: 'latest',
      locations: true,
      sourceType: 'script',
    });
  } catch (_) {
    return null;
  }

  const stmts = ast.body;
  // Find the assignment statement at `assignStmtPos` in the
  // top-level body and its preceding statements.
  let assignIdx = -1;
  for (let i = 0; i < stmts.length; i++) {
    if (stmts[i].start <= assignStmtPos && stmts[i].end > assignStmtPos) {
      assignIdx = i;
      break;
    }
  }
  if (assignIdx < 0) return null;
  const assignStmt = stmts[assignIdx];

  // The assignment: must be `elem.innerHTML = H`.
  if (assignStmt.type !== 'ExpressionStatement') return null;
  const expr = assignStmt.expression;
  if (!expr || expr.type !== 'AssignmentExpression' || expr.operator !== '=') return null;
  const lhs = expr.left;
  const rhs = expr.right;
  if (!lhs || lhs.type !== 'MemberExpression') return null;
  if (lhs.computed || !lhs.property || lhs.property.type !== 'Identifier') return null;
  if (lhs.property.name !== 'innerHTML' && lhs.property.name !== 'outerHTML') return null;
  if (!rhs || rhs.type !== 'Identifier') return null;
  const htmlVarName = rhs.name;

  // Walk backward from `assignIdx` to find the loop and the
  // optional open/close accumulator statements wrapping it.
  //
  // Shapes supported:
  //
  //   A) wrapped — `var X = '<tag>'; for (...) { ... } X += '</tag>';`
  //   B) no-wrap — `var X = ''; for (...) { ... }`  (or the
  //                var decl absent entirely if X is a
  //                pre-existing empty-string accumulator)
  //
  // In both shapes the for loop is the statement immediately
  // preceding the innerHTML assignment (modulo an optional
  // close-accum statement). The open-accum statement must
  // exist and declare X as a string literal, but that literal
  // can be empty — distinguishing shape (B) from (A).
  let closeStmtIdx = -1;
  let loopStmtIdx = -1;
  let openStmtIdx = -1;

  // First pass: look for a close-accum statement immediately
  // before the assignment (shape A). It's OPTIONAL.
  if (assignIdx - 1 >= 0) {
    const prev = stmts[assignIdx - 1];
    if (isAccumAssign(prev, htmlVarName)) {
      const lit = literalOfAccumAssign(prev);
      if (typeof lit === 'string' && /<\/[a-z][^>]*>/i.test(lit)) {
        closeStmtIdx = assignIdx - 1;
      }
    }
  }

  // Second pass: the for loop must sit at position
  // `assignIdx - 1` (shape B) OR `closeStmtIdx - 1` (shape A).
  const afterLoopIdx = closeStmtIdx >= 0 ? closeStmtIdx : assignIdx;
  if (afterLoopIdx - 1 >= 0) {
    const s = stmts[afterLoopIdx - 1];
    if (s.type === 'ForStatement' && s.body && s.body.type === 'BlockStatement') {
      loopStmtIdx = afterLoopIdx - 1;
    }
  }
  if (loopStmtIdx < 0) return null;

  // Third pass: the open-accum statement must sit BEFORE the
  // loop and declare X as a string literal (possibly empty).
  for (let i = loopStmtIdx - 1; i >= 0; i--) {
    const s = stmts[i];
    if (s.type === 'VariableDeclaration') {
      for (const d of s.declarations) {
        if (d.id && d.id.type === 'Identifier' && d.id.name === htmlVarName &&
            d.init && d.init.type === 'Literal' && typeof d.init.value === 'string') {
          openStmtIdx = i;
          break;
        }
      }
      if (openStmtIdx >= 0) break;
    }
  }
  if (openStmtIdx < 0) return null;

  const openStmt = stmts[openStmtIdx];
  const loopStmt = stmts[loopStmtIdx];
  const closeStmt = closeStmtIdx >= 0 ? stmts[closeStmtIdx] : null;

  // Extract the literal fragments.
  const openInit = openStmt.declarations.find(d => d.id.name === htmlVarName).init;
  const openLit = openInit.value;
  const closeLit = closeStmt ? literalOfAccumAssign(closeStmt) : null;

  // Shape (A) has a matching open/close tag pair; shape (B)
  // has an empty open literal (no wrapper element at all) and
  // no close statement.
  let outerTag = null;
  if (openLit.length > 0) {
    const openTree = html.parse(openLit);
    for (const c of openTree.children) {
      if (c.type === 'element') { outerTag = c.tag; break; }
    }
    if (outerTag == null) return null;
    if (closeLit == null) return null;   // open tag without close: malformed
    const closeMatch = closeLit.match(/<\/([a-z][a-z0-9]*)/i);
    if (!closeMatch || closeMatch[1].toLowerCase() !== outerTag) return null;
  } else {
    // Shape B: empty accumulator. The loop's children are
    // appended directly to the innerHTML target with no
    // wrapper element. closeLit must also be empty (or null).
    if (closeLit != null && closeLit.length > 0) return null;
  }

  // The loop body must contain exactly one statement:
  // `H += <concat expression>;`.
  const body = loopStmt.body.body;
  if (body.length !== 1) return null;
  const bodyStmt = body[0];
  if (!isAccumAssign(bodyStmt, htmlVarName)) return null;
  const bodyExpr = bodyStmt.expression.right;
  if (!bodyExpr) return null;

  // Flatten the concat expression into a sequence of
  // literal / expression fragments.
  const frags = flattenConcat(bodyExpr);
  if (!frags) return null;

  // Scan the fragments to identify:
  //   * the child tag (from the first literal's <childTag>)
  //   * the text content hole (first non-literal)
  //   * optionally, attribute hole(s)
  //
  // For the MVP we handle the shape:
  //
  //   '<child attr="/' + <attrExpr> + '">' + <textExpr> + '</child>'
  //
  // where there are at most one attribute hole and one text
  // hole. This covers the navigation-builder example and
  // the most common "list of items with a link" pattern.
  const parsed = parseLoopBodyFragments(frags);
  if (!parsed) return null;

  // We now have enough to emit the DOM-call rewrite. Build
  // the replacement source.
  const loopBodySrc = buildReplacementSource({
    jsSource,
    outerTag,
    outerAttrsStr: openLit,   // contains the opening tag + any attrs
    loopStmt,
    htmlVarName,
    childTag: parsed.childTag,
    childAttrs: parsed.childAttrs,  // array of {name, parts: [{type, value|expr}]}
    textExpr: parsed.textExpr,
    receiver: jsSource.slice(lhs.object.start, lhs.object.end),
  });
  if (!loopBodySrc) return null;

  // Return the replacement range: from openStmt.start to
  // assignStmt.end (the whole var + loop + close + assign).
  return {
    start: openStmt.start,
    end: assignStmt.end,
    replacement: loopBodySrc,
  };
}

function isAccumAssign(stmt, varName) {
  if (!stmt || stmt.type !== 'ExpressionStatement') return false;
  const e = stmt.expression;
  if (!e || e.type !== 'AssignmentExpression') return false;
  if (e.operator !== '+=') return false;
  if (!e.left || e.left.type !== 'Identifier' || e.left.name !== varName) return false;
  return true;
}

function literalOfAccumAssign(stmt) {
  if (!isAccumAssign(stmt, stmt.expression.left.name)) return null;
  const r = stmt.expression.right;
  if (r && r.type === 'Literal' && typeof r.value === 'string') return r.value;
  return null;
}

// Flatten a left-associative chain of `+` expressions into a
// list of { type: 'lit' | 'expr', value?: string, node?: AST }.
function flattenConcat(node) {
  const out = [];
  function walk(n) {
    if (n.type === 'BinaryExpression' && n.operator === '+') {
      walk(n.left);
      walk(n.right);
      return;
    }
    if (n.type === 'Literal' && typeof n.value === 'string') {
      out.push({ type: 'lit', value: n.value });
      return;
    }
    out.push({ type: 'expr', node: n });
  }
  walk(node);
  return out;
}

// parseLoopBodyFragments — recognises the common
// `<child attr="prefix' + E + '">' + T + '</child>` shape
// and returns { childTag, childAttrs, textExpr }.
//
// childAttrs is an array of { name, parts } where parts is a
// list of { type: 'literal' | 'expr', value?: string, node? }
// forming the value of the attribute. The MVP handles one
// attribute hole per attribute.
function parseLoopBodyFragments(rawFrags) {
  // Coalesce adjacent literal fragments so `"\""` + `">"`
  // (from source `"\"" + ">"`) becomes a single `"\">"`
  // literal the state machine can parse as "close attribute
  // then end of opening tag". Programmer-written concat
  // expressions often split literals at arbitrary points
  // and the matcher must be tolerant of that.
  const frags = [];
  for (const f of rawFrags) {
    if (f.type === 'lit' && frags.length > 0 && frags[frags.length - 1].type === 'lit') {
      frags[frags.length - 1] = {
        type: 'lit',
        value: frags[frags.length - 1].value + f.value,
      };
    } else {
      frags.push(f);
    }
  }
  // Require at least: literal opening, (optional expr), literal closing.
  if (frags.length < 2) return null;
  if (frags[0].type !== 'lit') return null;
  const openingLit = frags[0].value;
  // Find the child tag + attribute fragments by parsing the
  // opening literal's HTML-ish prefix.
  const childMatch = openingLit.match(/^<([a-z][a-z0-9]*)([^>]*?)(>)?$/i);
  if (!childMatch) return null;
  const childTag = childMatch[1].toLowerCase();
  // The attribute portion (before any hole) may be a
  // well-formed attr list, partial attr ending in `"`, or
  // an open attr like `href="/`. For the MVP we parse it as
  // a sequence of attrs — anything that doesn't form a clean
  // split falls through to null so the consumer leaves the
  // assignment alone.
  const attrsStr = childMatch[2];
  // Scan fragments after the opening literal. Look for the
  // pattern: `attr="prefix` + E + `"` which builds one
  // attribute's value from an expression.
  //
  // State machine:
  //   'attrs' — we're still inside the opening tag, waiting
  //             for the `>` that closes it.
  //   'children' — the opening tag is done; we're collecting
  //                text content until `</childTag>`.
  const childAttrs = [];
  let textExpr = null;
  let state = 'attrs';
  let i = 0;
  // Handle the opening literal's attrs portion inline.
  // If it already contains `>`, we're immediately in
  // children state.
  if (childMatch[3] === '>') {
    state = 'children';
  } else {
    // The opening literal's attrs may contain static attrs;
    // record them as literal-only parts.
    const staticAttrs = parseStaticAttrsFragment(attrsStr);
    for (const a of staticAttrs) childAttrs.push(a);
    // If attrsStr ends with `attr="value-prefix`, we have a
    // dangling attribute whose value is completed by
    // subsequent fragments.
    const dangling = attrsStr.match(/\s([a-z][a-z0-9-]*)\s*=\s*"([^"]*)$/i);
    if (dangling) {
      // Pop the last static attr if it's the same name (we
      // may have mis-parsed it above) and start a new attr
      // with a literal prefix.
      childAttrs.push({
        name: dangling[1].toLowerCase(),
        parts: [{ type: 'literal', value: dangling[2] }],
        _pending: true,
      });
    }
  }
  i = 1;
  while (i < frags.length) {
    const f = frags[i];
    if (state === 'attrs') {
      const pendingAttr = childAttrs[childAttrs.length - 1];
      if (f.type === 'expr' && pendingAttr && pendingAttr._pending) {
        pendingAttr.parts.push({ type: 'expr', node: f.node });
        i++;
        continue;
      }
      if (f.type === 'lit' && pendingAttr && pendingAttr._pending) {
        // The literal closes the attribute value with `"`
        // then possibly more attributes + the closing `>`.
        const closeIdx = f.value.indexOf('"');
        if (closeIdx < 0) return null;
        if (closeIdx > 0) {
          pendingAttr.parts.push({ type: 'literal', value: f.value.slice(0, closeIdx) });
        }
        delete pendingAttr._pending;
        const after = f.value.slice(closeIdx + 1);
        // after may have more attrs then `>`.
        const gtIdx = after.indexOf('>');
        if (gtIdx < 0) return null;
        const moreAttrs = after.slice(0, gtIdx);
        const rest = after.slice(gtIdx + 1);
        const staticAttrs = parseStaticAttrsFragment(moreAttrs);
        for (const a of staticAttrs) childAttrs.push(a);
        // `rest` is the start of the children literal (text
        // prefix). If non-empty, re-process frags[i] as the
        // rest lit under children state. If empty, advance to
        // the next fragment.
        state = 'children';
        if (rest.length > 0) {
          frags[i] = { type: 'lit', value: rest };
          continue;
        }
        i++;
        continue;
      }
      return null;
    }
    if (state === 'children') {
      if (f.type === 'expr' && textExpr == null) {
        textExpr = f.node;
        i++;
        continue;
      }
      if (f.type === 'lit') {
        // Must be `</childTag>` (possibly preceded by
        // whitespace from the input's formatting).
        const closingRe = new RegExp('</' + childTag + '\\s*>', 'i');
        if (closingRe.test(f.value)) {
          // Match the pattern. Confirm no more fragments follow.
          i++;
          if (i < frags.length) return null;
          return { childTag, childAttrs, textExpr };
        }
        return null;
      }
      // Second expression in children — not supported by the MVP.
      return null;
    }
    i++;
  }
  return null;
}

// parseStaticAttrsFragment — tolerant parser for an attribute
// list fragment like `class="x" id="y"`. Returns an array of
// { name, parts: [{type: 'literal', value}] } records. Any
// attribute whose value starts but doesn't close inside the
// fragment is NOT returned (the caller handles it as a
// dangling attribute).
function parseStaticAttrsFragment(s) {
  const out = [];
  const re = /\s*([a-z][a-z0-9-]*)\s*=\s*"([^"]*)"/gi;
  let m;
  while ((m = re.exec(s)) !== null) {
    out.push({
      name: m[1].toLowerCase(),
      parts: [{ type: 'literal', value: m[2] }],
    });
  }
  return out;
}

// buildReplacementSource — emit the imperative DOM-call
// replacement for a matched loop-built innerHTML pattern.
// When `outerTag` is null the pattern is the shape-B
// "no wrapper" form, where children are appended directly
// to the innerHTML target with no outer wrapper element.
function buildReplacementSource(ctx) {
  const jsSource = ctx.jsSource;
  const outerTag = ctx.outerTag;
  const receiver = ctx.receiver;
  const loopStmt = ctx.loopStmt;
  const childTag = ctx.childTag;
  const childAttrs = ctx.childAttrs;
  const textExpr = ctx.textExpr;

  // Extract the loop's init / test / update / body source
  // slices so we can reuse them verbatim in the emitted loop.
  const initSrc = loopStmt.init ? jsSource.slice(loopStmt.init.start, loopStmt.init.end) : '';
  const testSrc = loopStmt.test ? jsSource.slice(loopStmt.test.start, loopStmt.test.end) : '';
  const updateSrc = loopStmt.update ? jsSource.slice(loopStmt.update.start, loopStmt.update.end) : '';

  const lines = [];
  lines.push(receiver + '.replaceChildren();');
  // Parent container. Shape A has an outer wrapper element;
  // shape B (no wrapper) appends children directly to the
  // innerHTML target.
  let parentRef;
  if (outerTag) {
    lines.push('var __p = document.createElement(' + JSON.stringify(outerTag) + ');');
    // Static outer attributes from the opening literal: we
    // only honour the pure-attribute shape (no holes). Parse
    // the opening literal once more via html.js to lift them.
    const openTree = html.parse(ctx.outerAttrsStr || '');
    const openElem = openTree.children.find(c => c.type === 'element' && c.tag === outerTag);
    if (openElem && openElem.attrList) {
      for (const a of openElem.attrList) {
        lines.push('__p.setAttribute(' + JSON.stringify(a.name) + ', ' + JSON.stringify(a.value) + ');');
      }
    }
    lines.push(receiver + '.appendChild(__p);');
    parentRef = '__p';
  } else {
    parentRef = receiver;
  }
  // The for loop.
  lines.push('for (' + initSrc + '; ' + testSrc + '; ' + updateSrc + ') {');
  lines.push('  var __c = document.createElement(' + JSON.stringify(childTag) + ');');
  // Child attributes: static ones emit plain setAttribute;
  // ones with expression parts emit a concatenation.
  for (const attr of childAttrs) {
    const parts = attr.parts;
    if (parts.length === 1 && parts[0].type === 'literal') {
      lines.push('  __c.setAttribute(' + JSON.stringify(attr.name) + ', ' +
        JSON.stringify(parts[0].value) + ');');
      continue;
    }
    // Multi-part: build a concat expression at runtime.
    const pieces = parts.map(p => {
      if (p.type === 'literal') return JSON.stringify(p.value);
      return '(' + jsSource.slice(p.node.start, p.node.end) + ')';
    });
    lines.push('  __c.setAttribute(' + JSON.stringify(attr.name) + ', ' +
      pieces.join(' + ') + ');');
  }
  lines.push('  ' + parentRef + '.appendChild(__c);');
  if (textExpr) {
    const textSrc = jsSource.slice(textExpr.start, textExpr.end);
    lines.push('  __c.appendChild(document.createTextNode(' + textSrc + '));');
  }
  lines.push('}');

  return lines.join('\n');
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
  // Ordering matters. We try the LOOP-BUILT pattern matcher
  // FIRST, then fall back to the concrete parsedHtml path.
  //
  // Why loop-first: the engine's value-level analysis can
  // sometimes fold a loop down to a concrete value (e.g.
  // when the loop bound is a global array whose declared
  // contents are empty, items.length === 0 folds the entire
  // loop to an empty string). That's a PRECISE static answer
  // but a WRONG rewrite — at runtime the loop's array can be
  // mutated by code the analyser didn't see. The loop-built
  // detector preserves the runtime iteration semantics, so we
  // prefer it whenever the source shape matches.
  //
  // parsedHtml emission is the correct fallback when the
  // value really is a concrete compile-time string with no
  // surrounding loop pattern (e.g. `el.innerHTML = "<p>hi</p>"`).
  const stmtOffsets = new Set();
  for (const ih of trace.innerHtmlAssignments || []) {
    if (!matchesFile(ih.location)) continue;
    if (ih.kind !== 'innerHTML' && ih.kind !== 'outerHTML') continue;
    // Dedup: B4 multi-variant can emit the same assignment
    // twice (once per caller variant). Skip duplicates.
    const key = ih.location.pos + ':' + ih.location.endPos;
    if (stmtOffsets.has(key)) continue;
    stmtOffsets.add(key);

    // Loop-built shape first.
    const looped = detectLoopBuiltInnerHtml(jsSource, ih.location.pos);
    if (looped) {
      replacements.push(looped);
      continue;
    }

    // Concrete value → parsedHtml tree → imperative DOM calls.
    if (ih.parsedHtml) {
      const stmtText = sliceStatement(jsSource, ih.location);
      const m = stmtText.match(/^(.+?)\.(innerHTML|outerHTML)\s*=/);
      if (!m) continue;
      const receiver = m[1];
      const body = emitDomCalls(ih.parsedHtml, receiver);
      const replacement = receiver + '.replaceChildren();\n' + body;
      replacements.push({
        start: ih.location.pos,
        end: ih.location.endPos,
        replacement,
      });
      continue;
    }
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
    const isDocWrite = text === 'Document.write' || text === 'document.write';
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
      precision: options.precision || 'precise',
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
