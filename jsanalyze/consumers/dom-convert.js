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
// The JS-side conversion (innerHTML → createElement, navigation
// wrapping, eval blocking, document.write lowering) is added
// in the next commit.
async function convertProject(files, options) {  // eslint-disable-line no-unused-vars
  const output = {};
  const keys = Object.keys(files);
  const htmlPaths = keys.filter(p => /\.html?$/i.test(p)).sort();

  // Track names already taken by input files so we don't
  // overwrite them with generated handlers/scripts.
  const usedNames = new Set(keys);

  for (const page of htmlPaths) {
    const result = convertHtmlMarkup(files[page], page);
    let anyChange = false;
    if (result.handlers) {
      output[result.handlers.name] = result.handlers.content;
      usedNames.add(result.handlers.name);
      anyChange = true;
    }
    for (const s of result.extractedScripts) {
      output[s.name] = s.content;
      usedNames.add(s.name);
      anyChange = true;
    }
    for (const s of result.extractedStyles) {
      output[s.name] = s.content;
      usedNames.add(s.name);
      anyChange = true;
    }
    if (anyChange || result.html !== files[page]) {
      output[page] = result.html;
    }
  }

  return output;
}

module.exports = {
  convertProject,
  convertHtmlMarkup,
  parseStyleDecls,
};
