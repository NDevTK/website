// htmldom-convert.js
//
// DOM API Conversion consumer for jsanalyze.
//
// Converts unsafe DOM sinks (innerHTML / outerHTML / document.write
// / insertAdjacentHTML) into safe createElement/appendChild/textContent
// calls. Built on the jsanalyze walker as a pure consumer — takes an
// opaque walkerInternals object and produces DOM rewrite output.
//
// Public API:
//
//   const hc = HtmldomConvert;   // browser global
//   // or const hc = require('./htmldom-convert.js');
//
//   await hc.convertProject(files, options?)
//   await hc.convertJsFile(js, precedingCode?, knownDomFunctions?)
//   await hc.convertHtmlMarkup(html, htmlPath?, reservedIdents?)
//   await hc.extractHTML(input)
//   await hc.extractAllHTML(input)
//   await hc.extractAllDOM(input)
//
// All entry points return the same shapes as the pre-Stage-4b
// implementations — jsanalyze.js's 111 behavioral equivalence tests
// and 27 converter sinks verify byte-level compatibility.
//
// Implementation:
//   The converter body is defined inside makeConverter(walker),
//   a factory that receives the walker's internal primitives
//   (tokenize, buildScopeState, classification tables, etc.)
//   via destructuring. The factory runs once per process,
//   instantiating a closure-scoped copy of the converter that
//   reads those primitives. The facade awaits the walker's api
//   (jsanalyze.js has an async top-level IIFE), installs the
//   converter, and delegates every call to it.

(function () {
  'use strict';

  // ============================================================
  // Walker resolution — wait for jsanalyze.js to finish its async
  // initialization and expose __htmldomApi / module.exports.api.
  // ============================================================
  function resolveWalker() {
    if (typeof globalThis !== 'undefined' && globalThis.__htmldomApi && globalThis.__htmldomApi._walkerInternals) {
      return globalThis.__htmldomApi;
    }
    if (typeof module !== 'undefined' && module && typeof require === 'function') {
      try {
        const api = require('./jsanalyze.js');
        if (api && api._walkerInternals) return api;
      } catch (_) { /* fall through */ }
    }
    return null;
  }

  async function awaitWalker() {
    let api = resolveWalker();
    for (let i = 0; i < 200 && !api; i++) {
      await new Promise(r => setTimeout(r, 0));
      api = resolveWalker();
    }
    if (!api) throw new Error('htmldom-convert: jsanalyze.js walker not available');
    return api;
  }

  // ============================================================
  // Converter factory — instantiated once per walker
  // ============================================================
  //
  // Every function the walker's original converter code referenced
  // is destructured here as a closure-scoped local, so the copied
  // bodies work unchanged. This is Stage 4b.1: the walker still
  // owns its own copies of these functions, but the converter now
  // reads them through this destructured interface. Stage 4b.2
  // will delete the walker's copies of the converter functions.

  function makeConverter(walker) {
    const W = walker._walkerInternals;

    // Destructure walker primitives so the copied converter
    // bodies can reference them by their original names without
    // code changes.
    const tokenize                = W.tokenize;
    const tokenizeHtml            = W.tokenizeHtml;
    const decodeHtmlEntities      = W.decodeHtmlEntities;
    const decodeJsString          = W.decodeJsString;
    const serializeHtmlTokens     = W.serializeHtmlTokens;
    const parseStyleDecls         = W.parseStyleDecls;
    const scanMutations           = W.scanMutations;
    const buildScopeState         = W.buildScopeState;
    const extractHTML             = W.extractHTML;
    const extractAllHTML          = W.extractAllHTML;
    const extractAllDOM           = W.extractAllDOM;
    const collectChainTaint       = W.collectChainTaint;
    const getElementTag           = W.getElementTag;
    const isSanitizer             = W.isSanitizer;
    const isNavSink               = W.isNavSink;
    const isIdlProp               = W.isIdlProp;
    const classifySink            = W.classifySink;
    const countLines              = W.countLines;
    const makeVar                 = W.makeVar;
    const jsStr                   = W.jsStr;
    const IDENT_RE                = W.IDENT_RE;
    const PATH_RE                 = W.PATH_RE;
    const ATTR_TO_PROP            = W.ATTR_TO_PROP;
    const BOOLEAN_ATTRS           = W.BOOLEAN_ATTRS;
    const VOID_ELEMENTS           = W.VOID_ELEMENTS;
    const SVG_TAGS                = W.SVG_TAGS;
    const NAV_SAFE_FILTER         = W.NAV_SAFE_FILTER;
    const TAINT_SANITIZERS        = W.TAINT_SANITIZERS;

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

    return {
      convertHtmlBuilderFunctions,
      convertRaw,
      summarizeDomConstruction,
      convertOne,
      resolveRelativePath,
      findPageScripts,
      filterUnsafeSinks,
      convertJsFile,
      convertHtmlMarkup,
      convertProject,
    };
  }

  // ============================================================
  // Facade — delegates to the converter factory
  // ============================================================
  //
  // Lazily resolves the walker and instantiates the converter
  // once, then caches the instance. Each public method delegates
  // to the corresponding factory method. Walker diagnostic
  // functions (extractHTML, extractAllHTML, extractAllDOM) pass
  // through to the walker's own implementations since they're
  // still owned by jsanalyze.js.

  let _converter = null;
  let _converterPromise = null;
  async function getConverter() {
    if (_converter) return _converter;
    if (_converterPromise) return _converterPromise;
    _converterPromise = (async () => {
      const walker = await awaitWalker();
      _converter = makeConverter(walker);
      return _converter;
    })();
    return _converterPromise;
  }

  async function convertProject(files, options) {
    const c = await getConverter();
    return c.convertProject(files, options);
  }

  async function convertJsFile(jsContent, precedingCode, knownDomFunctions) {
    const c = await getConverter();
    return c.convertJsFile(jsContent, precedingCode, knownDomFunctions);
  }

  async function convertHtmlMarkup(htmlContent, htmlPath, reservedIdents) {
    const c = await getConverter();
    return c.convertHtmlMarkup(htmlContent, htmlPath, reservedIdents);
  }

  async function extractHTML(input) {
    const walker = await awaitWalker();
    return walker._walkerInternals.extractHTML(input);
  }

  async function extractAllHTML(input) {
    const walker = await awaitWalker();
    return walker._walkerInternals.extractAllHTML(input);
  }

  async function extractAllDOM(input) {
    const walker = await awaitWalker();
    return walker._walkerInternals.extractAllDOM(input);
  }

  // ============================================================
  // Export
  // ============================================================
  const api = Object.freeze({
    schemaVersion: '1',
    convertProject,
    convertJsFile,
    convertHtmlMarkup,
    extractHTML,
    extractAllHTML,
    extractAllDOM,
  });

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.HtmldomConvert = api;
  }
})();
