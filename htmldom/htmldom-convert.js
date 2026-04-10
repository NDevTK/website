// htmldom-convert.js
//
// DOM API Conversion consumer for jsanalyze.
//
// Converts unsafe DOM sinks (innerHTML / outerHTML / document.write
// / insertAdjacentHTML) into safe createElement/appendChild/textContent
// calls. Cross-file — understands HTML pages and the JS bundles
// they reference, merges per-script output into the bundle, and
// leaves the rest of the source alone.
//
// This file is a CONSUMER of jsanalyze, not a feature of it. The
// heavy lifting — symbolic JS interpretation, virtual DOM tracking,
// loop/branch preservation, cross-file function inlining — all
// happens in the walker that's currently shipped as part of
// htmldom.js (and will become jsanalyze.js in Stage 5).
//
// Stage 4a boundary
//   This file publishes the stable conversion API but still
//   delegates the actual work to the walker implementations
//   inside htmldom.js. The delegation is a narrow, named
//   boundary so Stage 4b can lift the converter code into
//   this file without touching the API surface or tests.
//
// Public API:
//
//   const converted = await htmldomConvert.convertProject(files);
//     Cross-file: takes a {filename: content} map, returns a new
//     file map with innerHTML-containing JS files rewritten and
//     HTML pages' inline scripts extracted.
//
//   const outJs = await htmldomConvert.convertJsFile(js, preceding?, knownDomFns?);
//     Single-file: takes a JS source, returns rewritten JS with
//     DOM API calls instead of innerHTML.
//
//   const markup = await htmldomConvert.convertHtmlMarkup(html, htmlPath?, reservedIdents?);
//     Single HTML page: extracts inline scripts + handlers into
//     separate JS files the caller can process independently.
//
//   const dom = await htmldomConvert.extractAllDOM(js);
//     Diagnostic: returns the virtual DOM state the walker built
//     (elements, ops, roots, per-element HTML). Used by UI
//     inspectors and tests.
//
//   const htmls = await htmldomConvert.extractAllHTML(js);
//     Diagnostic: returns every innerHTML/outerHTML assignment
//     site with its materialized chain tokens.
//
//   const extracted = await htmldomConvert.extractHTML(js);
//     Diagnostic: the first innerHTML site's extracted HTML
//     (the historical entry point; prefer extractAllHTML).

(function () {
  'use strict';

  // === Walker delegation ===
  //
  // htmldom.js installs its API on `globalThis.__htmldomApi` at
  // the end of its async IIFE. In Node, `require('./htmldom.js')`
  // also sets `module.exports = api` at the same point. Both
  // happen AFTER the top-level `await convert()` inside the IIFE,
  // so we need to tolerate async initialization: if the api isn't
  // available yet, we wait for a microtask and retry.
  //
  // Stage 4b will move the converter functions into this file
  // directly and this delegation block becomes a simple local
  // reference.

  function resolveWalker() {
    if (typeof globalThis !== 'undefined' && globalThis.__htmldomApi) {
      return globalThis.__htmldomApi;
    }
    if (typeof module !== 'undefined' && module && typeof require === 'function') {
      try {
        const api = require('./htmldom.js');
        if (api && typeof api.convertProject === 'function') return api;
      } catch (_) { /* fall through */ }
    }
    return null;
  }

  // Yield until the walker's api is visible. htmldom.js has a
  // top-level `await convert()` so requiring it from Node returns
  // an empty object synchronously; we wait for the next microtask
  // and re-check. Bounded to ~50 iterations (5ms) so a genuine
  // missing dependency surfaces as an error rather than a hang.
  async function awaitWalker() {
    let api = resolveWalker();
    for (let i = 0; i < 50 && !api; i++) {
      await new Promise(r => setTimeout(r, 0));
      api = resolveWalker();
    }
    if (!api) throw new Error('htmldom-convert: htmldom.js walker not available');
    return api;
  }

  // === Public API ===

  async function convertProject(files, options) {
    const walker = await awaitWalker();
    // convertProject takes (files) today. Options are reserved for
    // Stage 4b when we want to pass through jsanalyze settings.
    return walker.convertProject(files);
  }

  async function convertJsFile(jsContent, precedingCode, knownDomFunctions) {
    const walker = await awaitWalker();
    return walker.convertJsFile(jsContent, precedingCode, knownDomFunctions);
  }

  async function convertHtmlMarkup(htmlContent, htmlPath, reservedIdents) {
    const walker = await awaitWalker();
    return walker.convertHtmlMarkup(htmlContent, htmlPath, reservedIdents);
  }

  async function extractHTML(input) {
    // Historical single-site extractor. Exposed through the walker
    // via globalThis.__extractHTML (set early in the IIFE by the
    // test harness). For Node consumers, fall back to walker.api
    // if available.
    if (typeof globalThis !== 'undefined' && globalThis.__extractHTML) {
      return globalThis.__extractHTML(input);
    }
    const walker = await awaitWalker();
    if (walker && walker.extractHTML) return walker.extractHTML(input);
    throw new Error('htmldom-convert: extractHTML not available');
  }

  async function extractAllHTML(input) {
    if (typeof globalThis !== 'undefined' && globalThis.__extractAllHTML) {
      return globalThis.__extractAllHTML(input);
    }
    const walker = await awaitWalker();
    if (walker && walker.extractAllHTML) return walker.extractAllHTML(input);
    throw new Error('htmldom-convert: extractAllHTML not available');
  }

  async function extractAllDOM(input) {
    if (typeof globalThis !== 'undefined' && globalThis.__extractAllDOM) {
      return globalThis.__extractAllDOM(input);
    }
    const walker = await awaitWalker();
    if (walker && walker.extractAllDOM) return walker.extractAllDOM(input);
    throw new Error('htmldom-convert: extractAllDOM not available');
  }

  // === Export ===
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
