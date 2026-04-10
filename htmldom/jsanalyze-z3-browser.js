// jsanalyze-z3-browser.js
//
// Browser bootstrap for z3-solver. Must be loaded BEFORE jsanalyze.js
// so that jsanalyze.js's `_initZ3` can pick up the pre-registered
// `globalThis.__htmldomZ3Init` hook on its first branch.
//
// This file does three things that z3-solver's browser build
// requires and doesn't do itself:
//
//   1. Shims `window.global = window`. z3-solver's browser build
//      reads `global.initZ3` as a Node-style idiom. Browsers don't
//      define `global`, so we alias it to window. The shim is a
//      no-op if something else on the page has already set it.
//
//   2. Loads `vendor/z3-solver/z3-built.js` as a classic <script>
//      tag. That file is a UMD WASM loader that declares
//      `var initZ3 = (...)();` at top level, which in classic-script
//      context becomes a `window.initZ3` property. ESM import
//      cannot be used here — top-level `var` in an ES module
//      does NOT create a window property.
//
//      z3-built.js in turn fetches z3-built.wasm relative to its
//      own URL via `document.currentScript?.src`. Our vendor copy
//      sits at `htmldom/vendor/z3-solver/`, so the wasm file is
//      resolved to `htmldom/vendor/z3-solver/z3-built.wasm` —
//      which we vendor alongside.
//
//   3. Dynamic-imports the pre-bundled ESM wrapper
//      `vendor/z3-solver/browser.esm.js`. That file was bundled
//      with esbuild at vendor time so its nested CommonJS
//      `require('./high-level')` / `require('./low-level')` calls
//      are resolved into one self-contained module. Its default
//      export is the original browser.js module, which exposes
//      `init` — the high-level entry point that z3-solver's docs
//      tell you to await.
//
//      init() reads `global.initZ3` (now aliased to
//      window.initZ3 via step 1 + 2) and wires it into the
//      low-level loader, returning { Z3, Context, Solver, ... }.
//
// After all three steps, we expose a single function on
// `globalThis.__htmldomZ3Init` that jsanalyze.js's _initZ3 will
// call instead of its CDN fallback paths. The function is lazy —
// the bootstrap work only runs when the walker first needs Z3,
// not at page load, so an analyzer session that never hits an
// SMT path avoids the 33 MB wasm download entirely.
//
// This file is idempotent: if called twice, the second call
// returns the same cached promise.

(function () {
  'use strict';

  if (typeof window === 'undefined' || typeof document === 'undefined') {
    // Not in a browser — nothing to do. Node uses require('z3-solver')
    // directly in jsanalyze.js's _initZ3.
    return;
  }

  // Where the vendor files live. This path is relative to the page
  // that loads jsanalyze-z3-browser.js — i.e. relative to index.html.
  var VENDOR_DIR = 'vendor/z3-solver/';

  // Cached promise for the init function. The lazy bootstrap only
  // runs on first invocation, and only once.
  var _initPromise = null;

  function loadClassicScript(src) {
    return new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = src;
      s.async = false;
      s.onload = function () { resolve(); };
      s.onerror = function () {
        reject(new Error('jsanalyze-z3-browser: failed to load ' + src + ' — is vendor/z3-solver/ populated? See README.'));
      };
      document.head.appendChild(s);
    });
  }

  async function initZ3Browser() {
    // Step 1: alias `global` to `window`.
    if (typeof window.global === 'undefined') {
      window.global = window;
    }

    // Step 2: load z3-built.js so it populates window.initZ3.
    // Resolve against document.baseURI so this works regardless
    // of whether the page is served at the site root or a subpath.
    if (typeof window.initZ3 !== 'function') {
      var z3BuiltUrl = new URL(VENDOR_DIR + 'z3-built.js', document.baseURI).href;
      await loadClassicScript(z3BuiltUrl);
      if (typeof window.initZ3 !== 'function') {
        throw new Error('jsanalyze-z3-browser: z3-built.js loaded but window.initZ3 is not a function');
      }
    }

    // Step 3: dynamic-import the pre-bundled ESM wrapper.
    //
    // Dynamic import() treats its argument as a *module specifier*,
    // not a URL — which means a bare-looking string like
    // 'vendor/z3-solver/browser.esm.js' is rejected with
    // "Failed to resolve module specifier". We build an absolute
    // URL from the current document's base URI so the path is
    // unambiguous regardless of how the page is served (subpath,
    // dev server, production, etc.).
    var esmUrl = new URL(VENDOR_DIR + 'browser.esm.js', document.baseURI).href;
    var mod = await import(esmUrl);
    // The esbuild bundle uses `export default require_browser()`
    // so `mod.default` is the z3-solver browser.js module object.
    // Fall back to direct exports if a future bundle variant
    // re-exports `init` at the top level.
    var browserModule = mod.default || mod;
    if (typeof browserModule.init !== 'function') {
      throw new Error('jsanalyze-z3-browser: browser.esm.js has no init() export');
    }
    return browserModule.init;
  }

  // Lazily expose on globalThis. jsanalyze.js's _initZ3 checks
  // `typeof globalThis.__htmldomZ3Init === 'function'` first; we
  // satisfy that check by registering a wrapper that defers the
  // actual bootstrap until it's called.
  globalThis.__htmldomZ3Init = async function () {
    if (!_initPromise) {
      _initPromise = initZ3Browser();
    }
    var init = await _initPromise;
    return await init();
  };
})();
