// jsanalyze-z3-browser.js
//
// Browser bootstrap for z3-solver. Must be loaded BEFORE the
// jsanalyze browser bundle so that src/z3.js's `_initZ3` can
// pick up the pre-registered `globalThis.__htmldomZ3Init` hook
// on its first branch.
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
//      z3-built.js in turn fetches z3-built.wasm relative to
//      its own URL via `document.currentScript?.src`. The
//      single canonical vendor copy sits under
//      `jsanalyze/vendor/z3-solver/`, so the wasm file is
//      resolved relative to that directory.
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
// `globalThis.__htmldomZ3Init` that jsanalyze/src/z3.js's
// _initZ3 picks up on its first branch. The function is lazy —
// the bootstrap work only runs when the walker first needs Z3,
// not at page load, so an analyzer session that never hits an
// SMT path avoids the 33 MB wasm download entirely.
//
// This file is idempotent: if called twice, the second call
// returns the same cached promise.

(function () {
  'use strict';

  if (typeof window === 'undefined' || typeof document === 'undefined') {
    // Not in a browser — nothing to do. Node uses
    // require('z3-solver') directly in jsanalyze/src/z3.js's
    // _initZ3.
    return;
  }

  // Where the vendor files live. This path is relative to
  // the page that loads this script (index.html in the
  // analyzer/ directory). We point at the single canonical
  // vendor copy under jsanalyze/vendor/z3-solver/ so we're
  // not duplicating the 33 MB wasm.
  var VENDOR_DIR = '../jsanalyze/vendor/z3-solver/';

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

  // Wrap window.initZ3 so every invocation gets a Module object
  // carrying `mainScriptUrlOrBlob` (pointing at a Blob of
  // z3-built.js's source) plus a watchdog around async_call.
  // browser.esm.js calls `await initZ3()` with no arguments, so
  // without this wrapper Emscripten uses `_scriptName`
  // (document.currentScript.src captured at load time) as the
  // pthread worker's script URL, which re-fetches z3-built.js
  // through the COI service worker on every pthread spawn.
  //
  // SW-intercepted worker-script fetches terminate silently in
  // Chromium — the worker fires a plain `Event` on `onerror`
  // with `message` / `filename` / `lineno` / `error` all
  // undefined, so the pthread looks like it died for no reason
  // and async_call's capability is never resolved (the await
  // hangs forever). Passing a pre-built Blob makes emscripten
  // call `URL.createObjectURL` on it and use the resulting
  // `blob:` URL for `new Worker`, which never hits the SW.
  // `worker-src 'self' blob: data:` in the page's CSP covers
  // the blob-URL worker.
  //
  // The watchdog around `async_call` is defensive: if a pthread
  // ever dies silently again (any future SW change, a Z3 wasm
  // abort, etc.), the main-thread await rejects after the
  // budget instead of hanging, so the bridge's per-consumer
  // catch can recover and report an error.
  //
  // Idempotent via a sentinel flag.
  function installInitZ3Wrapper(z3BuiltBlob) {
    if (window.__htmldomZ3InitWrapped) return;
    window.__htmldomZ3InitWrapped = true;
    var origInitZ3 = window.initZ3;
    window.initZ3 = function (moduleArg) {
      moduleArg = moduleArg || {};
      if (z3BuiltBlob && !moduleArg.mainScriptUrlOrBlob) {
        moduleArg.mainScriptUrlOrBlob = z3BuiltBlob;
      }
      // Surface emscripten's own abort/assertion output — these
      // are the only signals we get when a WASM trap fires, and
      // they go to printErr before the worker onerror does. Low
      // volume; left unconditionally enabled.
      var userPrintErr = moduleArg.printErr;
      var userOnAbort  = moduleArg.onAbort;
      moduleArg.printErr = function () {
        var args = Array.prototype.slice.call(arguments);
        console.error.apply(console, ['[z3]'].concat(args));
        if (typeof userPrintErr === 'function') userPrintErr.apply(this, args);
      };
      moduleArg.onAbort = function (reason) {
        console.error('[z3] abort', reason);
        if (typeof userOnAbort === 'function') userOnAbort.call(this, reason);
      };
      var promise = origInitZ3.call(this, moduleArg);
      // Emscripten's factory assigns `moduleArg.async_call`
      // synchronously before returning the promise (see
      // z3-built.js's `Module.async_call = function (f, ...)`
      // at the top of the factory body). Wrap it now.
      if (typeof moduleArg.async_call === 'function') {
        var origAsyncCall = moduleArg.async_call;
        moduleArg.async_call = function (f) {
          var args = Array.prototype.slice.call(arguments, 1);
          return new Promise(function (resolve, reject) {
            var watchdog = setTimeout(function () {
              reject(new Error('z3 async_call watchdog timed out — pthread worker likely died silently'));
            }, 15000);
            var inner;
            try {
              inner = origAsyncCall.apply(moduleArg, [f].concat(args));
            } catch (syncErr) {
              clearTimeout(watchdog);
              reject(syncErr);
              return;
            }
            Promise.resolve(inner).then(
              function (v) { clearTimeout(watchdog); resolve(v); },
              function (e) { clearTimeout(watchdog); reject(e); }
            );
          });
        };
      }
      return promise;
    };
  }

  // Fetch z3-built.js as a Blob so we can hand it to
  // `Module.mainScriptUrlOrBlob`. Returns null on failure
  // (caller falls back to the script-URL path, which will hit
  // the SW-interception issue again — but at least we'll see
  // the fetch-failure reason in the console).
  async function fetchZ3BuiltBlob(z3BuiltUrl) {
    try {
      var resp = await fetch(z3BuiltUrl, { credentials: 'same-origin' });
      if (!resp.ok) {
        console.warn('jsanalyze-z3-browser: fetch z3-built.js failed status=', resp.status);
        return null;
      }
      return await resp.blob();
    } catch (err) {
      console.warn('jsanalyze-z3-browser: fetch z3-built.js threw', err);
      return null;
    }
  }

  async function initZ3Browser() {
    // Step 1: alias `global` to `window`.
    if (typeof window.global === 'undefined') {
      window.global = window;
    }

    // Step 2: load z3-built.js so it populates window.initZ3.
    // Resolve against document.baseURI so this works regardless
    // of whether the page is served at the site root or a subpath.
    var z3BuiltUrl = new URL(VENDOR_DIR + 'z3-built.js', document.baseURI).href;
    var blobPromise = fetchZ3BuiltBlob(z3BuiltUrl);
    if (typeof window.initZ3 !== 'function') {
      await loadClassicScript(z3BuiltUrl);
      if (typeof window.initZ3 !== 'function') {
        throw new Error('jsanalyze-z3-browser: z3-built.js loaded but window.initZ3 is not a function');
      }
    }
    var z3BuiltBlob = await blobPromise;
    installInitZ3Wrapper(z3BuiltBlob);

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
