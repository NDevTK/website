// coi-register.js
//
// Registers `coi-serviceworker.js` so the page becomes cross-origin
// isolated and `SharedArrayBuffer` (needed by Z3's pthread WASM
// build) is available. Must be loaded from index.html BEFORE any
// script that might touch Z3 — e.g. before monaco-init.js kicks
// off the analyzer pipeline.
//
// First load:  SW is registered but not yet controlling the page.
//              We set a session-storage flag and reload once; the
//              reload enters SW-controlled territory and SAB
//              becomes available on `window.crossOriginIsolated`.
// Next loads:  SW is already controlling, crossOriginIsolated is
//              true, nothing happens.
//
// The session-storage flag prevents reload loops in environments
// where the SW fails to enable isolation (e.g. Safari, which
// doesn't yet support `credentialless` COEP mode).

(function () {
  'use strict';

  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) {
    return;
  }
  if (location.protocol === 'file:') {
    // Service workers aren't allowed for file:// pages.
    return;
  }

  if (window.crossOriginIsolated) {
    // Already isolated — SW must have taken effect on a previous
    // load. Clear any leftover reload flag.
    sessionStorage.removeItem('__coiReloaded');
    return;
  }

  navigator.serviceWorker.register('coi-serviceworker.js').then(function () {
    if (!window.crossOriginIsolated) {
      // The SW is installed but isn't controlling this page yet.
      // A single reload hands control over and enables SAB. The
      // session-storage guard prevents a reload loop if the
      // browser doesn't honour our headers (Safari today).
      if (!sessionStorage.getItem('__coiReloaded')) {
        sessionStorage.setItem('__coiReloaded', '1');
        window.location.reload();
      } else {
        // Reload already attempted and still not isolated — give
        // up quietly. jsanalyze's _initZ3 will surface a clear
        // error when the walker next hits an SMT-reachable path.
        console.warn('coi-serviceworker: page is not cross-origin isolated after reload; Z3 will be unavailable.');
      }
    }
  }).catch(function (e) {
    console.error('coi-serviceworker: registration failed', e);
  });
})();
