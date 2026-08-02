// coi-register.js
//
// Registers `coi-serviceworker.js` so the page becomes cross-origin
// isolated and `SharedArrayBuffer` (needed by Z3's pthread WASM
// build) is available. Must be loaded from index.html BEFORE any
// script that might touch Z3 — e.g. before monaco-init.js kicks
// off the analyzer pipeline.
//
// First load:  SW is registered but not yet controlling the page.
//              Once it IS controlling, we reload once; the reload's
//              navigation goes through the SW, which adds the COOP +
//              COEP headers, and SAB becomes available on
//              `window.crossOriginIsolated`.
// Next loads:  SW is already controlling, crossOriginIsolated is
//              true, nothing happens.
//
// Reloading only once the SW controls this page is the whole
// subtlety here. `register()` resolves as soon as the registration
// EXISTS — the worker may still be installing, and `clients.claim()`
// in its activate handler has certainly not run yet. Reloading at
// that moment is a race: the second navigation is served without
// the SW about a quarter of the time, the page is not isolated,
// and the reload guard below then makes that permanent for the
// session — Z3 silently unavailable for the rest of the visit.
//
// So we wait for two things instead of guessing:
//
//   * `navigator.serviceWorker.ready` — resolves when a worker is
//     ACTIVE for this scope.
//   * a controller — `ready` does not imply the current page is
//     controlled, because a page loaded before activation stays
//     uncontrolled until `clients.claim()` takes effect. That
//     hand-over fires `controllerchange`, so we wait for it when
//     the controller isn't already there.
//
// The session-storage flag remains as the anti-loop backstop for
// environments where the SW controls the page but the browser
// still won't isolate it (Safari, which doesn't support the
// `credentialless` COEP mode).

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

  // Reload once, now that the SW is in a position to serve the
  // navigation. Guarded so a browser that ignores the headers
  // can't put us in a reload loop.
  function reloadUnderServiceWorker() {
    if (window.crossOriginIsolated) return;
    if (sessionStorage.getItem('__coiReloaded')) {
      // Already reloaded under SW control and still not isolated —
      // the browser doesn't honour the headers. Give up quietly;
      // jsanalyze's _initZ3 surfaces a clear error when the walker
      // next hits an SMT-reachable path.
      console.warn('coi-serviceworker: page is controlled by the service worker but ' +
        'still not cross-origin isolated; Z3 will be unavailable.');
      return;
    }
    sessionStorage.setItem('__coiReloaded', '1');
    window.location.reload();
  }

  navigator.serviceWorker.register('coi-serviceworker.js')
    .then(function () {
      // Wait for an ACTIVE worker before considering a reload.
      return navigator.serviceWorker.ready;
    })
    .then(function () {
      if (navigator.serviceWorker.controller) {
        reloadUnderServiceWorker();
        return;
      }
      // Active but not yet controlling this page. The worker's
      // activate handler calls clients.claim(), which hands
      // control over asynchronously and fires controllerchange.
      navigator.serviceWorker.addEventListener(
        'controllerchange', reloadUnderServiceWorker, { once: true });
    })
    .catch(function (e) {
      console.error('coi-serviceworker: registration failed', e);
    });
})();
