// coi-serviceworker.js
//
// Cross-Origin Isolation service worker. Enables `SharedArrayBuffer`
// for static-hosted pages by intercepting the navigation request and
// re-emitting the response with Cross-Origin-Opener-Policy +
// Cross-Origin-Embedder-Policy headers.
//
// Why we need it:
//   z3-solver's WASM build was compiled with pthread support. The
//   emscripten pthread runtime uses `SharedArrayBuffer` to share
//   memory between the main thread and worker threads. Browsers
//   only expose `SharedArrayBuffer` to pages that are "cross-origin
//   isolated" — a security state entered via:
//     Cross-Origin-Opener-Policy:   same-origin
//     Cross-Origin-Embedder-Policy: credentialless
//   These must come from HTTP headers; `<meta http-equiv>` tags
//   can set COEP but not COOP, so static file servers typically
//   can't enable COI without a service worker.
//
// Why credentialless (not require-corp):
//   `credentialless` is a relaxed COEP variant that allows
//   cross-origin subresources without a CORP header, stripping
//   credentials from the request instead. This lets the page
//   continue to load Monaco from cdnjs.cloudflare.com (which
//   doesn't set CORP headers) while still being cross-origin
//   isolated. Supported in Chrome/Edge 96+, Firefox 110+.
//   Safari currently doesn't support credentialless, so the Z3
//   path won't work there — the walker will throw with the
//   clear "Z3 is not available" error instead of hanging.
//
// Lifecycle:
//   1. First page load: index.html's inline script registers this
//      SW. The SW installs + activates but doesn't control the
//      current page yet (SWs only control pages loaded AFTER
//      activation). The inline script then reloads once.
//   2. Second page load: the SW intercepts the navigation, rewrites
//      the headers, and the browser enters cross-origin isolation.
//      `window.crossOriginIsolated === true` and SAB is available.
//   3. All subsequent loads: cached SW handles it; no reload.
//
// The SW is deliberately passive — it doesn't cache anything and
// doesn't modify response bodies. Its entire job is header
// injection on the top-level navigation.

/* eslint-env serviceworker */

self.addEventListener('install', function () {
  // Skip the "waiting" phase so the SW activates as soon as it's
  // installed, rather than waiting for all pages to close.
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  // Claim any already-open clients so a manual reload (triggered
  // by the inline bootstrap script) puts them under SW control.
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', function (event) {
  // Skip requests we shouldn't touch:
  //   - `only-if-cached` with non-same-origin mode is a Firefox
  //     quirk that throws if a SW responds with anything other
  //     than the cached response.
  if (event.request.cache === 'only-if-cached' && event.request.mode !== 'same-origin') {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then(function (response) {
        // Opaque responses (status 0) can't have their headers
        // rewritten — just pass through.
        if (response.status === 0) return response;

        var newHeaders = new Headers(response.headers);
        newHeaders.set('Cross-Origin-Embedder-Policy', 'credentialless');
        newHeaders.set('Cross-Origin-Opener-Policy', 'same-origin');

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: newHeaders,
        });
      })
      .catch(function (err) {
        // Log but don't swallow — return a network error so the
        // browser surfaces the real failure.
        console.error('coi-serviceworker: fetch failed', err);
        throw err;
      })
  );
});
