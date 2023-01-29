"use strict";
self.addEventListener('fetch', function (event) {
  event.respondWith(fetch(event.request).then(inject));
});

function inject(response) {
const headers = new Headers(response.headers);

headers.set('Content-Security-Policy', 'sandbox allow-top-navigation allow-scripts allow-modals allow-popups allow-presentation;');
//headers.set('X-Frame-Options', 'SAMEORIGIN');
headers.set('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
//headers.set('Cross-Origin-Embedder-Policy', 'credentialless');
headers.set('Strict-Transport-Security', 'max-age=31536000');

const policyOrigin = new URL(response.url).pathname;
switch (policyOrigin) {
  case '/tabPiP/':
    headers.set('Content-Security-Policy', '');
    break
}

return new Response(response.body, { headers: headers });
}
