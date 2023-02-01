"use strict";
self.addEventListener('fetch', function (event) {
  event.respondWith(fetch(event.request).then(inject));
});

function inject(response) {
const headers = new Headers(response.headers);

const sandboxAPI = new Headers();
sandboxAPI.set('Cross-Origin-Opener-Policy', 'same-origin');
sandboxAPI.set('Access-Control-Allow-Origin', '*');
sandboxAPI.set('Content-Security-Policy', 'sandbox');

headers.set('Content-Security-Policy', 'sandbox allow-top-navigation allow-scripts allow-modals allow-popups allow-presentation;');
//headers.set('X-Frame-Options', 'SAMEORIGIN');
headers.set('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
//headers.set('Cross-Origin-Embedder-Policy', 'credentialless');
headers.set('Strict-Transport-Security', 'max-age=31536000');

try {
  const policyURL = new URL(response.url);
  if (policyURL.protocol !== 'https:' || policyURL.origin !== 'https://ndev.tk') throw Untrusted;
  switch (policyURL.pathname) {
    case '/tabPiP/':
      headers.set('Content-Security-Policy', '');
      break
    case '/sandboxAPI/'
      return new Response('OK', { headers: sandboxAPI });
      break
  }
} catch {
  return new Response('policyOrigin error');
}

return new Response(response.body, { headers: headers });
}
