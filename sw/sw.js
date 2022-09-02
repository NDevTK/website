"use strict";
self.addEventListener('fetch', function (event) {
  event.respondWith(fetch(event.request).then(inject));
});

function inject(response) {
const headers = new Headers(response.headers);
headers.set('Cross-Origin-Opener-Policy', 'same-origin');
headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
return new Response(response.body, { headers: headers });
}
