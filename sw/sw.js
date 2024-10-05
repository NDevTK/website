"use strict";
self.addEventListener('fetch', function (event) {
  event.respondWith(hook);
});

async function hook(event) {
  console.log(event);
  return new Response('Hello from SW.');
}
