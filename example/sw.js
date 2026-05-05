self.addEventListener('push', function(event) {
  console.log('[Service Worker] Push event fired!', event);

  let payload = 'Default message fallback';
  
  if (event.data) {
    try {
      payload = event.data.text();
      console.log('[Service Worker] Push payload text: ', payload);
    } catch (e) {
      console.error('[Service Worker] Failed to read push data. Decryption issue?', e);
      payload = 'Decryption error';
    }
  } else {
    console.warn('[Service Worker] Push event received but event.data is null. This usually means the browser could not decrypt the payload.');
  }

  const title = 'CL Web Push';
  const options = {
    body: payload,
    icon: 'https://lisp-lang.org/favicon-32x32.png'
  };

  // Notify all clients (pages) that a push was received
  event.waitUntil(
    self.clients.matchAll().then(clients => {
      clients.forEach(client => client.postMessage('received'));
    })
  );

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(event) {
  console.log('[Service Worker] Notification click Received.');
  event.notification.close();
});

self.addEventListener('pushsubscriptionchange', function(event) {
  console.log('[Service Worker]: \'pushsubscriptionchange\' event fired.');
});

self.addEventListener('error', function(event) {
  console.error('[Service Worker] Global error: ', event);
});