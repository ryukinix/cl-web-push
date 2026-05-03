self.addEventListener('push', function(event) {
  console.log('[Service Worker] Push Received.');

  let payload = 'Default message fallback';
  
  if (event.data) {
    payload = event.data.text();
    console.log('[Service Worker] Push had this data: ', payload);
  }

  const title = 'CL Web Push';
  const options = {
    body: payload,
    icon: 'https://lisp-lang.org/favicon-32x32.png'
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(event) {
  console.log('[Service Worker] Notification click Received.');
  event.notification.close();
});