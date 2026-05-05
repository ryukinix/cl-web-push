# cl-web-push

A native Common Lisp library for the Web Push Protocol (RFC 8291). It
provides a full, from-scratch implementation of elliptic curve
Diffie-Hellman encryption, HKDF key scaling, and AES-GCM symmetric
block cipher logic alongside complete support for Voluntary
Application Server Identification (VAPID) authentications to dispatch
standardized pushes to any compatible browser.

## Features

- **Native VAPID generation and JWT Signing:** Leverages `ironclad` to
  handle ECDSA curve arithmetic and `P-256` keys natively.
- **Zero-Dependency Cryptography logic:** No wrapping of bindings for
  libsodium. We natively pad, build the AAD sequence blocks, and
  manipulate the HKDF extractions manually implementing `WebPush:
  info` logic over `ironclad`'s low-level block structures.
- **HTTP Push integration:** Fully constructs the payload, salt
  headers, and signature and dispatches them accurately to the
  endpoint via `dexador`.

## Installation

As this project is brand new, either clone the repo locally into your
`quicklisp/local-projects` folder or append its path dynamically.

```sh
cd ~/quicklisp/local-projects
git clone https://github.com/ryukinix/cl-web-push.git
```

Load it from quicklisp:

```common-lisp
(ql:quickload :cl-web-push)
```

## Usage

### 1. Generating your VAPID Keys

To send a push notification, you need your server application
keys. You can generate them sequentially using the built-in CLI tool
from your terminal shell easily without spinning the REPL:

```sh
sbcl --eval '(ql:quickload :cl-web-push)' --eval '(cl-web-push:generate-keys-cli)' --quit
```

This will output your standard `.env` variables that you should store
securely in your production backend environment:

```env
VAPID_PUBLIC_KEY=BLjgN2iS...
VAPID_PRIVATE_KEY=kCfzN6...
```

For generating programmatically inside Lisp:
```common-lisp
(multiple-value-bind (public private) (cl-web-push:generate-vapid-keys)
  (format t "Public: ~A~%" public)
  (format t "Private: ~A~%" private))
```

### 2. Dispatching a payload

With the VAPID parameters ready and the JSON endpoint data supplied by
your subscribed client (which contains the `endpoint`, `keys.p256dh`,
and `keys.auth`):

```common-lisp
;; Example Client JSON payload from your frontend `pushManager.subscribe` call
(defparameter *subscription-json*
  "{
    \"endpoint\": \"https://updates.push.services.mozilla.com/wpush/v2/gAAAAAB...\",
    \"keys\": {
      \"auth\": \"wXn7G-_2hYgZ...\",
      \"p256dh\": \"BHT...\"
    }
  }")

(cl-web-push:send-push-notification
 *subscription-json*
 "Hello! This is a push notification from Common Lisp." ; Your raw string payload
 *vapid-public-key*  ; The string exported from generate-vapid-keys
 *vapid-private-key* ; The string exported from generate-vapid-keys
 "mailto:admin@example.com") ;; Contact subject email
```

## Running the Unit Tests

Test behaviors are written inside `test-suite.lisp`. We enforce
coverage using Parachute.

```common-lisp
(asdf:test-system :cl-web-push)
```

## Ironclad Encryption Limitations

While `ironclad` is a powerful and essential cryptographic library for
Common Lisp, it does not currently provide a native, high-level
Application Programming Interface (API) for Authenticated Encryption
with Associated Data (AEAD) specifically using the AES-GCM
(Galois/Counter Mode) composition required by RFC 8291.

Although `ironclad` supports Counter (CTR) mode and Galois Message
Authentication Code (GMAC), its internal GMAC implementation does not
cleanly expose the discrete structure necessary to format the exact
padding sequences of the Associated Data (AAD) and the Ciphertext
lengths, nor does it allow injecting a derived $J_0$ mask
transparently for the final XOR tagging.

Because the Web Push protocol imposes strict byte-level padding
restrictions on the payload blocks before evaluating the
Authentication Tag, `cl-web-push` bypasses `ironclad`'s high-level MAC
wrappers. Instead, it utilizes `ironclad` solely for AES-CTR
encryption and ECB block transformations, and implements a manual
mathematical GHASH function over the Galois Field $GF(2^{128})$
natively in Lisp. This ensures that the generated cryptographic tags
align perfectly with the standard test vectors provided by the IETF
for AES128GCM payload encryption.
