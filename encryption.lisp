;;;; encryption.lisp

(in-package #:cl-web-push)

;; RFC 8291: Message Encryption for Web Push
;; We need to implement:
;; 1. ECDH (Elliptic Curve Diffie-Hellman) using P-256 (prime256v1/secp256r1)
;; 2. HKDF (HMAC-based Extract-and-Expand Key Derivation Function) - RFC 5869
;; 3. AES-128-GCM

;; Conversion of uncompressed EC point format used by Web Push Protocol
;; 0x04 || X || Y
(defun serialize-public-key (pub-key)
  "Convert an Ironclad secp256r1 public key to Web Push standard uncompressed representation.
   Web Push expects the 0x04 uncompressed format identifier."
  (let ((y-bytes (ironclad:secp256r1-key-y pub-key)))
    (when (or (not y-bytes) (= (length y-bytes) 0))
      (error "Cannot serialize public key: Ironclad returned empty Y bytes."))
    ;; y-bytes inside ironclad secp256r1 implementation is actually the concatenation of X and Y
    ;; AND IT ALREADY INCLUDES THE 0x04 UNCOMPRESSED MARKER IN IRONCLAD > 0.50!
    ;; Let's check if the format identifier is already present:
    (if (and (> (length y-bytes) 0) (= (aref y-bytes 0) 4) (= (length y-bytes) 65))
        y-bytes
        (let ((result (make-array (1+ (length y-bytes)) :element-type '(unsigned-byte 8))))
          (setf (aref result 0) 4) ; 0x04 Uncompressed
          (replace result y-bytes :start1 1)
          result))))

(defun derive-shared-secret (private-key public-key)
  "Derive the shared secret using ECDH."
  ;; Defend against malformed ironclad public keys lacking proper coordinates
  (let ((y-bytes (ironclad:secp256r1-key-y public-key)))
    (when (or (not y-bytes) (= (length y-bytes) 0))
      (error "Malformated ironclad secp256r1 public key logic object structurally missing initialized EC point coordinate arrays!")))
  ;; public-key object should already be reconstructed into format supported by diffie-hellman
  (ironclad:diffie-hellman private-key public-key))

(defun hkdf-extract (salt ikm)
  "HKDF-Extract(salt, ikm) -> PRK"
  (let ((hmac (ironclad:make-mac :hmac salt :sha256)))
    (ironclad:update-mac hmac ikm)
    (ironclad:produce-mac hmac)))

(defun hkdf-expand (prk info length)
  "HKDF-Expand(prk, info, length) -> OKM"
  ;; T(0) = empty string
  ;; T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
  ;; OKM = T(1) | T(2) | ... | T(n)
  (let ((hmac (ironclad:make-mac :hmac prk :sha256))
        (okm (make-array length :element-type '(unsigned-byte 8)))
        (t-prev (make-array 0 :element-type '(unsigned-byte 8))) 
        (i 1))
    (loop for pos from 0 below length by 32
          do (let ((t-i (progn
                          ;; We need a fresh hmac context for each block T(i) expansion
                          (let ((block-hmac (ironclad:make-mac :hmac prk :sha256)))
                            (when (> (length t-prev) 0) 
                              (ironclad:update-mac block-hmac t-prev))
                            (ironclad:update-mac block-hmac info)
                            (ironclad:update-mac block-hmac (make-array 1 :element-type '(unsigned-byte 8) :initial-element i))
                            (ironclad:produce-mac block-hmac)))))
               (replace okm t-i :start1 pos)
               (setf t-prev t-i)
               (incf i)))
    (subseq okm 0 length)))

(defun aes-gcm-encrypt (key nonce plaintext associated-data)
  "Encrypts plaintext using AES-GCM, returning (VALUES CIPHERTEXT AUTH-TAG).
   Key should be 16 bytes (AES-128). Nonce is typically 12 bytes but padded here to 16 for CTR/GMAC."
  (let* ((padded-nonce (if (= (length nonce) 12)
                           (let ((pad (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
                             (replace pad nonce)
                             ;; The standard counter padding for a 96-bit nonce appends 0x00000001
                             (setf (aref pad 15) 1) 
                             pad)
                           nonce))
         (ciphertext (make-array (length plaintext) :element-type '(unsigned-byte 8)))
         (cipher (ironclad:make-cipher :aes :key key :mode :ctr :initialization-vector padded-nonce))
         ;; MAKE-GMAC expects: ironclad:make-mac :gmac key cipher-name initialization-vector
         (gmac (ironclad:make-mac :gmac key :aes padded-nonce)))
    (when (and associated-data (> (length associated-data) 0))
       (ironclad:update-mac gmac associated-data))
    (when (> (length plaintext) 0)
      (ironclad:encrypt cipher plaintext ciphertext)
      (ironclad:update-mac gmac ciphertext))
    ;; GMAC typically requires the length of AAD and Ciphertext appended:
    (let ((len-block (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (when (> (length associated-data) 0)
        (setf (nibbles:ub64ref/be len-block 0) (* 8 (length associated-data))))
      (setf (nibbles:ub64ref/be len-block 8) (* 8 (length ciphertext)))
      (ironclad:update-mac gmac len-block))
    (values ciphertext (ironclad:produce-mac gmac))))

(defun build-info (type client-public-key server-public-key)
  "Construct the 'info' parameter for Web Push HKDF."
  ;; "WebPush: info" || 0x00 || client_public_key || server_public_key
  (let* ((prefix (ironclad:ascii-string-to-byte-array (format nil "WebPush: ~A~A" type (code-char 0))))
         (prefix-len (length prefix))
         (client-len (length client-public-key))
         (server-len (length server-public-key))
         (info (make-array (+ prefix-len client-len server-len) :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace info prefix :start1 0)
    (replace info client-public-key :start1 prefix-len)
    (replace info server-public-key :start1 (+ prefix-len client-len))
    info))

(defun encrypt-payload (payload client-auth-secret client-public-key server-private-key server-public-key salt)
  "Encrypt payload using AES-GCM (RFC 8291)."
  (let* ((shared-secret (derive-shared-secret server-private-key client-public-key))
         ;; 1. key_info = "WebPush: info" || 0x00 || client_public_key || server_public_key
         (key-info (build-info "info" (serialize-public-key client-public-key) (serialize-public-key server-public-key)))
         ;; 2. PRK = HKDF-Extract(auth_secret, shared_secret)
         (prk (hkdf-extract client-auth-secret shared-secret))
         ;; 3. IKM = HKDF-Expand(PRK, key_info, 32)
         (ikm (hkdf-expand prk key-info 32))
         
         ;; 4. salt is 16 bytes
         ;; 5. PRK_key = HKDF-Extract(salt, IKM)
         (prk-key (hkdf-extract salt ikm))
         
         ;; 6. CEK = HKDF-Expand(PRK_key, "Content-Encoding: aes128gcm" || 0x00, 16)
         (cek-info (ironclad:ascii-string-to-byte-array (format nil "Content-Encoding: aes128gcm~A" (code-char 0))))
         (cek (hkdf-expand prk-key cek-info 16))
         
         ;; 7. NONCE = HKDF-Expand(PRK_key, "Content-Encoding: nonce" || 0x00, 12)
         (nonce-info (ironclad:ascii-string-to-byte-array (format nil "Content-Encoding: nonce~A" (code-char 0))))
         (nonce (hkdf-expand prk-key nonce-info 12)))
    
    ;; Pad payload with 0x02 block (padding delimiter for aes128gcm per RFC 8291)
    (let* ((padded-payload (make-array (+ (length payload) 2) :element-type '(unsigned-byte 8) :initial-element 0)))
      (replace padded-payload payload)
      (setf (aref padded-payload (length payload)) 2) ;; Padding delimiter
      (let ((empty-aad (make-array 0 :element-type '(unsigned-byte 8))))
        (multiple-value-bind (ciphertext tag) (aes-gcm-encrypt cek nonce padded-payload empty-aad)
          (let ((result (make-array (+ (length ciphertext) (length tag)) :element-type '(unsigned-byte 8))))
            (replace result ciphertext)
            (replace result tag :start1 (length ciphertext))
            result))))))