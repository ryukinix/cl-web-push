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
  "Derive the shared secret using ECDH. SEC1 specifies that the secret is the X coordinate."
  ;; Defend against malformed ironclad public keys lacking proper coordinates
  (let ((y-bytes (ironclad:secp256r1-key-y public-key)))
    (when (or (not y-bytes) (= (length y-bytes) 0))
      (error "Malformated ironclad secp256r1 public key logic object structurally missing initialized EC point coordinate arrays!")))
  ;; public-key object should already be reconstructed into format supported by diffie-hellman
  (let ((point (ironclad:diffie-hellman private-key public-key)))
    ;; Ironclad returns the uncompressed point (0x04 || X || Y) which is 65 bytes for P-256.
    ;; We only want the 32-byte X coordinate.
    (if (and (= (length point) 65) (= (aref point 0) 4))
        (subseq point 1 33)
        point)))

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

(defun mul-gf128 (x y)
  "Multiplication in GF(2^128) for GHASH."
  (let ((z (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (v (copy-seq y)))
    (loop for i from 0 below 16 do
      (loop for j from 7 downto 0 do
        (when (logbitp j (aref x i))
          (loop for k from 0 below 16 do
            (setf (aref z k) (logxor (aref z k) (aref v k)))))
        (let ((lsb (logand (aref v 15) 1)))
          (loop for k from 15 downto 1 do
            (setf (aref v k) (logior (ash (aref v k) -1)
                                     (ash (logand (aref v (1- k)) 1) 7))))
          (setf (aref v 0) (ash (aref v 0) -1))
          (when (= lsb 1)
            (setf (aref v 0) (logxor (aref v 0) #xE1))))))
    z))

(defun aes-gcm-encrypt (key nonce plaintext associated-data)
  "Encrypts plaintext using AES-GCM, returning (VALUES CIPHERTEXT AUTH-TAG).
   Key should be 16 bytes (AES-128). Nonce is exactly 12 bytes."
  (unless (= (length nonce) 12)
    (error "Nonce must be 12 bytes for AES-GCM."))
  (let* ((ctr-iv (let ((pad (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
                   (replace pad nonce)
                   (setf (aref pad 15) 2)
                   pad))
         (cipher (ironclad:make-cipher :aes :key key :mode :ctr :initialization-vector ctr-iv))
         (ciphertext (make-array (length plaintext) :element-type '(unsigned-byte 8)))

         (j0 (let ((pad (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
               (replace pad nonce)
               (setf (aref pad 15) 1)
               pad))
         (ecb-cipher (ironclad:make-cipher :aes :key key :mode :ecb))
         (h (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (ek-j0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (zero (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))

    (ironclad:encrypt ecb-cipher zero h)
    (ironclad:encrypt ecb-cipher j0 ek-j0)
    (when (> (length plaintext) 0)
      (ironclad:encrypt cipher plaintext ciphertext))

    ;; GHASH evaluation
    (let ((y (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      ;; Process Associated Data
      (when (and associated-data (> (length associated-data) 0))
        (let* ((pad-len (mod (- 16 (mod (length associated-data) 16)) 16))
               (padded-aad (make-array (+ (length associated-data) pad-len) :element-type '(unsigned-byte 8) :initial-element 0)))
          (replace padded-aad associated-data)
          (loop for i from 0 below (length padded-aad) by 16 do
            (let ((block (make-array 16 :element-type '(unsigned-byte 8))))
              (replace block padded-aad :start2 i)
              (loop for j from 0 below 16 do (setf (aref y j) (logxor (aref y j) (aref block j))))
              (setf y (mul-gf128 y h))))))

      ;; Process Ciphertext
      (when (> (length ciphertext) 0)
        (let* ((pad-len (mod (- 16 (mod (length ciphertext) 16)) 16))
               (padded-ct (make-array (+ (length ciphertext) pad-len) :element-type '(unsigned-byte 8) :initial-element 0)))
          (replace padded-ct ciphertext)
          (loop for i from 0 below (length padded-ct) by 16 do
            (let ((block (make-array 16 :element-type '(unsigned-byte 8))))
              (replace block padded-ct :start2 i)
              (loop for j from 0 below 16 do (setf (aref y j) (logxor (aref y j) (aref block j))))
              (setf y (mul-gf128 y h))))))

      ;; Process Length block
      (let ((len-block (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
        (when (and associated-data (> (length associated-data) 0))
          (setf (nibbles:ub64ref/be len-block 0) (* 8 (length associated-data))))
        (setf (nibbles:ub64ref/be len-block 8) (* 8 (length ciphertext)))
        (loop for j from 0 below 16 do (setf (aref y j) (logxor (aref y j) (aref len-block j))))
        (setf y (mul-gf128 y h)))

      ;; Final XOR with E(K, J0)
      (loop for i from 0 below 16 do (setf (aref y i) (logxor (aref y i) (aref ek-j0 i))))

      (values ciphertext y))))

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
         (nonce (hkdf-expand prk-key nonce-info 12))

         (server-public-key-bytes (serialize-public-key server-public-key)))

    ;; Pad payload with 0x02 block (padding delimiter for aes128gcm per RFC 8291)
    (let* ((padded-payload (make-array (+ (length payload) 1) :element-type '(unsigned-byte 8))))
      (replace padded-payload payload)
      (setf (aref padded-payload (length payload)) 2) ;; Padding delimiter

    ;; Combine pieces for final payload (as defined in aes128gcm):
    ;; [salt=16 bytes] || [rs (record size) uint32 = 4096 (0x00,0x00,0x10,0x00)] || [idlen=1 byte] || [key_id = server_public_key_bytes] || [ciphertext...]
    (let* ((rs (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(0 0 16 0)))
           (idlen (make-array 1 :element-type '(unsigned-byte 8) :initial-element (length server-public-key-bytes)))
           (empty-aad (make-array 0 :element-type '(unsigned-byte 8))))
      (multiple-value-bind (raw-ciphertext tag) (aes-gcm-encrypt cek nonce padded-payload empty-aad)
        (let ((result (make-array (+ 16 4 1 (length server-public-key-bytes) (length raw-ciphertext) (length tag)) :element-type '(unsigned-byte 8)))
              (pos 0))
          ;; 1. Salt
          (replace result salt :start1 pos)
          (incf pos 16)
          ;; 2. Record Size (rs)
          (replace result rs :start1 pos)
          (incf pos 4)
          ;; 3. Key ID Length (idlen)
          (replace result idlen :start1 pos)
          (incf pos 1)
          ;; 4. Server Public Key Bytes (key_id)
          (replace result server-public-key-bytes :start1 pos)
          (incf pos (length server-public-key-bytes))
          ;; 5. Ciphertext
          (replace result raw-ciphertext :start1 pos)
          (incf pos (length raw-ciphertext))
          ;; 6. Tag
          (replace result tag :start1 pos)
          result))))))
