;;;; vapid.lisp

(in-package #:cl-web-push)

(defun b64url-encode (bytes)
  "Encodes bytes into a Base64 URL-safe string without padding."
  (string-right-trim "=" (cl-base64:usb8-array-to-base64-string bytes :uri t)))

(defun b64url-decode (string)
  "Decodes a Base64 URL-safe string."
  ;; Add padding if necessary
  (let* ((padding-len (mod (- 4 (mod (length string) 4)) 4))
         (padded-string (concatenate 'string string (make-string (if (= padding-len 4) 0 padding-len) :initial-element #\=))))
    (cl-base64:base64-string-to-usb8-array padded-string :uri t)))

(defun generate-vapid-keys ()
  "Generate VAPID keys using P-256 curve (secp256r1). 
   Returns (VALUES PUBLIC-KEY PRIVATE-KEY) serialized as Base64-URL strings."
  (multiple-value-bind (priv pub) (ironclad:generate-key-pair :secp256r1)
    (let* ((x (ironclad:secp256r1-key-x priv)) ; Private key material
           (y (ironclad:secp256r1-key-y pub))  ; Uncompressed public key material (0x04 || X || Y)
           (priv-b64 (b64url-encode x))
           (pub-b64 (b64url-encode y)))
      (values pub-b64 priv-b64))))

(defun create-vapid-jwt (audience subject private-key)
  "Create a signed JWT token using ES256 (secp256r1) for VAPID.
   `private-key` is the object returned by `ironclad:make-private-key :secp256r1 :x ...`."
  (let* ((header (b64url-encode (ironclad:ascii-string-to-byte-array "{\"typ\":\"JWT\",\"alg\":\"ES256\"}")))
         ;; Calculate expiration (12 hours from now)
         (exp (unix-time (+ 43200))) 
         (claims-alist (list (cons "aud" audience)
                             (cons "exp" exp)
                             (cons "sub" subject)))
         (claims (b64url-encode (ironclad:ascii-string-to-byte-array 
                                 (cl-json:encode-json-alist-to-string claims-alist))))
         (message (format nil "~A.~A" header claims))
         (message-bytes (ironclad:ascii-string-to-byte-array message))
         (signature (ironclad:sign-message private-key message-bytes)))
    (format nil "~A.~A" message (b64url-encode signature))))

(defun unix-time (&optional (offset 0))
  "Returns the current unix timestamp, optionally offset by X seconds."
  (+ (- (get-universal-time) 2208988800) offset))
