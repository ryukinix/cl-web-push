;;;; vapid.lisp

(in-package #:cl-web-push)

(defun b64url-encode (bytes)
  "Encodes bytes into a Base64 URL-safe string without padding."
  ;; standard WebPush expects no padding.
  ;; cl-base64 base64-string output needs standard conversions
  (let ((b64 (cl-base64:usb8-array-to-base64-string bytes)))
    (string-right-trim "=" (substitute #\_ #\/ (substitute #\- #\+ b64)))))

(defun b64url-decode (string)
  "Decodes a Base64 URL-safe string."
  (let* ((string-stripped (string-right-trim "=" string)) ;; Remove incoming equal paddings
         (padding-len (mod (- 4 (mod (length string-stripped) 4)) 4))
         (padding-len (if (= padding-len 4) 0 padding-len))
         ;; Use the standard '=' padding since cl-base64 base64-string-to-usb8-array with :uri nil supports it directly
         ;; actually, replacing hyphens with pluses and underscores with slashes manually handles standard b64url gracefully
         (converted (substitute #\+ #\- (substitute #\/ #\_ string-stripped)))
         (padded-string (concatenate 'string converted (make-string padding-len :initial-element #\=))))
    (cl-base64:base64-string-to-usb8-array padded-string)))

(defun generate-vapid-keys ()
  "Generate VAPID keys using P-256 curve (secp256r1). 
   Returns (VALUES PUBLIC-KEY PRIVATE-KEY) serialized as Base64-URL strings."
  (multiple-value-bind (priv pub) (ironclad:generate-key-pair :secp256r1)
    (let* ((x (ironclad:secp256r1-key-x priv)) ; Private key material
           (y (serialize-public-key pub))  ; Uncompressed public key material (0x04 || X || Y)
           (priv-b64 (b64url-encode x))
           (pub-b64 (b64url-encode y)))
      (values pub-b64 priv-b64))))

(defun create-vapid-jwt (audience subject private-key)
  "Create a signed JWT token using ES256 (secp256r1) for VAPID.
   `private-key` is the object returned by `ironclad:make-private-key :secp256r1 :x ...`."
  (let* ((header (b64url-encode (ironclad:ascii-string-to-byte-array "{\"typ\":\"JWT\",\"alg\":\"ES256\"}")))
         ;; Calculate expiration (12 hours from now)
         (exp (unix-time (+ 43200))) 
         ;; Use a direct string format instead of cl-json to avoid escaped forward slashes 
         ;; in audience URLs like "https:\/\/fcm.googleapis.com" which may fail strict parsers.
         (claims-json (format nil "{\"aud\":\"~A\",\"exp\":~A,\"sub\":\"~A\"}" 
                              audience exp subject))
         (claims (b64url-encode (ironclad:ascii-string-to-byte-array claims-json)))
         (message (format nil "~A.~A" header claims))
         (message-bytes (ironclad:ascii-string-to-byte-array message))
         (signature (ironclad:sign-message private-key message-bytes)))
    ;; ironclad:sign-message already returns exactly 64 bytes (R || S)
    ;; It does NOT return ASN.1 DER format.
    (format nil "~A.~A" message (b64url-encode signature))))

(defun unix-time (&optional (offset 0))
  "Returns the current unix timestamp, optionally offset by X seconds."
  (+ (- (get-universal-time) 2208988800) offset))
