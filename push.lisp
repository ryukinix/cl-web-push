;;;; push.lisp

(in-package #:cl-web-push)

(defun parse-subscription (subscription-json-string)
  "Parses a Web Push subscription JSON. 
   Returns an alist with :endpoint, :auth, and :p256dh."
  (let* ((json (cl-json:decode-json-from-string subscription-json-string))
         (endpoint (cdr (assoc :endpoint json)))
         (keys (cdr (assoc :keys json)))
         (p256dh (cdr (assoc :p256dh keys)))
         (auth (cdr (assoc :auth keys))))
    (list :endpoint endpoint :p256dh p256dh :auth auth)))

(defun send-push-notification (subscription-json-string payload vapid-public-key vapid-private-key vapid-subject)
  "Send a push notification to the given subscription endpoint."
  (let* ((sub (parse-subscription subscription-json-string))
         (endpoint (getf sub :endpoint))
         ;; Decode client subscription keys
         (client-auth-secret (b64url-decode (getf sub :auth)))
         (client-public-key-bytes (b64url-decode (getf sub :p256dh)))
         (client-public-key (ironclad:make-public-key :secp256r1 :y client-public-key-bytes))
         
         ;; Generate temporary server ECDH pair for this specific message encryption
         (server-keys (multiple-value-list (ironclad:generate-key-pair :secp256r1)))
         (server-private-key (first server-keys))
         (server-public-key (second server-keys))
         
         ;; Generate random 16-bye salt
         (salt (ironclad:random-data 16))
         
         ;; Encrypt Payload
         (payload-bytes (flexi-streams:string-to-octets payload :external-format :utf-8))
         (ciphertext (encrypt-payload payload-bytes client-auth-secret client-public-key server-private-key server-public-key salt))
         
         ;; Extract audience from endpoint (protocol://host)
         (audience (let* ((uri (quri:uri endpoint))) 
                     (format nil "~A://~A" (quri:uri-scheme uri) (quri:uri-host uri))))
         
         ;; Parse application VAPID keys
         (vapid-priv-bytes (b64url-decode vapid-private-key))
         (reconstructed-vapid-priv (ironclad:make-private-key :secp256r1 :x vapid-priv-bytes))
         (jwt (create-vapid-jwt audience vapid-subject reconstructed-vapid-priv))
         
         ;; Headers
         (crypto-key (format nil "dh=~A, p256ecdsa=~A"
                             (b64url-encode (serialize-public-key server-public-key))
                             vapid-public-key))
         (encryption (format nil "salt=~A" (b64url-encode salt)))
         (headers (list (cons "Authorization" (format nil "vapid t=~A, k=~A" jwt vapid-public-key))
                        (cons "Crypto-Key" crypto-key)
                        (cons "Encryption" encryption)
                        (cons "Content-Encoding" "aes128gcm")
                        (cons "TTL" "43200") ; 12 hours
                        (cons "Content-Type" "application/octet-stream"))))
    
    ;; Make HTTP POST request to the push service endpoint
    (dex:post endpoint 
              :headers headers
              :content ciphertext)))