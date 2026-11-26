;;;; push.lisp

(in-package #:cl-web-push)

(defun parse-subscription (subscription-json-string)
  "Parses a Web Push subscription JSON. 
   Returns an alist with :endpoint, :auth, and :p256dh."
  (let* ((json (cl-json:decode-json-from-string subscription-json-string))
         (endpoint (cdr (assoc :endpoint json)))
         (keys (cdr (assoc :keys json)))
         ;; JSON decoding maps camelCase/snake_case to Lisp keywords. 
         ;; "p256dh" can map to :P-256-DH or :P256DH depending on the JSON parser logic.
         (p256dh-str (or (cdr (assoc :p256dh keys))
                         (cdr (assoc :p-256-dh keys))
                         (cdr (assoc :p256-dh keys))))
         (p256dh (if p256dh-str 
                     (let ((decoded (b64url-decode p256dh-str)))
                       (if (= (length decoded) 64)
                           (let ((fixed (make-array 65 :element-type '(unsigned-byte 8) :initial-element 4)))
                             (replace fixed decoded :start1 1)
                             fixed)
                           decoded))
                     (make-array 0 :element-type '(unsigned-byte 8)))) ; Instead of 65 zero bytes
         (auth-str (cdr (assoc :auth keys)))
         (auth (if auth-str
                   auth-str
                   "")))
    (list :endpoint endpoint :p256dh p256dh :auth auth)))

(defun endpoint-audience (endpoint)
  "Extract the RFC 8292 origin audience (scheme://host[:port]) from ENDPOINT."
  (let* ((uri (quri:uri endpoint))
         (scheme (quri:uri-scheme uri))
         (host (quri:uri-host uri))
         (port (quri:uri-port uri))
         (default-port (cond ((string-equal scheme "https") 443)
                             ((string-equal scheme "http") 80)
                             (t nil))))
    (unless (and scheme host)
      (error "Invalid push subscription endpoint URL: ~S" endpoint))
    (if (and port (not (eql port default-port)))
        (format nil "~A://~A:~A" scheme host port)
        (format nil "~A://~A" scheme host))))

(defun send-push-notification (subscription-json-string payload vapid-public-key vapid-private-key vapid-subject
                               &key (ttl 43200) (urgency "high") (connect-timeout 10) (read-timeout 15))
  "Send a push notification to the given subscription endpoint."
  (let* ((sub (parse-subscription subscription-json-string))
         (endpoint (getf sub :endpoint))
         (auth-str (getf sub :auth))
         ;; Decode client subscription keys
         (client-auth-secret (if (and (stringp auth-str) (> (length auth-str) 0))
                                 (b64url-decode auth-str)
                                 (make-array 0 :element-type '(unsigned-byte 8))))
         (client-public-key-bytes (getf sub :p256dh))

         ;; Validate endpoint, auth secret (16 bytes per RFC 8291), and p256dh (65 bytes, 0x04 prefix)
         (is-valid-key? (and (= (length client-public-key-bytes) 65)
                             (= (aref client-public-key-bytes 0) 4)))

         (client-public-key (if is-valid-key?
                                (ironclad:make-public-key :secp256r1 :y client-public-key-bytes)
                                nil)))

    (unless (and (stringp endpoint) (> (length endpoint) 0))
      (error "Malformed client subscription: missing endpoint URL."))

    (unless (= (length client-auth-secret) 16)
      (error "Malformed client subscription auth secret (length=~A). Must be 16 bytes."
             (length client-auth-secret)))

    (unless client-public-key
      (error "Malformed client subscription public key format (p256dh bytes length=~A). Must be 65 bytes starting with 0x04."
             (length client-public-key-bytes)))

    (let ((y-bytes (ironclad:secp256r1-key-y client-public-key)))
      (unless (and y-bytes (> (length y-bytes) 0))
        (error "Constructed Ironclad public key has invalid empty Y coordinates.")))

    (let* (;; Generate temporary server ECDH pair for this specific message encryption
           (server-keys (multiple-value-list (ironclad:generate-key-pair :secp256r1)))
           (server-private-key (first server-keys))
           (server-public-key (second server-keys))

           ;; Generate random 16-byte salt
           (salt (ironclad:random-data 16))

           ;; Encrypt Payload
           (payload-bytes (flexi-streams:string-to-octets payload :external-format :utf-8))
           (ciphertext (encrypt-payload payload-bytes client-auth-secret client-public-key server-private-key server-public-key salt))

           ;; Extract audience from endpoint (scheme://host[:port])
           (audience (endpoint-audience endpoint))

           ;; Parse application VAPID keys
           (vapid-priv-bytes (b64url-decode vapid-private-key))
           (reconstructed-vapid-priv (ironclad:make-private-key :secp256r1 :x vapid-priv-bytes))
           (jwt (create-vapid-jwt audience vapid-subject reconstructed-vapid-priv))

           ;; Headers (RFC 8292 + RFC 8030)
           (headers `(("Authorization" . ,(format nil "vapid t=~A, k=~A" jwt vapid-public-key))
                      ("Content-Encoding" . "aes128gcm")
                      ("TTL" . ,(princ-to-string ttl))
                      ("Urgency" . ,urgency)
                      ("Content-Type" . "application/octet-stream"))))

      ;; Make HTTP POST request to the push service endpoint
      (dex:post endpoint
                :headers headers
                :content ciphertext
                :connect-timeout connect-timeout
                :read-timeout read-timeout))))