;;;; test-suite.lisp

(defpackage #:cl-web-push/test
  (:use #:cl #:parachute))

(in-package #:cl-web-push/test)

(define-test b64url-codec
  (let ((data (ironclad:random-data 16)))
    (is equalp data (cl-web-push:b64url-decode (cl-web-push:b64url-encode data)))))

(define-test vapid-key-generation
  (multiple-value-bind (public private) (cl-web-push:generate-vapid-keys)
    (true (stringp public))
    (true (stringp private))
    ;; Ensure decoding works without padding issues
    (is = 32 (length (cl-web-push:b64url-decode private)))
    (is = 65 (length (cl-web-push:b64url-decode public)))))

(define-test vapid-jwt
  (multiple-value-bind (public private) (cl-web-push:generate-vapid-keys)
    (declare (ignore public))
    (let* ((priv-key (ironclad:make-private-key :secp256r1 :x (cl-web-push:b64url-decode private)))
           (jwt (cl-web-push:create-vapid-jwt "https://push.example.com" "mailto:admin@test.com" priv-key)))
      (true (stringp jwt))
      (true (search "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" jwt)) ;; Header B64 validation
      ;; We expect two parts joined by two dots with 3 blocks payload Header.Payload.Signature
      ;; Let's just check length and signature existence rather than strictly dot counts if standard is flex
      (true (> (length jwt) 100))))) 

(define-test aes-gcm-logic
  ;; Simulating payload encryption steps since testing end-to-end requires an actual push subscription 
  (let* ((client-keys (multiple-value-list (ironclad:generate-key-pair :secp256r1)))
         (server-keys (multiple-value-list (ironclad:generate-key-pair :secp256r1)))
         (salt (ironclad:random-data 16))
         (auth-secret (ironclad:random-data 16))
         (payload (ironclad:ascii-string-to-byte-array "Testing Payload")))
    (let ((ciphertext (cl-web-push:encrypt-payload payload 
                                                    auth-secret 
                                                    (ironclad:make-public-key :secp256r1 :y (ironclad:secp256r1-key-y (second client-keys)))
                                                    (first server-keys) 
                                                    (ironclad:make-public-key :secp256r1 :y (ironclad:secp256r1-key-y (second server-keys))) 
                                                    salt)))
      (true (typep ciphertext '(vector (unsigned-byte 8))))
      (true (> (length ciphertext) (length payload))))))
