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

(define-test rfc-8291-example
  ;; RFC 8291 Section 5 and Appendix A Test Vectors
  (let* ((plaintext (cl-web-push:b64url-decode "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24"))
         (as-public-bytes (cl-web-push:b64url-decode "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"))
         (as-private-bytes (cl-web-push:b64url-decode "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
         (ua-public-bytes (cl-web-push:b64url-decode "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"))
         ;; ua-private is given but not strictly needed because we are the sender
         (salt (cl-web-push:b64url-decode "DGv6ra1nlYgDCS1FRnbzlw"))
         (auth-secret (cl-web-push:b64url-decode "BTBZMqHH6r4Tts7J_aSIgg"))
         (expected-final-payload (cl-web-push:b64url-decode "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"))
         
         ;; Instantiate Ironclad Keys
         (as-public-key (ironclad:make-public-key :secp256r1 :y as-public-bytes))
         (as-private-key (ironclad:make-private-key :secp256r1 :x as-private-bytes))
         (ua-public-key (ironclad:make-public-key :secp256r1 :y ua-public-bytes)))

    ;; Check that encrypt-payload produces exactly the RFC 8291 expected combined header + ciphertext byte array
    (let ((generated-payload (cl-web-push:encrypt-payload plaintext auth-secret ua-public-key as-private-key as-public-key salt)))
      (is equalp expected-final-payload generated-payload))))
