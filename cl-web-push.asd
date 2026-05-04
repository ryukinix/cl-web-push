;;;; cl-web-push.asd

(asdf:defsystem #:cl-web-push
  :description "Common Lisp library for Web Push Protocol"
  :author "Manoel V. Machado"
  :license "MIT"
  :serial t
  :depends-on (#:ironclad
               #:nibbles
               #:flexi-streams
               #:cl-base64
               #:cl-json
               #:dexador)
  :components ((:file "package")
               (:file "vapid")
               (:file "encryption")
               (:file "push")
               (:file "cli"))
  :in-order-to ((asdf:test-op (asdf:test-op #:cl-web-push/test))))

(asdf:defsystem #:cl-web-push/test
  :depends-on (#:cl-web-push
               #:parachute)
  :components ((:file "test-suite"))
  :perform (asdf:test-op (o c) (uiop:symbol-call '#:parachute '#:test '#:cl-web-push/test)))