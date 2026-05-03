;;;; cli.lisp

(in-package #:cl-web-push)

(defun generate-keys-cli ()
  "Generates VAPID keys and prints them to standard output in a .env format.
   Useful for a binary executable or shell invocation."
  (multiple-value-bind (pub priv) (generate-vapid-keys)
    (format t "VAPID_PUBLIC_KEY=~A~%" pub)
    (format t "VAPID_PRIVATE_KEY=~A~%" priv)))
