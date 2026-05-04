;;;; e2e.lisp
;; This is an interactive script to simulate the End-to-End flow.

(ignore-errors (ql:quickload '(:cl-web-push :hunchentoot)))

(defpackage #:cl-web-push/e2e
  (:use #:cl)
  (:export #:start-frontend #:trigger-push))
(in-package #:cl-web-push/e2e)

(defvar *server* nil)
(defvar *port* 8888)
(defvar *vapid-pub* nil)
(defvar *vapid-priv* nil)

(defun start-frontend ()
  "Starts a local server at http://localhost:8000 to serve the HTML/SW."
  (let ((examples-dir (merge-pathnames "example/" (asdf:system-source-directory :cl-web-push))))
    (setf hunchentoot:*dispatch-table*
          (list
           (hunchentoot:create-folder-dispatcher-and-handler
            "/" examples-dir)
           (hunchentoot:create-static-file-dispatcher-and-handler
            "" (merge-pathnames "index.html" examples-dir))))
    (setf *server* (hunchentoot:start
                    (make-instance 'hunchentoot:easy-acceptor :port *port*))))
  (format t "~%====================================~%")

  ;; Generate Keys for the session
  (multiple-value-bind (pub priv) (cl-web-push:generate-vapid-keys)
    (setf *vapid-pub* pub)
    (setf *vapid-priv* priv))

  (format t "~%1. Open your browser to http://127.0.0.1:~a/index.html~%" *port*)
  (format t "2. Paste this VAPID Public Key into the input box:~%~A~%" *vapid-pub*)
  (format t "3. Click Subscribe, allow permissions, and copy the generated JSON block.~%")
  (format t "4. Paste your json payload in this REPL.~%")
  (format t "====================================~%"))

(defun trigger-push (subscription-json-string)
  "Trigger the push notification using the globally state VAPID keys."
  (cl-web-push:send-push-notification
   subscription-json-string
   "Hello from Common Lisp! End-to-End works perfectly 🔥"
   *vapid-pub*
   *vapid-priv*
   "mailto:testing@example.com")
  (format t "Push notification dispatched! Check your browser context / OS notification center.~%"))

(eval-when (:execute)
  (start-frontend)
  (format t "JSON: ")
  (finish-output)
  (trigger-push (read-line)))
