;;;; e2e.lisp
;; This is an autonomous script to simulate the End-to-End flow.

(ignore-errors (ql:quickload '(:cl-web-push :hunchentoot :cl-json)))

(defpackage #:cl-web-push/e2e
  (:use #:cl)
  (:export #:run-e2e-test))
(in-package #:cl-web-push/e2e)

(defvar *server* nil)
(defvar *port* 8888)
(defvar *vapid-pub* nil)
(defvar *vapid-priv* nil)
(defvar *test-finished* nil)

(defun trigger-push (subscription-json-string)
  "Trigger the push notification using the globally state VAPID keys."
  (format t "Triggering push for subscription: ~A~%" subscription-json-string)
  (handler-case
      (multiple-value-bind (body status headers uri stream)
          (cl-web-push:send-push-notification
           subscription-json-string
           "Hello from Common Lisp! End-to-End works perfectly 🔥"
           *vapid-pub*
           *vapid-priv*
           "mailto:testing@example.com")
        (declare (ignore uri stream))
        (format t "Push notification dispatched!~%HTTP Status: ~A~%Response Body: ~A~%Headers: ~A~%" status body headers))
    (dex:http-request-failed (e)
      (format t "HTTP Request Failed!~%Status: ~A~%Response body: ~A~%"
              (dex:response-status e)
              (dex:response-body e)))
    (error (e)
      (format t "General Error triggering push: ~A~%" e))))

(hunchentoot:define-easy-handler (vapid-pub-handler :uri "/vapid-pub") ()
  (setf (hunchentoot:content-type*) "text/plain")
  *vapid-pub*)

(hunchentoot:define-easy-handler (subscribe-handler :uri "/subscribe") ()
  (let ((post-data (hunchentoot:raw-post-data :force-text t)))
    (if post-data
        (progn
          (trigger-push post-data)
          "OK")
        (progn
          (setf (hunchentoot:return-code*) hunchentoot:+http-bad-request+)
          "Missing post data"))))

(hunchentoot:define-easy-handler (verify-handler :uri "/verify-received") ()
  (format t "SUCCESS: Notification verified by client!~%")
  (setf *test-finished* t)
  "OK")

(defun run-e2e-test ()
  "Starts a local server and waits for the e2e test to complete."
  (let ((examples-dir (merge-pathnames "example/" (asdf:system-source-directory :cl-web-push))))
    ;; Generate Keys for the session
    (multiple-value-bind (pub priv) (cl-web-push:generate-vapid-keys)
      (setf *vapid-pub* pub)
      (setf *vapid-priv* priv))

    (setf *test-finished* nil)
    (setf *server* (hunchentoot:start
                    (make-instance 'hunchentoot:easy-acceptor
                                   :port *port*
                                   :document-root examples-dir)))

    (format t "~%====================================~%")
    (format t "E2E Test Server started at http://127.0.0.1:~a/~%" *port*)
    (format t "Waiting for test completion...~%")
    (format t "====================================~%")

    (loop until *test-finished* do (sleep 1))
    (when *server*
      (hunchentoot:stop *server*)
      (format t "Stopping server...~%"))))

(eval-when (:execute)
  (handler-case
      (run-e2e-test)
      (#+sbcl sb-sys:interactive-interrupt
       #-sbcl cl:error
       ()
       (format t "~%Ctrl+C detected! Aborting test...~%"))))
