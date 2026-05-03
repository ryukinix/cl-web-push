;;;; e2e.lisp
;; This is an interactive script to simulate the End-to-End flow.

(load #P"/usr/share/common-lisp/source/quicklisp/quicklisp.lisp" :if-does-not-exist nil)
(load (merge-pathnames ".quicklisp/setup.lisp" (user-homedir-pathname)) :if-does-not-exist nil)
(push #p"/home/lerax/Desktop/workspace/cl-web-push/" asdf:*central-registry*)

(ignore-errors (ql:quickload :cl-web-push))
(ignore-errors (ql:quickload :hunchentoot)) ; Used just to serve the static frontend

(defpackage #:cl-web-push/e2e
  (:use #:cl))
(in-package #:cl-web-push/e2e)

(defvar *server* nil)
(defvar *vapid-pub* nil)
(defvar *vapid-priv* nil)

(defun start-frontend ()
  "Starts a local server at http://localhost:8000 to serve the HTML/SW."
  (setf hunchentoot:*dispatch-table* 
        (list (hunchentoot:create-folder-dispatcher-and-handler 
               "/" #p"/home/lerax/Desktop/workspace/cl-web-push/example/")))
  (setf *server* (hunchentoot:start (make-instance 'hunchentoot:easy-acceptor :port 8000)))
  (format t "~%====================================~%")
  (format t "Frontend is running at http://localhost:8000/~%")
  
  ;; Generate Keys for the session
  (multiple-value-bind (pub priv) (cl-web-push:generate-vapid-keys)
    (setf *vapid-pub* pub)
    (setf *vapid-priv* priv))
  
  (format t "~%1. Open your browser to http://localhost:8000/~%")
  (format t "2. Paste this VAPID Public Key into the input box:~%~A~%" *vapid-pub*)
  (format t "3. Click Subscribe, allow permissions, and copy the generated JSON block.~%")
  (format t "4. Call (cl-web-push/e2e:trigger-push \"YOUR_JSON_HERE\") in this REPL.~%")
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
