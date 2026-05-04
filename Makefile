e2e:
	sbcl --noinform --load example/e2e.lisp --quit

check:
	sbcl --noinform --eval '(asdf:test-system :cl-web-push/test)' --quit
