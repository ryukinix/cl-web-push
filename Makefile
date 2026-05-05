e2e:
	sbcl --noinform --load example/e2e.lisp --quit

generate:
	@sbcl --noinform --eval '(ql:quickload :cl-web-push :silent t)' --eval '(cl-web-push:generate-keys-cli)' --quit

check:
	sbcl --noinform --eval '(asdf:test-system :cl-web-push/test)' --quit
