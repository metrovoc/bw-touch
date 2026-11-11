PREFIX ?= $(HOME)/.local
# "-" signs ad hoc. Set SIGN_IDENTITY to a code signing certificate name to sign with it.
SIGN_IDENTITY ?= -
SIGN_IDENTIFIER ?= bw-touch

.PHONY: build test install

build:
	swift build -c release

test:
	swift test

install: build
	install -d "$(PREFIX)/bin"
	install -m 755 .build/release/bw-touch "$(PREFIX)/bin/bw-touch"
	codesign --force --options runtime --identifier "$(SIGN_IDENTIFIER)" --sign "$(SIGN_IDENTITY)" "$(PREFIX)/bin/bw-touch"
