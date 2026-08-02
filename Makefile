.PHONY: all fmt fmt-check test vet assure trace-check evidence release-digest verify \
	staticcheck gosec govulncheck analyzers \
	man-lint install install-bin install-man uninstall uninstall-bin uninstall-man

# Portable install defaults (override per OS / packaging):
#   Linux FHS / Homebrew / many FreeBSD packages: MANDIR=$(PREFIX)/share/man
#   Traditional OpenBSD/FreeBSD ports:            MANDIR=$(PREFIX)/man
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man
DESTDIR ?=

GO      ?= go
INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 0755
INSTALL_DATA    ?= $(INSTALL) -m 0644

# Product CLIs (all targets). Unix stubs are optional extras.
BIN_COMMON = \
	integris \
	integris-assure \
	integris-evidence \
	integris-release-digest \
	integris-verify-config

BIN_UNIX = \
	integris-role-stub \
	integris-crash-stub

MAN1 = \
	integris.1 \
	integris-assure.1 \
	integris-evidence.1 \
	integris-release-digest.1 \
	integris-verify-config.1 \
	integris-role-stub.1 \
	integris-crash-stub.1

MAN7 = integris.7
MAN8 = integrisd.8

MAN_SOURCES = \
	$(addprefix man/man1/,$(MAN1)) \
	$(addprefix man/man7/,$(MAN7)) \
	$(addprefix man/man8/,$(MAN8))

all: verify

# gofmt walks directories recursively; use ./cmd ./internal (not ./... — gofmt rejects that).
fmt:
	gofmt -w ./cmd ./internal

fmt-check:
	@test -z "$$(gofmt -l ./cmd ./internal)" || { echo "Go files require formatting"; gofmt -l ./cmd ./internal; exit 1; }

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

assure:
	$(GO) run ./cmd/integris-assure validate --root .

trace-check:
	$(GO) run ./cmd/integris-assure trace --root . --check

evidence:
	$(GO) run ./cmd/integris-evidence -root .

release-digest:
	$(GO) run ./cmd/integris-release-digest -root .

staticcheck:
	GOTOOLCHAIN=go1.26.5 GOWORK=off $(GO) run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...

gosec:
	GOTOOLCHAIN=go1.26.5 GOWORK=off $(GO) run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 \
		-quiet -severity high -confidence high ./...

govulncheck:
	GOTOOLCHAIN=go1.26.5 GOWORK=off $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

analyzers: staticcheck gosec govulncheck

verify: fmt-check test vet assure trace-check man-lint

man-lint:
	@command -v mandoc >/dev/null || { echo "mandoc is required for man-lint"; exit 1; }
	@tmp=$$(mktemp); \
	mandoc -T lint $(MAN_SOURCES) >$$tmp 2>&1 || true; \
	if grep -E 'ERROR:' $$tmp >/dev/null; then cat $$tmp; rm -f $$tmp; exit 1; fi; \
	if grep -E 'WARNING:' $$tmp | grep -v 'referenced manual not found' >/dev/null; then \
		grep -E 'WARNING:' $$tmp | grep -v 'referenced manual not found' || true; \
		rm -f $$tmp; exit 1; \
	fi; \
	rm -f $$tmp; echo "man-lint ok ($(words $(MAN_SOURCES)) pages)"

install: install-bin install-man

install-bin:
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	@for b in $(BIN_COMMON); do \
		$(GO) build -trimpath -ldflags='-s -w' -o "$(DESTDIR)$(BINDIR)/$$b" "./cmd/$$b"; \
		chmod 0755 "$(DESTDIR)$(BINDIR)/$$b"; \
	done
	@if $(GO) env GOOS | grep -vqE '^(windows|plan9)$$'; then \
		for b in $(BIN_UNIX); do \
			$(GO) build -trimpath -ldflags='-s -w' -o "$(DESTDIR)$(BINDIR)/$$b" "./cmd/$$b"; \
			chmod 0755 "$(DESTDIR)$(BINDIR)/$$b"; \
		done; \
	fi

install-man:
	$(INSTALL) -d "$(DESTDIR)$(MANDIR)/man1" "$(DESTDIR)$(MANDIR)/man7" "$(DESTDIR)$(MANDIR)/man8"
	@for f in $(MAN1); do $(INSTALL_DATA) "man/man1/$$f" "$(DESTDIR)$(MANDIR)/man1/$$f"; done
	@for f in $(MAN7); do $(INSTALL_DATA) "man/man7/$$f" "$(DESTDIR)$(MANDIR)/man7/$$f"; done
	@for f in $(MAN8); do $(INSTALL_DATA) "man/man8/$$f" "$(DESTDIR)$(MANDIR)/man8/$$f"; done

uninstall: uninstall-bin uninstall-man

uninstall-bin:
	@for b in $(BIN_COMMON) $(BIN_UNIX); do rm -f "$(DESTDIR)$(BINDIR)/$$b"; done

uninstall-man:
	@for f in $(MAN1); do rm -f "$(DESTDIR)$(MANDIR)/man1/$$f"; done
	@for f in $(MAN7); do rm -f "$(DESTDIR)$(MANDIR)/man7/$$f"; done
	@for f in $(MAN8); do rm -f "$(DESTDIR)$(MANDIR)/man8/$$f"; done
