.PHONY: all fmt fmt-check test vet assure trace-check evidence release-digest verify \
	staticcheck gosec govulncheck analyzers

all: verify

# gofmt walks directories recursively; use ./cmd ./internal (not ./... — gofmt rejects that).
fmt:
	gofmt -w ./cmd ./internal

fmt-check:
	@test -z "$$(gofmt -l ./cmd ./internal)" || { echo "Go files require formatting"; gofmt -l ./cmd ./internal; exit 1; }

test:
	go test ./...

vet:
	go vet ./...

assure:
	go run ./cmd/integris-assure validate --root .

trace-check:
	go run ./cmd/integris-assure trace --root . --check

evidence:
	go run ./cmd/integris-evidence -root .

release-digest:
	go run ./cmd/integris-release-digest -root .

staticcheck:
	GOTOOLCHAIN=go1.26.5 GOWORK=off go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...

gosec:
	GOTOOLCHAIN=go1.26.5 GOWORK=off go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 \
		-quiet -severity high -confidence high ./...

govulncheck:
	GOTOOLCHAIN=go1.26.5 GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

analyzers: staticcheck gosec govulncheck

verify: fmt-check test vet assure trace-check
