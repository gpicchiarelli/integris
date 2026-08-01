.PHONY: all fmt fmt-check test vet assure trace-check evidence verify

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

verify: fmt-check test vet assure trace-check
