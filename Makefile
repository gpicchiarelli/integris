.PHONY: all fmt fmt-check test vet assure trace-check verify

all: verify

fmt:
	gofmt -w ./cmd

fmt-check:
	@test -z "$$(gofmt -l ./cmd)" || { echo "Go files require formatting"; gofmt -l ./cmd; exit 1; }

test:
	go test ./...

vet:
	go vet ./...

assure:
	go run ./cmd/integris-assure validate --root .

trace-check:
	go run ./cmd/integris-assure trace --root . --check

verify: fmt-check test vet assure trace-check
