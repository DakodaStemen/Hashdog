.DEFAULT_GOAL := help
.PHONY: help setup lint test build ci clean

help:
	@echo "make setup   download Go modules (needs Go matching go.mod)"
	@echo "make lint    gofmt, go vet, shellcheck (errors only) on the scripts"
	@echo "make test    go test -race"
	@echo "make build   build ./hashdog"
	@echo "make ci      lint + test + build"
	@echo "make clean   remove ./hashdog"

setup:
	@command -v go >/dev/null || { echo "need go on PATH" >&2; exit 1; }
	go mod download

# bench/ and docs/ scripts are legacy demo helpers with style-level shellcheck warnings;
# only error-level findings fail the lint.
lint:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed on:"; gofmt -l .; exit 1; }
	go vet ./...
	shellcheck -S error bench/*.sh docs/*.sh

test:
	go test -race -count=1 ./...

build:
	go build -o hashdog .

ci: lint test build

clean:
	rm -f hashdog
