built_at := $(shell date +%s)
git_commit := $(shell git describe --dirty --always)
version=$(shell cat version/version | tr -d '\n')

BIN:=./bin
GOLANGCI_LINT_VERSION?=1.30.0

ifeq ($(OS),Windows_NT)
    OSNAME = windows
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        OSNAME = linux
		GOLANGCI_LINT_ARCHIVE=golangci-lint-$(GOLANGCI_LINT_VERSION)-linux-amd64.tar.gz
    endif
    ifeq ($(UNAME_S),Darwin)
        OSNAME = darwin
		GOLANGCI_LINT_ARCHIVE=golangci-lint-$(GOLANGCI_LINT_VERSION)-darwin-amd64.tar.gz
    endif
endif

.PHONY: all
all: unit-test lint build

.PHONY: ci
ci: unit-test lint build-ci

.PHONY: build-local
build-local: deps unit-test
	operator-sdk build --go-build-args '-ldflags=-s -ldflags=-w' xo.90poe.io/vault-secrets-operator:$(version)

.PHONY: build
build:
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -mod=vendor \
	-ldflags="-s -w -X github.com/90poe/vault-secrets-operator/version.GitHash=$(git_commit) \
	-X github.com/90poe/vault-secrets-operator/version.BuildDate=$(built_at) \
	-X github.com/90poe/vault-secrets-operator/version.Version=$(version)" \
	-a -o ./artifacts/manager ./cmd/manager
	mv ./artifacts/manager ./artifacts/manager-unpacked
	upx -q -o ./artifacts/manager ./artifacts/manager-unpacked
	rm -rf ./artifacts/manager-unpacked

.PHONY: build-ci
build-ci:
	CGO_ENABLED=0 go build -mod=vendor \
	-ldflags="-s -w -X github.com/90poe/vault-secrets-operator/internal/version.GitHash=$(git_commit) \
	-X github.com/90poe/vault-secrets-operator/version.BuildDate=$(built_at) \
	-X github.com/90poe/vault-secrets-operator/version.Version=$(version)" \
	-a -o ./artifacts/manager ./cmd/manager

deps:
	operator-sdk generate crds
	operator-sdk generate k8s

unit-test:
	go test -v -parallel=2 -mod=vendor -cover -covermode=count \
	-coverprofile=coverage.out $$(go list ./...)

.PHONY: lint
lint: $(BIN)/golangci-lint/golangci-lint ## lint
	$(BIN)/golangci-lint/golangci-lint run

$(BIN)/golangci-lint/golangci-lint:
	curl -OL https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/$(GOLANGCI_LINT_ARCHIVE)
	mkdir -p $(BIN)/golangci-lint/
	tar -xf $(GOLANGCI_LINT_ARCHIVE) --strip-components=1 -C $(BIN)/golangci-lint/
	chmod +x $(BIN)/golangci-lint
	rm -f $(GOLANGCI_LINT_ARCHIVE)
