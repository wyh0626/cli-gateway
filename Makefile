VERSION ?= 0.3.0-dev
BINDIR ?= bin
PREFIX ?= /usr/local
CLI_NAME ?= cg
CLI_DISPLAY_NAME ?=
CLI_ENV_PREFIX ?=
CLI_CONFIG_DIR ?=
CLI_CACHE_DIR ?=
CLI_KEYRING_SERVICE ?=
CLI_USER_AGENT ?=

CLI_LDFLAGS = -s -w -X github.com/wyh0626/cli-gateway/client/internal/app.version=$(VERSION) -X github.com/wyh0626/cli-gateway/client/internal/branding.BuildName=$(CLI_NAME)
ifneq ($(strip $(CLI_DISPLAY_NAME)),)
CLI_LDFLAGS += -X 'github.com/wyh0626/cli-gateway/client/internal/branding.BuildDisplayName=$(CLI_DISPLAY_NAME)'
endif
ifneq ($(strip $(CLI_ENV_PREFIX)),)
CLI_LDFLAGS += -X github.com/wyh0626/cli-gateway/client/internal/branding.BuildEnvPrefix=$(CLI_ENV_PREFIX)
endif
ifneq ($(strip $(CLI_CONFIG_DIR)),)
CLI_LDFLAGS += -X github.com/wyh0626/cli-gateway/client/internal/branding.BuildConfigDirName=$(CLI_CONFIG_DIR)
endif
ifneq ($(strip $(CLI_CACHE_DIR)),)
CLI_LDFLAGS += -X github.com/wyh0626/cli-gateway/client/internal/branding.BuildCacheDirName=$(CLI_CACHE_DIR)
endif
ifneq ($(strip $(CLI_KEYRING_SERVICE)),)
CLI_LDFLAGS += -X github.com/wyh0626/cli-gateway/client/internal/branding.BuildKeyringService=$(CLI_KEYRING_SERVICE)
endif
ifneq ($(strip $(CLI_USER_AGENT)),)
CLI_LDFLAGS += -X github.com/wyh0626/cli-gateway/client/internal/branding.BuildUserAgent=$(CLI_USER_AGENT)
endif

.PHONY: help build build-gateway build-client install-client fmt fmt-check test test-race vet verify verify-m0 verify-m1 verify-m2 verify-m2a verify-m2b verify-m2c verify-m3a verify-m3b verify-m4 verify-m5 verify-m6 verify-client-c0 run run-demo run-issuer load-direct load-gateway container

help:
	@echo "Common targets:"
	@echo "  make build                         build cli-gateway and the default cg client"
	@echo "  make build-client CLI_NAME=acme    build a white-label client at bin/acme"
	@echo "  make install-client [PREFIX=...]   install the selected client"
	@echo "  make verify                        run formatting, vet, and unit tests"
	@echo "  make test-race                     run the race-enabled test suite"

build: build-gateway build-client

build-gateway:
	mkdir -p "$(BINDIR)"
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$(BINDIR)/cli-gateway" ./cmd/cli-gateway

build-client:
	mkdir -p "$(BINDIR)"
	CGO_ENABLED=0 go build -trimpath -ldflags="$(CLI_LDFLAGS)" -o "$(BINDIR)/$(CLI_NAME)" ./client/cmd/cg

install-client: build-client
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 "$(BINDIR)/$(CLI_NAME)" "$(DESTDIR)$(PREFIX)/bin/$(CLI_NAME)"

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

fmt-check:
	test -z "$$(gofmt -l .)"

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

verify: fmt-check vet test

verify-m0:
	go test ./internal/model ./internal/httpx ./internal/audit

verify-m1:
	go test ./internal/manifest ./internal/server ./cmd/cli-gateway

verify-m2:
	go test ./internal/auth ./internal/policy ./internal/upstream ./internal/invoke ./internal/server

verify-m2a:
	go test ./internal/auth ./internal/catalog ./internal/policy ./internal/server

verify-m2b:
	go test ./internal/upstream ./internal/invoke ./internal/server

verify-m2c:
	go test ./internal/runtime ./internal/catalog ./internal/invoke

verify-m3a:
	go test ./internal/auth ./internal/identity ./internal/cache ./internal/credential

verify-m3b:
	go test ./internal/breaker ./internal/audit ./internal/observability ./internal/limiter ./internal/runtime

verify-m4:
	go test ./client/... ./cmd/devissuer

verify-m5:
	go test ./internal/adapter/mcp ./internal/runtime ./internal/server

verify-m6: fmt-check vet test test-race

verify-client-c0:
	go test ./client/...

run:
	go run ./cmd/cli-gateway -manifest manifest.example.yaml

run-demo:
	go run ./cmd/demoapi

run-issuer:
	go run ./cmd/devissuer

load-direct:
	go run ./cmd/loadtest -url 'http://127.0.0.1:18081/v1/work?delay_ms=5' -c 32 -d 10s

load-gateway:
	go run ./cmd/loadtest -url 'http://127.0.0.1:18082/exec/demo/work' -method POST -body '{"args":{"delay-ms":5}}' -token-url 'http://127.0.0.1:18080/token' -c 32 -d 10s

container:
	docker build -f Containerfile -t cli-gateway:dev .
