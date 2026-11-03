# vmgate - a rootless userspace gateway for QEMU, on the gVisor netstack.
#
#   make            build ./vmgate
#   make test       unit and in-process integration tests (no QEMU needed)
#   make race       the same under the race detector
#   make check      gofmt check, vet, tests
#   make qemu       start vmgate and a QEMU guest (needs qemu-system-x86_64)

GO      ?= go
BINARY  ?= vmgate
PKG     := ./cmd/vmgate
TESTTIMEOUT ?= 240s

.PHONY: all build test race vet fmt fmt-check check qemu clean

all: build

build:
	$(GO) build -o $(BINARY) $(PKG)

test:
	$(GO) test -timeout $(TESTTIMEOUT) ./...

race:
	$(GO) test -race -timeout 300s ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

fmt-check:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then echo "$$files"; echo "unformatted, run: make fmt"; exit 1; fi

check: fmt-check vet test

qemu: build
	./examples/run-qemu.sh

clean:
	rm -f $(BINARY)
