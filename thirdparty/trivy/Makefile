PATH  := $(PATH):/usr/local/go/bin:$HOME/go/bin:
appname := trivy-cdxgen
sources := $(wildcard *.go)
docker_cmd := docker

# The toolchain is pinned, not merely floored. github.com/aquasecurity/trivy
# v0.74.0 — the newest release — is written against encoding/json/v2 as Go 1.26
# exposes it under GOEXPERIMENT=jsonv2, and Go 1.27 stabilised that package
# with a changed API (json.SkipFunc is gone), so 1.27 cannot compile it. go.mod
# states the same 1.26.8 this pin carries: the two move together. Every recipe
# builds with the same toolchain whatever the host or CI has installed. Drop
# both settings once a trivy release supports Go 1.27.
GOPIN := GOTOOLCHAIN=go1.26.8 GOEXPERIMENT=jsonv2

# Release binaries link only the parts of Trivy the wrapper can run. Trivy's
# core packages import its misconfiguration, vulnerability, Kubernetes and
# client/server stacks for a handful of constants and types, so a plain build
# links all of them. overlay/patches cuts those imports; `go run ./overlay`
# applies the patches to a vendored copy and writes a `go build -overlay`
# file (Go refuses overlays inside GOMODCACHE, hence the vendoring). The
# grpcnotrace tag keeps golang.org/x/net/trace and its html/template out.
# Both matter beyond their own size: text/template's reflection makes the
# linker keep every exported method of every reachable type. See README.md.
overlay := .overlay/overlay.json
slim := -mod=vendor -overlay=$(overlay) -tags grpcnotrace

build = $(GOPIN) CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build $(slim) -trimpath -buildvcs=false -ldflags "-s -w -extldflags=-Wl,-z,now,-z,relro" -o build/$(appname)-$(1)-$(2)$(3)
sha = cd build && sha256sum $(appname)-$(1)-$(2)$(3) > $(appname)-$(1)-$(2)$(3).sha256
generate_sbom = $(GOPIN) cdxgen -t go -o build/sbom-trivy-postbuild.cdx.json

.PHONY: all windows darwin linux linuxmusl sbom clean test fmt fmt-check lint local

all: windows linux linuxmusl darwin sbom

# The vendor directory and overlay are regenerated whenever the module
# requirements or the patches change. A patch that no longer applies to the
# vendored Trivy fails here, before anything is built.
$(overlay): go.mod go.sum $(wildcard overlay/*.go) $(wildcard overlay/patches/*.patch)
	$(GOPIN) go mod vendor
	$(GOPIN) go run ./overlay

# The tests run twice: against upstream Trivy, where they also check that the
# overlay's inlined values and analyzer list still match upstream, and against
# the patched build that ships.
test: $(overlay)
	$(GOPIN) go test ./...
	$(GOPIN) go test $(slim) . ./overlay

# A host binary for local checks, built exactly like the release binaries.
local: $(overlay)
	$(GOPIN) CGO_ENABLED=0 go build $(slim) -trimpath -buildvcs=false -ldflags "-s -w" -o build/$(appname)-local

# Only the wrapper's own sources: vendor/ and .overlay/ hold third-party code.
gofiles = *.go overlay

fmt:
	gofmt -w $(gofiles)

fmt-check:
	@test -z "$$(gofmt -l $(gofiles))" || { echo "gofmt needed on: $$(gofmt -l $(gofiles))"; exit 1; }

lint: $(overlay)
	$(GOPIN) go vet ./...
	$(GOPIN) go vet $(slim) . ./overlay

# `clean` is two lines on purpose: a target and its recipe on one line
# (`clean: rm -rf build/`) parses `rm` as a PREREQUISITE, and the target then
# has an empty recipe, so nothing is ever deleted.
clean:
	rm -rf build/ .overlay/ vendor/

##### LINUX BUILDS #####
linux: build/linux_amd64 build/linux_arm64 build/linux_arm build/linux_ppc64le build/linux_riscv64

linuxmusl: build/linuxmusl_amd64 build/linuxmusl_arm64

sbom:
	$(call generate_sbom)

build/linux_386: $(sources) $(overlay)
	$(call build,linux,386,)
	$(call sha,linux,386,)

build/linux_amd64: $(sources) $(overlay)
	$(call build,linux,amd64,)
	$(call sha,linux,amd64,)

build/linux_arm: $(sources) $(overlay)
	$(call build,linux,arm,)
	$(call sha,linux,arm,)

build/linux_arm64: $(sources) $(overlay)
	$(call build,linux,arm64,)
	$(call sha,linux,arm64,)

# CGO_ENABLED=0 makes the binary fully static, so the alpine container only
# supplies the musl environment the artifact is named for — the amd64
# container cross-compiles GOARCH=$* natively instead of emulating a foreign
# --platform, which turned an arm64 musl build into hours under qemu.
# The container runs as the invoking user so the volume-mounted outputs stay
# owned by that user on the host: as container root they arrive root-owned and
# the caller's chmod/upx on them fails with EPERM (build.sh stages build/*
# with `chmod +x`). HOME and GOPATH move to /tmp because the image's /root
# and /go are not writable by an unprivileged uid, and go refuses to build
# without a writable cache.
build/linuxmusl_%: $(sources) $(overlay)
	$(docker_cmd) run --rm \
		--user "$(shell id -u):$(shell id -g)" \
		-e HOME=/tmp -e GOPATH=/tmp/go \
		-v "$(PWD)":/src \
		-w /src \
		golang:1.26-alpine \
		sh -c 'GOTOOLCHAIN=go1.26.8 GOEXPERIMENT=jsonv2 CGO_ENABLED=0 GOOS=linux GOARCH=$* go build $(slim) -trimpath -buildvcs=false -ldflags "-s -w -extldflags=-Wl,-z,now,-z,relro" -o build/$(appname)-linuxmusl-$* && cd build && sha256sum $(appname)-linuxmusl-$* > $(appname)-linuxmusl-$*.sha256'

build/linux_ppc64le: $(sources) $(overlay)
	$(call build,linux,ppc64le,)
	$(call sha,linux,ppc64le,)

build/linux_riscv64: $(sources) $(overlay)
	$(call build,linux,riscv64,)
	$(call sha,linux,riscv64,)

##### DARWIN (MAC) BUILDS #####
darwin: build/darwin_amd64 build/darwin_arm64

build/darwin_amd64: $(sources) $(overlay)
	$(call build,darwin,amd64,)
	$(call sha,darwin,amd64,)

build/darwin_arm64: $(sources) $(overlay)
	$(call build,darwin,arm64,)
	$(call sha,darwin,arm64,)

##### WINDOWS BUILDS #####
windows: build/windows_amd64 build/windows_arm64

build/windows_386: $(sources) $(overlay)
	$(call build,windows,386,.exe)
	$(call sha,windows,386,.exe)

build/windows_amd64: $(sources) $(overlay)
	$(call build,windows,amd64,.exe)
	$(call sha,windows,amd64,.exe)

build/windows_arm64: $(sources) $(overlay)
	$(call build,windows,arm64,.exe)
	$(call sha,windows,arm64,.exe)
