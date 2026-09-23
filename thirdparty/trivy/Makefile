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

build = $(GOPIN) CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build -trimpath -buildvcs=false -ldflags "-s -w -extldflags=-Wl,-z,now,-z,relro" -o build/$(appname)-$(1)-$(2)$(3)
sha = cd build && sha256sum $(appname)-$(1)-$(2)$(3) > $(appname)-$(1)-$(2)$(3).sha256
generate_sbom = $(GOPIN) cdxgen -t go -o build/sbom-trivy-postbuild.cdx.json

.PHONY: all windows darwin linux linuxmusl sbom clean test fmt fmt-check lint

all: windows linux linuxmusl darwin sbom

test:
	$(GOPIN) go test ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l . )" || { echo "gofmt needed on: $$(gofmt -l .)"; exit 1; }

lint:
	$(GOPIN) go vet ./...

# `clean` is two lines on purpose: a target and its recipe on one line
# (`clean: rm -rf build/`) parses `rm` as a PREREQUISITE, and the target then
# has an empty recipe, so nothing is ever deleted.
clean:
	rm -rf build/

##### LINUX BUILDS #####
linux: build/linux_amd64 build/linux_arm64 build/linux_arm build/linux_ppc64le build/linux_riscv64

linuxmusl: build/linuxmusl_amd64 build/linuxmusl_arm64

sbom:
	$(call generate_sbom)

build/linux_386: $(sources)
	$(call build,linux,386,)
	$(call sha,linux,386,)

build/linux_amd64: $(sources)
	$(call build,linux,amd64,)
	$(call sha,linux,amd64,)

build/linux_arm: $(sources)
	$(call build,linux,arm,)
	$(call sha,linux,arm,)

build/linux_arm64: $(sources)
	$(call build,linux,arm64,)
	$(call sha,linux,arm64,)

# CGO_ENABLED=0 makes the binary fully static, so the alpine container only
# supplies the musl environment the artifact is named for — the amd64
# container cross-compiles GOARCH=$* natively instead of emulating a foreign
# --platform, which turned an arm64 musl build into hours under qemu.
build/linuxmusl_%: $(sources)
	$(docker_cmd) run --rm \
		-v "$(PWD)":/src \
		-w /src \
		golang:1.26-alpine \

build/linux_ppc64le: $(sources)
	$(call build,linux,ppc64le,)
	$(call sha,linux,ppc64le,)
		sh -c 'GOTOOLCHAIN=go1.26.8 GOEXPERIMENT=jsonv2 CGO_ENABLED=0 GOOS=linux GOARCH=$* go build -trimpath -buildvcs=false -ldflags "-s -w -extldflags=-Wl,-z,now,-z,relro" -o build/$(appname)-linuxmusl-$* && cd build && sha256sum $(appname)-linuxmusl-$* > $(appname)-linuxmusl-$*.sha256'

build/linux_riscv64: $(sources)
	$(call build,linux,riscv64,)
	$(call sha,linux,riscv64,)

##### DARWIN (MAC) BUILDS #####
darwin: build/darwin_amd64 build/darwin_arm64

build/darwin_amd64: $(sources)
	$(call build,darwin,amd64,)
	$(call sha,darwin,amd64,)

build/darwin_arm64: $(sources)
	$(call build,darwin,arm64,)
	$(call sha,darwin,arm64,)

##### WINDOWS BUILDS #####
windows: build/windows_amd64 build/windows_arm64

build/windows_386: $(sources)
	$(call build,windows,386,.exe)
	$(call sha,windows,386,.exe)

build/windows_amd64: $(sources)
	$(call build,windows,amd64,.exe)
	$(call sha,windows,amd64,.exe)

build/windows_arm64: $(sources)
	$(call build,windows,arm64,.exe)
	$(call sha,windows,arm64,.exe)
