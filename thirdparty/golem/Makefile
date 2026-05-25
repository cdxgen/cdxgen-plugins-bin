PATH := $(PATH):/usr/local/go/bin:$(HOME)/go/bin
appname := golem
version ?= 2.2.0
sources := $(shell find cmd internal -type f -name '*.go')
ldflags := -s -w -X main.version=$(version)

build = CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build -trimpath -ldflags "$(ldflags)" -o build/$(appname)-$(1)-$(2)$(3) ./cmd/golem
sha = cd build && sha256sum $(appname)-$(1)-$(2)$(3) > $(appname)-$(1)-$(2)$(3).sha256
generate_sbom = cdxgen -t go -o build/sbom-golem-postbuild.cdx.json

.PHONY: all windows darwin linux test sbom clean
all: test windows linux darwin sbom

test:
	go test ./...

clean:
	rm -rf build/

linux: build/linux_amd64 build/linux_arm64 build/linux_arm build/linux_ppc64le build/linux_riscv64

build/linux_amd64: $(sources)
	$(call build,linux,amd64,)
	$(call sha,linux,amd64,)

build/linux_arm: $(sources)
	$(call build,linux,arm,)
	$(call sha,linux,arm,)

build/linux_arm64: $(sources)
	$(call build,linux,arm64,)
	$(call sha,linux,arm64,)

build/linux_ppc64le: $(sources)
	$(call build,linux,ppc64le,)
	$(call sha,linux,ppc64le,)

build/linux_riscv64: $(sources)
	$(call build,linux,riscv64,)
	$(call sha,linux,riscv64,)

darwin: build/darwin_amd64 build/darwin_arm64

build/darwin_amd64: $(sources)
	$(call build,darwin,amd64,)
	$(call sha,darwin,amd64,)

build/darwin_arm64: $(sources)
	$(call build,darwin,arm64,)
	$(call sha,darwin,arm64,)

windows: build/windows_amd64 build/windows_arm64

build/windows_amd64: $(sources)
	$(call build,windows,amd64,.exe)
	$(call sha,windows,amd64,.exe)

build/windows_arm64: $(sources)
	$(call build,windows,arm64,.exe)
	$(call sha,windows,arm64,.exe)

sbom:
	$(call generate_sbom)
