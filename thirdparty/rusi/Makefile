.SHELLFLAGS := -euo pipefail -c

appname := rusi
workspace_manifest := Cargo.toml
build_dir := build
package_name := rusi-cli
cargo_nightly := cargo +nightly
host_os := $(shell uname -s | tr '[:upper:]' '[:lower:]')

linux_triples := \
	x86_64-unknown-linux-gnu \
	aarch64-unknown-linux-gnu \
	armv7-unknown-linux-gnueabihf \
	powerpc64le-unknown-linux-gnu \
	riscv64gc-unknown-linux-gnu
linuxmusl_triples := \
	x86_64-unknown-linux-musl \
	aarch64-unknown-linux-musl
windows_triples := \
	x86_64-pc-windows-gnu \
	aarch64-pc-windows-gnullvm
darwin_triples := \
	x86_64-apple-darwin \
	aarch64-apple-darwin

.PHONY: all all-supported bootstrap-linux bootstrap-darwin linux linuxmusl windows darwin sbom size clean

all: all-supported sbom

ifeq ($(host_os),linux)
all-supported: linux linuxmusl windows
else ifeq ($(host_os),darwin)
all-supported: darwin
else
all-supported:
	@echo "Unsupported host OS: $(host_os)" >&2
	@exit 1
endif

bootstrap-linux:
	rustup toolchain install nightly --profile minimal --component rust-src --component llvm-tools --component rustc-dev
	rustup target add --toolchain nightly $(linux_triples) $(linuxmusl_triples) $(windows_triples)
	$(cargo_nightly) install cargo-zigbuild --locked

bootstrap-darwin:
	rustup toolchain install nightly --profile minimal --component rust-src --component llvm-tools --component rustc-dev
	rustup target add --toolchain nightly $(darwin_triples)

linux: $(build_dir)/$(appname)-linux-amd64 $(build_dir)/$(appname)-linux-arm64 $(build_dir)/$(appname)-linux-arm $(build_dir)/$(appname)-linux-ppc64le $(build_dir)/$(appname)-linux-riscv64

linuxmusl: $(build_dir)/$(appname)-linuxmusl-amd64 $(build_dir)/$(appname)-linuxmusl-arm64

windows: $(build_dir)/$(appname)-windows-amd64.exe $(build_dir)/$(appname)-windows-arm64.exe

darwin: $(build_dir)/$(appname)-darwin-amd64 $(build_dir)/$(appname)-darwin-arm64

$(build_dir):
	mkdir -p "$(build_dir)"

define ensure_zigbuild
	@if [[ "$(host_os)" != "linux" ]]; then \
		echo "The $(1) target can only be built from Linux hosts in this Makefile." >&2; \
		exit 1; \
	fi
	@if ! command -v zig >/dev/null 2>&1; then \
		echo "zig is required to cross-build $(1); install zig and rerun make." >&2; \
		exit 1; \
	fi
	@if ! $(cargo_nightly) zigbuild --version >/dev/null 2>&1; then \
		echo "cargo-zigbuild is required to cross-build $(1); run 'make bootstrap-linux' first." >&2; \
		exit 1; \
	fi
endef

define ensure_darwin_host
	@if [[ "$(host_os)" != "darwin" ]]; then \
		echo "The $(1) target must be built on macOS in this Makefile." >&2; \
		exit 1; \
	fi
endef

define strip_binary
	@if command -v llvm-strip >/dev/null 2>&1; then \
		llvm-strip "$(1)" || true; \
	elif command -v strip >/dev/null 2>&1; then \
		strip -x "$(1)" >/dev/null 2>&1 || strip "$(1)" >/dev/null 2>&1 || true; \
	fi
endef

define write_sha
	@if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum "$(1)" > "$(1).sha256"; \
	else \
		shasum -a 256 "$(1)" > "$(1).sha256"; \
	fi
endef

define zigbuild_binary
	$(call ensure_zigbuild,$(3))
	mkdir -p "$(build_dir)"
	$(cargo_nightly) zigbuild --manifest-path "$(workspace_manifest)" --release --locked -p "$(package_name)" --target "$(1)"
	cp "target/$(1)/release/$(appname)$(4)" "$(build_dir)/$(2)$(4)"
	$(call strip_binary,$(build_dir)/$(2)$(4))
	$(call write_sha,$(build_dir)/$(2)$(4))
endef

define darwin_build_binary
	$(call ensure_darwin_host,$(3))
	mkdir -p "$(build_dir)"
	$(cargo_nightly) build --manifest-path "$(workspace_manifest)" --release --locked -p "$(package_name)" --target "$(1)"
	cp "target/$(1)/release/$(appname)" "$(build_dir)/$(2)"
	$(call strip_binary,$(build_dir)/$(2))
	$(call write_sha,$(build_dir)/$(2))
endef

$(build_dir)/$(appname)-linux-amd64: | $(build_dir)
	$(call zigbuild_binary,x86_64-unknown-linux-gnu,$(appname)-linux-amd64,linux-amd64,)

$(build_dir)/$(appname)-linux-arm64: | $(build_dir)
	$(call zigbuild_binary,aarch64-unknown-linux-gnu,$(appname)-linux-arm64,linux-arm64,)

$(build_dir)/$(appname)-linux-arm: | $(build_dir)
	$(call zigbuild_binary,armv7-unknown-linux-gnueabihf,$(appname)-linux-arm,linux-arm,)

$(build_dir)/$(appname)-linux-ppc64le: | $(build_dir)
	$(call zigbuild_binary,powerpc64le-unknown-linux-gnu,$(appname)-linux-ppc64le,linux-ppc64le,)

$(build_dir)/$(appname)-linux-riscv64: | $(build_dir)
	$(call zigbuild_binary,riscv64gc-unknown-linux-gnu,$(appname)-linux-riscv64,linux-riscv64,)

$(build_dir)/$(appname)-linuxmusl-amd64: | $(build_dir)
	$(call zigbuild_binary,x86_64-unknown-linux-musl,$(appname)-linuxmusl-amd64,linuxmusl-amd64,)

$(build_dir)/$(appname)-linuxmusl-arm64: | $(build_dir)
	$(call zigbuild_binary,aarch64-unknown-linux-musl,$(appname)-linuxmusl-arm64,linuxmusl-arm64,)

$(build_dir)/$(appname)-windows-amd64.exe: | $(build_dir)
	$(call zigbuild_binary,x86_64-pc-windows-gnu,$(appname)-windows-amd64,windows-amd64,.exe)

$(build_dir)/$(appname)-windows-arm64.exe: | $(build_dir)
	$(call zigbuild_binary,aarch64-pc-windows-gnullvm,$(appname)-windows-arm64,windows-arm64,.exe)

$(build_dir)/$(appname)-darwin-amd64: | $(build_dir)
	$(call darwin_build_binary,x86_64-apple-darwin,$(appname)-darwin-amd64,darwin-amd64)

$(build_dir)/$(appname)-darwin-arm64: | $(build_dir)
	$(call darwin_build_binary,aarch64-apple-darwin,$(appname)-darwin-arm64,darwin-arm64)

sbom: | $(build_dir)
	@if ! command -v cdxgen >/dev/null 2>&1; then \
		echo "cdxgen is required to generate the Rusi SBOM; install it and rerun make sbom." >&2; \
		exit 1; \
	fi
	cdxgen -t rust -o "$(build_dir)/sbom-rusi-postbuild.cdx.json"

size:
	@find "$(build_dir)" -maxdepth 1 -type f -name '$(appname)-*' -print0 2>/dev/null | \
	  xargs -0 ls -lh 2>/dev/null || true

clean:
	rm -rf "$(build_dir)"
