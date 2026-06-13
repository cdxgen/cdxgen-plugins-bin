appname := cdxui
version := $(shell node -p "require('../../package.json').version")

build_dir := build

define build
	@echo "Building $(appname) for $(1)-$(2)..."
	rustup target add $(3) 2>/dev/null || true
	cargo build --release --target $(3)
	mkdir -p $(build_dir)
	cp target/$(3)/release/$(appname)$(4) $(build_dir)/$(appname)-$(1)$(4)
	cd $(build_dir) && shasum -a 256 $(appname)-$(1)$(4) > $(appname)-$(1)$(4).sha256
endef

linux:
	$(call build,linux-amd64,$(version),x86_64-unknown-linux-gnu,)
	$(call build,linux-arm64,$(version),aarch64-unknown-linux-gnu,)
	$(call build,linux-arm,$(version),armv7-unknown-linux-gnueabihf,)
	$(call build,linux-riscv64,$(version),riscv64gc-unknown-linux-gnu,)

linuxmusl:
	$(call build,linuxmusl-amd64,$(version),x86_64-unknown-linux-musl,)
	$(call build,linuxmusl-arm64,$(version),aarch64-unknown-linux-musl,)

darwin:
	$(call build,darwin-amd64,$(version),x86_64-apple-darwin,)
	$(call build,darwin-arm64,$(version),aarch64-apple-darwin,)

windows:
	$(call build,windows-amd64,$(version),x86_64-pc-windows-gnu,.exe)
	$(call build,windows-arm64,$(version),aarch64-pc-windows-gnullvm,.exe)

sbom:
	@echo "Generating SBOM for $(appname)..."
	-cdxgen -t rust -o $(build_dir)/sbom-$(appname)-postbuild.cdx.json

all-supported: linux linuxmusl windows sbom

all: darwin sbom

test:
	cargo test

clean:
	rm -rf $(build_dir) target

.PHONY: all all-supported linux linuxmusl darwin windows sbom test clean
