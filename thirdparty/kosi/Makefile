SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

appname := kosi
build_dir := build
package_name := kosi-cli

host_os_raw := $(shell uname -s | tr '[:upper:]' '[:lower:]')
host_arch_raw := $(shell uname -m | tr '[:upper:]' '[:lower:]')

ifeq ($(findstring darwin,$(host_os_raw)),darwin)
  host_os := darwin
else ifeq ($(findstring linux,$(host_os_raw)),linux)
  host_os := linux
else ifneq (,$(findstring mingw,$(host_os_raw))$(findstring msys,$(host_os_raw))$(findstring cygwin,$(host_os_raw))$(findstring windows,$(host_os_raw)))
  host_os := windows
else
  host_os := unknown
endif

ifeq ($(host_arch_raw),arm64)
  host_arch := arm64
else ifeq ($(host_arch_raw),aarch64)
  host_arch := arm64
else ifeq ($(host_arch_raw),x86_64)
  host_arch := amd64
else ifeq ($(host_arch_raw),amd64)
  host_arch := amd64
else ifeq ($(host_arch_raw),ppc64le)
  host_arch := ppc64le
else ifeq ($(host_arch_raw),riscv64)
  host_arch := riscv64
else ifneq (,$(findstring armv,$(host_arch_raw)))
  host_arch := arm
else
  host_arch := unknown
endif

host_platform := $(host_os)-$(host_arch)

# GraalVM JDK 25 toolchain (05-BUILD-DIST.md). Overridable:
#   make native GRAAL_HOME=/path/to/graalvm
# Resolution order: an explicit GRAAL_HOME, then a JAVA_HOME that already
# provides native-image (sdkman/asdf/CI installs land there), then the pinned
# release under $HOME/tools. macOS layouts put the JDK under Contents/Home.
ifeq ($(host_os),darwin)
  graal_home_pinned := $(HOME)/tools/graalvm-community-25.3.4.1+1.1/Contents/Home
else
  graal_home_pinned := $(HOME)/tools/graalvm-community-25.3.4.1+1.1
endif
graal_home_default := $(if $(and $(JAVA_HOME),$(wildcard $(JAVA_HOME)/bin/native-image)),$(JAVA_HOME),$(graal_home_pinned))
GRAAL_HOME ?= $(graal_home_default)
graal_env = JAVA_HOME=$(GRAAL_HOME) PATH="$(GRAAL_HOME)/bin:$(PATH)"

gradle := ./gradlew --no-daemon

.PHONY: all all-supported bootstrap-darwin bootstrap-linux bootstrap-windows \
        native linux linuxmusl windows darwin \
        native-metadata native-metadata-check test corpusQuick corpusFull \
        golden goldenUpdate sbom size clean

## all: host-family native build plus tests, corpus ratchet and goldens.
all: all-supported
all-supported:
ifeq ($(host_os),darwin)
	$(MAKE) test corpusQuick golden darwin
else ifeq ($(host_os),linux)
	$(MAKE) test corpusQuick golden linux
else ifeq ($(host_os),windows)
	$(MAKE) test corpusQuick golden windows
else
	$(error "no supported build for $(host_os_raw); kosi ships native images for darwin, linux and windows")
endif

## bootstrap-*: install/verify the pinned GraalVM toolchain.
bootstrap-darwin bootstrap-linux bootstrap-windows:
	@test -x "$(GRAAL_HOME)/bin/native-image" || { \
	  echo "GraalVM (with native-image) not found at $(GRAAL_HOME)."; \
	  echo "Either point GRAAL_HOME at an existing install:"; \
	  echo "  make native GRAAL_HOME=/path/to/graalvm"; \
	  echo "or install a GraalVM CE JDK 25 build from"; \
	  echo "  https://github.com/graalvm/graalvm-ce-builds/releases"; \
	  echo "(sdkman: sdk install java 25-graalce) and re-run."; \
	  exit 1; \
	}
	@$(GRAAL_HOME)/bin/native-image --version

# native-image cannot cross-compile: every family target builds the binary
# for the host it runs on, under the platform name the packages stage
# (darwin-arm64, linux-amd64, ...). The release workflow runs each target on
# a matching runner — the same shape as golem. Declared gaps, named here and
# in scripts/plugin-platform-support.sh (never silently skipped):
#   ppc64le, 32-bit arm - not Native Image platforms at all
#   riscv64             - best-effort LLVM backend, not built at this phase
define build_native
	$(graal_env) $(gradle) :kosi-cli:kosiFatJar
	$(graal_env) native-image -jar modules/kosi-cli/build/dist/kosi-all.jar \
	  -Os --gc=serial \
	  -H:ConfigurationFileDirectories=native-metadata/kosi \
	  -H:IncludeResources='^kosi-libs/.*|^kosi-ext/.*|^META-INF/services/.*|^META-INF/.*\.xml$$|^META-INF/extensions/.*\.xml$$' \
	  -H:+UnlockExperimentalVMOptions \
	  -H:+AddAllCharsets \
	  --enable-monitoring=jfr \
	  $(1) -o $(2)
	@rm -f $(2).sha256
	@cd $(build_dir) && shasum -a 256 $(notdir $(2)) > $(notdir $(2)).sha256
endef

$(build_dir):
	mkdir -p "$(build_dir)"

$(build_dir)/kosi-darwin-%: native-metadata/kosi/reachability-metadata.json | $(build_dir)
	$(call build_native,,$(build_dir)/kosi-darwin-$*)

$(build_dir)/kosi-linux-%: native-metadata/kosi/reachability-metadata.json | $(build_dir)
	$(call build_native,,$(build_dir)/kosi-linux-$*)

$(build_dir)/kosi-linuxmusl-%: native-metadata/kosi/reachability-metadata.json | $(build_dir)
	$(call build_native,--static --libc=musl,$(build_dir)/kosi-linuxmusl-$*)

$(build_dir)/kosi-windows-%.exe: native-metadata/kosi/reachability-metadata.json | $(build_dir)
	$(call build_native,,$(build_dir)/kosi-windows-$*.exe)

## native: host-platform binary (whichever family this machine is).
native: $(build_dir)/kosi-$(host_platform)

# Host guards run BEFORE the build so a declared gap is a named error, not a
# GraalVM crash (serial make runs prerequisites in order).
.PHONY: check-darwin-host check-linux-host check-linuxmusl-host check-windows-host
check-darwin-host:
ifneq ($(host_os),darwin)
	@echo "Error: darwin kosi binaries are built on macOS runners (native-image cannot cross-compile)." >&2; exit 1
endif

check-linux-host: check-linux-arch
ifneq ($(host_os),linux)
	@echo "Error: linux kosi binaries are built on Linux runners (native-image cannot cross-compile)." >&2; exit 1
endif

check-linuxmusl-host: check-linux-arch
ifneq ($(host_os),linux)
	@echo "Error: linuxmusl kosi binaries are built on Linux runners with musl-gcc installed (apt install musl-tools)." >&2; exit 1
endif
	@command -v musl-gcc >/dev/null 2>&1 || { \
	  echo "Error: musl-gcc not found; --static --libc=musl needs it (apt install musl-tools)." >&2; \
	  exit 1; }

.PHONY: check-linux-arch
check-linux-arch:
ifeq ($(host_arch),ppc64le)
	@echo "Error: ppc64le is not a GraalVM Native Image platform; the JVM-jar fallback covers it (docs/KOSI.md)." >&2; exit 1
endif
ifeq ($(host_arch),arm)
	@echo "Error: 32-bit arm is not a GraalVM Native Image platform; the JVM-jar fallback covers it (docs/KOSI.md)." >&2; exit 1
endif
ifeq ($(host_arch),riscv64)
	@echo "Error: riscv64 is best-effort (LLVM backend) and not built at this phase." >&2; exit 1
endif

check-windows-host:
ifneq ($(host_os),windows)
	@echo "Error: windows kosi binaries are built on Windows runners with the MSVC toolchain (docs/BUILD.md §6)." >&2; exit 1
endif

## darwin: host-arch macOS binary (both macos runner types run this for both).
darwin: check-darwin-host $(build_dir)/kosi-darwin-$(host_arch)

## linux: host-arch Linux binary. ppc64le/arm/riscv64 are declared gaps.
linux: check-linux-host $(build_dir)/kosi-linux-$(host_arch)

## linuxmusl: static musl binary for the host arch (needs musl-gcc).
linuxmusl: check-linuxmusl-host $(build_dir)/kosi-linuxmusl-$(host_arch)

## windows: host-arch Windows binary (MSVC toolchain; docs/BUILD.md §6).
windows: check-windows-host $(build_dir)/kosi-windows-$(host_arch).exe

## native-metadata: re-run the tracing agent over the whole fixture tree —
## syntax AND resolved backends (the resolved pass exercises the Analysis
## API session, the reflection/ServiceLoader heart of the binary) — and
## merge the result into native-metadata/kosi. CI fails if the checked-in
## metadata differs from what the agent produces (native-metadata-check).
## The JetBrains compiler metadata is no longer used: P1 moved the substrate
## from the shaded kotlin-compiler-embeddable to the unrelocated -for-ide
## artifacts, whose reflection surface the agent re-derives from our runs.
native-metadata:
	@rm -rf /tmp/kosi-agent-run && mkdir -p /tmp/kosi-agent-run
	$(graal_env) $(gradle) :kosi-cli:kosiFatJar
	@for f in fixtures/*/; do \
	  slug=$$(basename $$f); \
	  $(graal_env) "$(GRAAL_HOME)/bin/java" -agentlib:native-image-agent=config-output-dir=/tmp/kosi-agent-run/$$slug \
	    -jar modules/kosi-cli/build/dist/kosi-all.jar analyze --dir $$f --out /dev/null; \
	  $(graal_env) "$(GRAAL_HOME)/bin/java" -agentlib:native-image-agent=config-output-dir=/tmp/kosi-agent-run/$$slug-resolved \
	    -jar modules/kosi-cli/build/dist/kosi-all.jar analyze --backend resolved --dir $$f --out /dev/null; \
	done
	python3 scripts/merge-agent-metadata.py /tmp/kosi-agent-run native-metadata/kosi/reachability-metadata.json

native-metadata-check: native-metadata
	@git diff --exit-code -- native-metadata/kosi/reachability-metadata.json || { \
	  echo "reachability metadata drifted; commit the regenerated file"; exit 1; }

## Tiers and gates (same entry points CI uses).
test:
	$(gradle) build

corpusQuick:
	$(gradle) corpusQuick

corpusFull:
	$(gradle) corpusFull

golden:
	$(gradle) golden

goldenUpdate:
	$(gradle) goldenUpdate

## sbom: post-build CycloneDX SBOM of the kosi workspace.
sbom:
	cdxgen -t kotlin -o $(build_dir)/sbom-kosi-postbuild.cdx.json

## size: staged native binaries and jars.
size:
	@find "$(build_dir)" -maxdepth 1 -type f -name '$(appname)-*' -print0 2>/dev/null | \
	  xargs -0 ls -lh 2>/dev/null || true

clean:
	rm -rf "$(build_dir)" modules/*/build .gradle .corpus-cache
