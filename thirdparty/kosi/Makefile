SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

appname := kosi
build_dir := build
package_name := kosi-cli

# GraalVM JDK 25 toolchain, pinned (05-BUILD-DIST.md). Overridable:
#   make native GRAAL_HOME=/path/to/graalvm
# The toolchain is scoped to the native targets; the Gradle tiers run on the
# ambient JDK (21+) so a machine without GraalVM can still run every gate
# except `native`.
GRAAL_HOME ?= $(HOME)/tools/graalvm-community-25.3.4.1+1.1/Contents/Home
graal_env = JAVA_HOME=$(GRAAL_HOME) PATH="$(GRAAL_HOME)/bin:$(PATH)"

gradle := ./gradlew --no-daemon
host_os := $(shell uname -s | tr '[:upper:]' '[:lower:]')
host_arch := $(shell uname -m)
ifeq ($(host_os),darwin)
  host_platform := darwin-$(subst arm64,aarch64,$(subst x86_64,amd64,$(host_arch)))
else ifeq ($(host_os),linux)
  host_platform := linux-$(subst aarch64,arm64,$(subst x86_64,amd64,$(host_arch)))
else
  host_platform := unknown
endif

.PHONY: all all-supported bootstrap-darwin bootstrap-linux native native-metadata \
        native-metadata-check test corpusQuick corpusFull golden goldenUpdate sbom size clean

## all: host-native build plus tests, corpus ratchet and goldens, then sbom.
all: all-supported
all-supported:
ifeq ($(host_os),darwin)
	$(MAKE) test corpusQuick golden native
else ifeq ($(host_os),linux)
	$(MAKE) test corpusQuick golden native
else
	$(error "no supported build for $(host_os); kosi ships native images for darwin and linux")
endif

## bootstrap-darwin / bootstrap-linux: install the pinned GraalVM toolchain.
bootstrap-darwin bootstrap-linux:
	@test -x "$(GRAAL_HOME)/bin/native-image" || { \
	  echo "GraalVM not found at $(GRAAL_HOME)."; \
	  echo "Install the pinned toolchain:"; \
	  echo "  mkdir -p $$HOME/tools && curl -sL -o /tmp/graalvm.tar.gz \\"; \
	  echo "    https://github.com/graalvm/graalvm-ce-builds/releases/download/graal-25.3.4.1/graalvm-community-jdk-25i3-25.0.4.1_$$(case '$(host_os)' in darwin) echo macos-aarch64;; *) echo linux-amd64;; esac)_bin.tar.gz"; \
	  echo "  tar xzf /tmp/graalvm.tar.gz -C $$HOME/tools/"; \
	  exit 1; \
	}
	@$(GRAAL_HOME)/bin/native-image --version

## native: deterministic fat jar + GraalVM native image for the host platform.
## KT-68829 (shaded JLine native-image entries referencing absent files) is
## handled inside the kosiFatJar task; reachability metadata is seeded from
## JetBrains' compiler-native-image config plus our tracing-agent pass.
native: $(build_dir)/kosi-$(host_platform)

$(build_dir)/kosi-$(host_platform): native-metadata/jetbrains/kotlin-compiler-embeddable-reachability-metadata.json
	$(graal_env) $(gradle) :kosi-cli:kosiFatJar
	$(graal_env) native-image -jar modules/kosi-cli/build/dist/kosi-all.jar \
	  -Os --gc=serial \
	  -H:ConfigurationFileDirectories=native-metadata/merged \
	  -H:DynamicProxyConfigurationFiles=native-metadata/proxy-config.json \
	  -H:IncludeResources='^kosi-ext/META-INF/extensions/.*\.xml$$|^META-INF/services/.*|^META-INF/.*\.xml' \
	  --initialize-at-run-time=org.jetbrains.kotlin.com.intellij.openapi.util.registry.EarlyAccessRegistry \
	  -o $(build_dir)/kosi-$(host_platform)
	@rm -f $(build_dir)/kosi-$(host_platform).sha256
	@cd $(build_dir) && shasum -a 256 kosi-$(host_platform) > kosi-$(host_platform).sha256

## native-metadata: re-run the tracing agent over the whole fixture tree and
## merge the result into native-metadata/kosi. CI fails if the checked-in
## metadata differs from what the agent produces (native-metadata-check).
native-metadata:
	@rm -rf /tmp/kosi-agent-run && mkdir -p /tmp/kosi-agent-run
	$(graal_env) $(gradle) :kosi-cli:kosiFatJar
	@for f in fixtures/*/; do \
	  slug=$$(basename $$f); \
	  java -agentlib:native-image-agent=config-output-dir=/tmp/kosi-agent-run/$$slug \
	    -jar modules/kosi-cli/build/dist/kosi-all.jar analyze --dir $$f --out /dev/null; \
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
