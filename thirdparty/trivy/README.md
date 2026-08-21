# cdxgen Trivy Wrapper

This directory contains the cdxgen-specific Trivy wrapper used to build the `trivy-cdxgen-*` binaries. It is a fork of the [Trivy](https://github.com/aquasecurity/trivy) main.go entry point, customized for cdxgen's SBOM generation workflow.

## What is Customized

Compared to the stock `cmd/trivy/main.go`, this wrapper is intentionally optimized for the way `cdxgen` calls Trivy. The changes are minimal and focused on SBOM output quality rather than vulnerability scanning behavior.

### Command Restriction

The wrapper exposes only three commands:

- `image` - scan a container image
- `rootfs` - scan an unpacked root filesystem
- `version` - print version information

All other Trivy commands (config, secret, misconfig, license, etc.) are removed to reduce binary size and attack surface.

### Default Output Format

The `image` and `rootfs` commands default to CycloneDX SBOM output instead of Trivy's default vulnerability report format. This eliminates the need for users to specify `--format cyclonedx` on every invocation.

### Offline Operation

The wrapper forces offline, no-update, no-progress operation. This means:

- No network access is made to check for updates
- No progress bars are displayed
- The binary is suitable for air-gapped environments

### Language Package Limitation

Language package collection is limited to Go modules and Go binaries. This is because cdxgen handles other language ecosystems through its own analyzers (golem for Go, rusi for Rust, etc.). The package manager scan (OS-level packages) is retained as it provides critical SBOM data.

### Output Suppression

Noisy output (debug logs, progress indicators) is suppressed unless `--debug` is passed. This keeps the SBOM output clean and machine-parseable.

### OS Package Enrichment

OS package components are enriched with additional metadata that cdxgen uses for compliance-grade SBOM output:

- Package manager capability/provide metadata (APK, DPKG, RPM)
- Installed command names and paths
- Installed file counts and file paths
- Package trust-state metadata (architecture, origin, source, status, vendor)
- Libc variant for distros published per libc (see apk-tools 3.x below)
- Native CycloneDX supplier population from maintainer metadata when available
- OS lifecycle metadata (OS family, OS name, end-of-life date, extended support status)

When the wrapper output is consumed by cdxgen, maintainer/vendor trust metadata is further promoted into native CycloneDX component fields such as `authors` and `manufacturer` when that can be done without overwriting differing existing values.

### apk-tools 3.x and Alpaquita Linux

Trivy's apk analyzer reads the installed-package database from `lib/apk/db/installed` and `usr/lib/apk/db/installed`, the apk-tools 2.x locations. apk-tools 3.x, shipped by BellSoft Alpaquita Linux, keeps the same paragraph text format at `var/lib/apk/db/installed`, and Alpaquita's os-release `ID` is not one Trivy maps to an OS family, so both its packages and its OS went undetected.

The wrapper adds:

- an apk analyzer for `var/lib/apk/db/installed`, so apk-tools 3.x packages, their licenses, dependencies, installed files and checksums are collected
- an OS analyzer for `etc/alpaquita-release`, so the OS is reported as family `alpaquita` with the release channel as its version
- purl normalization to `pkg:apk/alpaquita/<name>@<version>?arch=<arch>&distro=alpaquita-<channel>`, matching the shape Trivy emits for every other apk distro

The apk-tools 2.x paths are left to Trivy's own analyzer, so an image carrying both layouts is never counted twice.

#### Channels and libc variants

Alpaquita ships a rolling channel (`stream`) and LTS channels (`23`, `25`), each served from its own apk repository at `packages.bell-sw.com/alpaquita/<libc>/<channel>/core`, with its own package versions. The channel is therefore part of the `distro` qualifier — `distro=alpaquita-stream`, `distro=alpaquita-23` — never a flat vendor-only value.

The libc variant is orthogonal to the channel: every channel is published twice, for `musl` and for `glibc`, and the two builds of a package share its name and version (a stream image has `busybox 1.38.0-r2` either way). It is recorded as a `PackageLibc` property read from `LIBC_TYPE` in os-release, and deliberately kept out of the `distro` qualifier, which carries release channels only.

No `distro_name` qualifier is emitted: Alpaquita has no `VERSION_CODENAME`, so there is no codename to name.

## Usage

### Build a Local Test Binary

Build a local test binary from this directory:

```bash
GOEXPERIMENT=jsonv2 go build -o build/trivy-cdxgen-local .
```

### Generate a CycloneDX SBOM from an Unpacked Root Filesystem

```bash
./build/trivy-cdxgen-local rootfs --output result.cdx.json /path/to/rootfs
```

The exact local command used during regression validation was:

```bash
./build/trivy-cdxgen-local rootfs --debug --output "$OUT" "$ROOTFS"
```

## Examples

### Scan an Exported Image Rootfs

Pull the test image, export it with `docker`, unpack it, and run the local wrapper against the extracted rootfs:

```bash
docker pull alpine:latest
CID="trivy-cdxgen-docker-test"
ROOTFS="$(mktemp -d /tmp/docker-rootfs.XXXXXX)"
TAR="$(mktemp /tmp/docker-rootfs.XXXXXX.tar)"
docker create --name "$CID" alpine:latest
docker export "$CID" > "$TAR"
tar -xf "$TAR" -C "$ROOTFS"
./build/trivy-cdxgen-local rootfs --debug --output docker-backend.cdx.json "$ROOTFS"
docker rm -f "$CID"
```

### Scan a Local Rootfs Directory Directly

```bash
./build/trivy-cdxgen-local rootfs --output rootfs.cdx.json /tmp/rootfs
```

## Optional Enrichment Knobs

These environment variables control extra SBOM metadata:

### TRIVY_CDXGEN_INCLUDE_OS_CAPABILITIES

**Default:** `true`

Emits `Capability` properties for supported APK, DPKG, and RPM rootfs scans. When disabled, capability metadata is omitted from the SBOM output.

### TRIVY_CDXGEN_INCLUDE_OS_COMMANDS

**Default:** `true`

Emits `InstalledCommand` and `InstalledCommandPath` properties for OS packages. When disabled, command metadata is omitted.

### TRIVY_CDXGEN_INCLUDE_OS_FILES

**Default:** `true`

Emits one `InstalledFile` property per file installed by each OS package. This can significantly increase the intermediate Trivy SBOM size on full root filesystems, but it enables cdxgen to materialize package-owned file child components accurately. When disabled, file-level metadata is omitted.

## Build Notes

The wrapper requires Go 1.24+ with the `jsonv2` experiment enabled. The build command is:

```bash
GOEXPERIMENT=jsonv2 go build -o build/trivy-cdxgen-local .
```

The `jsonv2` experiment is required for the JSON marshaling of enriched package metadata.
