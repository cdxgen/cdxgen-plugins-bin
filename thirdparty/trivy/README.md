# cdxgen Trivy wrapper

This directory contains the cdxgen-specific Trivy wrapper used to build the `trivy-cdxgen-*` binaries.

## What is customized

Compared to the stock `cmd/trivy/main.go`, this wrapper is intentionally optimized for the way `cdxgen` calls Trivy:

- exposes only the `image`, `rootfs`, and `version` commands
- defaults `image`/`rootfs` scans to CycloneDX SBOM output
- forces offline, no-update, no-progress operation
- limits language package collection to Go modules and Go binaries while still collecting OS packages
- suppresses noisy output unless `--debug` is passed
- enriches OS package components with:
  - package-manager capability/provide metadata
  - installed command names
  - installed command paths
  - installed file counts
  - installed file paths
  - package trust-state metadata (`PackageArchitecture`, `PackageOrigin`, `PackageSource`, `PackageStatus`, `PackageVendor`)
  - native CycloneDX `supplier` population from maintainer metadata when available
  - OS lifecycle metadata (`OSFamily`, `OSName`, `OSEOL`, `OSExtendedSupport`)

When the wrapper output is consumed by `cdxgen`, maintainer/vendor trust metadata is further promoted into native CycloneDX component fields such as `authors` and `manufacturer` when that can be done without overwriting differing existing values.

## Usage

Build a local test binary from this directory:

```bash
GOEXPERIMENT=jsonv2 go build -o build/trivy-cdxgen-local .
```

Generate a CycloneDX SBOM from an unpacked root filesystem:

```bash
./build/trivy-cdxgen-local rootfs --output result.cdx.json /path/to/rootfs
```

The exact local command used during regression validation was:

```bash
./build/trivy-cdxgen-local rootfs --debug --output "$OUT" "$ROOTFS"
```

## Examples

### Scan an exported image rootfs

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

### Scan a local rootfs directory directly

```bash
./build/trivy-cdxgen-local rootfs --output rootfs.cdx.json /tmp/rootfs
```

## Optional enrichment knobs

These environment variables control extra SBOM metadata:

- `TRIVY_CDXGEN_INCLUDE_OS_CAPABILITIES` (default: `true`)
  - emits `Capability` properties for supported APK, DPKG, and RPM rootfs scans
- `TRIVY_CDXGEN_INCLUDE_OS_COMMANDS` (default: `true`)
  - emits `InstalledCommand` and `InstalledCommandPath` properties for OS packages
- `TRIVY_CDXGEN_INCLUDE_OS_FILES` (default: `true`)
  - emits one `InstalledFile` property per file installed by each OS package
  - this can significantly increase the intermediate Trivy SBOM size on full root filesystems, but it enables cdxgen to materialize package-owned file child components accurately
