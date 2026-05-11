# cdxgen Trivy wrapper

This directory contains the cdxgen-specific Trivy wrapper used to build the `trivy-cdxgen-*` binaries.

## What is customized

Compared to the stock `cmd/trivy/main.go`, this wrapper is intentionally optimized for the way `cdxgen` calls Trivy:

- exposes only the `image`, `rootfs`, and `version` commands
- defaults `image`/`rootfs` scans to CycloneDX SBOM output
- forces offline, no-update, no-progress operation
- limits package collection to OS packages
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

## Optional enrichment knobs

These environment variables control extra SBOM metadata:

- `TRIVY_CDXGEN_INCLUDE_OS_CAPABILITIES` (default: `true`)
  - emits `Capability` properties for supported APK, DPKG, and RPM rootfs scans
- `TRIVY_CDXGEN_INCLUDE_OS_COMMANDS` (default: `true`)
  - emits `InstalledCommand` and `InstalledCommandPath` properties for OS packages
- `TRIVY_CDXGEN_INCLUDE_OS_FILES` (default: `true`)
  - emits one `InstalledFile` property per file installed by each OS package
  - this can significantly increase the intermediate Trivy SBOM size on full root filesystems, but it enables cdxgen to materialize package-owned file child components accurately
