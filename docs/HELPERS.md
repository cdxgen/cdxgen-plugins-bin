# Upstream helpers: trivy, osquery, sourcekitten, dosai

Four of the bundled binaries are built from upstream projects rather than written here. Each is either a thin fork with a replaced entry point or a repackaged upstream release. This page records what each one does for cdxgen and what was changed.

## trivy-cdxgen

A fork of [Trivy](https://github.com/aquasecurity/trivy) with a cdxgen-specific `main`, built from the pinned source in `thirdparty/trivy`. Trivy is best known as a vulnerability scanner; this build repurposes its OS package inventory for SBOM generation.

What the wrapper does:

- exposes only `image`, `rootfs`, and `version`
- defaults to CycloneDX output
- forces offline, no-update, no-progress operation
- limits language package collection to Go modules and Go binaries
- enriches OS package components with capability/provide metadata, installed command names and paths, installed file counts and paths, package trust-state metadata (architecture, origin, source, status, vendor), supplier population from maintainer metadata, and OS lifecycle facts (family, name, end-of-life date, extended support status)

Environment controls, all defaulting to on:

| Variable                               | Emits                                                     |
| -------------------------------------- | --------------------------------------------------------- |
| `TRIVY_CDXGEN_INCLUDE_OS_CAPABILITIES` | Capability properties for supported APK, DPKG, RPM scans  |
| `TRIVY_CDXGEN_INCLUDE_OS_COMMANDS`     | InstalledCommand and InstalledCommandPath properties      |
| `TRIVY_CDXGEN_INCLUDE_OS_FILES`        | one InstalledFile property per installed file per package |

The file inventory can produce large BOMs on desktop images; that is the intended behavior, and the switch exists for the scans where it is not.

Platforms: linux-amd64, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, linux-riscv64, linux-arm, windows-arm64, darwin-arm64, darwin-amd64, ppc64.

## osquery

A repackaged [osquery](https://github.com/osquery/osquery) build used for live host instrumentation. cdxgen uses it for OBOM (operating system BOM) collection: installed software, running processes, file system state, and network sockets, queried over osquery's SQL interface.

Platforms: linux-amd64, linux-arm64, darwin-arm64, windows-amd64, windows-arm64.

## sourcekitten

Built from the [SourceKitten](https://github.com/jpsim/SourceKitten) release with `swift build -c release` by the script in `thirdparty/sourcekitten`. It gives cdxgen Swift semantics through Apple's SourceKit service: module and framework discovery, source parsing, and the dependency facts cdxgen needs for Swift projects. The packaging step also attaches a CycloneDX SBOM of the Swift dependencies.

Platforms: darwin-arm64, darwin-amd64, linux-amd64, linux-arm64.

## dosai

The [Dotnet Source and Assembly Inspector](https://github.com/owasp-dep-scan/dosai) from OWASP dep-scan, repackaged. dosai lists namespaces and methods from .NET sources and assemblies, including compiled `.dll` and `.exe` files, which lets cdxgen enumerate .NET dependencies through reflection and source analysis the way sourcekitten does for Swift.

Platforms: linux-amd64, linux-arm, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, darwin-amd64, darwin-arm64, windows-amd64, windows-arm64.

## Why fork or repackage instead of calling upstream

Three reasons recur. Control: trivy's main is replaced so the binary can only do the three things cdxgen needs, offline, in CycloneDX. Surface area: fewer commands means fewer flags to keep compatible across upstream releases. Provenance: every binary here is rebuilt or hashed in this repository's CI, with `.sha256` sidecars and, where built from source, an SBOM of its own.
