# trivy-cdxgen: container and rootfs OS package inventory

trivy-cdxgen is a fork of [Trivy](https://github.com/aquasecurity/trivy) with a cdxgen-specific entry point, built from the pinned source in `thirdparty/trivy`. Trivy is best known as a vulnerability scanner. This build repurposes its OS package analyzers for one job: producing CycloneDX SBOMs of container images and unpacked root filesystems, offline, with compliance-grade enrichment.

cdxgen invokes it for Docker and OCI image scans and for rootfs scans when the binary is present. A custom build can be wired in with `TRIVY_CMD`.

## What the fork changes

The wrapper keeps upstream's analyzers and strips everything cdxgen does not need. Compared to stock `cmd/trivy/main.go`:

Only three commands survive: `image` for a container image, `rootfs` for an unpacked filesystem, and `version`. The config, secret, misconfiguration, and license scanning commands are removed, which reduces both binary size and the surface area to keep compatible across upstream releases.

`image` and `rootfs` default to CycloneDX output, so no flag is needed per invocation. Operation is forced offline: no update checks, no progress bars, which makes the binary suitable for air-gapped builds. Noisy output is suppressed unless `--debug` is passed. Language package collection is limited to Go modules and Go binaries, because cdxgen covers other ecosystems with its own analyzers: golem for Go source, rusi for Rust, sourcekitten for Swift, dosai for .NET.

## OS package enrichment

The point of the fork is the metadata attached to each OS package component, which cdxgen promotes into the final BOM:

Capability and provides metadata from the package manager for supported APK, DPKG, and RPM scans. Installed command names and paths. One installed-file record per file a package places on disk, with counts. Trust-state metadata: architecture, origin, source, status, and vendor. Native CycloneDX supplier population from maintainer metadata, promoted into `authors` and `manufacturer` fields where that does not overwrite differing existing values. OS lifecycle facts: family, name, end-of-life date, and extended support status.

Three environment variables control the enrichment, all defaulting to on:

| Variable                               | Emits                                                     |
| -------------------------------------- | --------------------------------------------------------- |
| `TRIVY_CDXGEN_INCLUDE_OS_CAPABILITIES` | Capability properties for supported APK, DPKG, RPM scans  |
| `TRIVY_CDXGEN_INCLUDE_OS_COMMANDS`     | InstalledCommand and InstalledCommandPath properties      |
| `TRIVY_CDXGEN_INCLUDE_OS_FILES`        | one InstalledFile property per installed file per package |

The file inventory can produce large BOMs on desktop images. That is the intended behavior, and the switch exists for the scans where it is not.

## apk-tools 3.x and Alpaquita Linux

Upstream Trivy reads the apk database from the apk-tools 2.x locations, `lib/apk/db/installed` and `usr/lib/apk/db/installed`. apk-tools 3.x, shipped by BellSoft Alpaquita Linux, keeps the same format at `var/lib/apk/db/installed`, and Alpaquita's os-release ID is not one Trivy maps to a family, so both its packages and its OS went undetected. The wrapper adds an apk analyzer for the new path and an OS analyzer for `etc/alpaquita-release`, and normalizes purls to the `pkg:apk/alpaquita/<name>@<version>?arch=<arch>&distro=alpaquita-<channel>` shape Trivy uses for every other apk distro. The 2.x paths are left to upstream's analyzer, so an image carrying both layouts is never counted twice.

Alpaquita's rolling and LTS channels each serve their own repository, so the channel is part of the `distro` qualifier, never a flat vendor value. The libc variant, musl or glibc, is recorded as a `PackageLibc` property read from `LIBC_TYPE` in os-release and deliberately kept out of the qualifier.

## Direct usage

Build a local binary and scan an unpacked rootfs:

```bash
cd thirdparty/trivy
GOTOOLCHAIN=go1.26.5 GOEXPERIMENT=jsonv2 go build -o build/trivy-cdxgen-local .
./build/trivy-cdxgen-local rootfs --output result.cdx.json /path/to/rootfs
```

To check an exported image:

```bash
docker create --name tc alpine:latest
docker export tc > alpine.tar
mkdir rootfs && tar -xf alpine.tar -C rootfs
./build/trivy-cdxgen-local rootfs --output rootfs.cdx.json ./rootfs
docker rm -f tc
```

## Platforms

linux-amd64, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, linux-riscv64, linux-arm, windows-arm64, darwin-arm64, darwin-amd64, and ppc64.

## What it will not do

It does not scan for vulnerabilities, misconfigurations, secrets, or licenses. Those commands were removed on purpose. It does not analyze language dependencies beyond Go modules and binaries. Treat it as an OS package inventory engine that speaks CycloneDX natively.
