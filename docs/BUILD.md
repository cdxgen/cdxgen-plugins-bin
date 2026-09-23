# Building and publishing

This page is the reference for the build system. For a guided walkthrough with expected output, see [Lesson 7](LESSON7.md).

## Prerequisites

| Tool                     | Needed for                            |
| ------------------------ | ------------------------------------- |
| Go 1.27+                 | golem, trustinspector, trivy-cdxgen   |
| Rust stable toolchain    | rusi, cdxui, cdxrs                    |
| Swift 5.9+ (macOS/Linux) | sourcekitten                          |
| Node.js 20+              | metadata generation and check scripts |
| upx                      | optional compression in `build.sh`    |

## Full local build

```bash
./build.sh
```

The script cleans and recreates `plugins/<helper>` directories, runs each helper's `make all` (or reuses an existing `build/` output when present), compresses the trivy amd64 binary with upx, then runs every `packages/<platform>/build-<platform>.sh` to assemble the platform packages. Two gates follow, and both must pass:

```bash
bash scripts/check-plugin-coverage.sh packages/<platform> ...
bash scripts/check-package-size.sh   packages/<platform> ...
```

Coverage runs first on purpose. A package can be under its size limit and still be missing a plugin; shipping the package without golem is the worse outcome, so the gate that catches it runs before the one that measures bytes.

## Per-helper builds

Each custom helper builds from its own directory:

```bash
cd thirdparty/golem && make all          # Go cross-builds into build/
cd thirdparty/rusi && make all           # cargo cross-builds into build/
cd thirdparty/cdxrs && make all
cd thirdparty/cdxui && make all
cd thirdparty/trustinspector && make all
```

Every Makefile emits the same artifact convention into `build/`:

```
build/<helper>-<platform-tuple>
build/<helper>-<platform-tuple>.sha256
```

The platform tuple matches the directory names under `packages/`: `linux-amd64`, `linux-arm64`, `linuxmusl-amd64`, `linuxmusl-arm64`, `linux-riscv64`, `linux-arm`, `linux-ppc64le`, `darwin-arm64`, `darwin-amd64`, `windows-amd64`, `windows-arm64`. Not every helper supports every tuple; the coverage script is the source of truth for which binaries each platform package must contain.

Some helpers also produce a CycloneDX SBOM of themselves:

```bash
cd thirdparty/rusi && make sbom
```

## Staging

`scripts/stage-built-plugins.sh` copies each helper's `build/` output into `plugins/<helper>/`, normalizes permissions, and produces the provenance files:

- `sbom-postbuild.cdx.json`, the post-build CycloneDX inventory of the helpers
- `plugins-manifest.json`, with generated-at, package identity, and per-helper purl, version, hash, binary path, and SBOM reference

Regenerate metadata alone with:

```bash
node scripts/generate-metadata.js
```

The manifest is data only. cdxgen parses it to attribute helper identity in `metadata.tools`; it never executes anything the manifest names beyond the binaries it would have resolved anyway.

## Publishing

Three channels are published from CI, and they are expected to move in this order:

1. This repository's platform packages, because cdxgen pins cdxrs by major version and falls back to JavaScript with a single log line on a mismatch. When a cdxrs release changes the major, publish here before releasing cdxgen.
2. GitHub Releases receive the raw binaries with `.sha256` sidecars, for example `golem-linuxmusl-amd64` and `golem-linuxmusl-amd64.sha256`.
3. GHCR receives ORAS artifacts, one tag per binary:

```bash
bash scripts/publish-helper-oras.sh <helper> <platform-tuple>
# produces ghcr.io/cdxgen/cdxgen-plugins-bin:<helper>-<tuple>
# with checksum and, where built, an SBOM attachment
```

## CI workflows

| Workflow                    | Job                                                            |
| --------------------------- | -------------------------------------------------------------- |
| `test.yml`                  | repository-level checks, script tests                          |
| `native-builds.yml`         | cross-platform builds of the custom helpers                    |
| `release.yml`               | staged release: packaging, coverage, size, npm, releases, ORAS |
| `golem-e2e.yml`             | end-to-end golem analysis against sample Go projects           |
| `cdxrs-test.yml`            | cdxrs unit and integration tests                               |
| `cdxui-test.yml`            | cdxui checks                                                   |
| `rusi-test.yml`             | rusi test suite                                                |
| `trivy-cdxgen-sbom-e2e.yml` | trivy-cdxgen SBOM assertions against sample images and rootfs  |

## Troubleshooting builds

- A missing tuple in `build/` almost always means a missing cross-toolchain target. For Rust, `rustup target add <tuple>`; for Go, the toolchain cross-compiles out of the box.
- If `check-package-size.sh` fails after a new helper landed, first run `check-plugin-coverage.sh`. New coverage frequently explains the size delta.
- The trivy fork builds with its own `go.mod` in `thirdparty/trivy`; do not hoist it into a parent module, the pinning to upstream trivy is intentional.
