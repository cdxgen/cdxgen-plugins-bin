# Third-Party Tools

This folder contains source code and build scripts for the third-party tools used by the cdxgen plugin ecosystem. Each subdirectory documents the origin of the upstream project, the customizations made for cdxgen, and the build process for the target platform binaries.

## Tool Overview

| Tool                  | Origin                                                | Purpose                                     | Maintained By |
| --------------------- | ----------------------------------------------------- | ------------------------------------------- | ------------- |
| trivy-cdxgen          | [Trivy](https://github.com/aquasecurity/trivy)        | Container and rootfs OS package inventory   | cdxgen team   |
| sourcekitten          | [SourceKitten](https://github.com/jpsim/SourceKitten) | Swift source analysis via SourceKit         | cdxgen team   |
| trustinspector-cdxgen | Custom                                                | Trust anchor and code-signing inspection    | cdxgen team   |
| golem                 | Custom                                                | Go source semantic analysis and data-flow   | cdxgen team   |
| rusi                  | Custom                                                | Rust source semantic analysis and data-flow | cdxgen team   |
| cdxrs                 | Custom                                                | Rust BOM validation and registry fetch      | cdxgen team   |
| cdxui                 | Custom                                                | Interactive terminal BOM explorer           | cdxgen team   |
| kosi                  | Custom                                                | Kotlin source semantic analysis             | cdxgen team   |

## trivy

The files here were copied from [https://github.com/aquasecurity/trivy/blob/main/cmd/trivy/main.go](https://github.com/aquasecurity/trivy/blob/main/cmd/trivy/main.go). The exact changes made are documented in [./trivy/README.md](./trivy/README.md).

The customizations are intentionally minimal and focused: the wrapper exposes only the commands needed for SBOM generation, defaults to CycloneDX output, forces offline mode, and enriches OS package components with metadata that cdxgen uses for compliance-grade SBOM output.

## sourcekitten

SourceKitten binaries are built from [https://github.com/jpsim/SourceKitten](https://github.com/jpsim/SourceKitten). The build script downloads the release tarball, compiles with `swift build -c release`, and packages the resulting binary alongside a CycloneDX SBOM of the Swift dependencies.

## trustinspector

`trustinspector` is a cdxgen-maintained helper that emits trust-focused JSON for repository keyrings, certificate stores, macOS code-signing/notarization state, and Windows Authenticode / WDAC inventory. See [./trustinspector/README.md](./trustinspector/README.md).

## golem

Golem (Go Library Evidence Mapper) is a cdxgen-maintained static analyzer for Go source trees. It uses Go SSA, type information, and call graph analysis to produce compact JSON reports about code structure, dependencies, call relationships, cryptographic use, and selected data flows. See [./golem/README.md](./golem/README.md).

## rusi

Rusi (Rust Source Inspector) is a cdxgen-maintained Rust source analysis helper that emits semantic source evidence, call graph output, and optional compiler-assisted data-flow findings. It operates in two modes: a stable mode using the `syn` parser, and a compiler mode using an embedded rustc wrapper for MIR/HIR-derived evidence. See [./rusi/README.md](./rusi/README.md).

## cdxrs

`cdxrs` is a cdxgen-maintained Rust-native CycloneDX BOM tooling binary: BOM summary statistics, schema-version listing, schema and semantic validation, and parallel registry URL fetching with an on-disk cache. Its output is byte-identical to the JavaScript path it replaces, which lets cdxgen fall back silently when the binary is absent. See [./cdxrs/README.md](./cdxrs/README.md).

## cdxui

`cdxui` is a cdxgen-maintained interactive terminal UI for exploring CycloneDX BOMs, with an optional `--generate` mode that spawns cdxgen and loads the resulting BOM. See [./cdxui/README.md](./cdxui/README.md).

## kosi

Kosi (Kotlin Source Inspector) is a cdxgen-maintained Kotlin source analysis helper: inventory, call graph and reachability, taint slices, endpoints and services, and crypto evidence, from one deterministic JSON report. It is the Kotlin sibling of golem and rusi. See [./kosi/README.md](./kosi/README.md) and the operator's guide at [./kosi/docs/KOSI.md](./kosi/docs/KOSI.md).
