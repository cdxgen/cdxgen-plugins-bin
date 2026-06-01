# Introduction

This repo contains binary executables that could be invoked by [cdxgen](https://github.com/cdxgen/cdxgen).

<img src="./cdxgen.png" width="200" height="auto" />

[![SBOM](https://img.shields.io/badge/SBOM-with_%E2%9D%A4%EF%B8%8F_by_cdxgen-FF753D)](https://github.com/cdxgen/cdxgen)
![NPM][badge-npm]
![NPM Downloads][badge-npm-downloads]

## Usage

The package is usually consumed indirectly by cdxgen. cdxgen resolves helper binaries from the installed optional package and invokes them only for features that need native collection or deeper language analysis.

## Installation

Install cdxgen, which installs this plugin as an optional dependency.

```bash
npm install -g @cyclonedx/cdxgen
```

cdxgen would automatically use the plugins from the global node_modules path to enrich the SBOM output for certain project types such as `docker`.

## Bundled helpers

The published packages currently bundle helper binaries such as:

- `trivy-cdxgen-*` for container/rootfs OS package inventory
- `osqueryi-*` for live-host OBOM collection
- `sourcekitten` and `dosai` for Swift/.NET enrichment
- `trustinspector-cdxgen-*` for deep trust inspection of repository keyrings, CA stores, macOS code-sign/notarization state, and Windows Authenticode / WDAC policy inventory
- `golem-*` for Go source semantic library evidence and optional static/CHA/RTA/VTA call graph exports
- `rusi-*` for Rust source semantic evidence, call graph export, and compiler-assisted data-flow analysis

Helper binaries are also published individually for automation-friendly retrieval:

- GitHub Releases upload the raw helper binaries alongside their `.sha256` sidecars, for example `golem-linuxmusl-amd64` + `golem-linuxmusl-amd64.sha256`
- GHCR / ORAS publishes one tag per helper binary using the binary filename as the tag, for example `ghcr.io/cdxgen/cdxgen-plugins-bin:golem-linuxmusl-amd64` and `ghcr.io/cdxgen/cdxgen-plugins-bin:trustinspector-cdxgen-linuxmusl-arm64`

## Plugin manifest + provenance bundle

Each packaged `plugins/` directory includes:

- `sbom-postbuild.cdx.json` — a post-build CycloneDX inventory of the bundled helpers
- `plugins-manifest.json` — a lightweight provenance bundle containing the generated-at timestamp, package identity, and per-plugin component metadata (purl, version, hash, binary path, and merged SBOM reference)

`cdxgen` reads `plugins-manifest.json` automatically when present so the generated BOM can record more precise helper-tool identity/version data under `metadata.tools`.

The manifest is **data only**. cdxgen does not execute commands, scripts, or paths from it; the file is parsed as JSON and used only to tighten helper provenance in `metadata.tools`.

[badge-npm]: https://img.shields.io/npm/v/%40cdxgen%2Fcdxgen-plugins-bin
[badge-npm-downloads]: https://img.shields.io/npm/dm/%40cdxgen%2Fcdxgen-plugins-bin
[npmjs-cdxgen]: https://www.npmjs.com/package/@cdxgen/cdxgen-plugins-bin
