# Introduction

This repo contains binary executables that could be invoked by [cdxgen](https://github.com/cdxgen/cdxgen).

<img src="./cdxgen.png" width="200" height="auto" />

[![SBOM](https://img.shields.io/badge/SBOM-with_%E2%9D%A4%EF%B8%8F_by_cdxgen-FF753D)](https://github.com/cdxgen/cdxgen)
![NPM][badge-npm]
![NPM Downloads][badge-npm-downloads]

## Usage

## Installation

Install cdxgen, which installs this plugin as an optional dependency.

```bash
sudo npm install -g @cyclonedx/cdxgen
```

cdxgen would automatically use the plugins from the global node_modules path to enrich the SBOM output for certain project types such as `docker`.

## Bundled helpers

The published packages currently bundle helper binaries such as:

- `trivy-cdxgen-*` for container/rootfs OS package inventory
- `osqueryi-*` for live-host OBOM collection
- `sourcekitten` and `dosai` for Swift/.NET enrichment
- `trustinspector-cdxgen-*` for deep trust inspection of repository keyrings, CA stores, macOS code-sign/notarization state, and Windows Authenticode / WDAC policy inventory

## Plugin manifest + provenance bundle

Each packaged `plugins/` directory now includes:

- `sbom-postbuild.cdx.json` — a post-build CycloneDX inventory of the bundled helpers
- `plugins-manifest.json` — a lightweight provenance bundle containing the generated-at timestamp, package identity, and per-plugin component metadata (purl, version, hash, binary path, and merged SBOM reference)

`cdxgen` reads `plugins-manifest.json` automatically when present so the generated BOM can record more precise helper-tool identity/version data under `metadata.tools`.

[badge-npm]: https://img.shields.io/npm/v/%40cdxgen%2Fcdxgen-plugins-bin
[badge-npm-downloads]: https://img.shields.io/npm/dm/%40cdxgen%2Fcdxgen-plugins-bin
[npmjs-cdxgen]: https://www.npmjs.com/package/@cdxgen/cdxgen-plugins-bin
