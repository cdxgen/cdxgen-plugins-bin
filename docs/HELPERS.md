# Upstream helpers: fork or repackage

Five of the nine binaries are written and maintained in this repository: [golem](GOLEM.md), [rusi](RUSI.md), [cdxrs](CDXRS.md), [cdxui](CDXUI.md), and [trustinspector](TRUSTINSPECTOR.md). Each lives in full under `thirdparty/` with its own tests, docs, and threat model.

The other four come from upstream projects and have a dedicated page each: [trivy-cdxgen](TRIVY.md), [sourcekitten](SOURCEKITTEN.md), [dosai](DOSAI.md), and [osquery](OSQUERY.md). This page records why two of them are treated differently from the others, since the choice is deliberate and it affects provenance.

## The trivy fork

trivy is the only true fork. Its `main.go` is replaced with a cdxgen-specific entry point, pinned in `thirdparty/trivy`, so the binary can only do three things: scan an image, scan a rootfs, and print its version, offline, defaulting to CycloneDX output. The detail lives on the [trivy-cdxgen page](TRIVY.md); the reason for forking rather than calling upstream is control. Fewer commands means fewer flags to keep compatible across upstream releases, and a binary that cannot do anything else is one that cannot do anything else in your environment either.

## The repackaged releases

sourcekitten is built from the pinned upstream release with a one-line build script. dosai and osquery are downloaded release artifacts, verified and hashed by `scripts/thirdparty-downloads.sh`. None of their code changes here.

Repackaging inherits upstream's release integrity: the binaries you get are the binaries upstream published, with `.sha256` sidecars produced at packaging time. If your trust model requires binaries compiled in this repository, osquery is the one where that matters most, and the [osquery page](OSQUERY.md) explains how to build and wire in your own.

## What every helper shares regardless of origin

Whether forked, rebuilt, or repackaged, every binary passes through the same staging, coverage, and size gates, gets a `.sha256` sidecar, and is published to npm, GitHub Releases, and GHCR through ORAS. The [build reference](BUILD.md) and [architecture page](ARCHITECTURE.md) describe the pipeline and the provenance manifest cdxgen reads.
