# cdxgen trustinspector helper

This directory contains the cdxgen-specific trust inspection helper used to build the `trustinspector-cdxgen-*` binaries.

## What it does

The helper provides lightweight JSON output for trust-oriented OS and rootfs inspection workflows:

- deep inspection of trusted keyring material and certificate stores in unpacked root filesystems
- macOS code-signing and notarization metadata for selected application or binary paths
- Windows Authenticode metadata for selected executable paths
- Windows WDAC active-policy inventory
- macOS Gatekeeper posture fallback when direct host inspection is requested

The tool is intentionally cdxgen-oriented and emits stable, merge-friendly JSON rather than full CycloneDX documents.

## Command modes

- `trustinspector rootfs <dir>` — inspect trust anchors inside an unpacked root filesystem
- `trustinspector paths <path> [path...]` — inspect signing/notarization state for selected binaries or apps
- `trustinspector host` — inspect host trust posture such as Gatekeeper or WDAC active policies

## CI notes

The repository test workflow now includes a Windows smoke path that builds the helper, validates manifest generation, runs `trustinspector host`, and inspects a signed Windows system binary with `trustinspector paths`.
