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
