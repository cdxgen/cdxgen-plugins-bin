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

- `trustinspector-cdxgen rootfs <dir>` — inspect trust anchors inside an unpacked root filesystem
- `trustinspector-cdxgen paths <path> [path...]` — inspect signing/notarization state for selected binaries or apps
- `trustinspector-cdxgen host` — inspect host trust posture such as Gatekeeper or WDAC active policies

## JSON output shape

Each invocation returns a single JSON object. Only the field relevant to the selected command is populated.

### Common property object

```json
{
  "name": "cdx:windows:authenticode:status",
  "value": "Valid"
}
```

### `rootfs` response

```json
{
  "materials": [
    {
      "kind": "public-key",
      "path": "/usr/share/keyrings/debian-archive-keyring.gpg",
      "name": "debian-archive-keyring.gpg",
      "sha1": "...",
      "sha256": "...",
      "algorithm": "RSA",
      "keyStrength": 4096,
      "fingerprint": "...",
      "keyId": "...",
      "createdAt": "2024-01-01T00:00:00Z",
      "expiresAt": "2034-01-01T00:00:00Z",
      "trustDomain": "apt",
      "fileExtension": "gpg",
      "userIds": [
        "Debian Archive Automatic Signing Key <ftpmaster@debian.org>"
      ],
      "properties": [{ "name": "cdx:crypto:keyId", "value": "..." }]
    },
    {
      "kind": "certificate",
      "path": "/etc/ssl/certs/ca-certificates.crt",
      "name": "demo-root",
      "sha1": "...",
      "sha256": "...",
      "subject": "CN=demo-root,O=Example Org",
      "issuer": "CN=demo-root,O=Example Org",
      "serial": "42",
      "createdAt": "2023-11-14T22:13:20Z",
      "expiresAt": "2027-01-15T08:00:00Z",
      "trustDomain": "ca-store",
      "category": "ca-store",
      "format": "X.509",
      "fileExtension": "crt",
      "fingerprint": "...",
      "properties": [{ "name": "cdx:crypto:isCA", "value": "true" }]
    }
  ]
}
```

### `paths` response

```json
{
  "inspections": [
    {
      "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "properties": [
        { "name": "cdx:windows:authenticode:status", "value": "Valid" },
        { "name": "cdx:windows:authenticode:isOSBinary", "value": "true" }
      ]
    }
  ]
}
```

On macOS the `properties` array instead contains keys such as `cdx:darwin:codesign:*` and `cdx:darwin:notarization:*`.

### `host` response

```json
{
  "hostFindings": [
    {
      "kind": "windows-wdac-status",
      "name": "wdac-active-policies",
      "version": "0",
      "description": "C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active",
      "properties": [
        { "name": "cdx:windows:wdac:activePolicyCount", "value": "0" }
      ]
    }
  ]
}
```

`hostFindings[*]` may also include:

- `path` for file-backed findings such as individual WDAC policy files
- `sha256` for file-backed findings
- macOS Gatekeeper posture entries with `cdx:darwin:gatekeeper:*` properties

## Stability notes

- The top-level object keys are stable: `materials`, `inspections`, `hostFindings`
- `properties` is always an array of `{ name, value }` objects when present
- unknown future properties may be added, so downstream consumers should ignore keys they do not recognize

## CI notes

The repository test workflow includes a Windows smoke path that builds the helper, validates manifest generation, runs `trustinspector host`, and inspects a signed Windows system binary with `trustinspector paths`.
