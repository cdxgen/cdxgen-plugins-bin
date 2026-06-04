# TrustInspector

TrustInspector is a specialized helper for performing trust-oriented inspection of operating system and root filesystem components. It is designed to provide lightweight, structured JSON evidence for security audits and compliance workflows.

## Capabilities

TrustInspector automates the collection of trust metadata across different platforms and inspection targets.

| Target      | Inspection Type         | Details                                                                                                  |
| :---------- | :---------------------- | :------------------------------------------------------------------------------------------------------- |
| **RootFS**  | Keyring/Cert Inspection | Deep inspection of trusted keyring material and CA stores in unpacked root filesystems.                  |
| **Paths**   | Signing/Notarization    | Verification of macOS code-signing/notarization and Windows Authenticode metadata for specific binaries. |
| **Host**    | Posture Assessment      | Inspection of host trust posture, such as Windows WDAC active policies or macOS Gatekeeper status.       |
| **Windows** | Policy Inventory        | Inspection of active Windows Defender Application Control (WDAC) policies.                               |

## Practical Usage

TrustInspector is operated via specific command modes that dictate the inspection logic and JSON output shape.

### RootFS Inspection

To inspect trust anchors (keyrings, CA stores) within an unpacked root filesystem:

```bash
trustinspector-cdxgen rootfs /path/to/unpacked/rootfs
```

### Path Inspection

To inspect the signing or notarization state of specific files or directories:

```bash
trustinspector-cdxgen paths /path/to/binary /another/path
```

### Host Posture Assessment

To inspect the security posture of the host machine (e.g., WDAC or Gatekeeper):

```bash
trustinspector-cdxgen host
```

## Command Modes and Workflow

The tool branches its logic based on the selected command mode.

```mermaid
graph TD
    CMD[Command Mode] -->|rootfs| R[Inspect untrusted root filesystem keyrings]
    CMD -->|paths| P[Inspect signing state of selected files]
    CMD -->|host| H[Inspect host security policy/posture]
```

## JSON Output Structure

The tool emits stable, merge-friendly JSON objects. Each invocation returns a single object containing the relevant findings.

### `rootfs` Response Example

Returns a list of `materials` found in the filesystem.

```json
{
  "materials": [
    {
      "kind": "public-key",
      "path": "/usr/share/keyrings/debian-archive-keyring.gpg",
      "name": "debian-archive-keyring.gpg",
      "algorithm": "RSA",
      "trustDomain": "apt"
    }
  ]
}
```

### `paths` Response Example

Returns `inspections` results for the provided paths.

```json
{
  "inspections": [
    {
      "path": "C:\\Windows\\System32\\powershell.exe",
      "properties": [
        { "name": "cdx:windows:authenticode:status", "value": "Valid" }
      ]
    }
  ]
}
```

## Stability and CI

- **Stable Schema**: Top-level keys (`materials`, `inspections`, `hostFindings`) and the `properties` array format are stable.
- **Downstream Consumption**: The tool is optimized for `cdxgen` to ingest findings as metadata.
- **Testing**: The repository includes a Windows smoke test path that validates manifest generation and host/path inspection.
