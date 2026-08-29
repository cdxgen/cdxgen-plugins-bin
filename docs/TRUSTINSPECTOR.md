# trustinspector: trust posture inspection

trustinspector inspects trust material and code-signing state on hosts and in unpacked root filesystems. It is a custom helper maintained by the cdxgen team, built in Go, and shipped as `trustinspector-cdxgen-<platform-tuple>`.

Its output is deliberately not a CycloneDX document. It emits stable, merge-friendly JSON designed to be consumed by cdxgen's enrichment pipeline, which turns findings into properties on the right BOM components.

## Modes

```bash
trustinspector-cdxgen rootfs <dir>            # trust anchors in an unpacked rootfs
trustinspector-cdxgen paths <path> [path...]  # signing state for specific binaries or apps
trustinspector-cdxgen host                    # host trust posture
```

`rootfs` scans for system keyring files such as `/usr/share/keyrings/debian-archive-keyring.gpg`, certificate authority stores such as `/etc/ssl/certs/ca-certificates.crt`, and private keyrings and certificate stores in user directories. This mode matters for container BOMs: the trust anchors a image ships are part of its supply-chain surface.

`paths` inspects code-signing and notarization state for specific files. On macOS it runs `codesign` checks and looks for notarization. On Windows it reads Authenticode signatures and flags OS binaries.

`host` reports the posture of the machine itself: Gatekeeper status on macOS, active WDAC policies on Windows.

## Output structure

A single JSON object with three optional top-level keys, depending on mode:

| Key             | Contents                                                                                      |
| --------------- | --------------------------------------------------------------------------------------------- |
| `materials`     | trust material: keyrings and certificates with SHA-1, SHA-256, algorithm, key strength, fingerprint, and trust domain |
| `inspections`   | per-path signing state with properties like `cdx:darwin:codesign:*` and `cdx:windows:authenticode:*` |
| `hostFindings`  | host posture with properties like `cdx:windows:wdac:activePolicyCount` and `cdx:darwin:gatekeeper:*` |

## What belongs in a trust review

Two categories of material are inspected: public keys (keyring files, signing keys, CA trust stores) and X.509 certificates (CA, intermediate, and leaf). For each, the JSON records identity and strength facts that downstream policy can act on: an SHA-1 signed intermediate in a container image is a finding a human wants surfaced, not a judgment the tool makes silently.

## Wiring it into a pipeline

cdxgen invokes trustinspector for container and host-level scans when the binary is available, so the usual answer is: nothing to do, the properties appear on the BOM. To drive it directly, for example to audit every image rootfs unpacked in CI:

```bash
trustinspector-cdxgen rootfs ./unpacked-image > trust.json
jq '.materials | length' trust.json
jq '.inspections' trust.json
```

Custom builds are honored with `TRUSTINSPECTOR_CMD`.

## Platforms

linux-amd64, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, darwin-amd64, darwin-arm64, windows-amd64, and windows-arm64. Rootfs inspection works everywhere; `paths` and `host` produce platform-specific findings and degrade gracefully elsewhere.
