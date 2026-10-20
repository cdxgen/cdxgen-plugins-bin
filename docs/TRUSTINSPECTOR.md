# trustinspector: trust posture inspection

trustinspector inspects trust material and code-signing state on hosts and in unpacked root filesystems. It is a custom helper maintained by the cdxgen team, built in Go, and shipped as `trustinspector-cdxgen-<platform-tuple>`.

Its output is deliberately not a CycloneDX document. It emits stable, merge-friendly JSON designed to be consumed by cdxgen's enrichment pipeline, which turns findings into properties on the right BOM components.

## Modes

```bash
trustinspector-cdxgen rootfs [--extra-dir <rel>] [--embedded] <dir>  # trust anchors in an unpacked rootfs
trustinspector-cdxgen certs [--stdin] [--embedded] [--root <dir>] <file>...  # parse exactly these files
trustinspector-cdxgen paths <path> [path...]                         # signing state for specific binaries or apps
trustinspector-cdxgen host                                          # host trust posture and trust stores
```

`rootfs` scans the system CA directories (Debian, RHEL/Fedora and p11-kit layouts, including blocklists), Java trust stores (JKS, JCEKS, PKCS#12 `cacerts`), language bundles (`certifi`/botocore/ruby `cacert.pem`), and server config trees (nginx, Apache, HAProxy, letsencrypt, Kubernetes, containerd, Docker, Envoy, Traefik), each tagged with a `sourceType`. `--extra-dir` adds more directories; `--embedded` also scans ELF/Mach-O/PE binaries for embedded PEM certificates. Private keys are classified from the PEM header line only and never decoded. This mode matters for container BOMs: the trust anchors an image ships are part of its supply-chain surface.

`certs` parses exactly the files it is given with the same parsers and reports paths relative to `--root`; cdxgen's source CBOM uses it for curated file lists.

`paths` inspects code-signing and notarization state for specific files. On macOS it runs `codesign` checks and looks for notarization. On Windows it reads Authenticode signatures and flags OS binaries.

`host` reports the posture of the machine itself — Gatekeeper status on macOS, active WDAC policies on Windows — and enumerates the host's trust stores into `materials`: the macOS system keychains (`security find-certificate -a -p`) and the Windows `Cert:\LocalMachine\{Root,CA,AuthRoot,Disallowed}` stores (a `Disallowed` certificate is OS-level distrust, `sourceType: ca-blocklist`). On Linux `host` runs the rootfs scan on `/`.

## Output structure

A single JSON object with an identifying envelope and three optional payload keys, depending on mode. `schema` names the report shape (currently `trustinspector/report-2`; every report-1 key keeps its meaning), and `tool`/`toolVersion` identify the binary that produced it; the payload keys stay at the top level so existing consumers keep parsing unchanged.

| Key            | Contents                                                                                                              |
| -------------- | --------------------------------------------------------------------------------------------------------------------- |
| `materials`    | trust material: keyrings and certificates with SHA-1, SHA-256, algorithm, key strength, fingerprint, and trust domain |
| `inspections`  | per-path signing state with properties like `cdx:darwin:codesign:*` and `cdx:windows:authenticode:*`                  |
| `hostFindings` | host posture with properties like `cdx:windows:wdac:activePolicyCount` and `cdx:darwin:gatekeeper:*`                  |
| `options`      | the scan options (`embedded`, `extraDirs`)                                                                             |
| `warnings`     | bound hits (files over 16 MiB, tree size/depth limits), skipped issuer linking, unreadable stores                     |

Certificate materials carry identity fields for distrust matching: `certSha256`, `spkiSha256` (SHA-256 over the DER `SubjectPublicKeyInfo`, the value a SPKI-based distrust list such as Go's CVE-2026-111943 set matches), `role` (root/intermediate/leaf), `selfSigned`, SKI/AKI, key usage, `keyName`/`keyBits`/`keyAlgorithmOid`, `signatureAlgorithm`/`signatureAlgorithmOid`, and `issuers` (the certificates in the same report whose key verified this one's signature). Post-quantum keys and signatures (ML-DSA, SLH-DSA, ML-KEM) are named from their OIDs (`ML-DSA-65`, `SLH-DSA-SHA2-128s`), and unknown ones by the dotted OID. A self-issued certificate whose signature Go cannot check is reported as `selfSigned` with `selfSignedUnverified`, and an issuer it cannot verify goes to `issuersUnverified`. Certificates are deduplicated by `certSha256`; every location is kept in `paths` with its `sourceTypes`, and cross-signed twins share one `spkiSha256`. See `thirdparty/trustinspector/README.md` for the full field list and a real example.

## What belongs in a trust review

Two categories of material are inspected: public keys (keyring files, signing keys, CA trust stores) and X.509 certificates (CA, intermediate, and leaf). For each, the JSON records identity and strength facts that downstream policy can act on: an SHA-1 signed intermediate in a container image is a finding a human wants surfaced — its `signatureAlgorithm` is recorded so a rule can fire — not a judgment the tool makes silently.

JKS/JCEKS trust stores are read from the OpenJDK on-disk layout; their trailing integrity digest is not verified, which the helper's README documents.

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
