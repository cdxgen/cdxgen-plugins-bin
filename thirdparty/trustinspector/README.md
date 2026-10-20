# cdxgen trustinspector Helper

This directory contains the cdxgen-specific trust inspection helper used to build the `trustinspector-cdxgen-*` binaries. It is a custom tool maintained by the cdxgen team for trust-oriented OS and root filesystem inspection.

## What It Does

The helper provides lightweight JSON output for trust-oriented OS and rootfs inspection workflows. It is intentionally cdxgen-oriented and emits stable, merge-friendly JSON rather than full CycloneDX documents. The output is designed to be consumed by cdxgen's SBOM enrichment pipeline.

### Capabilities

- **Deep inspection of trusted keyring material and certificate stores** in unpacked root filesystems
- **macOS code-signing and notarization metadata** for selected application or binary paths
- **Windows Authenticode metadata** for selected executable paths
- **Windows WDAC active-policy inventory**
- **macOS Gatekeeper posture fallback** when direct host inspection is requested

### Trust Material Types

The tool inspects two categories of trust material:

1. **Public keys** - keyring files, signing keys, and certificate authority trust stores
2. **Certificates** - X.509 certificates, including CA certificates, intermediate certificates, and leaf certificates

## Command Modes

### rootfs

```bash
trustinspector-cdxgen rootfs [--extra-dir <rel>] [--embedded] <dir>
```

Inspect trust anchors inside an unpacked root filesystem. Directories are
scanned relative to the root with a sourceType each:

| sourceType | Locations (relative to the root) |
|---|---|
| `ca-store` | `etc/ssl/certs`, `etc/pki/tls/certs`, `etc/pki/ca-trust/extracted`, `etc/ssl/cert.pem`, `var/lib/ca-certificates`, `usr/share/pki/ca-trust-source/anchors`, `etc/pki/ca-trust/source/anchors`, `usr/local/share/ca-certificates`, ... |
| `ca-blocklist` | `etc/pki/ca-trust/source/{blocklist,blacklist}`, `usr/share/pki/ca-trust-source/{blocklist,blacklist}` |
| `ca-deselected` | entries prefixed `!` in `etc/ca-certificates.conf`, resolved under `usr/share/ca-certificates` |
| `java-truststore` | `cacerts`, `jssecacerts`, `*.jks`, `*.jceks`, `*.truststore`, `*.p12`/`*.pfx` files under JVM and application roots, detected by content |
| `language-bundle` | `cacert.pem` bundles under `usr/lib`, `usr/local/lib`, `opt` (certifi, botocore, pip, ruby) |
| `server-config` | `etc/nginx`, `etc/apache2`, `etc/httpd`, `etc/haproxy`, `etc/letsencrypt`, `etc/kubernetes/pki`, `var/lib/kubelet/pki`, `etc/docker/certs.d`, `etc/containerd/certs.d`, `etc/envoy`, `etc/traefik` |
| `generic` | `--extra-dir <rel>` (repeatable; `..` and absolute paths are rejected) |

The `private` directory exclusion matches only `etc/ssl/private` and
`etc/pki/tls/private` **relative to the scanned root**, so scanning a tree
whose absolute host path contains `/private/` (macOS temp dirs) works.

Formats are detected by content, not extension: PEM `CERTIFICATE`, PEM
`TRUSTED CERTIFICATE` (the OpenSSL `X509_CERT_AUX` reject list becomes
`trustRejectedPurposes`), DER certificates, PKCS#7 SignedData
(`.p7b`/`.p7c`, RFC 5652), JKS/JCEKS trusted-certificate entries, PKCS#12
trust stores, and private keys classified from the PEM header line only
(`kind: "private-key"`, never decoded).

PKCS#12 trust stores are decoded with
[go-pkcs12](https://github.com/sslmate/go-pkcs12) `DecodeTrustStore`, which
never returns private keys, trying the public JDK default password
`changeit` and then the empty password. JDK `cacerts` shipped since Java 9
carry no MAC and decode only with the empty password. A PKCS#12 file whose
certificate entries are not marked trusted (as written by
`openssl pkcs12 -export -nokeys`) is reported as `kind: "keystore"` with
`cdx:crypto:keystoreReadable=false` rather than guessed at.

JKS/JCEKS stores are read from the OpenJDK on-disk layout directly, listing
trusted-certificate entries and skipping private-key entries without
decoding them. The trailing integrity digest is **not** verified: a store
with a corrupted digest still lists its certificates.

**Bounds.** Symlinks are skipped, files over 16 MiB are skipped, directory
trees stop at 20,000 files or depth 12. Every bound hit adds an entry to the
envelope's `warnings` array, as does skipping issuer linking past 5,000
certificates.

### --embedded

Opt-in (`trustinspector-cdxgen rootfs --embedded <dir>` or on `certs`):
scan regular files that are ELF, Mach-O or PE binaries (magic check, at most
128 MiB) for embedded PEM `CERTIFICATE` blocks, reported with
`sourceType: "embedded-binary"`. DER-embedded certificates are out of scope.

### certs

```bash
trustinspector-cdxgen certs [--stdin] [--embedded] [--root <dir>] <file>...
```

Parse exactly the given files with the same parsers as `rootfs`, with
sourceType `generic` (host materials excepted). `--root` reports paths
relative to that directory with a leading `/`. This mode exists for cdxgen's
source CBOM, which passes a curated file list.

### paths

```bash
trustinspector-cdxgen paths <path> [path...]
```

Inspect signing/notarization state for selected binaries or apps. On macOS, this checks codesigning and notarization status. On Windows, this checks Authenticode signing and OS binary status.

### host

```bash
trustinspector-cdxgen host
```

Inspect host trust posture such as Gatekeeper (macOS) or WDAC active policies (Windows). This provides a high-level view of the host's trust configuration.

`host` also enumerates the host's trust stores into `materials`:

- **macOS**: `security find-certificate -a -p` on
  `/Library/Keychains/System.keychain` (`macos:System`) and
  `/System/Library/Keychains/SystemRootCertificates.keychain`
  (`macos:SystemRoots`); a certificate present in both carries both labels.
- **Windows**: one PowerShell call enumerating
  `Cert:\LocalMachine\{Root,CA,AuthRoot,Disallowed}`; certificates in
  `Disallowed` are OS-level distrust and get `sourceType: "ca-blocklist"`.
- **Linux**: the rootfs scan runs on `/` (without `--embedded`).

A store that cannot be read or a certificate Go cannot parse is reported as
an envelope `warnings` entry, never silently dropped.

### version

```bash
trustinspector-cdxgen version
trustinspector-cdxgen --version
```

Print the tool version. The released binaries stamp the package version at build time; a source build without the stamp reports `dev`.

### Exit codes

`0` success, `2` usage error (unknown command, unparseable flag, missing argument), `3` runtime error. `1` is reserved for expectations failures, which trustinspector has no gate of, following the suite convention kosi documents.

## JSON Output Shape

Each invocation returns a single JSON object. Only the field relevant to the selected command is populated.

### Common Property Object

All properties follow a consistent `{name, value}` format:

```json
{
  "name": "cdx:windows:authenticode:status",
  "value": "Valid"
}
```

### rootfs Response

The current shape is `trustinspector/report-2`. Every report-1 key keeps its
name and meaning, so a report-1 consumer parses report-2 unchanged; the
report-1 example below is kept as the compatibility reference.

Report-2 adds an `options` object (`{embedded, extraDirs}`) and a `warnings`
array, and certificate materials gain identity fields: `certSha256` (the
lowercase digest behind `fingerprint`), `spkiSha256` and
`spkiSha256Base64` (SHA-256 over the DER `SubjectPublicKeyInfo` — the value
a SPKI-based distrust list such as Go's CVE-2026-111943 set matches, and the
base64 form is the RFC 7469 pin format), `serialHex`, `version`, `role`
(`root`/`intermediate`/`leaf`), `selfSigned`, `pathLen`, `subjectKeyId`/
`authorityKeyId`, `keyUsage` (RFC 5280 §4.2.1.3 names), `extKeyUsage`,
`signatureAlgorithm` and `signatureAlgorithmOid` (so an SHA-1 signed
intermediate is visible downstream), `dnsNames` (capped at 20 with
`dnsNamesTruncated`), AIA/OCSP/CRL URLs, `policyOids`,
`hasNameConstraints`, `trustRejectedPurposes`, `keyName` (`RSA-2048`,
`ECDSA-P256`, `Ed25519`, `ML-DSA-65`, …), `keyBits` (absent for post-quantum
keys), `keyAlgorithmOid`, and `issuers`: the `certSha256` list of
certificates in the same report whose subject is this one's issuer and whose
key verified this one's signature (SHA-1 signatures included; the link means
"signed by this key"). Cross-signed twins share one `spkiSha256` and stay
separate materials; certificates are deduplicated by `certSha256` with
**every** location kept in `paths` and every location kind in `sourceTypes`.

Post-quantum certificates (ML-DSA, RFC 9881; SLH-DSA, RFC 9909; ML-KEM,
RFC 9935) are named from their OIDs: `ML-DSA-65`, `SLH-DSA-SHA2-128s`,
`ML-KEM-768`. Go 1.27 parses ML-DSA but neither SLH-DSA nor ML-KEM, so the
names never come from `crypto/x509`. A key or signature algorithm with no
known name is named by its dotted OID (composite ML-DSA, pre-standard
algorithms). When Go cannot check a signature (an unimplemented algorithm,
or MD5):

- a certificate whose subject equals its issuer and whose authority key
  identifier is absent or equals its subject key identifier still counts as
  `selfSigned`, with `selfSignedUnverified: true`, so an SLH-DSA root is a
  `root`;
- a parent whose subject and key identifier match goes to
  `issuersUnverified`, never to `issuers`.

The report-1 `algorithm` and `keyStrength` fields are unchanged.

A report-2 certificate material, trimmed from a real run over a demo tree
(`trustinspector-cdxgen rootfs --embedded`), showing a cross-signed
intermediate found in a CA bundle, a certifi language bundle, an nginx
fullchain and a Go binary that embeds it:

```json
{
  "schema": "trustinspector/report-2",
  "tool": "trustinspector-cdxgen",
  "toolVersion": "dev",
  "options": { "embedded": true },
  "materials": [
    {
      "kind": "certificate",
      "path": "/etc/nginx/ssl/fullchain.pem",
      "paths": [
        "/etc/nginx/ssl/fullchain.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/usr/lib/python3/dist-packages/certifi/cacert.pem",
        "/usr/local/bin/goapp"
      ],
      "name": "Shady Issuing CA 1",
      "trustDomain": "generic",
      "sourceType": "server-config",
      "sourceTypes": ["ca-store", "embedded-binary", "language-bundle", "server-config"],
      "algorithm": "RSA",
      "keyStrength": 2048,
      "createdAt": "2026-10-20T06:16:20Z",
      "expiresAt": "2031-10-19T06:16:20Z",
      "fingerprint": "5F538780506FC907EDB782453924A61593BB43EA61B388F57E3FF48F9DFC1641",
      "subject": "CN=Shady Issuing CA 1,O=Shady CA",
      "issuer": "CN=Demo Root A,O=Demo Trust",
      "serial": "103720797013478346624383885901329702858998349739",
      "serialHex": "122b005b615cd02529cf4711916fd1e7811affab",
      "certSha256": "5f538780506fc907edb782453924a61593bb43ea61b388f57e3ff48f9dfc1641",
      "spkiSha256": "58d0b4ffea33301fe6e6d00c839a516e68a513a4277cf54d93f9db3358bfe1e2",
      "spkiSha256Base64": "WNC0/+ozMB/m5tAMg5pRbmilE6QnfPVNk/nbM1i/4eI=",
      "version": 3,
      "isCA": true,
      "selfSigned": false,
      "role": "intermediate",
      "pathLen": 0,
      "subjectKeyId": "f97e1e51f753a9d8f9aaaa04ae268eb699731857",
      "authorityKeyId": "305fe35d1640f33b4ebe3453e1bdd27e805dfb07",
      "issuers": ["99f90c426d3bf6899fb59d2dee67276d80fc7e66ddd2d3b8c0a59492a6ec8bb7"],
      "keyUsage": ["keyCertSign", "cRLSign"],
      "signatureAlgorithm": "SHA256-RSA",
      "signatureAlgorithmOid": "1.2.840.113549.1.1.11",
      "issuingCertificateUrls": ["http://example.invalid/root.crt"],
      "crlDistributionPoints": ["http://example.invalid/root.crl"],
      "properties": [{ "name": "cdx:crypto:isCA", "value": "true" }]
    },
    {
      "kind": "keystore",
      "path": "/usr/lib/jvm/java-21/lib/security/cacerts",
      "format": "PKCS12",
      "properties": [{ "name": "cdx:crypto:keystoreReadable", "value": "false" }]
    },
    {
      "kind": "private-key",
      "path": "/etc/nginx/ssl/privkey.pem",
      "format": "PKCS8"
    }
  ]
}
```

The `host` mode adds `hostStores` labels (`macos:System`,
`macos:SystemRoots`, `windows:LocalMachine\Root`, `...\CA`,
`...\AuthRoot`, `...\Disallowed`) to certificate materials.

#### report-1 compatibility example (superseded)

```json
{
  "schema": "trustinspector/report-1",
  "tool": "trustinspector-cdxgen",
  "toolVersion": "4.0.1",
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

### paths Response

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

### host Response

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

## Stability Notes

- The top-level object keys are stable: the envelope keys `schema` (report shape, currently `trustinspector/report-2`; every report-1 key keeps its meaning), `tool` and `toolVersion`, plus the payload keys `materials`, `inspections`, `hostFindings`, and the report-2 additions `options` and `warnings`
- `properties` is always an array of `{name, value}` objects when present
- Unknown future properties may be added, so downstream consumers should ignore keys they do not recognize
- Materials, `paths`, `sourceTypes`, `issuers`, `hostStores` and every other list are sorted; running the same scan twice produces byte-identical JSON

## CI Notes

The repository test workflow includes a Windows smoke path that builds the helper, validates manifest generation, runs `trustinspector host`, and inspects a signed Windows system binary with `trustinspector paths`.
