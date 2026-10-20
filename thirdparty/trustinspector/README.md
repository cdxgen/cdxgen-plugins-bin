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

| sourceType        | Locations (relative to the root)                                                                                                                                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ca-store`        | `etc/ssl/certs`, `etc/pki/tls/certs`, `etc/pki/ca-trust/extracted`, `etc/ssl/cert.pem`, `var/lib/ca-certificates`, `usr/share/pki/ca-trust-source/anchors`, `etc/pki/ca-trust/source/anchors`, `usr/local/share/ca-certificates`, ... |
| `ca-blocklist`    | `etc/pki/ca-trust/source/{blocklist,blacklist}`, `usr/share/pki/ca-trust-source/{blocklist,blacklist}`                                                                                                                                |
| `ca-deselected`   | entries prefixed `!` in `etc/ca-certificates.conf`, resolved under `usr/share/ca-certificates`                                                                                                                                        |
| `java-truststore` | `cacerts`, `jssecacerts`, `*.jks`, `*.jceks`, `*.truststore`, `*.p12`/`*.pfx` files under JVM and application roots, detected by content                                                                                              |
| `language-bundle` | `cacert.pem` bundles under `usr/lib`, `usr/local/lib`, `opt` (certifi, botocore, pip, ruby)                                                                                                                                           |
| `server-config`   | `etc/nginx`, `etc/apache2`, `etc/httpd`, `etc/haproxy`, `etc/letsencrypt`, `etc/kubernetes/pki`, `var/lib/kubelet/pki`, `etc/docker/certs.d`, `etc/containerd/certs.d`, `etc/envoy`, `etc/traefik`                                    |
| `generic`         | `--extra-dir <rel>` (repeatable; `..` and absolute paths are rejected)                                                                                                                                                                |

The `private` directory exclusion matches only `etc/ssl/private` and
`etc/pki/tls/private` **relative to the scanned root**, so scanning a tree
whose absolute host path contains `/private/` (macOS temp dirs) works. A file
inside two candidate directories (Debian's `etc/ssl/certs/java/cacerts`) takes
the more specific one's `sourceType`.

**The scan never leaves the root.** Every file is opened through Go's
`os.Root`, which refuses a symlink leading outside the root in any path
component: an image whose `etc/pki` or `etc/ssl/cert.pem` links to a host
path is not credited with the host's certificates. Symlinks as the final
component and non-regular files (FIFOs, devices, sockets) are skipped, and
reported paths are always root-relative.

Formats are detected by content, not extension. Binary containers are
recognized first (the JKS/JCEKS magic, the PKCS#12 PFX structure, DER
certificates, PKCS#7 SignedData per RFC 5652), so PEM text inside them (an
alias, an extension) cannot shadow their entries; then PEM `CERTIFICATE` (and
OpenSSL's legacy `X509 CERTIFICATE`), `TRUSTED CERTIFICATE` (the OpenSSL
`X509_CERT_AUX` trust and reject lists become `trustAcceptedPurposes` and
`trustRejectedPurposes`; OpenSSL rejects any purpose missing from a
non-empty trust list), `PKCS7`, and private keys classified from the PEM
header only (`kind: "private-key"`, one per key, `RSA`/`EC`/`DSA`/`PKCS8`/
`OPENSSH` with an `ENCRYPTED-` prefix when encrypted; the body is never
decoded). Certificates with a negative serial number, which Go rejects by
default but OpenSSL and Java accept, are parsed (`x509negativeserial=1`).

PKCS#12 trust stores are decoded with
[go-pkcs12](https://github.com/sslmate/go-pkcs12) `DecodeTrustStore`, which
never returns private keys, trying the public JDK default password
`changeit` and then the empty password. JDK `cacerts` shipped since Java 9
carry no MAC and decode only with the empty password. A PKCS#12 file whose
certificate entries are not marked trusted (as written by
`openssl pkcs12 -export -nokeys`) is reported as `kind: "keystore"` with
`cdx:crypto:keystoreReadable=false` rather than guessed at. So is one that
declares more than 200,000 key-derivation iterations for its MAC or an
encrypted safe (keytool writes 10,000; OpenSSL 2,048): go-pkcs12 would run
the KDF that many times per password tried, so a 1 KiB file could stall a
scan. One scan spends at most 20 million iterations on PKCS#12 decoding.

JKS/JCEKS stores are read from the OpenJDK on-disk layout directly, listing
trusted-certificate entries and skipping private-key entries without
decoding them. The trailing integrity digest is **not** verified: a store
with a corrupted digest still lists its certificates. A store that cannot be
read to the end keeps the certificates read so far and is also reported as
`kind: "keystore"` with `cdx:crypto:keystoreReadable=partial`: a truncated
entry, a trusted entry Go cannot parse, or a JCEKS secret-key entry, which
`JceKeyStore` writes as a Java-serialized `SealedObject` with no length to
skip by.

**Bounds.** Files over 16 MiB are skipped (and reads are capped, so a file
cannot grow past the check), a walk reads at most 20,000 files and visits
at most 500,000 entries of any type, and directories deeper than 12 levels
are not descended. Every bound hit adds an entry to the envelope's
`warnings` array, as does skipping issuer linking past 5,000 certificates.
`certs` mode holds the files it is given to the same size and regular-file
rules.

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
`path` is the smallest path, preferring a trust-material file over a binary
that embeds the certificate, and `sourceType`, `sha1`/`sha256` (that file's
digests), `trustDomain` and `fileExtension` follow it, so the report-1
meaning of those fields holds.

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
fullchain and a Go binary that embeds it, and the nginx private key, of which
only the format is reported:

```json
{
  "schema": "trustinspector/report-2",
  "tool": "trustinspector-cdxgen",
  "toolVersion": "dev",
  "options": {
    "embedded": true
  },
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
      "sourceTypes": [
        "ca-store",
        "embedded-binary",
        "language-bundle",
        "server-config"
      ],
      "fileExtension": "pem",
      "sha256": "f00fbadc161add02fe807f872176ef20369a341fd1331324ea95a39db6821742",
      "algorithm": "RSA",
      "keyStrength": 2048,
      "createdAt": "2026-10-20T13:15:05Z",
      "expiresAt": "2031-10-19T13:15:05Z",
      "fingerprint": "B7E3ADE96801C1F2D04689C57EA84188E1D9406A551FE6D0AE06B20E1E38155F",
      "subject": "CN=Shady Issuing CA 1,O=Shady CA",
      "issuer": "CN=Demo Root A,O=Demo Trust",
      "serial": "335341999633489949168156085538979015142032877912",
      "serialHex": "3abd415d68132d260ea1f960ed6fa5a5f9e12958",
      "format": "X.509",
      "certSha256": "b7e3ade96801c1f2d04689c57ea84188e1d9406a551fe6d0ae06b20e1e38155f",
      "spkiSha256": "67bae0308a72afe7de4f8f373b5f2c24c4f43d9b28576ff00c18bbecd15e65c4",
      "spkiSha256Base64": "Z7rgMIpyr+feT483O18sJMT0PZsoV2/wDBi77NFeZcQ=",
      "version": 3,
      "isCA": true,
      "selfSigned": false,
      "role": "intermediate",
      "pathLen": 0,
      "subjectKeyId": "4228ba74962e460561584d37649ca09498adf87a",
      "authorityKeyId": "6b94824c1b76af75856f1e4921e90cd37305482f",
      "issuers": [
        "a373d9950cc0387b2be327c527fe8fc036ad8f335704004da9e82a58286b70b5"
      ],
      "keyName": "RSA-2048",
      "keyBits": 2048,
      "keyAlgorithmOid": "1.2.840.113549.1.1.1",
      "keyUsage": ["keyCertSign", "cRLSign"],
      "signatureAlgorithm": "SHA256-RSA",
      "signatureAlgorithmOid": "1.2.840.113549.1.1.11",
      "issuingCertificateUrls": ["http://example.invalid/root.crt"],
      "crlDistributionPoints": ["http://example.invalid/root.crl"]
    },
    {
      "kind": "private-key",
      "path": "/etc/nginx/ssl/privkey.pem",
      "paths": ["/etc/nginx/ssl/privkey.pem"],
      "sourceType": "server-config",
      "sourceTypes": ["server-config"],
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
