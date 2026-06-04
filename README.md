# cdxgen-plugins-bin

Binary plugins that extend the capabilities of [cdxgen](https://github.com/cdxgen/cdxgen), the open-source BOM (Bill of Materials) generator. This repository builds, packages, and distributes native helper binaries that cdxgen invokes to perform deep analysis tasks that require language-specific tooling, operating system instrumentation, or cryptographic inspection.

## Purpose

cdxgen generates BOMs in CycloneDX format by analyzing project source code, container images, and host environments. However, certain analysis domains require specialized native binaries that go beyond what a pure Node.js application can provide:

- **Container and OS package inventory** requires native access to package managers (APK, DPKG, RPM) and filesystem structures
- **Operating system instrumentation** needs live process, file, and network data from the host
- **Language-specific semantic analysis** requires compilers and type systems (Go SSA, Rust HIR/MIR, Swift SourceKit)
- **Cryptographic evidence collection** depends on native TLS stacks and certificate inspection
- **Code-signing and trust anchor inspection** requires platform-native APIs (macOS codesign, Windows Authenticode)

This repository bundles those native binaries into installable npm packages so that cdxgen can invoke them transparently when the appropriate analysis mode is triggered.

## Bundled Helpers

### trivy-cdxgen

A custom wrapper around [Trivy](https://github.com/aquasecurity/trivy) optimized for cdxgen's SBOM generation workflow. Trivy is originally an open-source vulnerability scanner, but this wrapper is specifically tailored for OS package inventory rather than vulnerability scanning.

**What it does:**

- Generates CycloneDX SBOMs from container images or unpacked root filesystems
- Collects OS package information (APK, DPKG, RPM) with enrichment metadata
- Forces offline mode to avoid network access during SBOM generation
- Limits language package collection to Go modules and Go binaries
- Suppresses noisy output unless debug mode is enabled

**Customizations over stock Trivy:**

- Exposes only the `image`, `rootfs`, and `version` commands
- Defaults to CycloneDX SBOM output format
- Forces offline, no-update, no-progress operation
- Enriches OS package components with capability/provide metadata, installed command names, installed command paths, installed file counts, installed file paths, package trust-state metadata (architecture, origin, source, status, vendor), native CycloneDX supplier population from maintainer metadata, and OS lifecycle metadata (OS family, OS name, end-of-life date, extended support status)

**Environment variable controls:**

- `TRIVY_CDXGEN_INCLUDE_OS_CAPABILITIES` (default: true) - emits Capability properties for supported APK, DPKG, and RPM rootfs scans
- `TRIVY_CDXGEN_INCLUDE_OS_COMMANDS` (default: true) - emits InstalledCommand and InstalledCommandPath properties for OS packages
- `TRIVY_CDXGEN_INCLUDE_OS_FILES` (default: true) - emits one InstalledFile property per file installed by each OS package

**Supported platforms:** linux-amd64, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, linux-riscv64, linux-arm, windows-arm64, darwin-arm64, darwin-amd64, ppc64

### osquery

A wrapper around [osquery](https://github.com/osquery/osquery), the SQL-powered operating system instrumentation platform. osquery exposes the operating system as a high-performance relational database, allowing cdxgen to query live host data for OBOM (Operating System Bill of Materials) collection.

**What it does:**

- Collects live host process information (running processes, process metadata)
- Enumerates installed software packages from the host OS
- Queries file system state and configuration
- Provides network connection and socket information
- Enables real-time OS-level evidence collection for compliance and security auditing

**Supported platforms:** linux-amd64, linux-arm64, darwin-arm64, windows-amd64, windows-arm64

### sourcekitten

A Swift source analysis tool built from [SourceKitten](https://github.com/jpsim/SourceKitten), which is a command-line tool and framework for interacting with Apple's SourceKit service. SourceKit provides Swift language semantics (parsing, indexing, syntax highlighting) via a JSON API.

**What it does:**

- Provides Swift source code parsing and semantic analysis
- Enables cdxgen to discover Swift package dependencies through SourceKit
- Extracts module and framework information from Swift projects
- Supports both macOS and Linux environments

**Supported platforms:** darwin-arm64, darwin-amd64, linux-amd64, linux-arm64

### dosai

The [Dotnet Source and Assembly Inspector](https://github.com/owasp-dep-scan/dosai) (Dosai) is a tool to list details about the namespaces and methods from sources and assemblies. It provides .NET-specific semantic analysis similar to what SourceKitten does for Swift.

**What it does:**

- Inspects .NET assemblies and source code for namespace and method discovery
- Enables cdxgen to enumerate .NET project dependencies through reflection and source analysis
- Supports both compiled assemblies (.dll, .exe) and source-level analysis

**Supported platforms:** linux-amd64, linux-arm, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, darwin-amd64, darwin-arm64, windows-amd64, windows-arm64

### trustinspector-cdxgen

A custom cdxgen-maintained helper that performs trust-oriented OS and root filesystem inspection. It emits stable, merge-friendly JSON rather than full CycloneDX documents, designed for integration with cdxgen's SBOM enrichment pipeline.

**What it does:**

- **rootfs mode**: Inspects trust anchors inside an unpacked root filesystem, including trusted keyring material and certificate stores
- **paths mode**: Inspects code-signing and notarization state for selected application or binary paths
- **host mode**: Inspects host trust posture such as Gatekeeper (macOS) or WDAC active policies (Windows)

**JSON output structure:**

The tool returns a single JSON object with three possible top-level keys:

- `materials` - trust material (keyrings, certificates) with SHA1, SHA256, algorithm, key strength, fingerprint, and trust domain metadata
- `inspections` - code-signing/notarization state for specific binary paths, with properties like `cdx:darwin:codesign:*`, `cdx:darwin:notarization:*`, `cdx:windows:authenticode:*`
- `hostFindings` - host trust posture findings with properties like `cdx:windows:wdac:activePolicyCount`, `cdx:darwin:gatekeeper:*`

**Supported platforms:** linux-amd64, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, darwin-arm64, darwin-amd64, windows-amd64, windows-arm64

### golem

Go Library Evidence Mapper (Golem) is a static analyzer for Go source trees. It loads a module or workspace with the Go toolchain, resolves types, builds SSA when needed, and writes a compact JSON report about code structure, dependencies, call relationships, cryptographic use, and selected data flows.

**What it does:**

- **Source evidence**: Records imports, declarations, type-resolved library usages, build directives, native sidecar files, service and endpoint clues, security-sensitive API signals
- **Call graphs**: Builds call graphs using Go SSA with support for static, CHA (Class Hierarchy Analysis), RTA (Rapid Type Analysis), and VTA (Variable Type Analysis) modes
- **Data-flow analysis**: SSA-based taint slicer that tracks source-to-sink flows for security analysis (CLI input to process execution, request input to response, environment data to logs, secret material to crypto APIs)
- **Cryptographic evidence**: Classifies crypto API use, identifies weak primitives (MD5, SHA-1, DES), detects TLS misconfigurations (InsecureSkipVerify), and discovers key material indicators

**Call graph modes:**

| Mode   | Implementation   | Practical behavior                                                                            |
| ------ | ---------------- | --------------------------------------------------------------------------------------------- |
| none   | No graph         | Fastest mode. Reports source evidence only.                                                   |
| static | static.CallGraph | Fast and deterministic. Direct calls are reliable, dynamic dispatch is limited.               |
| cha    | cha.CallGraph    | More conservative for interface dispatch. Usually more edges.                                 |
| rta    | rta.Analyze      | Starts from discovered init and main roots. Useful for executable reachability.               |
| vta    | vta.CallGraph    | Uses variable type analysis over functions reachable in the static graph. Often more precise. |

**Data-flow modes:**

- `security` - tracks security-relevant flows (input to execution, input to logging, etc.)
- `crypto` - tracks cryptographic data flows
- `all` - includes all taint flows, including third-party module cache paths

**Supported platforms:** linux-amd64, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, darwin-arm64, darwin-amd64, windows-amd64, windows-arm64

### rusi

Rust Source Inspector (Rusi) is a Rust code analysis engine for evidence collection. It is designed to help downstream tooling and reviewers answer questions about what packages, files, symbols, and imports exist in a Rust repository, which APIs look security-sensitive, and what cryptographic libraries appear relevant for CBOM-style review.

**What it does:**

- **Stable backend**: Discovers Rust files from the workspace/package layout, parses source with syn, records imports, declarations, library/API usage clues, and security signals, constructs a deterministic source-level call graph, and performs lightweight interprocedural data-flow analysis
- **Compiler backend**: Uses an embedded nightly rustc wrapper and MIR/HIR-derived evidence for type-resolved call evidence, dispatch metadata for traits and dyn dispatch, native interop evidence, richer crypto evidence, and MIR-informed data-flow evidence
- **Cryptographic evidence**: Recognizes common crypto families (sha2, sha1, md5, blake3, aes-gcm, chacha20poly1305, hmac, pbkdf2, argon2, rsa, ed25519-dalek, rustls, jsonwebtoken)
- **Data-flow analysis**: Tracks source-to-sink flows for environment, CLI, file, and HTTP sources; process execution, filesystem write/delete, network request/connect, SQL, and HTML-response sinks

**Custom pattern support:**

Rusi can merge custom JSON modeling with the built-in stable data-flow pack through `--patterns` flag, allowing users to define custom sources, sinks, and passthroughs:

```json
{
  "sources": [
    { "pattern": "mycrate::config::read_key", "category": "custom-source" }
  ],
  "sinks": [
    {
      "pattern": "mycrate::shell::run",
      "category": "custom-command",
      "relevant_arguments": [0]
    }
  ]
}
```

**Supported platforms:** linux-amd64, linux-arm64, linuxmusl-amd64, linuxmusl-arm64, darwin-arm64, windows-amd64

## Installation

The package is consumed indirectly by cdxgen. Install cdxgen, which installs this plugin as an optional dependency:

```bash
npm install -g @cyclonedx/cdxgen
```

cdxgen automatically uses the plugins from the global node_modules path to enrich the SBOM output for certain project types such as Docker containers, Swift projects, Go projects, Rust projects, and host-level scans.

## Plugin Manifest and Provenance Bundle

Each packaged `plugins/` directory includes:

- `sbom-postbuild.cdx.json` - a post-build CycloneDX inventory of the bundled helpers
- `plugins-manifest.json` - a lightweight provenance bundle containing the generated-at timestamp, package identity, and per-plugin component metadata (purl, version, hash, binary path, and merged SBOM reference)

cdxgen reads `plugins-manifest.json` automatically when present so the generated BOM can record more precise helper-tool identity/version data under `metadata.tools`.

The manifest is **data only**. cdxgen does not execute commands, scripts, or paths from it; the file is parsed as JSON and used only to tighten helper provenance in `metadata.tools`.

## Distribution Channels

Helper binaries are available through multiple channels for automation-friendly retrieval:

### npm packages

Platform-specific npm packages are published to npm under the `@cdxgen/cdxgen-plugins-bin` scope. Each platform package (linux-amd64, darwin-arm64, etc.) contains the platform-appropriate helper binaries.

### GitHub Releases

Raw helper binaries are uploaded alongside their SHA-256 sidecars. For example: `golem-linuxmusl-amd64` and `golem-linuxmusl-amd64.sha256`.

### GHCR / ORAS

Individual helper binaries are published to GitHub Container Registry using ORAS. Each binary has its own tag corresponding to the binary filename. For example:

- `ghcr.io/cdxgen/cdxgen-plugins-bin:golem-linuxmusl-amd64`
- `ghcr.io/cdxgen/cdxgen-plugins-bin:trustinspector-cdxgen-linuxmusl-arm64`

ORAS tags include the binary, its SHA-256 checksum sidecar, and optionally a CycloneDX SBOM of the binary itself.

## Build Process

The build process is orchestrated through GitHub Actions workflows and local build scripts:

1. **Third-party builds**: Each third-party tool has its own build script that compiles the binary for the target platform
2. **Artifact staging**: Binaries are copied into the `plugins/` directory with platform-specific naming
3. **Compression**: UPX is used to compress binaries where applicable
4. **Checksum generation**: SHA-256 checksums are generated for all binaries
5. **Metadata generation**: A Node.js script generates `sbom-postbuild.cdx.json` and `plugins-manifest.json`
6. **Size validation**: Package size limits are enforced to stay within npm constraints
7. **Release**: npm packages are published with provenance, and ORAS tags are created for individual binaries

### UPX Compression

Binaries are compressed using UPX (Ultimate Packer for eXecutables) with LZMA compression to reduce package size. This is particularly important for large binaries like Trivy and osquery.

## Security Considerations

### Untrusted Input Handling

All helper binaries treat the analyzed repository as untrusted input. Golem and Rusi do not execute `go:generate` or `cargo:generate` commands. They record these directives as evidence only.

### Secret Handling

Golem and Rusi do not copy raw secret-bearing content into reports. This includes environment values, command output, embedded file contents, private keys, tokens, passwords, and literal string values that appear to contain cryptographic material. They may report names, categories, counts, symbols, file paths, source ranges, and material types.

### Network Access

Golem avoids network access initiated by its own logic. Package loading uses the local Go toolchain and module environment, so module downloads can still occur depending on the user's Go configuration. Run with a controlled module cache and proxy configuration when analyzing untrusted or sensitive projects.

### Report Sensitivity

Even when raw secrets are omitted, reports can contain sensitive metadata including absolute source paths, package and module paths, private repository names, internal service names, endpoint paths, function names, dependency names, and source line numbers. Treat reports as internal analysis output unless they have been reviewed and redacted for the intended audience.

### Static Analysis Limitations

Golem and Rusi output is evidence for prioritization. A finding is not proof of exploitability, and the absence of a finding is not proof of safety. Static analysis can miss behavior that depends on runtime configuration, reflection, plugins, dynamic loading, generated code not present in the loaded files, platform-specific files excluded by the selected build tags, or packages that fail to load.

## Use Cases

### Software Supply Chain Security

Security analysts use these plugins to build comprehensive SBOMs that capture not just dependency information but also the structural evidence needed for supply chain risk assessment. The combination of container OS packages (trivy), host-level process and package data (osquery), and language-specific source analysis (golem, rusi) provides a multi-layered view of software composition.

### Cryptographic Compliance Auditing

CBOM (Cryptographic Bill of Materials) generation is a primary use case for golem and rusi. Both tools classify cryptographic libraries, identify weak primitives, detect TLS misconfigurations, and discover key material indicators. This enables organizations to audit their cryptographic posture without manual code review.

### Regulatory Compliance (NIST SSDF, EU Cyber Resilience Act)

The trustinspector plugin enables compliance teams to verify code-signing policies, certificate authority trust anchors, and host-level security posture. This is particularly relevant for organizations subject to NIST SP 800-218 (SSDF) or the EU Cyber Resilience Act, which require evidence of secure development practices.

### Host-Level Inventory for Compliance

osquery enables real-time OS-level inventory that goes beyond package managers. For organizations that need to verify that running systems match their declared software inventory, or that need to detect unauthorized processes and configurations, osquery provides the live data needed.

### Container Security Baseline

The trivy-cdxgen wrapper provides a fast, offline-capable way to generate container OS package inventories without triggering vulnerability scans. This is useful for organizations that need to track OS package composition for compliance purposes without the overhead of full vulnerability scanning.

## Debugging

To enable debug output for the plugin loader, set the `CDXGEN_DEBUG_MODE` environment variable:

```bash
CDXGEN_DEBUG_MODE=debug cdxgen -t docker ubuntu:24.04
```

This will print plugin resolution information to stdout.

## Repository Structure

```
.
├── README.md                    # This file
├── package.json                 # npm package definition
├── index.js                     # Plugin loader entry point
├── build.sh                     # Local build orchestration script
├── scripts/
│   ├── generate-metadata.js     # Plugin manifest and SBOM generation
│   ├── thirdparty-downloads.sh  # Third-party binary download helper
│   ├── stage-built-plugins.sh   # Plugin binary staging helper
│   ├── publish-helper-oras.sh   # ORAS publishing helper
│   └── check-package-size.sh    # NPM package size validation
├── packages/
│   ├── linux-amd64/             # Platform-specific npm packages
│   ├── linux-arm64/
│   ├── linuxmusl-amd64/
│   ├── linuxmusl-arm64/
│   ├── linux-riscv64/
│   ├── linux-arm/
│   ├── windows-amd64/
│   ├── windows-arm64/
│   ├── darwin-arm64/
│   ├── darwin-amd64/
│   └── ppc64/
├── plugins/                     # Staged plugin binaries (generated)
├── thirdparty/
│   ├── README.md                # Third-party source overview
│   ├── trivy/                   # Trivy wrapper source
│   ├── sourcekitten/            # SourceKitten build script
│   ├── trustinspector/          # trustinspector source
│   ├── golem/                   # Golem source and analysis
│   └── rusi/                    # Rusi source and analysis
└── .github/workflows/
    ├── release.yml              # Release workflow (npm + ORAS)
    └── native-builds.yml        # Native binary build workflow
```

## License

MIT
