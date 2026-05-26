# golem

Golem (Go Library Evidence Mapper) is a native Go helper for cdxgen. It analyzes Go source projects with the Go toolchain and emits detailed semantic evidence about packages, modules, imports, declarations, type-resolved library usages, build directives, native interop artifacts, security-sensitive API signals, and optional call graphs.

It also emits a dedicated `crypto` evidence attribute for Go cryptography review. This includes crypto libraries, algorithms, protocols, related material indicators, operations, and crypto-specific findings. Values are kept small and safe: source locations, symbols, categories, counts, OIDs, and material types are emitted; raw keys, secrets, embedded file contents, and generator command output are not.

## Usage

```bash
golem analyze --dir /path/to/go/project --format json --out golem.json
golem analyze --dir . --callgraph static --format graphml --out callgraph.graphml
golem analyze --dir . --callgraph rta --format gexf --out callgraph.gexf
golem analyze --dir . --callgraph pointer --format json --out golem-pointer.json
golem analyze --dir . --dataflow security --dataflow-callgraph cha --dataflow-graph-out dataflows.graphml --format json --out golem-dataflow.json
```

When used through cdxgen, the normal entry point is `evinse`:

```bash
cdxgen -t go -o bom.json /absolute/path/to/go/project
evinse -i bom.json -o bom.evinse.json -l go --golem-callgraph static /absolute/path/to/go/project
```

Advanced cdxgen options map directly to Golem analysis settings:

| cdxgen option            | Golem behavior                                           |
| ------------------------ | -------------------------------------------------------- | --- | -------- | --------------------------------- |
| `--golem-command`        | Use a specific helper binary instead of the bundled one. |
| `--golem-callgraph none  | static                                                   | rta | pointer` | Select call graph depth and cost. |
| `--golem-patterns ./...` | Select Go package patterns.                              |
| `--golem-tags tag1,tag2` | Load packages with build tags.                           |
| `--golem-tests`          | Include test variants in package loading and evidence.   |

## Call graph modes

- `none`: source and library evidence only.
- `static`: fast static SSA call graph. This is the cdxgen Evinse default.
- `cha`: Class Hierarchy Analysis for broader interface dispatch candidates.
- `rta`: Rapid Type Analysis from discovered `init` and `main` roots.
- `vta`: Variable Type Analysis for more precise dynamic call resolution when affordable.
- `pointer`: points-to call graph for main packages. This is the most expensive mode.

## API endpoint, service, and data-flow evidence

Golem extracts API endpoint and service evidence suitable for downstream CycloneDX `services` enrichment. It recognizes common `net/http` route/listener patterns, route groups from popular Go frameworks, RPC registration-style calls, and sanitized literal external URLs. URL evidence removes user info, query strings, and fragments before emission so tokens and other secret-bearing values are not copied into the report.

Semantic data-flow slicing is available with `--dataflow security`, `--dataflow crypto`, or `--dataflow all`. The slicer uses Go SSA and emits compact source-to-sink nodes, edges, slices, summaries, and optional GraphML/GEXF sidecars. Built-in pattern packs cover CLI/env/HTTP/framework input, process execution, filesystem, data APIs, crypto APIs, and cgo/native interop. Custom source/sink/passthrough/sanitizer packs can be supplied with `--dataflow-patterns`.

`--dataflow-callgraph` controls dynamic summary replay for interface and function-value-heavy programs. `static` is the default, `cha` is more conservative for interface dispatch, and `vta` can be useful when its experimental x/tools implementation supports the analyzed shape. Sanitizer patterns can remove configured taint kinds via `removesTaintKinds`; for example path base-name extraction can suppress path traversal flows while still preserving unrelated taint kinds.

For large repositories, Golem uses all available Go scheduler cores by default during analysis. Use `--max-procs` to cap scheduler parallelism, `--dataflow-workers` to cap the per-function data-flow worker pool, and `--memory-limit` to set Go's soft memory limit (for example `4GiB` or `800MiB`). Add `--progress` and optionally `--progress-interval 10s` to emit coarse package-loading, SSA, call graph, and data-flow progress logs to stderr.

## Output formats

- `json`: complete evidence schema consumed by cdxgen.
- `graphml`: call graph sidecar suitable for graph tools.
- `gexf`: call graph sidecar suitable for Gephi and similar tools.

Graph formats require a non-`none` call graph mode.

## cdxgen evidence mapping

cdxgen maps the JSON report into CycloneDX without requiring a new BOM format.

```
golem modules/imports/usages/call graph
  |
  v
evinse -l go
  |
  +--> component.evidence.occurrences
  +--> component.evidence.callstack.frames
  +--> component.properties: cdx:golem:*
  +--> metadata.component.properties: cdx:golem:*
```

Important property groups include:

- run metadata: `cdx:golem:toolVersion`, `cdx:golem:callGraphMode`, package/module/file counts, call graph node/edge counts
- build posture: `cdx:golem:buildDirectiveKinds`, `cdx:golem:goGenerateCount`, `cdx:golem:goEmbedCount`, `cdx:golem:nativeArtifactCount`, `cdx:golem:nativeArtifactKinds`
- module posture: `cdx:golem:modulePath`, `cdx:golem:goVersion`, `cdx:golem:localReplacement`, `cdx:golem:vendored`, `cdx:golem:privateModuleCandidate`, `cdx:golem:licenseFileCount`
- usage evidence: `cdx:golem:usageScopes`, `cdx:golem:testOnly`, `cdx:golem:occurrenceEvidenceKinds`, import/symbol occurrence counts
- security review: `cdx:golem:securitySignalCategory`, `cdx:golem:securitySignalSeverity`, metadata signal category and severity summaries
- crypto/CBOM review: `cdx:golem:cryptoLibraryCount`, `cdx:golem:cryptoAssetCount`, `cdx:golem:cryptoOperationCount`, `cdx:golem:cryptoMaterialCount`, `cdx:golem:cryptoProtocolCount`, `cdx:golem:cryptoFindingCount`, `cdx:golem:cryptoAlgorithms`, `cdx:golem:cryptoFinding`

The cdxgen repo documents the consumer side in `docs/GO_EVINSE_GOLEM.md`, `docs/GO_EVINSE_GOLEM_THREAT_MODEL.md`, `docs/CUSTOM_PROPERTIES.md`, and `docs/BOM_AUDIT.md`.

## Security and compliance evidence

The JSON report includes Go-specific evidence useful for AppSec and compliance review:

- build constraints from `//go:build` and legacy `// +build`
- `//go:generate` directives without executing generator commands
- `//go:embed` patterns, targets, and safe risk indicators for embedded credentials or crypto material
- native sidecar files such as C/C++/Objective-C/assembly/native object files
- cgo directives and `import "C"`/`C.symbol` signals when present
- security-sensitive API signals for unsafe, reflection, syscall, plugin loading, process execution, environment access, HTTP, TLS, weak crypto, weak randomness, archive handling, templates, database opens, and filesystem writes
- focused heuristics such as `tls.Config{InsecureSkipVerify:true}`
- dedicated crypto evidence under `crypto`, including algorithms such as MD5, SHA-1/SHA-2, AES, RSA, Ed25519, HMAC, PBKDF2, and X25519 when type-resolved selectors are present
- related cryptographic material indicators such as private keys, public keys, tokens, nonces, salts, credentials, and passwords, detected from symbol names and literal presence without copying literal values
- crypto protocol evidence such as TLS usage and TLS misconfiguration findings

Signal values are categories/counts/symbol names and source locations only; `golem` does not copy raw environment values, command output, embedded file contents, or secrets into JSON.

The first crypto implementation is intentionally not a full data-flow engine. It is a precise source/classification layer that cdxgen can convert into CycloneDX cryptographic assets. Source-to-sink flows for key material, plaintext, ciphertext, and protocol sinks should be added as a separate graph pass so the output can preserve the same safety and compactness guarantees.

## Threat model notes

Golem treats the target Go repository as untrusted input. It loads packages and classifies source-level facts, but it must not execute `go:generate` commands and must not copy secret-bearing file contents into the output. Reviewers should still treat module paths and source locations as potentially internal information before publishing an enriched BOM.

The evidence is meant to prioritize review. A high-severity API signal is not proof of exploitability, and test-only usage is not proof of safety. Pair Golem output with code review, vulnerability data, build provenance, and runtime context.

## BOM audit and REPL workflow

After `evinse -l go`, cdxgen users can audit and inspect Golem properties directly:

```bash
cdx-audit --bom bom.evinse.json --direct-bom-audit --categories golem
cdxi bom.evinse.json
```

Useful `cdxi` commands are `.golemsummary`, `.golemhotspots`, `.golemcoverage`, `.occurrences`, and `.callstack`.

## Build

```bash
go test ./...
make all
```

The Makefile cross-compiles static binaries for Linux, macOS, and Windows targets used by `cdxgen-plugins-bin`.

## Real repository smoke tests

```bash
go build -trimpath -ldflags "-s -w" -o build/golem-darwin-arm64 ./cmd/golem
python3 scripts/real-e2e.py --golem ./build/golem-darwin-arm64
```

The real E2E script is opt-in because it clones public GitHub repositories and can trigger Go module downloads while loading package metadata.
