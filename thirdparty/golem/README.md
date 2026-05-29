# Golem

Golem (Go Library Evidence Mapper) is a static analyzer for Go source trees. It loads a module or workspace with the Go toolchain, resolves types, builds SSA when needed, and writes a compact JSON report about code structure, dependencies, call relationships, cryptographic use, and selected data flows.

The analyzer is designed for evidence collection rather than exploit proof. It keeps output small and reviewable: symbols, source locations, package context, module metadata, graph edges, classifications, and summary counts are emitted. Raw secrets, embedded file contents, command output, and generated command execution are not emitted.

## Quick start

Build or run Golem from this directory:

```bash
go run ./cmd/golem analyze --dir /path/to/go/project --format json --out golem.json
```

Useful analysis variants:

```bash
go run ./cmd/golem analyze --dir . --callgraph static --format graphml --out callgraph.graphml
go run ./cmd/golem analyze --dir . --callgraph rta --format gexf --out callgraph.gexf
go run ./cmd/golem analyze --dir . --dataflow security --dataflow-graph-out dataflows.graphml --out golem-dataflow.json
go run ./cmd/golem analyze --dir . --tags prod,linux --tests --out golem-tests.json
```

The default package pattern is `./...`. Use `--patterns` to narrow the load set and `--tags` or `--tests` to match the build shape you want to inspect.

If `--dir` does not contain `go.mod` or `go.work`, Golem automatically discovers child directories containing `go.mod` and merges results across them. Use `--no-recurse` to disable this behavior.

## What Golem reads

Golem uses `golang.org/x/tools/go/packages` with syntax, imports, dependencies, types, type information, file lists, module metadata, and type sizes enabled. Package loading is therefore close to what `go list` and the compiler see for the requested patterns, build tags, and test setting.

The first analysis pass walks package ASTs and type information. It records imports, declarations, type-resolved library usages, build directives, native sidecar files, service and endpoint clues, security-sensitive API signals, and cryptographic evidence. SSA is built only when a call graph or data-flow mode is requested.

The JSON model is defined in `internal/model/model.go`. The main report contains package-level and file-level evidence, global rollups, diagnostics, optional call graph data, and optional data-flow data.

For a field-by-field JSON reference, see `JSON_ATTRIBUTE_REFERENCE.md`.

## Output formats

`json` is the complete report format. `graphml` and `gexf` export the call graph only and require `--callgraph static`, `cha`, `rta`, or `vta`. Data-flow graph sidecars are written with `--dataflow-graph-out` and use `--dataflow-graph-format graphml` or `gexf`.

## Call graphs

Call graphs are built from Go SSA using the implementations in `golang.org/x/tools/go/callgraph`:

| Mode | Implementation | Practical behavior |
| --- | --- | --- |
| `none` | No graph | Fastest mode. Reports source evidence only. |
| `static` | `static.CallGraph` | Fast and deterministic. Direct calls are reliable, dynamic dispatch is limited. |
| `cha` | `cha.CallGraph` | More conservative for interface dispatch. Usually more edges. |
| `rta` | `rta.Analyze` | Starts from discovered `init` and `main` roots. Useful for executable reachability. |
| `vta` | `vta.CallGraph` | Uses variable type analysis over functions reachable in the static graph. Often more precise, but depends on the shapes supported by `x/tools`. |

Golem converts the raw graph into stable node and edge records. A node represents an SSA function with package path, package name, module, package URL when available, receiver, signature, local or external classification, standard library classification, synthetic flag, and source position. An edge records caller, callee, call site location, package URLs for both ends, and whether the call site has a static callee.

Graph filtering is explicit. Standard-library functions are excluded unless `--include-stdlib` is set. Local module functions are included by default and can be disabled with `--include-local=false`.

Call graphs are also used by data-flow analysis when `--dataflow-callgraph` is not `none`. In that case Golem indexes dynamic callees by call site and replays method summaries through those edges.

## Cryptographic evidence

Cryptographic evidence is collected during the AST and type-information pass. It is not a full cryptographic protocol verifier. Its purpose is to make crypto-relevant code easy to find and classify.

The implementation has four main inputs:

1. Imports are mapped to crypto families. For example, `crypto/aes` is classified as symmetric crypto, `crypto/tls` as protocol use, `crypto/x509` as certificate handling, and `golang.org/x/crypto/*` as external crypto support.
2. Selector expressions are resolved through `packages.Package.TypesInfo`. Known symbols such as `crypto/md5.Sum`, `crypto/aes.NewCipher`, `crypto/rsa.GenerateKey`, `crypto/ed25519.Sign`, `crypto/hmac.New`, `crypto/rand.Read`, `crypto/x509.ParseCertificate`, `crypto/tls.LoadX509KeyPair`, `pbkdf2.Key`, and `curve25519.X25519` are classified into assets, operations, material types, protocols, strengths, standards, OIDs, and findings.
3. TLS configuration literals are inspected for `InsecureSkipVerify: true` and produce a critical finding.
4. Assignments and value declarations are checked for string literals bound to names that look like key material or secrets, such as private keys, public keys, secrets, passwords, tokens, credentials, IVs, nonces, salts, and generic keys. The literal value is not copied into the report.

The crypto section emits `libraries`, `assets`, `operations`, `materials`, `protocols`, and `findings`. IDs are stable, records are deduplicated, and evidence is attached both to files and to the aggregate report. Findings distinguish type-resolved evidence from name-and-literal indicators through the `confidence` field.

This approach is strong at finding direct, type-resolved use of known Go crypto APIs and weak primitives such as MD5, SHA-1, and DES. It is intentionally weaker for custom wrappers, reflection-heavy code, generated bindings, protocol state validation, key lifetime analysis, and determining whether a weak primitive is used in a security context or only as a checksum.

## Data-flow analysis

Data-flow analysis is enabled with `--dataflow security`, `--dataflow crypto`, or `--dataflow all`. It is implemented as an SSA-based taint slicer in `internal/analyzer/dataflow.go`. Pattern packs select the source and sink categories. The `all` mode also lets the candidate function set include non-local third-party functions; the other enabled modes focus materialized analysis on local code unless standard library inclusion is requested.

The analyzer starts by loading source, sink, passthrough, and sanitizer patterns. Built-in packs cover base CLI and environment input, HTTP input and response APIs, common web frameworks, process execution, filesystem operations, data APIs, cryptographic APIs, native interop, configuration libraries, and cloud SDK boundaries. Custom JSON can extend these patterns through `--dataflow-patterns`.

A data-flow run has two phases. First, Golem infers per-function summaries for parameter-to-return flows, parameter-to-sink flows, and calls that return source values. This summary pass iterates up to four times so simple interprocedural relationships can stabilize. Second, Golem analyzes selected functions and materializes concrete source-to-sink slices.

Within a function, taint is tracked through SSA values, stores, loads, map updates, field and index addresses, channel sends and receives, `select`, `phi` nodes, conversions, interface wrapping, type assertions, slices, binary operations, and closure bindings. Calls are handled by matching patterns, replaying summaries for static callees, replaying dynamic summaries from the selected call graph, and using compatibility checks for interface method summaries. Known passthrough calls propagate taint from arguments or receivers to returns.

Sanitizers can either stop a trace completely or remove selected taint kinds. They can also mark categories as sanitized, which suppresses later sinks in those categories while allowing unrelated taint to continue. This lets a path sanitizer reduce filesystem findings without hiding a secret flowing to a log sink.

A slice contains source and sink IDs, node and edge IDs, categories, taint kinds, package paths, package URLs, sink argument information, rule metadata, severity, risk score, confidence, path length, sanitizer nodes, duplicate grouping, and a stable `flowKey`. Data-flow graph sidecars include the nodes and edges used by the slices.

By default, Golem drops call graph edges and data-flow slices that are entirely rooted in external Go module cache paths (for example `/go/pkg/mod/...`) to reduce third-party-only noise in downstream evidence. Use `--include-all-flows` to keep those flows.

Large repositories can be controlled with these limits:

| Option | Default | Purpose |
| --- | ---: | --- |
| `--dataflow-max-slices` | `1000` | Stop materializing slices after this count and emit truncation diagnostics. |
| `--dataflow-workers` | `0` | Number of per-function workers. `0` uses available scheduler parallelism. |
| `--dataflow-large-repo-functions` | `1000` | Function count where large-repo materialization safeguards start. |
| `--dataflow-max-function-instructions` | `200` | Skip slice materialization for very large functions in large repositories. Summaries are still inferred. |
| `--dataflow-max-trace-nodes` | `64` | Maximum node IDs retained in an in-memory trace. |
| `--dataflow-max-trace-edges` | `128` | Maximum edge IDs retained in an in-memory trace. |
| `--dataflow-skip-generated` | `false` | Skip generated files during slice materialization. |
| `--dataflow-skip-tests` | `false` | Skip tests, examples, and benchmarks during slice materialization. |

Use `--max-procs` to cap Go scheduler parallelism, `--memory-limit` to set Go's soft memory limit, and `--progress` to print coarse package loading, SSA, call graph, and data-flow progress logs.

## Strengths

Golem benefits from Go's parser, type checker, package loader, and SSA representation rather than text-only matching. That gives it accurate package paths, symbols, signatures, receivers, build tags, test variants, and source positions for compiled code.

The report is deterministic enough for review workflows: evidence is sorted, IDs are stable, repeated findings are deduplicated, and graph exports can be compared between runs. The analyzer also avoids copying secret-bearing content into output and records diagnostics when package loading, graph construction, or data-flow budgets affect completeness.

Data-flow analysis is intentionally practical. It combines local SSA propagation, memory and channel modeling, summaries, optional call graph replay, sanitizer semantics, and review-focused metadata. This catches common flows such as request input to response, CLI input to process execution, environment or configuration data to logs, paths to filesystem APIs, and secret-looking material to crypto APIs.

## Weaknesses and assumptions

Golem is static analysis. It does not execute the program, evaluate runtime configuration, or prove reachability under real deployment conditions. A reported flow is a review candidate, not an exploit claim. Missing a flow is also possible, especially when behavior depends on reflection, code generation, build-time side effects, plugins, dynamic loading, complex aliasing, or values constructed outside the loaded package set.

The data-flow engine is path-insensitive and mostly field-insensitive. It uses compact traces and bounded materialization, so long or highly branched flows may be truncated. Summaries are approximate and intentionally small. Interface and function-value calls improve when a call graph is enabled, but dynamic dispatch remains conservative.

Crypto evidence classifies API use and obvious material indicators. It does not validate protocol handshakes, key sizes derived at runtime, entropy quality beyond recognized APIs, certificate validation logic beyond simple patterns, or whether a weak primitive is acceptable for a non-security checksum.

Package loading follows the local Go environment. Missing modules, unsupported build tags, cgo settings, platform differences, or incomplete workspaces can change what Golem sees. Always inspect diagnostics before treating absence of evidence as meaningful.

## Threat model

Threat model notes live in `THREAT_MODEL.md`. In short, Golem treats the analyzed repository as untrusted input, does not run `go:generate`, and avoids copying raw secret values into the report. Source paths, package names, module paths, and symbols can still be sensitive metadata.

## Build and test

```bash
go test ./...
go build -trimpath -ldflags "-s -w" -o build/golem ./cmd/golem
```

Cross-platform release builds are handled by the Makefile:

```bash
make all
```

An opt-in real repository smoke test is available. It may clone public repositories and download Go modules:

```bash
go build -trimpath -ldflags "-s -w" -o build/golem ./cmd/golem
python3 scripts/real-e2e.py --golem ./build/golem
```
