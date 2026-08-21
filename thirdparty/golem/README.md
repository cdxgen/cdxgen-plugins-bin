# Golem (Go Library Evidence Mapper)

Golem is a static analyzer for Go source trees. It loads a module or workspace with the Go toolchain, resolves types, builds SSA when needed, and writes a compact JSON report about code structure, dependencies, call relationships, cryptographic use, and selected data flows.

The analyzer is designed for evidence collection rather than exploit proof. It keeps output small and reviewable: symbols, source locations, package context, module metadata, graph edges, classifications, and summary counts are emitted. Raw secrets, embedded file contents, command output, and generated command execution are not emitted.

## Requirements

Go 1.27 or later to build. Golem analyzes modules declaring any `go` directive
up to that, which `TestFlowFoundAcrossGoDirectiveRange` holds it to: the same
flow must be reported at go1.16, 1.18, 1.21, 1.23, 1.25 and 1.27.

The version that builds Golem is also the newest language version Golem can
type-check — `go/types` applies the rules of the release it was compiled from,
whatever `go` command is on PATH. A module declaring a newer directive than that
is not analyzed correctly, so the report carries the ceiling as
`runtime.languageVersion` and a `go-version` diagnostic names any module that
exceeds it. Without that the failure is silent in the worst way: a cascade of
type errors that read like defects in the code under analysis, and an empty call
graph and data flow with no explanation.

## Quick Start

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

## What Golem Reads

Golem uses `golang.org/x/tools/go/packages` with syntax, imports, dependencies, types, type information, file lists, module metadata, and type sizes enabled. Package loading is therefore close to what `go list` and the compiler see for the requested patterns, build tags, and test setting.

The first analysis pass walks package ASTs and type information. It records imports, declarations, type-resolved library usages, build directives, native sidecar files, service and endpoint clues, security-sensitive API signals, and cryptographic evidence. SSA is built only when a call graph or data-flow mode is requested.

The JSON model is defined in `internal/model/model.go`. The main report contains package-level and file-level evidence, global rollups, diagnostics, optional call graph data, and optional data-flow data.

For a field-by-field JSON reference, see [JSON_ATTRIBUTE_REFERENCE.md](JSON_ATTRIBUTE_REFERENCE.md).

## Output Formats

`json` is the complete report format. `graphml` and `gexf` export the call graph only and require `--callgraph static`, `cha`, `rta`, or `vta`. Data-flow graph sidecars are written with `--dataflow-graph-out` and use `--dataflow-graph-format graphml` or `gexf`.

## Call Graphs

Call graphs are built from Go SSA using the implementations in `golang.org/x/tools/go/callgraph`:

| Mode   | Implementation   | Practical behavior                                                                                                                                                                                                   |
| ------ | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| none   | No graph         | Fastest mode. Reports source evidence only.                                                                                                                                                                          |
| static | static.CallGraph | Fast and deterministic. Direct calls are reliable, dynamic dispatch is limited.                                                                                                                                      |
| cha    | cha.CallGraph    | More conservative for interface dispatch. Usually more edges.                                                                                                                                                        |
| rta    | rta.Analyze      | Starts from the resolved root set (see `--roots`). Useful for executable reachability.                                                                                                                               |
| vta    | vta.CallGraph    | Uses variable type analysis over functions reachable in the static graph. Often more precise, but depends on the shapes supported by x/tools.                                                                        |
| auto   | CHA → RTA → VTA  | Seeds RTA from the resolved roots, then iterates VTA twice over that result, falling back down the chain on timeout (`--callgraph-timeout`). The algorithm that actually ran is recorded in `callGraph.diagnostics`. |

Golem converts the raw graph into stable node and edge records. A node represents an SSA function with package path, package name, module, package URL when available, receiver, signature, local or external classification, standard library classification, synthetic flag, and source position. An edge records caller, callee, call site location, package URLs for both ends, and whether the call site has a static callee.

Graph filtering is explicit and is applied as a _view_, after reachability has been computed on the complete graph, so filtering never changes what golem concluded.

Standard-library functions are excluded unless `--include-stdlib` is set, and local module functions can be excluded with `--include-local=false`. Excluding a scope does not sever the graph: a path that runs through omitted nodes is preserved as a single edge marked `collapsed`, carrying the hop count and the packages traversed, so a handler invoked through `net/http` still has an edge from the code that registered it. Bridges are only walked through statically resolved calls — following speculative interface dispatch inside omitted code multiplies guesses, and on a mid-sized service that turns a few thousand real edges into tens of thousands of invented ones. The final hop into a visible node may be a dispatch, since that is the callback shape worth keeping.

`--dependency-detail` controls how much of a dependency's interior is shown: `collapse` (default) replaces interior chains with one annotated edge, `drop` removes them, and `full` keeps everything. In every case the boundary edge from local code into a dependency is retained, because that edge is the evidence a reachability consumer wants. `--include-all-flows` is an alias for `full`.

`--roots` selects entry points: `main` (default, with `init` and type-resolved framework registrations), `init`, `exported`, `tests`, `handlers`, `all`, or `symbol:<regex>`, repeatable. Root selection is limited to the module under analysis. `exported` is what makes a library analyzable — with `main`/`init` roots a module without a `main` yields almost nothing, since nothing is reachable.

`callGraph.reachability` reports, per node, whether any root reaches it, the shortest distance, and which roots. Pass `--reachable-symbols <file>` to also emit shortest witness paths for named symbols (`--max-paths-per-symbol`, default 3).

Call graphs are also used by data-flow analysis when `--dataflow-callgraph` is not `none`. In that case Golem indexes dynamic callees by call site and replays method summaries through those edges.

## Cryptographic Evidence

Cryptographic evidence is collected during the AST and type-information pass. It is not a full cryptographic protocol verifier. Its purpose is to make crypto-relevant code easy to find and classify.

The implementation has four main inputs:

1. **Imports are mapped to crypto families.** For example, `crypto/aes` is classified as symmetric crypto, `crypto/tls` as protocol use, `crypto/x509` as certificate handling, and `golang.org/x/crypto/*` as external crypto support.

2. **Selector expressions are resolved through `packages.Package.TypesInfo`.** Known symbols such as `crypto/md5.Sum`, `crypto/aes.NewCipher`, `crypto/rsa.GenerateKey`, `crypto/ed25519.Sign`, `crypto/hmac.New`, `crypto/rand.Read`, `crypto/x509.ParseCertificate`, `crypto/tls.LoadX509KeyPair`, `pbkdf2.Key`, and `curve25519.X25519` are classified into assets, operations, material types, protocols, strengths, standards, OIDs, and findings.

3. **TLS configuration literals are inspected for `InsecureSkipVerify: true`** and produce a critical finding.

4. **Assignments and value declarations are checked for string literals bound to names that look like key material or secrets**, such as private keys, public keys, secrets, passwords, tokens, credentials, IVs, nonces, salts, and generic keys. The literal value is not copied into the report.

The crypto section emits `libraries`, `assets`, `operations`, `materials`, `protocols`, and `findings`. IDs are stable, records are deduplicated, and evidence is attached both to files and to the aggregate report. Findings distinguish type-resolved evidence from name-and-literal indicators through the `confidence` field.

This approach is strong at finding direct, type-resolved use of known Go crypto APIs and weak primitives such as MD5, SHA-1, and DES. It is intentionally weaker for custom wrappers, reflection-heavy code, generated bindings, protocol state validation, key lifetime analysis, and determining whether a weak primitive is used in a security context or only as a checksum.

## Data-Flow Analysis

Data-flow analysis is enabled with `--dataflow security`, `--dataflow crypto`, or `--dataflow all`. It is implemented as an SSA-based taint slicer in `internal/analyzer/dataflow.go`. Pattern packs select the source and sink categories. The `all` mode also lets the candidate function set include non-local third-party functions; the other enabled modes focus materialized analysis on local code unless standard library inclusion is requested.

The analyzer starts by loading source, sink, passthrough, and sanitizer patterns. Built-in packs cover base CLI and environment input, HTTP input and response APIs, common web frameworks, process execution, filesystem operations, data APIs, cryptographic APIs, native interop, configuration libraries, and cloud SDK boundaries. Custom JSON can extend these patterns through `--dataflow-patterns`.

A data-flow run has two phases. First, Golem infers per-function summaries for parameter-to-return flows, parameter-to-sink flows, and calls that return source values. This summary pass iterates up to four times so simple interprocedural relationships can stabilize. Second, Golem analyzes selected functions and materializes concrete source-to-sink slices.

Within a function, taint is tracked through SSA values, stores, loads, map updates, field and index addresses, channel sends and receives, select, phi nodes, conversions, interface wrapping, type assertions, slices, binary operations, and closure bindings. Calls are handled by matching patterns, replaying summaries for static callees, replaying dynamic summaries from the selected call graph, and using compatibility checks for interface method summaries. Known passthrough calls propagate taint from arguments or receivers to returns.

Sanitizers can either stop a trace completely or remove selected taint kinds. They can also mark categories as sanitized, which suppresses later sinks in those categories while allowing unrelated taint to continue. This lets a path sanitizer reduce filesystem findings without hiding a secret flowing to a log sink.

A slice contains source and sink IDs, node and edge IDs, categories, taint kinds, package paths, package URLs, sink argument information, rule metadata, severity, risk score, confidence, path length, sanitizer nodes, duplicate grouping, and a stable `flowKey`. Data-flow graph sidecars include the nodes and edges used by the slices.

By default, Golem drops call graph edges and data-flow slices that are entirely rooted in external Go module cache paths (for example `/go/pkg/mod/...`) to reduce third-party-only noise in downstream evidence. Use `--include-all-flows` to keep those flows.

### Resource Limits

Large repositories can be controlled with these limits:

| Option                                 | Default | Purpose                                                                                                  |
| -------------------------------------- | ------- | -------------------------------------------------------------------------------------------------------- |
| `--dataflow-max-slices`                | 1000    | Stop materializing slices after this count and emit truncation diagnostics.                              |
| `--dataflow-workers`                   | 0       | Number of per-function workers. 0 uses available scheduler parallelism.                                  |
| `--dataflow-large-repo-functions`      | 1000    | Function count where large-repo materialization safeguards start.                                        |
| `--dataflow-max-function-instructions` | 200     | Skip slice materialization for very large functions in large repositories. Summaries are still inferred. |
| `--dataflow-max-trace-nodes`           | 64      | Maximum node IDs retained in an in-memory trace.                                                         |
| `--dataflow-max-trace-edges`           | 128     | Maximum edge IDs retained in an in-memory trace.                                                         |
| `--dataflow-skip-generated`            | false   | Skip generated files during slice materialization.                                                       |
| `--dataflow-skip-tests`                | false   | Skip tests, examples, and benchmarks during slice materialization.                                       |

Use `--max-procs` to cap Go scheduler parallelism, `--memory-limit` to set Go's soft memory limit, and `--progress` to print coarse package loading, SSA, call graph, and data-flow progress logs.

## Strengths

Golem benefits from Go's parser, type checker, package loader, and SSA representation rather than text-only matching. That gives it accurate package paths, symbols, signatures, receivers, build tags, test variants, and source positions for compiled code.

The report is deterministic enough for review workflows: evidence is sorted, IDs are stable, repeated findings are deduplicated, and graph exports can be compared between runs. The analyzer also avoids copying secret-bearing content into output and records diagnostics when package loading, graph construction, or data-flow budgets affect completeness.

Data-flow analysis is intentionally practical. It combines local SSA propagation, memory and channel modeling, summaries, optional call graph replay, sanitizer semantics, and review-focused metadata. This catches common flows such as request input to response, CLI input to process execution, environment or configuration data to logs, paths to filesystem APIs, and secret-looking material to crypto APIs.

## Weaknesses and Assumptions

Golem is static analysis. It does not execute the program, evaluate runtime configuration, or prove reachability under real deployment conditions. A reported flow is a review candidate, not an exploit claim. Missing a flow is also possible, especially when behavior depends on reflection, code generation, build-time side effects, plugins, dynamic loading, complex aliasing, or values constructed outside the loaded package set.

The data-flow engine is path-insensitive and mostly field-insensitive. It uses compact traces and bounded materialization, so long or highly branched flows may be truncated. Summaries are approximate and intentionally small. Interface and function-value calls improve when a call graph is enabled, but dynamic dispatch remains conservative.

Call-graph construction was reworked in phase 1: nodes are classified by visibility rather than dropped, paths through omitted nodes are preserved as annotated collapsed edges, `--roots` selects entry points (`exported` makes library-only modules analyzable — `gorilla/mux` goes from one node and no edges to 90 nodes and 122 edges), `--callgraph auto` seeds VTA from RTA, edges carry a dispatch kind, and `callGraph.reachability` reports per-node reachability with witness paths.

Two taint engines ship. `--taint-engine seam` (Summary Evaluation Across
Modules) is the default; `--taint-engine legacy` is the older engine, kept as an
escape hatch. SEAM replaces the legacy per-function walker with an SSA fixpoint
over basic blocks, summaries computed bottom-up over the call graph's SCC
condensation, an implements-index for interface dispatch, a structured model
database with prefix matching for the cgo boundary, and argument-write effects
for the standard-library carriers (`io.Copy`, `json.Unmarshal`,
`strings.Builder`, `context.Value`, error wrapping). A `known-fail` marker can
name an engine (`known-fail=seam:9`), because a defect closed in one engine and
open in the other is the normal state of the project and the corpus has to be
able to say so.

On the quick tier (94 paired results) SEAM reaches recall 1.000 against legacy's
0.766 at the same precision, 0.982, with no open defects against 23 and 0.90x the
median wall clock. It finds flows legacy cannot — through package-level
variables, eight-deep call chains, a slice of pointers, into `html/template`,
across the cgo boundary, through deferred closures and through goroutine worker
pools. Promotion is gated by `golem bench --taint-engine seam --compare
<legacy.json> --fail-unless-promotable`, which also compares per-fixture flow
counts on the real repositories in `--tier full` and refuses to return a verdict
from criteria it had no data for.

Recall is also measured on real code, not only on the corpus. Two deliberate
vulnerability benchmarks carry ground truth, in
`testdata/bench/annotations/`: on `go-test-bench` SEAM finds all nine declared
routes to legacy's one, and on `shiftleft-go-demo` four of five to legacy's
two. The fifth is a zip slip through a cgo archive library whose package
produces no SSA; it is marked `known-fail=33`.

Annotating a real repository is also where the limits of the model get written
down. shiftleft-go-demo declares seven exploits and only five are taint flows:
its two IDOR routes reach a compile-time-constant parameterized statement and
are authorization failures, and its CSA route is a client-side check. A taint
engine that reported those would be wrong, and the annotation file says so. Closing that gap needed five fixes that no corpus fixture would have
prompted, the largest being dispatch through a func-typed struct field
(`internal/seam/funcfield.go`) and reading taint out of a variadic slice when
applying a passthrough — without which `fmt.Sprintf`, the commonest taint
carrier in Go, returned clean.

The following limitations are measured by the corpus rather than estimated, and each is tracked by a `known-fail` marker:

- **Dependencies are not summarized outside `--dataflow all`.** In the default modes no summary is computed for any function in a third-party module, so a flow contained within a dependency is invisible (`testdata/corpus/dep-only-flow`). Where taint does appear to cross a dependency in those modes, it is usually the blanket "assume an unresolved call returns its arguments" rule rather than an understanding of the callee — which also invents flows through functions that discard their input (`dep-drops-taint-negative`).
- **Standard-library coverage is a model list, not a general mechanism.** The common carriers are modelled — `io.Copy`, `io.ReadAll`, `bufio.Scanner`, `strings.Builder`, `bytes.Buffer`, `encoding/json.Unmarshal`, `context.WithValue`/`Value`, error wrapping — including the calls that fill memory reached through an argument rather than returning it. Anything not on that list still terminates taint, and `dataFlow.unmodeledSinks` is not yet emitted, so absence is silent.
- **Only one route to a value is kept.** When taint reaches a value by two routes the shorter one is reported and the other is dropped, because a trace is a path and merging two of them leaves a slice whose nodes and edges disagree about how the taint travelled. Every reported slice is a connected source-to-sink path, enforced on every corpus case; the route shown is not necessarily the only one.
- **Symbols are matched as substrings of the SSA symbol text.** Patterns written in source notation are normalised into the notation the SSA printer uses, which is what makes `database/sql` and the framework patterns match at all; but the matcher is still textual, so a pattern can match a symbol it was not meant to. Structural matching on resolved types is the durable fix.
- **Loops, deep chains and recursion.** The intra-procedural pass runs once per function with no fixpoint and treats a value cycle as untainted; the summary pass iterates a fixed four times (`loop-carried-taint`, `deep-chain-8-levels`, `recursion`, `mutual-recursion`).
- **Globals and generics.** Package-level variables carry no taint between functions, and summaries do not follow generic instantiations back to their origin (`global-var-carrier`, `generic-container`, `generic-constraint-method`).
- **The native boundary is recognised but not yet traversed by every analysis.** cgo crossings are reported in `nativeBoundary[]` in both directions, the conversion functions are modelled as taint operations, and `//go:linkname` produces real call-graph edges. What does not yet work: taint does not cross a pull linkname, because the local declaration has no body to walk into (`linkname`); there is no C-side call graph, so a flow that enters C and returns through a different function is two findings rather than one; and `--build-matrix` is not implemented, so a single build configuration is analysed and `buildShapeDeltas[]` reports what that configuration left out rather than analysing it.

Crypto evidence classifies API use and obvious material indicators. It does not validate protocol handshakes, key sizes derived at runtime, entropy quality beyond recognized APIs, certificate validation logic beyond simple patterns, or whether a weak primitive is acceptable for a non-security checksum.

Package loading follows the local Go environment. Missing modules, unsupported build tags, cgo settings, platform differences, or incomplete workspaces can change what Golem sees. Always inspect diagnostics before treating absence of evidence as meaningful.

## Threat Model

Threat model notes live in [THREAT_MODEL.md](THREAT_MODEL.md). In short, Golem treats the analyzed repository as untrusted input, does not run `go:generate`, and avoids copying raw secret values into the report. Source paths, package names, module paths, and symbols can still be sensitive metadata.

## Measured Behaviour

Golem's accuracy is measured rather than asserted. Two artifacts do the work:

- **The annotated corpus** (`testdata/corpus/`). Each case is a self-contained
  module carrying inline expectations, checked by `TestCorpus`:

  ```go
  // golem:want     flow source=http-input sink=command-execution [count=N] [mode=security|all] [connected] [known-fail=<defect>]
  // golem:want-not flow source=http-input sink=filesystem
  // golem:want     edge from=pkg.Handler to=pkg.exec calltype=static
  // golem:want     reachable symbol=vulnpkg.Bad from=main.main maxdepth=4
  ```

  Values match exactly; prefix one with `~` for a substring match. Every case is
  evaluated in both `security` and `all` data-flow mode, because an expectation
  that only holds under `--dataflow all` is a gap rather than a feature — mark
  those with `mode=all`. Unknown category names are rejected at parse time, so a
  negative expectation cannot be vacuously satisfied by naming a category golem
  never emits.

  `known-fail=<n>` records a defect the expectation currently trips over. The
  suite is a ratchet in both directions: an unmarked failure fails the build, and
  a marked expectation that starts passing also fails, asking for the marker to be
  removed. Known limitations cannot accumulate silently and cannot outlive their
  fix.

- **The benchmark** (`golem bench`), which runs the corpus plus pinned upstream
  repositories and compares the measurements to `testdata/bench/baseline.json`:

  ```bash
  golem bench --tier quick --baseline testdata/bench/baseline.json --fail-on-regression
  golem bench --tier full --only go-test-bench --sarif /tmp/sarif
  golem golden --tier full --only gorilla-mux            # verify report digests
  ```

  Upstream fixtures are pinned to full commit SHAs and fetched by SHA, so a
  baseline describes one exact tree. Metrics: precision, recall and F1 from
  per-expectation outcomes with every unsanctioned flow counted as a false
  positive; `edgeConnectivity`, the fraction of reported flows whose node and edge
  lists form a real path from source to sink; `integrityViolations`, references to
  identifiers absent from the report; and `dependencyCrossingSlices`, flows that
  leave the module under analysis. Regressions block; improvements are reported
  so the baseline gets refreshed.

  Golden artifacts are report _digests_ (counts, category distributions, content
  hashes over sorted identifiers, and a bounded sample of spelled-out flows)
  rather than whole reports, which for a medium repository run to tens of
  megabytes of mostly machine-specific detail.

Current quick-tier measurement, for reference: 90 expectations across 41 corpus
cases, 38 of them marked against a known defect. On the labeled upstream
fixtures `edgeConnectivity` is 0.43 to 0.84 — a quarter to a half of reported
flows carry a path that does not connect, which the small corpus cases never
trigger. `golem bench --tier full` reproduces this.

## Build and Test

```bash
go test ./... -short   # ~15s: everything except the corpus suites
go test ./...          # ~3.5min: adds the corpus and engine-parity suites
go test ./... -golem.full   # ~8min: the above over every data-flow mode
go build -trimpath -ldflags "-s -w" -o build/golem ./cmd/golem
```

The corpus suites are slow for a structural reason worth knowing: every `Analyze`
call loads and builds SSA for the whole standard-library closure, about 1.3
seconds even for a twelve-line fixture, and the suites make a few hundred such
calls. The work is parallel and the fixed cost dominates, so the useful levers
are how many configurations run rather than how fast the analysis is.

Cross-platform release builds are handled by the Makefile:

```bash
make all
```

An opt-in real repository smoke test is available. It may clone public repositories and download Go modules:

```bash
go build -trimpath -ldflags "-s -w" -o build/golem ./cmd/golem
python3 scripts/real-e2e.py --golem ./build/golem
```
