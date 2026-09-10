# Kosi JSON attribute reference

This document describes the JSON emitted by `kosi analyze`. The canonical
schema lives in `modules/kosi-schema`; this file must change in the same PR as
any behaviour it describes. Conventions (03-SCHEMA.md):

1. `camelCase` throughout (golem's convention; cdxgen's own JSON is camelCase).
2. Deterministic, minified, byte-identical across runs on the same input;
   `--pretty` only re-indents.
3. Canonical top-level arrays only — per-file arrays are not serialised;
   group by `position.filename`.
4. Edges carry no field that already exists on the node they reference.
5. Every truncation, cap, fallback and unresolved thing is a `diagnostics[]`
   entry with a machine-readable `code` plus a counter in `stats`.
6. Additive-only after the first cdxgen release. `usages[]`, `callGraph`,
   `dataFlow.slices[]`, `crypto` and `apiEndpoints[]` are consumed by
   cdxgen/evinse and dep-scan; never regress them.

## Report envelope

| JSON path | Type | Purpose | Typical use case |
| --- | --- | --- | --- |
| `schemaVersion` | string | `kosi/1` | contract check |
| `tool` | object | name/version/commit | provenance |
| `runtime` | object | compiler and JVM provenance | capability negotiation |
| `options` | object | every effective option | reproduce a run |
| `modules` | ModuleRef[] | projects and source sets | module-scoped consumers |
| `packages` | PackageEvidence[] | per-module rollup + file list | purl joins |
| `files` | FileEvidence[] | path, module, language | inventory |
| `imports` | ImportUsage[] | canonical imports | library usage |
| `declarations` | Declaration[] | canonical declarations | symbol indexes |
| `usages` | LibraryUsage[] | calls/references by name | cdxgen-critical |
| `securitySignals` | SecuritySignal[] | non-flow findings (later phases) | findings UIs |
| `crypto` | CryptoEvidence | CBOM evidence (later phases) | CBOM |
| `callGraph` | CallGraph? | null until a call-graph mode runs | reachability |
| `dataFlow` | DataFlowEvidence? | null until taint runs | slices |
| `apiEndpoints` | ApiEndpoint[] | inbound endpoints (later phases) | SaaSBOM |
| `services` | ServiceRef[] | outbound deps (later phases) | services[] |
| `urls` | UrlEvidence[] | URL/host/JDBC strings (later phases) | URL identification |
| `diagnostics` | Diagnostic[] | machine-readable conditions | silence is a bug |
| `stats` | object | counters | scale judgement |

### tool

| Attribute | Type | Value |
| --- | --- | --- |
| `name` | string | `kosi` |
| `version` | string | tool version (e.g. `0.1.0`) |
| `description` | string | human description |
| `commit` | string | git commit injected at build time (`unknown` fallback) |

### runtime

| Attribute | Type | Purpose |
| --- | --- | --- |
| `kotlinVersion` | string | built-with compiler version; **the analysable ceiling** |
| `languageVersionRange` | object | `first`/`firstNonDeprecated`/`latestStable`, read from the bundled compiler's `LanguageVersion` constants at run time, never hard-coded |
| `jvmVersion` | string | JVM the analysis ran on (JVM tier only; `X`-free) |
| `host` | string | `<os>-<arch>` of the analysis host |
| `workingDirectory` | string | absolute analysis root |
| `nativeImage` | boolean | true when running as a GraalVM native image |

### options

Every effective option including defaults. Defaults live in
`AnalyzeOptions` (kosi-schema) — the single source the CLI parser and the
bench harness both consume (a test on each side asserts the equality).
Flags: `backend`, `dataflow`, `callgraph`, `dependencyDetail`, `roots`,
`dataflowMaxSlices`, `dataflowWorkers`, `dataflowMaxFunctionInstructions`,
`dataflowMaxTraceNodes`, `dataflowMaxTraceEdges`, `accessPathDepth`,
`dataflowSkipGenerated`, `callgraphTimeoutSeconds`, `maxPathsPerSymbol`,
`includeStdlib`, `unknownCall`, `languageVersion`, `apiVersion`, `jvmTarget`,
`progressive`, `optIn`, `multiplatformTarget`, `classpath` (repeatable jars),
`classpathFile` (one jar path per line, `#` comments), `jdkHome`,
`pretty`, `format`.
An explicit `--classpath`/`--classpath-file` replaces offline resolution
entirely (02-ARCHITECTURE.md §3 acquisition order); otherwise the resolved
backend scans build files as text and locates coordinates in the local
Gradle/Maven caches and `build/libs`. `--jdk-home` names the JDK module and
defaults to the running JVM. Unknown flags are a usage error, never a silent
degrade.

## modules — ModuleRef

| Attribute | Type | Purpose |
| --- | --- | --- |
| `name` | string | `app`, or `meta:commonMain` for KMP source sets |
| `modulePath` | string | module directory relative to the analysis root (`.` for root) |
| `platform` | string | `jvm`/`android`/`js`/`native`/`common` |
| `workspaceMember` | string | Gradle path (`:app`) or Maven module path |
| `purl` | string | `pkg:maven/<group>/<name>@<version>` or `pkg:generic/...` |
| `sourceRoots` | string[] | source roots relative to the analysis root |
| `declaredLanguageVersion` | string? | parsed from build files; null when absent |
| `declaredApiVersion` | string? | as declared |
| `effectiveLanguageVersion` | string | clamped into the bundled compiler's band |
| `jvmTarget` | string? | as declared |

Version clamping (08-VERSION-POLICY.md §4): a declared version below
`FIRST_SUPPORTED` is clamped up with a `kotlin-language-version` diagnostic;
a declared version above the ceiling is clamped down with `kotlin-version`;
`apiVersion` above the language version gets `kotlin-api-version`. Analysis
never refuses to run and never pretends the declared version was honoured.

## files — FileEvidence

| Attribute | Type | Purpose |
| --- | --- | --- |
| `path` | string | relative, POSIX separators |
| `modulePath` | string | owning module |
| `purl` | string | owning module purl |
| `language` | string | `kotlin` or `java` (Java is parsed at the resolved tier; evidence-only at the syntax tier, where `java-source-not-parsed` fires) |
| `generated` | boolean | false; build/output trees are excluded outright |

## imports — ImportUsage

| Attribute | Type | Purpose |
| --- | --- | --- |
| `name` | string | imported FQN, backtick-free (`kotlin.io.println`); `star` marks wildcard |
| `alias` | string? | `import ... as x` |
| `star` | boolean | wildcard import |
| `purl` | string? | resolved tier: the purl of the library jar whose package prefix the import matches (longest prefix wins; null when no resolved jar contains it, and always null at the syntax tier) |
| `filePath`, `position` | | occurrence |

## declarations — Declaration

| Attribute | Type | Purpose |
| --- | --- | --- |
| `id` | string | `dec-000001...`, stable for a given tree state |
| `name` | string | simple name |
| `qualifiedName` | string | `<modulePath>:<pkg>.<containers>.<name>` — rooted at the module so `commonMain` and `androidMain` actuals are distinguishable |
| `canonicalName` | string | generic-free, hash-free, backtick-free join key |
| `jvmOwner`, `jvmDescriptor` | string? | resolved tier: internal owner name (`t/Greeter`) and erased descriptor (`(Ljava/lang/String;)Ljava/lang/String;`) computed through the compiler's own JVM type mapping; null when not computable, never guessed |
| `kind` | string | `function`, `method`, `constructor`, `property`, `getter`, `setter`, `class`, `object`, `companion`, `interface`, `enum`, `sealed-class`, `data-class`, `annotation`, `typealias`, `extension-function`, `lambda`, `init` |
| `signature` | string? | normalised source signature |
| `returnType` | string? | declared return type (functions) or declared type (properties, typealias targets) |
| `extensionReceiverType` | string? | extension receiver |
| `visibility` | string | `public` (default), `private`, `internal`, `protected`; the resolved tier adds `package-private` (Java default visibility) and `local` |
| `modifiers` | string[] | `inline`, `suspend`, `operator`, `infix`, `expect`, `actual`, `external`, `abstract`, `open`, `override`, `const`, `tailrec`, plus factual extras (`data`, `sealed`, `value`, `inner`, `lateinit`, `companion`) |
| `annotations` | AnnotationEvidence[] | name + first const string argument |
| `overrides` | string[] | resolved tier: canonical names of every symbol this declaration overrides (empty at the syntax tier) |
| `supertypes` | string[] | resolved tier: canonical names of direct supertypes of class-like declarations, `kotlin.Any` elided (empty otherwise) |
| `position` | Position | 1-based line/column |
| `generated` | boolean? | null at the syntax tier |

## usages — LibraryUsage (cdxgen-critical)

| Attribute | Type | Purpose |
| --- | --- | --- |
| `id` | string | `use-000001...` |
| `name` | string | dotted callee text with argument lists elided: `stmt.executeQuery`, `a.b.c`, `ProcessBuilder`; operator calls use the Kotlin operator function name (`plus`, `contains`, `compareTo`, ...); callable references render `Receiver::name` |
| `simpleName` | string | last segment |
| `usageKind` | string | `call`, `operator`, `reference` |
| `modulePath`, `purl`, `filePath`, `position` | | occurrence |

Property accesses that are not calls are not emitted at the syntax tier.

## diagnostics — Diagnostic

| Attribute | Type | Purpose |
| --- | --- | --- |
| `code` | string | machine-readable; stable registry below |
| `severity` | string | `info`, `warning`, `error` |
| `message` | string | human explanation |
| `position` | Position? | when localisable |
| `count` | int? | aggregate counter |

Codes emitted by the syntax tier. The list is closed: `DiagnosticCodes` in
`kosi-schema` is the registry, `Diagnostic` rejects a code that is not in it,
and a corpus annotation naming an unregistered code is an annotation error
rather than a negative expectation that passes vacuously.

| code | severity | meaning |
| --- | --- | --- |
| `parse-error` | error | a file failed to parse; positions included |
| `syntax-backend-no-resolution` | info | states plainly that the tier resolves nothing and `resolvedCallRatio` is 0.0 by construction |
| `kotlin-language-version` | warning | declared language version below the band; clamped |
| `kotlin-version` | warning | declared language version above the ceiling; clamped |
| `kotlin-api-version` | warning | declared apiVersion above the language version; clamped |
| `no-build-files` | info | no Gradle/Maven build files; analysed as a plain source tree |
| `no-sources` | warning | no Kotlin/Java sources under the discovered roots |
| `unreadable-source` | error | file could not be read; also emitted with a `count` when the resolved tier's session would not open collected files that `files[]` still lists |
| `java-source-not-parsed` | warning | Java sources are in `files[]` but not parsed at the syntax tier; `count` is how many. Never emitted by the resolved tier, which parses Java PSI through the same symbols |
| `classpath-partial` | warning | the resolved tier could not build a complete classpath: offline resolution names every missing `group:artifact:version` coordinate (`count` is how many), and a missing JDK home is reported the same way |
| `resolution-errors` | warning | frontend resolution reported diagnostics in a file; `message` summarises per-checker counts, `count` is the total |
| `symbol-resolution-failed` | warning | symbol operations threw during resolution (`count` is how many); the affected declarations carry text-derived evidence only, so a wholesale resolution breakage cannot look like a clean report |
| `version-override` | info | an explicit `--language-version`/`--jvm-target` flag overrides a module's declared value; the message names both |
| `lowering-failed` | warning | the P2 lowering could not perform a construct (`count` is how many functions were affected); the message itemises the failures by construct next to the function count they were computed over, matching `stats.loweringFailures{}` and `stats.functionsLowered` |
| `callgraph-timeout` | warning | an `auto` callgraph fell back down the chain (vta -> rta -> sealed) after exceeding the deterministic work budget derived from `--callgraph-timeout`; the message names both the algorithm that gave up and the one that produced the graph |
| `callgraph-unresolved-calls` | warning | call sites that resolved to no callee and emit no edge (`count` is how many) |
| `callgraph-root-not-found` | warning | a declared root scope matched no function, so reachability starts nowhere for it |
| `fixpoint-cap` | warning | the P4 taint worklist hit its per-function iteration budget before converging (`count` is how many functions, out of `stats.functionsAnalysed`); the affected functions' slices are best-effort and flows a further round would have added are absent |
| `dataflow-truncated` | info | a dataflow limit shortened the analysis (`stats.truncations{}` itemises which: a function skipped for exceeding `--dataflow-max-function-instructions`, generated members skipped under `--dataflow-skip-generated`, or the `--dataflow-max-slices` cap reached) |

## stats

`fileCount`, `declarationCount`, `usageCount`, `importCount`,
`resolvedCallRatio` — 0.0 at the syntax tier (explained by
`syntax-backend-no-resolution`); at the resolved tier: explicit Kotlin calls
whose resolution produced symbols divided by all explicit calls, 0.0 when
there are no calls — with `callsTotal` and `callsResolved`, the denominator
and numerator it was computed from, published beside it: a 0.0 over 0 calls
and a 0.0 over 400 calls are the same number and opposite facts, so the ratio
is never published alone (the same rule as `sliceCount` beside
`connectivity`). Java sources contribute declarations but no calls, so the
ratio measures Kotlin call sites — `callsTotal` says how many there were —
plus `unknownCallPropagations` (resolved tier with `--dataflow` on: the calls
the engine had no pack entry for and propagated anyway per the default
`--unknown-call propagate` — counted per call where taint ACTUALLY moved, so
the conservative default's precision cost is a number; with the engine off it
is the call sites that resolved to no callee),
`loweringFailures{}` — itemised by
construct, published beside `functionsLowered`, the function count it was
computed over (a rate without its denominator is not a result) —
`fixpointCapHits` published beside `functionsAnalysed`, the function count the
taint worklist actually ran over (the same denominator rule) —
`sourceCount`/`sinkCount` are the source/sink SITES the model pack matched in
analysed code (not pack sizes; resolution regressions shrink them) —
`sliceCount`, `crossDependencySliceCount`, `reachableSliceCount`,
`truncations{}`,
`degraded` (`kotlin-version` when a version mismatch coincides with heavy
resolution fallout — never read such a report as facts about the code).

**Deliberate deviation from the v1 sketch, for the PR:** the
`analysisMillis{}` and `peakRssBytes` keys are NOT emitted. Embedding a
process's own timings inside an artifact whose contract is byte-identical
output makes the contract impossible to keep (golem/rusi ship byte-identical
reports and measure themselves out of band). Wall clock and peak RSS are
bench-harness metrics (`kosi bench` output), which is a measurement tool, not
a deterministic artifact.

## Pattern/annotation notation

One normalised form everywhere (02-ARCHITECTURE.md §7): dot-separated,
generic-free, whitespace-free symbol paths; a pattern matches a symbol when
the pattern's segments are a suffix of the symbol's segments
(`executeQuery` matches `stmt.executeQuery`; `Statement.executeQuery` matches
`java.sql.Statement.executeQuery`). Model packs (`models/*.json`) and corpus
annotations both use it; a build-time test fails the build when a shipped
pattern can never match any renderer output.

## callGraph — CallGraph (resolved tier, P3)

Published when `--backend resolved` runs and `--callgraph` is not `none`;
`null` otherwise (including every syntax-tier run, which resolves nothing
and therefore builds no graph). `mode` is the REQUESTED `--callgraph` mode;
`algorithmUsed` is what actually produced the graph (`vta`, `rta`, `sealed`,
`cha`, `static`) — `auto` runs vta and falls back down the chain (rta, then
sealed) on a deterministic work budget, recording every fallback as a
`callgraph-timeout` diagnostic in `callGraph.diagnostics`.

Reachability is computed on the COMPLETE graph; the `--include-stdlib` and
`--dependency-detail` options then shape the VIEW that `nodes[]`/`edges[]`
publish. A path a view filter cuts survives as one `collapsed` edge carrying
`collapsedHops` and `collapsedPackages` — it never silently vanishes
(`dependency-detail drop` is the exception a consumer chooses explicitly:
dependency nodes are dropped and paths through them are severed, by
definition of the option).

### callGraph.nodes[] — CallGraphNode

| Attribute | Type | Purpose |
| --- | --- | --- |
| `id` | string | `node-000001...`, stable for a given tree state |
| `name` | string | simple name |
| `qualifiedName` | string | `<relativePath>:<canonicalName>` |
| `canonicalName` | string | the join key (`pkg.Class.method`, `kotlin.io.println`) |
| `jvmDescriptor` | string? | erased descriptor when the resolved tier computed one; null never guessed |
| `kind` | string | `function`, `method`, `getter`, `setter`, `constructor` |
| `modulePath`, `purl`, `filePath` | string | attribution (empty for external nodes) |
| `local` | boolean | workspace function (every lowered function is a node, edges or not) |
| `stdlib` | boolean | `kotlin.*` / JDK callee |
| `external` | boolean | not workspace (stdlib or dependency) |
| `synthetic` | boolean | synthesized member (`copy`, `componentN`), attributed via the lowering |
| `suspend` | boolean | `suspend` function |
| `visibility` | string | `public`, `protected`, `internal`, `private`, `package-private`, `local`; `unknown` for external nodes |
| `ownerVisibility` | string? | enclosing class visibility; null for top-level functions and external nodes — a public member of an internal class is not public API, and `--roots exported` gates on this, so the field is on the node |
| `position` | Position? | declaration site; null for external nodes |

### callGraph.edges[] — CallGraphEdge

| Attribute | Type | Purpose |
| --- | --- | --- |
| `id` | string | `edge-000001...` |
| `sourceId`, `targetId` | string | caller -> callee; both always present in `nodes[]` |
| `callType` | string | `static` (dispatch-free: constructors, operators, extensions, top-level, private, final, object/companion/enum members), `receiver-typed` (single resolved dispatch target on an open owner, or a library leaf), `interface-cha` (open-hierarchy candidate set), `sealed-exact` / `sealed-bounded` (closed target set of a sealed hierarchy or enum), `lambda-inlined` (the retained evidence edge of a scope-function inlining), `collapsed` (a path a view filter cut, re-bridged), `framework-registered`, `override`, `higher-order`, `suspend`, `structured-concurrency`, `reflective`, `java-interop`, `external` (the last six are reserved vocabulary; each populating phase updates this line) |
| `line` | int | the call site's line (0 for synthesized and collapsed edges) |
| `method` | string? | callee simple name |
| `candidateCount` | int? | dispatch target count when the site had more than one |
| `collapsedHops` | int? | present on `collapsed` edges: edges traversed through the omitted region |
| `collapsedPackages` | string[]? | distinct packages traversed, sorted |

### callGraph.reachability[] — ReachabilityEntry

| Attribute | Type | Purpose |
| --- | --- | --- |
| `nodeId` | string | one entry per view node |
| `reached` | boolean | reachable from any declared root |
| `distance` | int | BFS distance on the complete graph; -1 when unreached |
| `roots` | string[] | the root SCOPES (`main`, `exported`, `handlers`, `symbol:...`) from which the node is reachable |

Root scopes: `main` (top-level `main`), `exported` (the public API: local,
non-synthetic, visibility public/protected, in a class that is itself
public/protected), `handlers` (RESOLVED framework annotation FQNs on the
function or its class — type-resolved, never name-matched), `tests`
(test-source-set files), `android` (Android component supertypes), `all`,
`symbol:<regex>`. A scope that matches nothing emits
`callgraph-root-not-found`.

### callGraph.stats

The four-way breakdown, a DISJOINT partition (synthetic first, then local,
then stdlib, then dependency; edges classify by target): `localNodes`,
`stdlibNodes`, `dependencyNodes`, `syntheticNodes`, and the same four for
edges. The parts sum to the totals — the promotion gate checks that.

### --reachable-symbols <file> (sidecar)

`--reachable-symbols` writes shortest witness paths for every reached symbol
(JSON; `--max-paths-per-symbol` paths per symbol, default 3, one per root
scope that reaches it): `{"maxPathsPerSymbol":3,"symbols":[{"canonicalName":
...,"nodeId":...,"paths":[{"root":<nodeId>,"edges":[<edgeId>...]}]}]}`. Every
edge id exists in the report and the walk is connected — the same invariant
the connectivity gate checks, published for consumers.

## dataFlow — DataFlowEvidence (resolved tier, P4)

Published when `--backend resolved` runs and `--dataflow` is not `none`
(default `security`); `null` at the syntax tier, which has no KIR and no flow
engine (docs/KOSI.md defect 1). The P4 engine is INTRAPROCEDURAL, field-
sensitive taint over each lowered function's CFG, iterated with a worklist to
a real fixpoint (`kosi-flow`, compiler-free). `--dataflow reachable`
additionally intersects the slices with the call graph's reachability from the
declared roots and sets `reachableFromRoots` on the survivors;
`--dataflow crypto` and `--dataflow all` run the same pack today (the crypto
collector's own model arrives with P8); `security-deps` behaves as `security`
until P9.

Everything that decides a category is DATA: the shipped model pack
(`kosi-models/resources/models/security-pack-v0.json`, merged with user packs
via `--patterns` when that flag lands). The engine hard-codes no rule about
categories. Pack argument-index convention: `0` is the RECEIVER when the
callee has one, otherwise the first argument; `n` is the n-th element of that
`(receiver,) arguments` sequence; `-1` is the call's result. Constructor
callees render as the class FQN with no `<init>` suffix, so a constructor's
first parameter is index 0.

### dataFlow.slices[] — FlowSlice

| Attribute | Type | Purpose |
| --- | --- | --- |
| `id` | string | `slice-000001...`, ordered by source then sink site |
| `sourceId`, `sinkId` | string | both always present in `nodes[]` |
| `sourceName`, `sinkName` | string | callee FQNs matched from the pack |
| `sourceFunction`, `sinkFunction` | string | the one function both ends live in (intraprocedural) |
| `sourceCategory`, `sinkCategory` | string | pack categories (independent: `untrusted-input` can reach `log-injection`) |
| `taintKinds` | string[] | the categories travelling on the trace |
| `nodeIds[]`, `edgeIds[]` | string[] | the trace: `edgeIds` form a connected walk from source to sink (asserted on every slice by `kosi golden` and the promotion gate) |
| `pathLength` | int | `edgeIds.size` |
| `elided` | boolean? | true when the trace cap (`--dataflow-max-trace-nodes`) cut the MIDDLE of the walk; the endpoints survive and an `elided`-kind edge keeps the walk connected |
| `sanitizerNodeIds` | string[] | reserved for sanitizer-aware traces |
| `sinkArgumentIndex` | int | which sink argument was tainted (the pack convention above) |
| `accessPath` | string | the tainted register (and path suffix) at the sink, `base::field` form |
| `crossesModule`, `crossesDependency` | boolean | false at P4 by construction; the gate fails any slice claiming otherwise |
| `reachableFromRoots` | boolean | `--dataflow reachable` only |
| `ruleId`, `ruleName`, `description`, `severity`, `confidence`, `riskScore` | | `severity` comes from the matched SINK PACK ENTRY (severity as data), `confidence` is `high` for pack-matched (resolved) sites, `riskScore` derives from severity |
| `flowKey` | string | SHA-256 over the flow's endpoints and trace — stable across runs for suppression |

Invariants asserted by `kosi golden` and the promotion gate on every slice:
`sourceId ∈ nodeIds`, `sinkId ∈ nodeIds`, `edgeIds` form a connected walk
source -> sink, and `ruleId`/`severity`/`confidence`/`riskScore`/`flowKey` are
non-empty.

### dataFlow.nodes[] / edges[] — FlowNode / FlowEdge

One node per trace program point (deduplicated across slices, ids assigned
after sorting by file/line/kind/name): `kind` is `source`, `sink`, or the
propagation role (`call`, `concat`, `field`, `index`, `assign`, `phi`,
`elvis`, `new`, `propagate`). Edges (`dfe-...`) are deduplicated by
`(sourceId, targetId, kind)`; kind `elided` marks a cap-cut walk.

The endpoints are guaranteed: `sourceId` always names a node of kind
`source` and `sinkId` a node of kind `sink`. When the backward walk cannot
reach the source — the trace cap, a cycle, or a transfer that moved a fact
without recording provenance — the source is prepended and the slice is
marked `elided` rather than published as a shorter complete trace (R54).

### dataFlow.stats

`sliceCount`, `uniqueFlows` (distinct `flowKey`s), `crossDependencySlices`,
`reachableSlices`, `connectivity` (fraction of slices whose walk is
connected; 1.0 is the gate — but note it walks the edge list built from the
trace's own consecutive nodes, so it is 1.0 by construction and catches only
an id-assignment defect), `integrityViolations` (slices failing any
invariant, including the endpoint-kind check that `connectivity` cannot see;
0 is the gate, and this is the one with teeth). Both counts are computed from
the emitted slices; `crossDependencySlices` in particular is counted, never
written as a constant the gate then reads back (R55). `summariesComputed`/`summariesByOrigin{}` (empty at P4 — computed
interprocedural summaries are P5; `origin` is how a reviewer tells a computed
summary from blanket propagation).

### dataFlow.patterns — ModelPackRef

The effective pack: `builtin` names, `user` names, and the five entry counts
(`sourceCount`, `sinkCount`, `passthroughCount`, `sanitizerCount`,
`effectCount`). These are PACK sizes — the matched SITES in code are
`stats.sourceCount`/`stats.sinkCount`.

## Later-phase sections

`crypto`, `apiEndpoints`, `services`, `urls` and
`securitySignals` are part of the v1 envelope now (emitted empty or null) so
consumers can rely on the shape; their population is phase work and each
populating phase updates this document in the same PR. `dataFlow` is
populated as of P4 (above).
