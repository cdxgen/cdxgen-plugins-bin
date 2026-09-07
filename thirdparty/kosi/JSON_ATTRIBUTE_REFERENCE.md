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
`progressive`, `optIn`, `multiplatformTarget`, `pretty`, `format`.
Phase 0 accepts `--backend syntax` only; other tiers are usage errors, not
silent degrades.

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
| `language` | string | `kotlin` or `java` (Java is evidence-only at the syntax tier) |
| `generated` | boolean | false at the syntax tier; build/output trees are excluded outright |

## imports — ImportUsage

| Attribute | Type | Purpose |
| --- | --- | --- |
| `name` | string | imported FQN, backtick-free (`kotlin.io.println`); `star` marks wildcard |
| `alias` | string? | `import ... as x` |
| `star` | boolean | wildcard import |
| `purl` | string? | resolved purl (null at the syntax tier) |
| `filePath`, `position` | | occurrence |

## declarations — Declaration

| Attribute | Type | Purpose |
| --- | --- | --- |
| `id` | string | `dec-000001...`, stable for a given tree state |
| `name` | string | simple name |
| `qualifiedName` | string | `<modulePath>:<pkg>.<containers>.<name>` — rooted at the module so `commonMain` and `androidMain` actuals are distinguishable |
| `canonicalName` | string | generic-free, hash-free, backtick-free join key |
| `jvmOwner`, `jvmDescriptor` | string? | null until the resolved tier |
| `kind` | string | `function`, `method`, `constructor`, `property`, `getter`, `setter`, `class`, `object`, `companion`, `interface`, `enum`, `sealed-class`, `data-class`, `annotation`, `typealias`, `extension-function`, `lambda`, `init` |
| `signature` | string? | normalised source signature |
| `returnType` | string? | declared return type (functions) or declared type (properties, typealias targets) |
| `extensionReceiverType` | string? | extension receiver |
| `visibility` | string | `public` (default), `private`, `internal`, `protected` |
| `modifiers` | string[] | `inline`, `suspend`, `operator`, `infix`, `expect`, `actual`, `external`, `abstract`, `open`, `override`, `const`, `tailrec`, plus factual extras (`data`, `sealed`, `value`, `inner`, `lateinit`, `companion`) |
| `annotations` | AnnotationEvidence[] | name + first const string argument |
| `overrides` | string[] | empty until resolution exists |
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
| `unreadable-source` | error | file could not be read |
| `java-source-not-parsed` | warning | Java sources are in `files[]` but not parsed at this tier; `count` is how many |

## stats

`fileCount`, `declarationCount`, `usageCount`, `importCount`,
`resolvedCallRatio` (0.0 at the syntax tier, explained by a diagnostic),
`unknownCallPropagations`, `loweringFailures{}`, `fixpointCapHits`,
`sourceCount`, `sinkCount`, `sliceCount`, `crossDependencySliceCount`,
`reachableSliceCount`, `truncations{}`, `degraded`.

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

## Later-phase sections

`callGraph`, `dataFlow`, `crypto`, `apiEndpoints`, `services`, `urls` and
`securitySignals` are part of the v1 envelope now (emitted empty or null) so
consumers can rely on the shape; their population is phase work and each
populating phase updates this document in the same PR.
