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
| `securitySignals` | SecuritySignal[] | non-flow findings (not yet populated) | findings UIs |
| `crypto` | CryptoEvidence | CBOM evidence | CBOM |
| `callGraph` | CallGraph? | null until a call-graph mode runs | reachability |
| `dataFlow` | DataFlowEvidence? | null until taint runs | slices |
| `apiEndpoints` | ApiEndpoint[] | inbound endpoints | SaaSBOM |
| `services` | ServiceRef[] | outbound deps | services[] |
| `urls` | UrlEvidence[] | URL/host/JDBC strings | URL identification |
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
`pretty`, `format`, plus the flags: `deps` (`--deps`: the
dependency-jar tier — implied by `--dataflow security-deps`),
`depsMaxClasses` (the tier's class budget, 500), `maxAnalysisSeconds`
and `maxRssMb` (budgets; `null` = off — an absent key IS off — a
tripped budget degrades the run with a named diagnostic and the partial
report still ships).
An explicit `--classpath`/`--classpath-file` replaces offline resolution
entirely (02-ARCHITECTURE.md §3 acquisition order); otherwise the resolved
backend scans build files as text and locates coordinates in the local
Gradle/Maven caches and `build/libs`. `--jdk-home` names the JDK module; without
it kosi tries the running JVM's `java.home`, then `JAVA_HOME`, then the
`java` launcher on `PATH`, then the conventional install roots, and accepts
a macOS bundle directory in place of the `Contents/Home` inside it. The
chain past `java.home` is what a NATIVE binary depends on — an image has no
`java.home` — and a run that reaches the end of it is tagged
`stats.degraded = "no-jdk"`, because a resolved tier with no JDK resolves
every `java.*` symbol to nothing. Unknown flags are a usage error, never a
silent degrade.

**Which option values travel.** The report records every effective
option verbatim — reproduction needs the real jar paths and JDK home. The
DIGEST goldens are the consumer that cannot: `classpath` entries and
`jdkHome` are absolute by construction when set, and an explicitly absolute
`classpathFile` names one machine just as much. At the digest boundary
(`Digests.compute`) each ABSOLUTE path value among those three members
enters as the fixed marker `<absolute-path>`, so two environments running
the same slot set with their own absolute pins digest equal, while setting
such an option still differs from leaving it unset and a relative value
(a committed pin like `classpath.txt`) stays digested as given. The golden
gate's in-run portability comparison digests `options` RAW on purpose: a
report whose own bytes name their location is not portable, whatever the
digest would tolerate.

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
| `source-coverage-gap` | warning | discovery collected under half of the ≥20 NON-TEST Kotlin/Java files present under the analysed root (`stats.sourceCoverage{}` carries both ratios) — modules outside the Maven/Gradle source-root convention may be missing from every downstream result |
| `classpath-strategy-conflict` | error | a forced `--classpath-strategy` contradicts the explicit classpath flags (refused before the run) |
| `unreadable-source` | error | file could not be read; also emitted with a `count` when the resolved tier's session would not open collected files that `files[]` still lists. also names a file whose text the platform's file-type layer classified as plain text (a file of several MB), so it cannot be parsed as Kotlin |
| `psi-depth-cap` | warning | a file's syntax nests deeper than the 2,000-level walk budget, so its recursive walks (declarations, usages, KIR lowering) were NOT run; the file stays in `files[]`, everything derived from walking its syntax is absent, and the message names the file and its measured depth (`count` 1 per file). The budget and the measurements behind it are in the report; the dataflow tier also counts a `stack-overflow` truncation in `stats.truncations{}` if the engine itself ever overflows |
| `stack-overflow-skipped` | error | analysing this file (or, in the dataflow tier, this function) threw `StackOverflowError`; the unit was skipped, the run completed for every other file, and the message names it. Previously, the same error took the whole report down |
| `java-source-not-parsed` | warning | Java sources are in `files[]` but not parsed at the syntax tier; `count` is how many. Never emitted by the resolved tier, which parses Java PSI through the same symbols |
| `classpath-partial` | warning | the resolved tier could not build a complete classpath: offline resolution names every missing `group:artifact:version` coordinate (`count` is how many), and a missing JDK home is reported the same way |
| `resolution-errors` | warning | frontend resolution reported ERROR-severity diagnostics in a file; `message` summarises per-checker counts, `count` is the total. only ERROR-severity factories count (warning-severity ones like DEPRECATION used to be included, drowning the signal), and the bundled corpus entries ratchet their fixtures' error classes via corpus.toml `tolerated_resolution_errors` — an undeclared class fails the row (a stub that stopped typechecking passed every want) |
| `symbol-resolution-failed` | warning | symbol operations threw during resolution (`count` is how many); the affected declarations carry text-derived evidence only, so a wholesale resolution breakage cannot look like a clean report |
| `version-override` | info | an explicit `--language-version`/`--jvm-target` flag overrides a module's declared value; the message names both |
| `lowering-failed` | warning | the lowering could not perform a construct (`count` is how many functions were affected); the message itemises the failures by construct next to the function count they were computed over, matching `stats.loweringFailures{}` and `stats.functionsLowered` |
| `callgraph-timeout` | warning | an `auto` callgraph fell back down the chain (vta -> rta -> sealed) after exceeding the deterministic work budget derived from `--callgraph-timeout`; the message names both the algorithm that gave up and the one that produced the graph |
| `callgraph-unresolved-calls` | warning | call sites that resolved to no callee and emit no edge (`count` is how many) |
| `callgraph-root-not-found` | warning | a declared root scope matched no function, so reachability starts nowhere for it |
| `fixpoint-cap` | warning | the taint worklist hit its per-function iteration budget before converging (`count` is how many functions, out of `stats.functionsAnalysed`); the affected functions' slices are best-effort and flows a further round would have added are absent |
| `dataflow-truncated` | info | a dataflow limit shortened the analysis (`stats.truncations{}` itemises which: a function skipped for exceeding `--dataflow-max-function-instructions`, generated members skipped under `--dataflow-skip-generated`, or the `--dataflow-max-slices` cap reached) |
| `summary-iteration-cap` | warning | the summary fixpoint's SCC hit its iteration budget before its members' summaries converged; the last iterate is what callers applied (labelled `origin=recursive-approx`), and `stats.sccIterationCapHits` names how many out of `stats.sccsProcessed` |
| `dispatch-join-width` | info | a virtual call site joined more dispatch-target summaries than the width budget; the full JOIN was applied and precision may suffer where the targets disagree; the histogram is `dataFlow.stats.dispatchJoins{}` |
| `taint-unnameable-invoke` | info | call sites where what runs is a function VALUE the engine could not name — a `FunctionN.invoke` whose receiver holds no traceable body, or a call on an interface neither the workspace nor the `--deps` tier resolves. Taint STOPS at each one, so an absent flow through them means unexamined, not clean. A site the engine DOES name is never counted, even when it moved nothing: a named callee with no live facts is an ordinary clean result, and a function-valued PARAMETER is named by the caller (its failures are `lambda-unresolved`). `count` and `stats.unnameableInvokes` are the same number, counted once per site |
| `lambda-unresolved` | info | a lambda value (callable reference, local function) could not be resolved to an extracted body, so no summary was applied through it (`count` is how many) |
| `deps-bodyless` | info | `--deps`: body-less dependency records (abstract, interface, native, stripped) were counted and EXCLUDED from the tier — an empty body is indistinguishable from a no-op, so none was ever summarised as "no flow" |
| `deps-class-not-found` | info | workspace calls name classes absent from every classpath jar; their summaries cannot be computed (`count` is how many calls, first ten named) |
| `deps-class-limit` | warning | the `--deps-max-classes` budget capped the LOWERED dependency set; `count` is the number of selected classes CUT (named, first few in the message), never a silent zero of the tier; the budget bounds the LOWERED set, not the selection |
| `bytecode-unlowered` | warning | constructs the bytecode lowering declined, itemised in the message and merged into `stats.loweringFailures{}` under `bytecode:` keys; every affected method is treated as body-less and excluded, never summarised from a half-body |
| `analysis-time-budget` | warning | the `--max-analysis-seconds` budget tripped; the run degraded WITHOUT discarding computed evidence (`count` is functions skipped after the trip) |
| `rss-budget` | warning | the `--max-rss-mb` budget tripped; same degradation contract |
| `callgraph-failed` | error | the call graph crashed and is ABSENT from the report — named as such while the already-computed evidence still ships; never swallowed into a green result |
| `compile-backend-gap` | warning | `--backend compile` is a declared gap — kosi cannot execute the analysed build offline for generated sources, so the report is the RESOLVED tier's and no generated declaration appears in it |

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
`unnameableInvokes` — call sites invoking a function VALUE the engine could
not name, where taint stops; a zero here is what makes a zero `sliceCount`
mean "nothing found" rather than "nothing followed". It counts only sites
nothing named: not a named callee that moved no facts, not a
function-valued parameter the caller resolves, and not a call the `--deps`
tier answered — so the number does not contradict the flows published beside
it. It is environment-sensitive in one direction: JDK attachment changes how
many `java.*` receivers resolve, so treat repo-level totals as +/- environment —
`sliceCount`, `crossDependencySliceCount`, `crossModuleSliceCount`,
`reachableSliceCount`, `sccsProcessed` beside `sccIterationCapHits` (the summary fixpoint's population and its cap count — a cap without its
population is not a result), `suspendCrossingSliceCount` (slices whose
source and sink are separated by a suspend boundary),
`truncations{}`,
`bodylessRecords` (dependency records with no body — excluded from the
tier entirely, the population every dependency denominator excludes),
`dependencyClasses` / `dependencyFunctions` (classes lowered from jars
and methods lowered WITH bodies — the tier's denominators),
`degraded` (`no-jdk` when the resolved tier ran with no JDK attached, so
every `java.*` symbol resolved to nothing; `kotlin-version` when a version
mismatch coincides with heavy resolution fallout — never read such a
report as facts about the code. `no-jdk` is the tag to check on a native
binary in particular: it has no `java.home` of its own and falls back to
`JAVA_HOME`, the `java` launcher on `PATH`, and the conventional install
roots, in that order, before giving up),
`classpath{}` (the acquisition record — `strategy` names the ONE
strategy that produced the attached classpath or `none` when nothing
attached, `entries` counts the attached jars, `missing` the coordinates a
fired strategy could not locate, and `attempts[]` records every strategy
the chain tried with whether it fired; the vocabulary is
`explicit|file|jars|cache|none`, forced with `--classpath-strategy`. A
classpath-less run and a run that found nothing are the same sparse graph
and opposite facts), and
`sourceCoverage{}` (`discovered` against `present` — files[] against
the same extensions under the analysed root under the collector's own
exclusion policy — plus `testPresent`, how many of those sit under a test
directory, and two ratios. `ratio` is `discovered/present`, what is on
disk; `nonTestRatio` divides by the non-test files only, which is what
DISCOVERY can be judged against, because a source root is a MAIN source
root and test files are present-but-not-sought. A repository with a large
test suite would otherwise be indistinguishable from one whose modules were
dropped, and those are opposite facts. The `source-coverage-gap` diagnostic
reads `nonTestRatio`: less than half of ≥20 present non-test files).

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

## callGraph — CallGraph (resolved tier)

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
| `callType` | string | `static` (dispatch-free: constructors, operators, extensions, top-level, private, final, object/companion/enum members), `receiver-typed` (single resolved dispatch target on an open owner, or a library leaf), `interface-cha` (open-hierarchy candidate set), `sealed-exact` / `sealed-bounded` (closed target set of a sealed hierarchy or enum), `lambda-inlined` (the retained evidence edge of a scope-function inlining), `collapsed` (a path a view filter cut, re-bridged), `framework-registered`, `override`, `higher-order`, `suspend`, `structured-concurrency`, `reflective`, `java-interop`, `external` (the last six are reserved vocabulary; this line is updated as each is populated) |
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

### --sarif-out <file> (sidecar)

SARIF 2.1.0 export of `dataFlow.slices[]`: one RULE per slice rule id, one
RESULT per slice — the sink is the result location, the trace is the
RELATED LOCATIONS in walk order, and the same walk renders as a `codeFlow`.
Slice properties (`flowKey`, `taintKinds`, `origins`, `confidence`,
`riskScore`, `crossesDependency`) ride `result.properties`. Usage error (not
an empty file) when the run produced no data-flow evidence.

### --reachable-symbols <file> (sidecar)

`--reachable-symbols` writes shortest witness paths for every reached symbol
(JSON; `--max-paths-per-symbol` paths per symbol, default 3, one per root
scope that reaches it): `{"maxPathsPerSymbol":3,"symbols":[{"canonicalName":
...,"nodeId":...,"paths":[{"root":<nodeId>,"edges":[<edgeId>...]}]}]}`. Every
edge id exists in the report and the walk is connected — the same invariant
the connectivity gate checks, published for consumers.

## dataFlow — DataFlowEvidence (resolved tier)

Published when `--backend resolved` runs and `--dataflow` is not `none`
(default `security`); `null` at the syntax tier, which has no KIR and no flow
engine (defect 1 in the change tracker). The engine is field-sensitive taint over each
lowered function's CFG, iterated with a worklist to a real fixpoint
(`kosi-flow`, compiler-free), plus the interprocedural summaries: bottom-up
over the call graph's SCC condensation, applied at call sites AFTER the pack
(in pack, then computed summary, then `--unknown-call` default order) and
joined per dispatch target under the run's `--callgraph` mode. The engine routes
coroutine builders through the same machinery: `launch`/`async`/
`withContext`/`runBlocking`/`LaunchedEffect` and the flow operators inline
their lambda bodies at LOWERING time (the body's taint is the caller's),
`emit`/`send` assign into the builder's value register, and
`Deferred.await` / `Channel.receive` are pack passthroughs (receive reads the
channel's ELEMENT state). A suspend boundary is transparent to the analysis —
suspension does not launder taint — and `stats.suspendCrossingSlices` counts
the slices whose trace crosses one. `--dataflow reachable` additionally
intersects the slices with the call graph's reachability from the declared
roots and keeps only the survivors (their `pathKind` is unchanged — the
intersection IS the reachability fact; `stats.reachableSlices` equals
`sliceCount` there); `--dataflow crypto` and `--dataflow all` run the same
pack today; `security-deps` behaves as `security` unless `--deps` is in effect.

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
| `sourceFunction`, `sinkFunction` | string | the function each END lives in — two different functions (and modules) for an interprocedural slice |
| `sourceCategory`, `sinkCategory` | string | pack categories (independent: `untrusted-input` can reach `log-injection`) |
| `sourceParameter` | string? | for a slice that entered through an endpoint HANDLER's parameter, the value-parameter it entered through — `#0` is the first non-receiver parameter. `null` for every other birth. Before this field an endpoint-rooted slice could say "this handler is reachable from untrusted input" but never WHICH input |
| `sourceTransport` | string? | the transport that parameter's annotation names — `path`, `query`, `header`, `cookie`, `form`, `body` (the endpoints pack's `parameterAnnotations[].kind`). `null` when the handler (or framework) names no annotation for it |
| `taintKinds` | string[] | the categories travelling on the trace |
| `nodeIds[]`, `edgeIds[]` | string[] | the trace: `edgeIds` form a connected walk from source to sink (asserted on every slice by `kosi golden` and the promotion gate) |
| `pathLength` | int | `edgeIds.size` |
| `elided` | boolean? | true when the walk was cut — the trace cap (`--dataflow-max-trace-nodes`), a summary whose composed path was stabilized (`pathKind` is then `partial`); the endpoints survive and an `elided`-kind edge keeps the walk connected |
| `pathKind` | string | what the slice's trace IS — `complete` (a full source→sink walk), `partial` (the walk was elided; endpoints guaranteed, the middle cut), `symbol-only` (no provable path; the finding stands on the symbol match alone — measured population zero on the whole corpus today, reserved so the vocabulary is closed). Replaces `reachableFromRoots` (false in every shipped slot, true by construction in the one mode that published it — the mode, not the slice, carried the information) and `rootWitness` (null everywhere). The depth report's reachability table reads this field |
| `frames[]` | object[] | the trace as named hops — ordered `(function, file, line, role)`, source first, sink last, one per hop the VALUE took (callee-internal hops splice in at every summary boundary, so a six-frame chain names all six). `role` is from the closed vocabulary `FrameRole`: `source`, `move`, `call`, `return`, `dispatch`, `summary`, `sanitizer-not-applied`, `sink`. `dispatch` frames carry the per-hop evidence `dispatchWidth` (targets considered), `dispatchTargets[]` (applied) and `dispatchNarrowedBy`, the closed narrowing vocabulary: `single-impl` (the interface has one implementation), `vta` (the receiver's construction type), `di-binding` (the survivors are all container-managed and something was dropped — an interface with three implementations and ONE Spring/Hilt/CDI binding is not an interface with one implementation, and the two are different evidence), or absent when nothing narrowed. Empty only where `pathKind` is `symbol-only` (no walk, no hops to name). The corpus reads this list for the deep tier's `frames=N` and `via=fn:...` expectations; cdxgen renders it as `callstack` evidence |
| `framesCutBy` | string? | when the frame list is not the whole walk, the cap that cut it (today `trace-nodes`) — the frame-list form of the PARTIAL contract. `null` on a complete list |
| `kind` (nodes) | string | `source`, `sink`, or the propagation role — now including `suspend` (a coroutine boundary the trace crosses) |
| `sanitizerNodeIds` | string[] | reserved for sanitizer-aware traces |
| `sinkArgumentIndex` | int | which sink argument was tainted (the pack convention above) |
| `accessPath` | string | the tainted register (and path suffix) at the sink, `base::field` form |
| `crossesModule`, `crossesDependency` | boolean | computed from the slice ENDS: the source and sink functions' module paths and purls — true exactly when those differ |
| `origins[]` | string[] | sorted distinct summary origins the trace crossed at interprocedural boundaries: `computed`, `pack`, `default`, `recursive-approx`. `pack` on a source birth is provenance, not a boundary; the default-origin gate counts BOUNDARY origins (`default`/`computed`/`recursive-approx`) only |
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
marked `elided` rather than published as a shorter complete trace.

### crossesDependency vs crossesModule

The two flags answer different questions and are computed from different
facts. `crossesModule` compares the two slice ENDS' module paths (a
multi-module workspace crossing). `crossesDependency` is set when the
TRACE enters a real external jar — a purl the `--deps` tier was lowered
from — and stays `false` for a slice that only crosses workspace modules,
however many purls differ between its ends. Trace nodes carried in from a
jar keep the jar's purl and a `jar-name!class/path` filePath; they are not
workspace files and are not attributed to any module.

### dataFlow.stats

`sliceCount`, `uniqueFlows` (distinct `flowKey`s), `crossDependencySlices`,
`crossModuleSlices`, `reachableSlices`, `connectivity` (fraction of slices
whose walk is connected; 1.0 is the gate — but note it walks the edge list
built from the trace's own consecutive nodes, so it is 1.0 by construction
and catches only an id-assignment defect), `integrityViolations` (slices
failing any invariant, including the endpoint-kind check that `connectivity`
cannot see; 0 is the gate, and this is the one with teeth). All counts are
computed from the emitted slices; nothing here is a constant a gate reads
back. Also:
`summariesComputed`/`summariesByOrigin{}` — the summary table's size by
origin (`computed`, `pack`, `recursive-approx`); `summaryCrossingSlices` —
slices whose trace crossed at least one summary BOUNDARY;
`defaultOriginSlices` — those whose boundary origins are ALL `default`
(blanket propagation carried them); `dispatchJoins{}` — the histogram of
dispatch-join widths at virtual sites; `suspendCrossingSlices` — slices
whose trace crosses a suspend boundary. Also:
`bytecodeSummaries` — dependency summaries (origin `bytecode`) that a
workspace call site actually applied with a taint move — the gate's
producer-named numerator, never a count of every jar function summarised;
`crossDependencyBytecodeSlices` — slices whose trace enters a jar the tier
lowered AND whose boundary origins carry `bytecode`. Also:
`maxObservedDepth` — the deepest named-hop count any published slice
carries ("how deep does kosi actually go" as a report field, not a review
anecdote); `depthHistogram{}` — slice count by frame count, exact buckets;
`dispatchWidthHistogram{}` — targets CONSIDERED per virtual hop,
pre-narrowing (where `dispatchJoins{}` counts APPLIED summaries — both
stay because the bench reads the old one); `truncations{}` — every dataflow
cap that bound the run, by published name, with its cut count. Empty
`truncations{}` is the claim "no cap bound", which is what the deep tier's
gate asserts. Narrowing modes (`reachable`, `crypto`) recompute the depth
measurements from the surviving slices and leave the run-level
`dispatchWidthHistogram`/`truncations` alone.

### dataFlow.summaries[] — FlowSummary

One entry per workspace function the summary fixpoint ran over (origin
`computed`, or `recursive-approx` when its SCC hit the iteration budget),
plus one per pack entry that actually moved taint at a call site (origin
`pack`, shaped by the pack entry itself), plus — under `--deps` — one per
dependency summary a workspace call site actually applied (origin
`bytecode`: a fixpoint over a jar's lowered body; the tier's approximation
state stays visible in `stats.sccIterationCapHits` over `stats.sccsProcessed`).
Parameter ids are `p<i>` over the
function's parameter list (dispatch receiver first when present).

| Attribute | Type | Purpose |
| --- | --- | --- |
| `functionId`, `function` | string | the function's canonical name (or the pack entry's pattern for pack-origin summaries) |
| `parameterNames[]`, `parameterTypes[]` | string[] | the parameter list the `p<i>` ids index |
| `paramToReturn[]` | string[] | parameters whose taint reaches the return value |
| `paramToReturnFields[]` | string[] | parameter-object FIELDS reaching the return's same field, as `p<i>.<suffix>` — `fun get(raw: String) = Session(token = raw)` publishes `p1.token`: the callee stored the argument into the returned object's field, and the caller reads it back off the result |
| `sourceFieldWrites[]` | string[] | taint born at a source INSIDE the callee and stored into parameter i's object, as `p<i>.<suffix>:<category>` — after the call, the caller's argument carries the write (`fun taint(job: Job) { job.command = readLine() }`) |
| `invokes[]` | string[] | what the body passes when it invokes a function-valued parameter — `p<j>(arg<k>)<-p<i>` (my parameter i's taint) or `p<j>(arg<k>)<-source:<category>` (a source born in me). This is the channel that lets a passed lambda's body consume taint that never leaves the callee |
| `paramToParam[]` | string[] | write effects `p<i>->p<j>` (parameter i's taint lands on parameter j) |
| `paramToReceiver[]` | string[] | parameters whose taint is stored into the receiver |
| `paramToSink{}` | map<string, int[]> | parameter -> argument indexes of the sinks it reaches inside the callee |
| `sourceReturns[]` | string[] | categories born at a source call inside the body and returned |
| `sanitizes[]` | string[] | categories a pack sanitizer inside the body clears |
| `accessPaths{}` | map<string, string> | parameter -> the receiver access-path suffixes its taint is written to (`\|`-separated) |
| `origin` | string | `computed` (a real fixpoint over the body), `pack` (a pack entry supplied the effect), `bytecode` (a fixpoint over a dependency jar's lowered class file), `recursive-approx` (the workspace SCC hit its iteration budget; last iterate), `default` (the `--unknown-call` fallback at a call site, no body seen) |

A higher-order note: a lambda VALUE passed to a workspace callee is itself
summarised (the lowering extracts the body; `KirLambda.captures` name the
enclosing registers bound at application time). A `summary-iteration-cap`
diagnostic names SCCs that hit the budget; a `dispatch-join-width`
diagnostic names virtual sites whose join exceeded the width budget; a
`lambda-unresolved` diagnostic names lambda values (callable references,
local functions) with no extractable body.

### dataFlow.patterns — ModelPackRef

The effective pack: `builtin` names, `user` names, and the five entry counts
(`sourceCount`, `sinkCount`, `passthroughCount`, `sanitizerCount`,
`effectCount`). These are PACK sizes — the matched SITES in code are
`stats.sourceCount`/`stats.sinkCount`.

## apiEndpoints — ApiEndpoint (resolved tier)

Inbound entry points, one object per route/component. `framework` is a
closed vocabulary (the shipped `endpoints-pack-v0.json` ids: `spring-mvc`,
`spring-webflux`, `ktor`, `micronaut`, `quarkus`, `http4k`, `grpc`,
`android`); `foundBy` names HOW the endpoint was found — `annotation`
(a mapping annotation at its resolved fqn), `dsl` (a routing call, the
handler resolved to the extracted lambda body), or `manifest` (an Android
component). The framework match is on RESOLVED type identity: an
annotation the front end could not resolve is never treated as the
framework's, which is what keeps a homonym annotation from becoming an
endpoint.

| Attribute | Type | Notes |
| --- | --- | --- |
| `id` | string | `ep-NNNNNN`, assigned after sorting |
| `framework` | string | pack vocabulary, above |
| `httpMethod` | string[] | empty for RPC and for methods left open (`@RequestMapping` without a method). **Naming quirk, deliberate:** the JSON key is SINGULAR (`httpMethod`) while it holds an ARRAY — the internal schema field is `httpMethods`. This mismatch already cost cdxgen every verb (its collector read the plural key and got `undefined`, since fixed), and the singular key is now load-bearing for the cdxgen join and its OpenAPI naming convergence, so it stays. Consumers must read `httpMethod` and expect a list. |
| `pathTemplate` | string | class-level prefixes composed (`/admin` + `/users`); Android uses the action or component name; gRPC uses `/<Service>/<Method>` |
| `pathParameters` | string[] | `{id}` template parameters |
| `handlerSymbol` / `handlerCanonicalName` | string | the canonical name of the handler; EMPTY when no handler could be named — an Android component that declares no lifecycle override of its own, so the framework's is what runs. The resolved-handler gate counts empty as unresolved. Empty does NOT mean the component went unread: see `substantiated` |
| `substantiated` | boolean | whether kosi READ the code behind this endpoint. `true` by construction for annotation and DSL endpoints — they exist because a declaration was read. For a manifest component it is true exactly when the component's CLASS is among the analysed declarations, matching `Outer$Inner` and `Outer.Inner` as the one class they are. `false` says "the manifest declares this attack surface and kosi read none of it" — a library component, or a run that discovered none of the sources — and is counted in the `endpoint-unsubstantiated` diagnostic. A published endpoint is never a claim about behaviour that was not read |
| `exported`, `permissions`, `deepLinkHosts` | Android only | from the manifest; `exported` falls back to the intent-filter rule |
| `reachableSources` | string[] | the source categories the handler introduces (`untrusted-input` under `--endpoint-sources` when a flow enters here) |
| `sliceIds` | string[] | endpoint-rooted slices (same flag) |
| `foundBy` | string | `annotation` \| `dsl` \| `manifest` \| `config` |

## services — ServiceRef and urls — UrlEvidence (resolved tier)

Outbound client calls the pack's `outbound[]` shapes match
(`java.net.URL`, `DriverManager.getConnection`, OkHttp, Retrofit, Ktor
client, RestTemplate, Redis, Kafka). Every value carries its
`resolution`: `literal` (a string constant), `folded` (const-folded from
a `const val` or a string template), `config` (resolved through
`application.yml`/`.properties`/`BuildConfig`), `env` (an
`System.getenv` read — the KEY is the evidence; kosi never reads the
analysed build's environment), or `unresolved` (never a guess). `urls[]`
carries the same values with their enclosing symbol.

## securitySignals — SecuritySignal

| Attribute | Type | Purpose |
| --- | --- | --- |
| `code` | string | closed vocabulary (02-ARCHITECTURE.md §8); `native-interop` emits today |
| `message` | string | human explanation naming the seam |
| `modulePath`, `purl` | string | attribution (empty for cinterop `.def` files, which are not module sources) |
| `filePath` | string | relative path, or the `.def` file's repo-relative path |
| `position` | Position | 1-based |
| `symbol` | string? | the attaching symbol (the `external fun`'s canonical name, the function containing the `loadLibrary` call, the `.def` file path) — the key corpus `fn=` matching uses |

Emitted by structure, never by name heuristics: an `external` MODIFIER on a
lowered function (JNI seam), a RESOLVED `System/Runtime.loadLibrary|load`
call (the binding site), and `.def` files under the conventional cinterop
source-set directories (`nativeInterop/cinterop`, `cinterop`). A function
merely NAMED like a native one is a corpus negative, not a finding.

## crypto — CryptoEvidence (resolved tier)

`assets[]` name algorithms and transforms with their parsed shape:
`algorithmFamily`, `primitive`, `mode`, `padding`, `keySizeBits`,
`curve` — every one read from the shipped mapping table
(`crypto-mappings-v0.json`), never inferred. `AES` alone is reported as
`AES` without a mode or padding: the JCA's defaults are the JCA's
business. `resolution` is the value's provenance (`literal`/`folded`/
`config`/`env`/`unresolved`) and `form` its syntactic shape
(`literal`/`const`/`template`/`config`) — the gate counts mode/padding
extraction per form. `materials[]` carry secret material BY NAME (kind,
file, position) — never a value. `findings[]` are the mapping rows' risk
codes (`ecb-mode`, `weak-digest`, `weak-cipher`, `insecure-tls-version`,
`jwt-alg-none`, `trust-all-manager`, `predictable-random`,
`low-iteration-pbkdf2`). Crypto-flow slices are ordinary
`dataFlow.slices[]` whose source is a `hardcoded-secret` literal source
(the pack's `literalSources[]` name rule) and whose sink is
`crypto-asset` or `insecure-tls`.

`securitySignals` remains part of the v1 envelope (emitted empty) so
consumers can rely on the shape; its population is future work.
`dataFlow` is populated today (above).
