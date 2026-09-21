# Kosi (Kotlin Source Inspector)

kosi is a Kotlin/JVM code analysis engine for evidence collection — the Kotlin
sibling of `golem` (Go) and `rusi` (Rust). It answers, for a Kotlin project:

- which Kotlin/Java sources, modules and source sets exist (Gradle, Maven,
  Android variants, Kotlin Multiplatform), and their declared/effective
  language versions
- which imports, declarations and library calls occur (canonical, sorted,
  byte-identical output)
- which functions call which, and what is reachable from `main`, the exported
  API, or framework-registered handlers
- which untrusted data reaches dangerous calls — field-sensitive
  intraprocedural and interprocedural taint with
  sources/sinks/passthroughs/sanitizers/effects as data, including coroutine
  and `Flow` propagation, and optionally through dependency bytecode
- inbound endpoints per framework and outbound `services[]`/`urls[]` with
  config-resolved values
- a crypto/CBOM: transform strings parsed for mode/padding/key size/curve, TLS
  and JWT misconfigurations, Android keystore, secret material by name, and
  crypto-flow slices
- which packages/purls the evidence attaches to

Two analysis tiers share one report contract (`schemaVersion: kosi/1`):

- **syntax** (`--backend syntax`) — PSI-only parsing via
  `kotlin-compiler-embeddable`, with **no classpath and no build execution**.
- **resolved** (`--backend resolved`) — Kotlin *and* Java PSI with type
  resolution against a classpath, carrying the call graph, taint, endpoints and
  crypto evidence.

## Quick start

```bash
# from this directory
./gradlew installDist --no-daemon
./modules/kosi-cli/build/install/kosi-cli/bin/kosi-cli analyze --dir /path/to/project --out report.json
```

Useful variants:

```bash
kosi analyze --dir . --pretty                       # indented output
kosi analyze --dir . --backend syntax               # explicit (default) tier
kosi analyze --dir . --backend resolved --roots exported --callgraph auto   # call graph + reachability
kosi analyze --dir . --backend resolved --deps --dataflow security-deps     # taint through dependency bytecode
kosi analyze --dir . --backend resolved --format graphml --out graph.graphml # GraphML (or gexf) of the call graph
kosi analyze --dir . --backend resolved --reachable-symbols witnesses.json  # shortest witness paths (JSON)
kosi kir dump --dir .                               # KIR dump (resolved tier), round-trip + CFG validated
kosi bench --tier fixtures                          # corpus ratchet, both modes
kosi golden                                         # digest goldens, trace invariants
kosi version                                        # versions, compiler band, capabilities
```

On a large repository the recipe that answers the most is:

```bash
kosi analyze --dir . --backend resolved --dataflow reachable \
    --callgraph auto --roots exported --endpoint-sources \
    --classpath-file classpath.txt
```

### Memory

The analysis holds the whole project's PSI, KIR and summaries in memory. A
repository of a few thousand source files wants **16 GB of heap or more**
(`-Xmx16g`); below that the JVM tends to die at whichever class it needed
next, so a `NoClassDefFoundError` naming a kosi class is usually starvation
rather than a corrupt build. kosi recognises that shape and says so instead of
printing a bare stack trace. Deeply nested sources are a *stack* question, not
a heap one: the analysis runs on a 512 MB stack and bounds every PSI walk
per file (`psi-depth-cap`, `stack-overflow-skipped`), so an overflow that still
reaches the CLI is already outside those bounds and is reported with the file
that caused it.

### Call graph and reachability (resolved tier)

`--callgraph none|static|cha|sealed|rta|vta|auto` builds `callGraph` —
dispatch-resolved edges with call types (`static`, `receiver-typed`,
`interface-cha`, `sealed-exact`, `sealed-bounded`, `lambda-inlined`,
`framework-registered`, `override`, `collapsed`), per-node reachability from
`--roots` (`main`, `exported` for libraries' public API, `handlers` for
type-resolved framework registrations, `tests`, `android`, `all`,
`symbol:<regex>`), and node/edge breakdowns by
local/stdlib/dependency/synthetic. Reachability is computed on the complete
graph; `--include-stdlib` and `--dependency-detail collapse|drop|full` then
shape the VIEW: a path a filter cuts survives as one `collapsed` edge
carrying the hop count and the packages traversed — it never silently
vanishes. `auto` runs vta, falling back down the chain (rta, then sealed) on
a deterministic work budget recorded as `callgraph-timeout`.

### Taint analysis (resolved tier)

`--dataflow none|security|crypto|reachable|security-deps|all` (default
`security`) runs the field-sensitive taint engine over the lowered KIR and
publishes `dataFlow.slices[]` — each slice a connected trace from a source call
to a sink argument, with `severity`/`ruleId`/`flowKey` and an `accessPath`.
Sources, sinks, passthroughs, sanitizers and effects are DATA in the shipped
model pack (`modules/kosi-models/src/main/resources/models/`); user packs
extend or override entries. Taint is tracked on access paths, so sinking one
field of a partly-tainted object does not report its clean siblings — ACROSS
call boundaries as well as within them. Loop-carried flows converge to a
worklist fixpoint; a cap that is hit is the `fixpoint-cap` diagnostic over
`stats.functionsAnalysed`, never a silent truncation. `--dataflow reachable`
keeps only slices whose function is reachable from the declared roots and flags
them.

The engine is interprocedural. Function summaries (parameters to returns, to
other parameters, to the receiver, to sinks) are computed bottom-up over the
call graph's SCC condensation — each component converging by a worklist over
the summaries actually read, so recursion terminates without recomputing what
cannot have changed — and applied at call sites in a fixed order: the model
pack first, then the computed summaries of the dispatch targets (joined per
`--callgraph` mode, narrowed by receiver construction types under rta/vta),
then the `--unknown-call` default. Every slice records `origins[]` — which of
those moved its taint — so computed summaries are distinguishable from blanket
propagation.

Higher-order calls are covered: lambda values lower into their own bodies with
captures bound at the call site, and a function-valued parameter's invocation
is recorded on the value itself. Coroutines are first-class:
`launch`/`async`/`withContext`/`runBlocking`/`LaunchedEffect` and the flow
operators analyse their lambda bodies in the caller's context,
`flow { emit(x) }` carries `x` to whatever `collect` reads, `async{}.await()`
is a passthrough, and `Channel.send`/`receive` move taint through the
channel's element state. `stats.suspendCrossingSlices` reports how many slices
cross a suspend boundary.

With `--deps`, dependency classes from the resolved classpath are lowered to
the same KIR from bytecode, their summaries carry `origin=bytecode`, and
cross-dependency slices are published alongside the application's own.

### Endpoints and services (resolved tier)

`apiEndpoints[]` covers Spring MVC, WebFlux and Actuator, springdoc, Spring
Messaging, Ktor, Micronaut, Quarkus/JAX-RS, http4k, Javalin, Ratpack, Vert.x,
SparkJava, Servlet/`web.xml`, gRPC, GraphQL, AWS Lambda, Azure Functions and
Android manifest components (activities, services, receivers, providers,
including `namespace`-based packages and deep links). Each endpoint carries its
path template, HTTP methods, path/query parameters, media types, declared
authentication, and the handler it resolves to.

An endpoint kosi could not read is never passed off as one it did: a manifest
component whose class is not among the analysed declarations stays published —
the manifest is real — but carries `substantiated=false` and is counted in an
`endpoint-unsubstantiated` diagnostic.

Under `--endpoint-sources`, endpoint handler parameters are seeded as taint
sources and endpoint-rooted slices carry the endpoint they enter through.

Outbound calls become `services[]` and `urls[]`, with values resolved from
`application.properties`/`.yaml` where they are provably determined and
published as `unresolved` with the key named where the configuration disagrees.

Exit codes: `0` success, `1` expectations failed (ratchet/golden/bench),
`2` usage error, `3` runtime error.

## What kosi reads

- `settings.gradle(.kts)`, `build.gradle(.kts)`, `gradle.properties` — member
  list (including members included through local helper functions), plugins,
  compiler settings, Android build types/flavors and `namespace`, KMP source
  sets. **Parsed as text, never executed.**
- `pom.xml` — Maven modules, coordinates, kotlin-maven-plugin settings.
- `.kt` and `.java` sources under discovered source roots. `stats.sourceCoverage`
  reports how many of the files present under the analysed root were actually
  discovered, and a large shortfall is a `source-coverage-gap` diagnostic rather
  than a silence.
- `AndroidManifest.xml`, `web.xml`, `application.properties`/`.yaml`.
- `corpus.toml` for the evaluation harness; annotations (`kosi:want`,
  `kosi:want-not`) in fixture sources; SHA-pinned upstream repos fetched into
  `.corpus-cache/` for the small/medium tiers.

### Syntax tier (default)

- Parses without classpath or JDK; unresolved things stay unresolved **and
  are reported** (`syntax-backend-no-resolution`, `parse-error`, ...).
- Emits `modules`, `packages`, `files`, `imports`, `declarations`, `usages`
  (by name, dotted receiver form), `diagnostics`, `stats`.
- Version policy: the analysable band comes from the bundled compiler's
  `LanguageVersion` constants at runtime — on Kotlin 2.4.0 that is 2.0–2.4 with
  `FIRST_NON_DEPRECATED` 2.2. Projects declaring older versions are clamped
  with a `kotlin-language-version` diagnostic; newer declarations get
  `kotlin-version`. Reports carry `runtime.kotlinVersion` and
  `runtime.languageVersionRange`.

## Development

```bash
./gradlew build # unit tests, all modules
./gradlew corpusQuick # fixture-tier ratchet, security + all modes
./gradlew corpusFull # fixtures + pinned real-repo tiers (network)
./gradlew golden # digest goldens for every fixture/slot
make native # GraalVM native image (see docs/BUILD.md)
make size # staged binary sizes
```

Before the first `corpusFull`, warm the repo classpaths
(`scripts/warm-corpus-classpath.sh --tier vuln-repo`, or per slug): the
vuln-repo tier's `min_findings` floors are measured against WARMED
classpaths, and an entry whose declared classpath file is missing fails its
bench rows rather than ratcheting a number measured against nothing.

The corpus is a two-way ratchet: a regressed expectation fails the build and
a `known-fail` that starts passing fails the build (XPASS). Scoped markers
(`known-fail=syntax:1`) describe per-backend defects.

See `docs/BUILD.md` for the build and native-image details,
`JSON_ATTRIBUTE_REFERENCE.md` for the report contract, `THREAT_MODEL.md` for
the security model, and `docs/KOSI.md` for the operator guide.
