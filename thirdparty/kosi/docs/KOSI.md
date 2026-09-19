# Using kosi

kosi (Kotlin Source Inspector) analyses a Kotlin/Java project and emits one
deterministic JSON report: inventory, call graph and reachability, taint
slices, inbound endpoints and outbound services, and crypto evidence. It is
the Kotlin sibling of `golem` (Go) and `rusi` (Rust), and it is what cdxgen
calls to put Kotlin evidence into a BOM.

This page is the operator's guide: what kosi can see, what it cannot, how to
run it, and how to read the parts of the report that describe kosi's own
limits. `README.md` is the tour, `JSON_ATTRIBUTE_REFERENCE.md` is the report
contract, `docs/BUILD.md` is the build and the gate policy, and
`THREAT_MODEL.md` is the security model.

## The two tiers

Everything kosi reports is produced at one of two tiers, and the tier decides
what is knowable.

**Syntax tier** (`--backend syntax`, the default) parses sources with the
embedded Kotlin compiler's PSI. No classpath, no JDK required, no build
execution — build files are read as *text* and never run. It gives you
modules, packages, files, imports, declarations and name-level usages. It
cannot resolve a call to a declaration, so there is no call graph, no taint
and no endpoint model. Unresolved things are reported, not hidden
(`syntax-backend-no-resolution`).

**Resolved tier** (`--backend resolved`) runs the Kotlin Analysis API in
standalone mode against a real classpath. This is where the call graph,
reachability, the taint engine, endpoints/services/urls and the CBOM come
from. Its quality is bounded by the classpath it is given: see *Classpath* below.

## Running it

```bash
kosi analyze --dir /path/to/project --out report.json
kosi analyze --dir . --backend resolved --roots exported --callgraph auto
kosi analyze --dir . --backend resolved --dataflow all --endpoint-sources
kosi version    # versions, compiler band, capabilities
```

Exit codes: `0` success, `1` an expectation failed (ratchet, golden, bench),
`2` usage error, `3` runtime error.

The project to analyse is named by `--dir`, and **a bare path is a usage
error**: `kosi analyze /path/to/project` exits 2 naming the flag that takes
it. It used to be accepted and dropped, which meant the run silently
analysed the working directory and produced a perfectly valid report about
a tree the caller never named — the one wrong answer no amount of
determinism can catch.

Output is minified and byte-identical across runs on the same input;
`--pretty` only re-indents. Nothing in the report depends on filesystem
ordering, hash iteration order or wall-clock time — that is a gated property,
not an aspiration, and reports from two machines on the same input compare
equal byte for byte. That last property has teeth in the tool itself:
`kosi golden` analyses every fixture from two different absolute locations
in one run and fails on any section that differs, and
`scripts/two-environment-proof.sh` (see docs/BUILD.md) compares two
checkouts at the same commit under different Gradle cache states.

### Classpath

The resolved tier needs the project's dependencies on disk. kosi resolves
them from the build's own view (Gradle/Maven module metadata and the local
caches) and reports what it could not find rather than guessing. Two numbers
tell you how well it did:

- `stats.resolvedCallRatio` — the share of call sites whose callee kosi
  resolved. Below roughly 0.9 the call graph is partial, and everything
  downstream of it (reachability, interprocedural taint) is partial with it.
- `diagnostics[]` with `classpath-partial`, `classpath-file`,
  `deps-class-not-found` — the specific things that were missing.

`--classpath-file` pins the classpath explicitly. A relative path resolves
against `--dir`, not the working directory, and that relative form is what the
report records: where a tree is checked out is not an input to the analysis, so
it never reaches the output. Each line is a jar path, or a
`group:artifact:version=jar` binding when what matters is that a coordinate is
present rather than what it contains.

For repeatable measurement on a corpus, `scripts/warm-corpus-classpath.sh`
fetches and pins the classpath first; a report taken against a cold cache and
one taken against a warm cache are not comparable, and a measured finding
floor belongs to the warm one.

## What the analysis sees

**Call graph and reachability.** `--callgraph none|static|cha|sealed|rta|vta|auto`
builds dispatch-resolved edges typed by how they were resolved (`static`,
`receiver-typed`, `interface-cha`, `sealed-exact`, `sealed-bounded`,
`lambda-inlined`, `framework-registered`, `override`, `collapsed`), with
reachability from `--roots` (`main`, `exported`, `handlers`, `tests`,
`android`, `all`, `symbol:<regex>`). Reachability is always computed on the
complete graph; `--include-stdlib` and `--dependency-detail` shape only the
view, and a path a filter cuts survives as one `collapsed` edge carrying the
hop count and packages traversed. `auto` tries vta and falls back down the
chain on a deterministic work budget, recorded as `callgraph-timeout`.

**Taint.** `--dataflow none|security|crypto|reachable|all` runs a
field-sensitive engine over kosi's own IR and publishes `dataFlow.slices[]`:
a connected trace from a source call to a sink argument with severity, rule
id, access path and `origins[]` — which mechanism moved the taint, so a
computed summary is distinguishable from a blanket unknown-call default.
Sources, sinks, passthroughs, sanitizers and effects are DATA in the shipped
model pack (`modules/kosi-models/.../models/`); user packs extend or override
them. The engine is interprocedural: summaries are computed bottom-up over
the call graph's SCC condensation and applied at call sites in a fixed order
(model pack, then computed summaries of dispatch targets, then the
`--unknown-call` default). Coroutines and Flow are first-class —
`launch`/`async`/`withContext`/`runBlocking`, `flow { emit(x) }` to
`collect`, `Channel.send`/`receive` — and `stats.suspendCrossingSlices`
counts the slices that cross a suspend boundary.

Since P24 the engine also tracks **object identity**: an allocation-site
alias analysis runs over the same CFG, so a value reached through a second
reference to one object, through a field of another object, or carried
inside an object across a call boundary is followed rather than lost, and
a lambda is an object whose target is known where it was allocated. Every
slice publishes `frames[]` — the trace as named hops, `(function, file,
line, role)`, source first and sink last, with callee-internal hops
spliced in at each summary boundary — plus `stats.maxObservedDepth`, a
depth histogram, a dispatch-width histogram and `truncations{}`, which
names any cap that bound the run. A slice whose frame list was cut says so
in `framesCutBy`; nothing infers depth from a silence.

Since P25 the engine also reads **dependency injection as dispatch
evidence**. A Spring, Micronaut, Dagger/Hilt or CDI application never
constructs the implementation behind an interface — the container does, from
an annotation — so an analysis that reasons only from `new` was blind to
exactly the classes that run: the taint died at the service boundary and the
report said nothing. A stereotype (`@Component`, `@Service`, `@Repository`,
`@Controller`, `@RestController`, `@Configuration`, `@Singleton`,
`@Inject`, `@ApplicationScoped`, `@Bean`, Hilt's entry points) is now a
construction site the framework performs, matched on RESOLVED annotation
FQNs. Where an interface has several implementations and the container binds
one, the call narrows to it and the hop says `dispatchNarrowedBy:
di-binding` — narrowing that rests on an annotation, named apart from
narrowing that rests on a `new`.

Function VALUES are followed in every spelling the language offers: a
lambda (trailing, named-argument, implicit `it`, multi-parameter), a
callable reference (`::top`, `obj::method`, a local `fun`), an anonymous
`fun`, and a function held in a local. `fixtures/spelling-gallery` writes
one flow twenty-five ways and carries a want per spelling that works and a
numbered known-fail per spelling that does not — destructured lambda
parameters, constructor references, function values in a field or a
collection, SAM conversions, anonymous object expressions and extension
lambdas are the six that do not, each with a tracker defect.

**Endpoints, services, URLs.** Inbound routes per framework (Spring MVC and
WebFlux, Ktor, Micronaut, Quarkus/JAX-RS, http4k, gRPC, Android manifest
components) land in `apiEndpoints[]` with path template, methods, declared
authentication and media types; outbound calls and URL/host/JDBC strings land
in `services[]` and `urls[]` with config-resolved values where the value is
declared. `--endpoint-sources` makes endpoint handler parameters taint
sources, which is how a route becomes the root of a slice.

**Crypto.** `crypto` carries transform strings parsed for mode/padding/key
size/curve, TLS and JWT misconfiguration, Android keystore use, secret
material by name, and crypto-flow slices.

## What it does not see, and how it says so

kosi is designed so that every cap, fallback, truncation and unresolved thing
is a machine-readable `diagnostics[]` entry with a counter in `stats`. If a
consumer wants to know whether an empty result means "nothing there" or "kosi
gave up", the report answers it. The honest limits worth knowing before you
read a result:

- **An empty declaration is not a denial.** `authentication: []` on an
  endpoint means no requirement was *declared* at a site kosi models — not
  that the route is open.
- **Analysis budgets.** The taint fixpoint, the per-function instruction
  count, the slice count and the trace size all have caps
  (`fixpoint-cap`, `dataflow-max-*`, `dataflow-truncated`). A cap that is hit
  is a diagnostic over `stats.functionsAnalysed`, never a silent truncation.
- **Summary budgets.** A function whose summary exceeds the effect budget
  publishes no summary at all, and its callers fall back to the labelled
  unknown-call default; the trips are counted as `summary-effect-budget` in
  `stats.truncations`. Dropping the whole summary is deliberate — half a
  summary is a wrong summary. `--max-summary-sink-effects` sets the budget,
  so what it costs on your code is measurable rather than assumed.
- **Access-path depth.** Taint is tracked on access paths of bounded depth;
  deeper paths collapse to a `*` element and are tracked as the collapsed
  path, which is sound but coarser. A path deeper than a fact key can spell
  is dropped from composition rather than approximated, and every such drop
  is counted as `composed-path-depth` in `stats.truncations`.
- **Unknown calls.** `--unknown-call` decides what happens at a call kosi
  cannot resolve. Whatever it decides, the slices it produces say so in
  `origins[]`, and the corpus gate holds the default-only share of findings
  under 10%.
- **Reflection, dynamic loading and generated code** are reported as
  conditions (`dynamic-code-load`, `generated-functions`,
  `dataflow-skip-generated`), not silently followed.

## How cdxgen consumes it

cdxgen runs kosi through `lib/ecosystems/kosi.js` and evinse:

- `usages[]`, `imports[]` and `packages[]` join evidence to purls;
- `dataFlow.slices[]` become data-flow evidence;
- `services[]` and `urls[]` become outbound service entries;
- `apiEndpoints[]` become inbound `services[]` rows, named the way cdxgen's
  OpenAPI detector names its own so a spec-derived entry and a kosi-derived
  one converge instead of duplicating;
- `crypto` feeds the CBOM.

`CDXGEN_KOSI_DISABLE=1` skips kosi entirely: the run logs once and the BOM
stays valid with zero kosi artifacts. A missing or unusable kosi binary is a
silent fallback by design, never a failed BOM.

## Platform support

kosi ships as a GraalVM native image per platform, plus a portable JVM jar.
Native images exist for linux-amd64, linux-arm64, linuxmusl-amd64 and
darwin-arm64. Where no native image exists — darwin-amd64 (no GraalVM for JDK
25 publishes a macOS x64 build, and native-image cannot cross-compile),
windows-amd64/arm64 (no MSVC build job yet; the recipe is `docs/BUILD.md` §6),
ppc64le and 32-bit linux-arm (not Native Image platforms), linux-riscv64 and
linuxmusl-arm64 — consumers with a JDK 21+ get `kosi-portable.jar`, and
consumers without one get cdxgen's own JS-side Kotlin analysis. Every gap is
named in `scripts/plugin-platform-support.sh`; none is silent.

## Reproducing a run

`options` in the report records every effective option, and `runtime` records
the compiler version, the analysable language band, the JVM and the host. A
report is reproducible from those two objects plus the input tree and the
classpath — which is why the classpath state belongs in any comparison of two
numbers.

## Development gates

```bash
./gradlew build        # unit tests, all modules
./gradlew corpusQuick  # fixture-tier ratchet, security + all modes
./gradlew corpusFull   # fixtures + pinned real-repo tiers (network)
./gradlew golden       # digest goldens, trace invariants
```

The corpus is a two-way ratchet: a regressed expectation fails the build, and
a `known-fail` that starts passing fails the build too. `docs/BUILD.md`
records which of these run per push and which are run deliberately on a
machine that can hold them.
