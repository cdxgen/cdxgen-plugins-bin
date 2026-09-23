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

The resolved tier needs the project's dependencies on disk. kosi ACQUIRES
them through a named chain of read-only strategies, tried in order until one
attaches a jar — `--classpath-strategy` forces exactly one, and the report
names the winner on every run:

1. `explicit` — `--classpath` / `--classpath-file` flags (what cdxgen passes).
2. `file` — a classpath file already in the analysed tree: `classpath.txt`
   (the warmed convention) or an Eclipse `.classpath`.
3. `jars` — a `libs/` directory of vendored jars.
4. `cache` — offline: coordinates parsed as text from build files, located
   in `~/.gradle/caches/modules-2` and `~/.m2/repository`.

`stats.classpath` publishes `{strategy, entries, missing, attempts[]}` —
`attempts[]` records every strategy the chain tried and whether it fired,
`strategy` is the winner or **`none`, stated explicitly**: a classpath-less
run and a run that found nothing produce the same sparse graph and are
opposite facts, and the report is where you tell them apart. Three numbers
tell you how well the attached classpath did:

- `stats.classpath.entries` / `missing` — how much of it attached.
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

kosi itself never executes the analysed build (see THREAT_MODEL.md). The
strategies that DO run build tooling live in the operator-side
`scripts/acquire-classpath.sh <dir>`: Gradle dependency reports (per
subproject, all configurations — Android variants included), Maven
`dependency:build-classpath`, a present classpath file, a jar directory, and
the text-declared coordinates handed to kosi's own cache scan. Each arm
reports whether it fired; the winner writes `<dir>/classpath.txt` with a
`# strategy:` provenance header, which the `file` strategy then picks up.
`--pull` additionally downloads each coordinate's transitive closure into
the local caches (a dependency report lists coordinates without downloading
their jars). For pinned corpus repos,
`scripts/warm-corpus-classpath.sh` remains the measurement-side warmer; a
report taken against a cold cache and one taken against a warm cache are not
comparable, and a measured finding floor belongs to the warm one.

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

The engine also tracks **object identity**: an allocation-site
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

The engine also reads **dependency injection as dispatch
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
narrowing that rests on a `new`. The BINDING METHODS are read too:
`@Binds` (the parameter IS the implementation — no construction anywhere),
`@Provides`/`@Bean` by parameter or by construction, and Koin's provider
lambdas (`single<Api> { ApiImpl() }`, `factory`, `viewModel`, both the 3.x
and 2.x package spellings). A container that manages TWO implementations of
one interface publishes BOTH — a dispatch width of 2, labelled `di-binding`,
which is the honest answer — and a container that binds the non-sinking
implementation publishes no finding at all.

The engine also models **what the framework does with the value**,
not only where it enters. Persistence interfaces are sinks: a Spring Data
repository method (a derived query name or `@Query`) and a Room
`@Dao`/`@Query` method are matched on what the DECLARATION carries — the
repository base it extends or the annotations on it — because the interface
is user code and no callee pattern can name it; Exposed's `Transaction.exec`
is a plain sink. Deserializers (Jackson `readValue`, kotlinx
`decodeFromString`, Gson `fromJson`) produce FIELD-BEARING results: the
produced object carries the input's taint on its fields, which is how a
request body reaches a sink through a DTO. Retrofit and Feign INTERFACES are
outbound services: the annotated method is the call, and the method's
annotation value is the path, published in `services[]`/`urls[]`. Android's
cross-component channel is modelled end to end — `getIntent()` is a source,
`putExtra`/`putString` are write effects, and a `ContentProvider`'s
`query`/`insert`/`update`/`delete` arguments are seeded inputs (any app on
the device can call a provider). Property initializers are lowered as the
executable code they are, so a Koin module at top level — the framework's
own idiom — is visible to the whole engine.

Function VALUES are followed in every spelling the language offers: a
lambda (trailing, named-argument, implicit `it`, multi-parameter), a
callable reference (`::top`, `obj::method`, a local `fun`), an anonymous
`fun`, and a function held in a local. `fixtures/spelling-gallery` writes
one flow twenty-five ways and carries a want per spelling that works and a
numbered known-fail per spelling that does not — destructured lambda
parameters, constructor references, function values in a field or a
collection, SAM conversions, anonymous object expressions and extension
lambdas are the six that do not, each with a tracker defect.

**Endpoints, services, URLs.** Inbound routes per framework land in
`apiEndpoints[]` with path template (deployment base path included), methods,
declared authentication and media types. The frameworks are:
- Spring MVC and WebFlux, including Spring Data REST, Actuator and springdoc;
- Ktor, Micronaut, Quarkus/JAX-RS and Quarkus Reactive Routes;
- http4k, Javalin, Ratpack, Vert.x, SparkJava and Servlet/`web.xml`;
- gRPC, GraphQL, AWS Lambda and Azure Functions;
- Android manifest components.

See JSON_ATTRIBUTE_REFERENCE.md for `foundBy`, `anyMethod`, `pathUnresolved`
and `transport`. `atom-tools convert -t kotlin` turns the report into a valid
OpenAPI 3.1 document.

Beyond endpoints, outbound calls and URL/host/JDBC strings land
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

## How much memory

kosi holds the whole analysed workspace — every source file's PSI, the
resolved symbols behind it, and the attached classpath's classes — in one
heap. Memory therefore scales with the repository, and the default JVM heap
(a quarter of physical RAM) is not enough for a large one.

| repository size | `-Xmx` | measured |
|---|---|---|
| up to ~500 source files | 4 GiB | AndroGoat (34 files, 223-jar classpath) peaks around 1 GiB |
| ~500–2,000 files | 8 GiB | okhttp (573), coil (452), detekt (1,105) all complete |
| ~2,000+ files, or a resolved classpath | **16 GiB or more** | dagger (1,950 files) produces **no report at all** under 8 GiB; it completes at 16 GiB. thunderbird-android (3,318) completes at 8 GiB |

```
java -Xmx16g -jar kosi-all.jar analyze --dir <repo> ...
```

**A starved run does not say "out of memory".** A JVM with no room to define
one more class throws `NoClassDefFoundError` naming whichever class it
happened to need next, which can be a kosi class, a Kotlin stdlib class, or an
IntelliJ one. dagger at `-Xmx8g` failed with nothing but
`kosi: io/cdxgen/kosi/flow/Summarizer$compute$4`. kosi now recognises that
shape and prints the heap it was given, the machine's physical memory, and the
suggestion to raise `-Xmx` — but if you see a bare class name from an older
build, the heap is the first thing to check.

Analysis time is bounded separately by `--max-analysis-seconds` and resident
size by `--max-rss-mb`; both are reported as diagnostics rather than silent
truncation.

## How much stack

The stack is no longer yours to tune. kosi runs the whole analysis on a
thread with an explicit **512 MB stack** (committed lazily — an unused
reservation costs no memory), so one deeply nested source file cannot exhaust
a default-sized stack; the dataflow workers carry the same stack. Measured on
the generated `s + s + ...` fixture, darwin-aarch64:

| stack | deepest source analysed | notes |
|---|---|---|
| a default-sized thread | ~1,200 nesting levels | 1,250 overflows; 2,000 terms dies at any heap |
| `-Xss64m` | ≥ 5,000 levels | what tuning the flag by hand buys |
| kosi's analysis thread (512 MB) | ≥ 400,000 levels | measured; the file's SIZE becomes the limit first |

**The policy bound below the stack.** Anything past **2,000 nesting levels**
is not walked at all, whatever the stack: a file over the budget keeps its
package, imports and `files[]` entry, loses its declarations, usages and
lowering, and the report carries a `psi-depth-cap` diagnostic naming the file
and its depth. Deepest real-world code sits in the low hundreds; the bound
exists so that a bounded run is distinguishable from a complete one. A file
(or dataflow function) that somehow still overflows degrades to a
`stack-overflow-skipped` diagnostic naming it — one pathological file costs
its own evidence, never the report.

**A file of several megabytes is not Kotlin to the platform.** IntelliJ's
file-type layer classifies very large files as plain text; kosi reports that
file via `unreadable-source` with the size, and analyses the rest.

### Memory for the test tiers

The corpus and bench tiers fork their own JVM. That fork takes **half of
physical RAM, clamped to [6, 24] GiB**, and prints what it chose:

```
kosi tier JVM: 21 @ /path/to/java heap=24g (auto: half of physical)
```

Pin it with `-Pkosi.testHeapGb=<n>`. CI pins 6, the value calibrated to
the shared runners; a developer machine gets the larger share because the
bigger corpus tiers are meant to run locally.

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

The jar is `make fat-jar`'s output (`modules/kosi-cli/build/dist/kosi-all.jar`)
staged as `kosi-portable.jar`. It is built once on the amd64 runner in
`native-builds.yml`, cached at
`ghcr.io/cdxgen/cdxgen-plugins-bin:kosi-portable`, and attached to each
GitHub release; it is deliberately absent from the per-platform npm packages,
whose staging matches a platform fragment this name does not carry.

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
