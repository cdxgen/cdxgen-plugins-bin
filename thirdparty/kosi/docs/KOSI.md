# Kosi phase status and defect registry

Companion to `$HOME/kotlin-plans/07-REVIEW-PROTOCOL.md`: merged phases,
measured numbers, and the numbered defects that `known-fail=<n>` corpus
markers refer to. Defects stay numbered; closing one requires the XPASS
ratchet proof.

## Phase 3 — the call graph and reachability (this branch)

Branch `feat/kosi-p3-callgraph`, off `feat/kosi` (`94aecaa`).

**What ships.** `kosi-graph` (compiler-free, KIR + schema types only) builds
`callGraph` on the resolved tier: dispatch resolution per mode (`static`,
`cha`, `sealed` with closed-set narrowing and `sealed-exact`/`sealed-bounded`
labels, `rta`, `vta`, `auto` = vta falling back to rta then sealed), roots
(`main`, `exported`, `handlers`, `tests`, `android`, `all`, `symbol:<regex>`;
framework registrations matched against RESOLVED annotation FQNs — a
homonym annotation in a different package must not and does not register a
handler, pinned by `framework-handlers`' negative half), reachability with
per-node `distance`/`roots[]`, shortest witness paths via
`--reachable-symbols`, GraphML/GEXF export, and the post-hoc view filter
(`--include-stdlib`, `--dependency-detail collapse|drop|full`) where a path a
filter cuts survives as one `collapsed` edge carrying hop count and traversed
packages. RTA is genuinely reachability-driven: classes instantiate only
from reached constructor sites (plus singletons and root receivers), and a
virtual site connects candidates only once their owner class is live — dead
implementations get no edges (`virtual-dispatch`'s negative half pins this
through a `known-fail`-free want-not).

**KIR format bumped to `kir 2`:** dispatch facts the graph needs — per-call
source lines on `Call`/`DynamicCall`/`New`, real `visibility`/`modifiers`
(were hard-coded `public`/empty), resolved `overrides`, enclosing-class
`supertypes`, `ownerFlags`, `ownerAnnotations`, `ownerVisibility`, and
per-function `jvmDescriptor` for overload identity. Missing facts narrow
dispatch toward MORE candidates, never fewer (unknown visibility never reads
as exact), and a shortfall surfaces as `symbol-resolution-failed`.

**Gate, measured (JVM, darwin-aarch64, M4 Pro, pinned toolchain for the
binary):**

- Edge connectivity **1.000 over 3 edge-reached nodes (of 66 reached)**
  across 58 graph slots. The denominator counts only nodes at distance > 0,
  because a root is reached with no edge involved: measured against every
  reached node instead, the corpus scored 1.000 over 62 having traversed
  nothing at all (R50). Vacuity stays reported — a run whose reached set is
  entirely roots is NOT_EVALUATED, never a pass — and `reachable-depth` is
  the fixture that keeps it evaluated.
- `--roots exported` public-API reach **0.9839 (61 of 62)** on fixtures,
  against a denominator taken from `declarations[]` rather than from the
  graph's own nodes. Read off the graph the figure was a tautology, 1.0000
  everywhere including all five repos (R49). The single miss is
  `fixtures.interop.Greeter.greet`: a Java-declared method the Kotlin
  lowering has no body for, so it never becomes a node — a real gap, named
  rather than absorbed, that P9's bytecode tier closes. The repo figures
  below predate the denominator change and are being re-measured; the 0.95
  bar first read 0.839 on nowinandroid, which was a DEFINITION mismatch
  (the bench's public-API denominator ignored enclosing-class visibility
  while the root rule gated on it), fixed by publishing `ownerVisibility`
  on the node. Note that unifying those two predicates is precisely what
  made the metric tautological, which is why the denominator now comes from
  outside the graph.
- Breakdowns recorded per slot and checked for internal consistency
  (`graph-breakdown`): e.g. spring-fu 706 nodes = 598 local + 108
  synthetic; anki-android 12029 = 9681 local + 2173 synthetic + 175 stdlib
  + 0 dependency in the default view (see deviation below).
- `--include-stdlib` toggles the counts through the real pipeline
  (`includeStdlibChangesTheGraphThroughTheRealPipeline`): a `main` calling
  into the stdlib shows stdlib nodes/edges only with the flag on, and the
  breakdown moves with it — the golem always-true filter defect has a
  failing test on both sides.
- Determinism: two runs byte-identical on all **30** fixtures — report,
  GraphML export, and witness sidecar — on the JVM AND in the native image;
  native equals JVM byte-for-byte on the same input, `tool.commit` aside
  (the image bakes in its build commit). Native binary built on the pinned
  GraalVM CE 25.3.4.1 (`native-image 25.0.4.1`). The first native-vs-JVM
  sweep of this phase reported all fixtures identical while the image was in
  fact dying on two of them; see R53 for what the comparison was actually
  measuring.
- Ratchet still fails both ways, re-proven on this branch: a broken
  expectation exits 1; a `known-fail=99` stamped on a passing expectation
  XPASSes and exits 1; restored, exit 0.
- Bench matrix grows to 4 slots (`security`, `all`, `resolved`, `exported`),
  goldens to 116 pairs; the corpus evaluates 788 annotation outcomes over
  **29** corpus fixtures x 4 slots (the review added `reachable-depth`):
  687 pass / 0 fail / 14 xfail / 0 xpass, structural recall 1.000
  (393 of 393) over the non-known-fail positives. The xfail count grew from 12 to 14 with the fourth slot
  (command-exec's known-fail markers evaluate once per slot by design).

**Promotion checks added** (each tested through the baseline file — write,
read back with the production parser, then evaluate; the standing R44
rule): `edge-connectivity` (witness-confirmed nodes over the EDGE-TRAVERSED
reached set, vacuity-guarded — see R50 for why the denominator is not every
reached node), `exported-reach` (both counts published, >= 0.95, denominator
from `declarations[]` — see R49 for why not from the graph),
`graph-breakdown` (the four-way split must exist and must sum to the
totals). The round-trip guard `FixtureResultJsonTest` now covers every new
gate field with distinctive non-default values — and caught a real R44-shaped
defect during development: the graph fields were read by `fromJson` but
three of them (`reachedNodes`, `publicCallables`, `reachedPublicCallables`)
were never WRITTEN by `toJson`, so a baseline comparison would have seen
zeros. In-memory objects passed; the file round-trip did not.

**Deviations recorded for this phase:**

6. **`--callgraph-timeout` is a deterministic work budget, not wall
   clock.** Byte-identical output is a gate; a wall-clock fallback would
   break it precisely on the large inputs the fallback exists for. `auto`
   budgets `timeoutSeconds * 1,000,000` work units (evaluations + edge
   emissions) per algorithm before falling back down the chain, recorded as
   `callgraph-timeout`.
7. **CHA "including library types from the classpath" is approximated at
   the source tier.** Library callees have no bodies, so external nodes are
   leaves and dispatch INTO library code is one receiver-typed edge.
   Dispatch THROUGH a library interface to workspace implementations IS
   resolved (a local `Runnable` implementation receives the call);
   library-internal overrides arrive with P9's bytecode tier.
8. **`lambda-inlined` retained edges and higher-order bodies.** Scope
   functions keep their evidence edge; standalone lambda bodies are still
   not extracted as functions (a P2 shape), so `higher-order` edges wait
   for that lowering work; the corpus pins none of it.

## Phase 2 — the native JDK, then KIR (merged 2026-09-09)

Branch `feat/kosi-p2-kir`, off `feat/kosi` (`20b9e27`).

**The blocker, closed.** Defect 3: a native image registers no jrt
filesystem provider, so `addBinaryRootsFromJdkHome` could not read a
modular JDK's `lib/modules` and every `java.*` symbol stayed unresolved
(`weak-crypto` 0 of 4 in the image vs 4 of 4 on the JVM). The fix reads
the module image DIRECTLY in the image through the image runtime's own
`jdk.internal.jimage.BasicImageReader` and materializes ONE JAR PER MODULE
under `$TMPDIR/kosi-jdk/<stamp>/` (keyed by path+size+mtime, atomically
moved, reused across processes), handed to the SDK module as plain `.jar`
binary roots. Two measured facts drove the shape:

- The JDK's own standalone jrt provider cannot rescue an image:
  `JrtFileSystemProvider.newFileSystem` re-loads its implementation classes
  from the TARGET JDK's `jrt-fs.jar` through a URLClassLoader at run time,
  and native image can neither execute build-time-unknown bytecode nor (by
  default) even open a `jar:` URL — both probed, not assumed.
- A single merged jar resolves nothing: the search scope's package trie
  derives `java.base.java.lang.String` from the merged layout. One root
  per module is the shape upstream produces on the JVM; it is load-bearing,
  not taste. The per-module jars carry module-relative entries (asserted by
  `JdkModulesTest`), the JVM keeps the upstream jrt route, and the same
  fixtures are byte-identical across substrates.

JVM-side extraction reads the same image through the public jrt NIO
filesystem (env-key `java.home`), so the extraction is exercised by tests
on every platform; the image-only reflection entries live in the checked-in
reachability metadata (preserved by `merge-agent-metadata.py`, which the
JVM tracing agent cannot see) and the build opens the package with
`--add-opens java.base/jdk.internal.jimage=ALL-UNNAMED`.

`--jdk-home` now either works or is a usage error naming why: a home
without `lib/modules` (and without an exploded `modules/` tree) is
rejected — `AnalysisException`, exit RUNTIME — never silently downgraded
to a partial classpath. With no flag, resolution tries `java.home` then
`JAVA_HOME` (the image case); when neither names a JDK, `classpath-partial`
remains, naming every source tried.

**KIR (02-ARCHITECTURE.md §4).** `kosi-kir` is the owned IR: 21
instructions, basic blocks, field-sensitive access paths (depth cap 5,
`*` collapse), and a validator whose reachability walk fails any
unreachable-but-emitted block (the check-removed test is
`KirValidatorTest.anUnreachableEmittedBlockIsAFinding`). `kosi-front`
lowers PSI + one resolution pass into it; every §4 desugaring is
implemented with a per-construct test in `KirLoweringTest`, negative-first
(a while loop must not invent `hasNext`, an all-literal template must stay
a Load, a plain class gets no synthetic members). A construct the lowering
cannot perform is counted by construct in `stats.loweringFailures{}`,
published beside `stats.functionsLowered` (the denominator), and diagnosed
as `lowering-failed`. `kosi kir dump` enforces the round-trip
(dump -> read -> dump byte-identical) and CFG validation on every dump.

One naming decision worth recording: the KIR's operator names are the
SYNTAX tier's names (`compareTo`, `equals`, `plus` — from
`SyntaxAnalyzer.operatorFunctionName`), not JVM-style aliases (`less`,
`notEquals`), so both tiers and the corpus speak one naming.

**Fixtures**: 5 new (delegated-properties, destructuring, for-iterable,
operators, use-close), each with a negative half that names what a
plausibly over-broad lowering would emit; corpus grows to 480 annotations.

## Phase 1 — resolved front end (merged 2026-09-09)

Shipped:

- **Substrate fixed.** The dependency allowlist amendment
  (02-ARCHITECTURE.md §1) is in: kotlin-compiler-embeddable is gone and
  kosi-front runs on the unrelocated `-for-ide` split artifacts, the
  unrelocated IntelliJ platform at 251.27812.49 (the build Kotlin v2.4.0
  pins in `versions.intellijSdk`, same version KSP2 uses), and the
  third-party libraries KSP2 pins. `kosi version` reports
  `analysis-api-standalone: available` on the JVM — the probe builds a real
  session and resolves a declaration through it.
- `AnalysisEnvironment`: one standalone session per analysis run; the
  syntax tier parses through the same session, so both tiers share one
  substrate. The bench runs 48 sessions per `corpusQuick` without leakage.
- **Resolved tier** (`--backend resolved`): project discovery reuses
  kosi-project; the session sees one merged workspace module over exactly
  the files SourceCollector collected (module attribution stays
  report-level). Resolved `declarations` carry `jvmOwner`/`jvmDescriptor`
  via the compiler's own JVM type mapping, `supertypes`, and
  `overrides` (allOverriddenSymbols); `imports[].purl` names the jar whose
  package prefix the import matches; **Java sources are parsed through the
  same symbols** (`java-source-not-parsed` is gone from resolved reports —
  defect 2 closed on this backend, still open at syntax by design).
- **Offline classpath resolution** with a loud partial: coordinates parsed
  as text from build.gradle(.kts)/pom.xml/libs.versions.toml, located in
  the local Gradle/Maven caches and `build/libs`; every miss becomes a
  `classpath-partial` diagnostic naming the coordinate; explicit
  `--classpath`/`--classpath-file`/`--jdk-home` flags implement the plan's
  acquisition order 1/2/4. Corpus entries may carry a build-produced
  `classpath_file` (scripts/warm-corpus-classpath.sh — developer-side,
  kosi never executes a project build).
- **stats.resolvedCallRatio** is computed: explicit Kotlin calls whose
  resolution produced symbols / all explicit calls. The `empty-classpath`
  fixture (deliberately unresolvable coordinate) must emit
  `classpath-partial` and still report the unresolved call; the
  ResolvedBackendTest asserts the ratio collapse and fails if the
  diagnostic is removed. The bench matrix has a third `resolved` slot, so
  every fixture's resolved behaviour is ratcheted.
- **Version policy** (08-VERSION-POLICY.md in full): ceiling and band from
  the bundled compiler (kept from P0), clamp path (`kotlin-language-version`),
  ceiling (`kotlin-version`), `kotlin-api-version`, recorded
  `version-override` diagnostics for CLI passthrough, and
  `stats.degraded = "kotlin-version"` when a version mismatch coincides
  with heavy resolution fallout. Four version fixtures exist: `old-language-version`
  (declares 1.9: clamp + analysis continues), `latest-syntax` (2.4 context
  parameters + explicit backing fields resolve clean), `future-syntax`
  (eap tier only, ceiling diagnostic), plus the clamp-covered
  `maven-project`/`multi-module-gradle` and real-hybrid `anki-android`.
  `FlowFoundAcrossLanguageVersionRange` analyses the taint fixture at
  every accepted language version (enumerated at runtime) and asserts the
  flow outcome plus resolved facts are identical across the band; the flow
  outcome is XFAIL until P4 by design — the ratchet makes it real when the
  engine lands.
- Corpus: 20 fixtures × 3 slots; pinned repos now span Spring (spring-fu),
  Ktor (ktor-samples), Android (nowinandroid), KMP (kampkit) and
  mixed-Java (anki-android), with per-repo `resolvedCallRatio` in the bench
  result.
- **Native image: both tiers run, on the pinned toolchain only.** Verified
  2026-09-09 on the pinned GraalVM CE 25.3.4.1 (`native-image 25.0.4.1`,
  darwin-arm64): `kosi version` reports all three components available,
  `analyze` and `analyze --backend resolved` both exit 0, and two runs of
  either are byte-identical.
  **The toolchain is part of the contract.** The same sources built on
  GraalVM CE 25.0.2 produce a binary that cannot create the analysis
  session at all — `UnsatisfiedLinkError: Can't load library: awt`, because
  the platform's mock application schedules a Swing runnable and that JDK's
  `Toolkit.<clinit>` loads its natives before reading the `awt.toolkit`
  property, so `KosiNoopToolkit` is never selected. On the pinned build the
  property route works. The review reached the wrong verdict here first, by
  building on CE 25.0.2 (which `make` preferred through `JAVA_HOME`): the
  earlier claim that the mechanism "cannot work on JDK 25" was wrong and is
  retracted. What the episode did expose is that the Makefile resolved the
  toolchain from whatever `JAVA_HOME` happened to provide `native-image`,
  so the binary under review need not be built with the reviewed toolchain
  — see R42.
  **Real remaining gap (defect 3): the native resolved tier does not see
  the JDK.** `java.home` is unset in an image, so no SDK module is attached
  and every `java.*` symbol is unresolved — loudly, as `classpath-partial`,
  and the ratio shows it (`weak-crypto` resolved 0/4 in the image vs 4/4 on
  the JVM), so native and JVM reports of the resolved tier are NOT
  byte-identical. Passing `--jdk-home` does not rescue it: it fails with
  `ProviderNotFoundException: Provider "jrt" not found`, because the image
  has no jrt filesystem provider to read a modular JDK's `lib/modules`.
  Fixing it means shipping/loading `jrt-fs.jar` (or an equivalent reader)
  in the image — P2's first item. The syntax tier is unaffected and its
  native output is byte-identical to the JVM's.
  Both backends now fail with kosi's own RUNTIME error naming the cause
  whenever the session cannot be created, never a raw platform stack trace
  and never a silent degrade. The image still needed three recorded fixes,
  all kept: the K1 application environment is seeded once per process with a
  configuration pointing
  INTELLIJ_PLUGIN_ROOT at the materialized `kosi-ext` descriptors (the
  stock session builder creates a fresh configuration whose jar-location
  lookup cannot work in an image — `PathManager.urlToFile` rejects image
  `resource:` URLs); a no-op `awt.toolkit` (the platform's mock application
  schedules one runnable through Swing and the image has no AWT natives);
  `-H:+AddAllCharsets` (the platform loads UTF-32BE by name) and
  `--enable-monitoring=jfr` (the low-level-api-fir flight recorder refuses
  to run otherwise). The stdlib jar ships inside the fat jar
  (`kosi-libs/kotlin-stdlib.jar`) and is materialized at run time as the
  session's stdlib binary root.
- Binary: 93,709,760 bytes (89.4 MiB) on the pinned GraalVM CE 25.3.4.1
  (`native-image 25.0.4.1`), re-measured at review time and within 0.1% of
  the PR's 93,627,264. For contrast the same sources on CE 25.0.2 produce
  106,000,640 bytes — binary size is toolchain-specific, so every number
  names its GraalVM. Up from P0's 53,185,568 — the unrelocated IntelliJ platform + FIR + Analysis API is
  the closed world now. Determinism: two runs byte-identical on every
  fixture for both tiers, on the JVM and in the image. Native output equals
  JVM output for the syntax tier; for the resolved tier it does not, because
  the image attaches no JDK module (defect 3).
- **Per-repo `resolvedCallRatio`** (resolved slot, this machine):
  spring-fu 0.9405, anki-android 0.9232, ktor-samples 0.9024,
  nowinandroid 0.7564, kampkit 0.6639. **Named limitation, not hidden:**
  three of five pinned repos meet the 0.90 P1 gate; nowinandroid and
  kampkit do not. nowinandroid's remaining gap is AndroidX multiplatform
  artifacts whose AAR variants cannot always be matched by a non-AGP
  consumer (the warm script retries with androidJvm/aar attributes and
  pulls most; the rest are variant combinations only AGP constructs).
  kampkit's cap is inherent to JVM-tier analysis: iosMain sources
  reference Kotlin Native-only libraries that do not exist as JVM jars.
  Follow-up levers: AGP-style variant-aware AAR resolution, and P9's
  bytecode tier which reads dependency jars directly. The gate is now
  ENFORCED, not merely reported: `Promotion` carries a
  `per-repo-resolved-call-ratio` check that fails on any per-repo drop below
  the baseline and on any repo at or above 0.90 falling through it, reports
  NOT_EVALUATED when a run has no repo tiers to look at, and names the
  below-target repos with their measured values in the detail line.

## Phase 0 — measurement harness + native-image spike (merged 2026-09-08)

Shipped:

- Gradle workspace, 13 modules per the architecture doc, closed dependency
  allowlist, one `kotlinVersion = 2.4.0` property.
- `kosi-schema`: hand-rolled streaming JSON writer (sorted keys, minified,
  `--pretty`) + strict reader; full v1 report types.
- `kosi-project`: Gradle (settings/build/gradle.properties), Maven (pom.xml),
  Android build types/flavors, KMP source sets — all parsed as text, never
  executed.
- `kosi-front`: syntax backend over `kotlin-compiler-embeddable` PSI;
  language-version band read from the bundled compiler's `LanguageVersion`
  constants (2.4.0 → band 2.0–2.4, first-non-deprecated 2.2) with clamp
  diagnostics; standalone-session capability probe.
- `kosi-corpus`: `kosi:want`/`kosi:want-not` parser, scoped known-fail
  (`known-fail=<backend>:<defect>`), category validation against the shipped
  packs, evaluator with PASS/FAIL/XFAIL/XPASS.
- `kosi-bench`: security + all matrix slots derived from CLI defaults
  (asserted by tests on both sides), structural recall, connectivity and
  slice-integrity checkers (exercised vacuously at P0), digest goldens,
  baseline write/compare, promotion gate that reports unevaluated criteria
  instead of silently passing them.
- 16 fixtures (≥10 required), each with a negative half written before the
  positive; one intentional `known-fail` (command-exec).
- Native-image spike: works. `make native` produces
  `build/kosi-darwin-arm64` (44.7 MiB); numbers and pitfalls in
  `docs/BUILD.md`.

Measured (host: darwin-aarch64, M4 Pro):

| Metric | value |
| --- | --- |
| fixtures | 16, ×2 slots = 32 corpus cases |
| annotations | 204 (128 positive / 76 negative) |
| recall (fixtures tier, per slot) | 1.000 (126/126 non-known-fail positives) |
| precision | not evaluable (no slices) |
| connectivity | 1.000 (vacuous — no slices; stated as such) |
| integrity violations | 0 |
| open known-fails | 1 marker, 2 outcomes (XFAIL in both slots) |
| node/edge breakdown | n/a (no call graph at the syntax tier) |
| wall clock | median 3 ms, worst ~10 ms per fixture/slot (JVM in-process) |
| native binary | 44.7 MiB; cold start < 10 ms; native == JVM output |
| determinism | `cmp` byte-identical across runs, JVM and native |

Gate proofs recorded in the PR body:

1. `cmp` determinism on multiple fixtures, JVM and native.
2. Two-way ratchet: breaking an expectation fails `corpusQuick`; a
   known-fail that starts passing fails `corpusQuick` (XPASS); both reverted.
3. Every corpus case runs in `security` **and** `all`.
4. `kosi golden`: 32 fixture/slot pairs, 0 problems, content-compared
   digests.
5. Bench/CLI defaults equality asserted by tests in both modules.

## Recorded deviations from the plans

1. **`analysisMillis`/`peakRssBytes` are not in report `stats`.** Byte-identical
   output and embedded self-timings are mutually exclusive; the bench
   harness measures them out of band. (03-SCHEMA.md stats table)
2. **`analysis-api-for-ide`/`analysis-api-standalone-for-ide` POMs declare
   transitive modules (analysis-api, analysis-api-standalone[-base],
   analysis-api-fir-standalone-base) that are shadowed into the jars but not
   published anywhere** (Maven Central and the JetBrains repo both 404 at
   2.4.0). kosi-front excludes the phantom transitives — detekt carries the
   same exclusions. Additionally, the standalone session cannot be
   *constructed* from the allowlist alone (needs unrelocated IntelliJ
   platform classes; KSP2 fat-jars ~6000 of them). `kosi version` reports the
   gap in `components["analysis-api-standalone"]` (unavailable, with the
   missing class named) on the JVM **and** in the native image; the
   resolved tier (P1) must
   either add `org.jetbrains.kotlin:kotlin-compiler` (unrelocated substrate)
   to the allowlist or vendor the platform classes — decision recorded there.
3. **JetBrains' compiler-native-image metadata does not exist at tag v2.4.0**;
   it is seeded from a pinned master commit instead
   (`native-metadata/jetbrains/PINNED-SOURCE.txt`).
4. **This GraalVM (CE 25.0.4.1) ignores reachability-metadata `proxy` entries
   passed via `-H:ConfigurationFileDirectories`** and wants
   `-H:DynamicProxyConfigurationFiles` in an array-of-interface-arrays
   format; resources are passed via `-H:IncludeResources`. Recorded in
   docs/BUILD.md §3.
5. **UPX-LZMA is not used**: packed binary segfaults on macOS
   (docs/BUILD.md §4).

## Defect registry (numbers referenced by `known-fail=<backend>:<n>`)

| # | backend | defect | status |
| --- | --- | --- | --- |
| 1 | syntax | no flow engine at the syntax tier: no slices, no call graph; `command-exec` carries `known-fail=1` for `flow source=untrusted-input sink=process-exec`. The resolved front end (P1) has no flow engine either, so the marker stays backend-agnostic until P4 | open |
| 2 | syntax | Java sources are listed in `files[]` but not parsed at the syntax tier: their declarations are absent (R19 added the diagnostic; P1 closes the gap at the resolved tier, where Java PSI is parsed through the same symbols). `java-interop` and `empty-classpath` carry `known-fail=syntax:2` on the expectations that need the resolved tier | open (resolved tier: closed) |
| 3 | resolved | the native image attaches no JDK module: `java.home` is unset in an image, so `java.*` symbols go unresolved (reported as `classpath-partial`, and visible in the ratio — `weak-crypto` resolves 0/4 in the image vs 4/4 on the JVM), and `--jdk-home` fails with `ProviderNotFoundException: Provider "jrt" not found` because the image has no jrt filesystem provider for a modular JDK's `lib/modules`. Resolved-tier native output is therefore not byte-identical to JVM output; the syntax tier is unaffected | **closed in P2** — the image reads `lib/modules` through its own jimage reader and attaches per-module jars; `weak-crypto` 4/4 in the image, 8 fixtures byte-identical native vs JVM, `--jdk-home` works or is a usage error (see Phase 2) |

## Defects found and fixed during the P3 review

| # | Area | Defect | Fix |
|---|------|--------|-----|
| R49 | kosi-bench | **`exported-reach` was a tautology and could not fail.** Its denominator was the graph's own public nodes; the `exported` root selector picks exactly the public local nodes; a root is reached at distance 0 by definition. Numerator and denominator were therefore the same set by construction, which is why the gate read exactly `1.0000` on every fixture and on all five pinned repos — anki-android's headline `7976/7976` is the tell. Unifying the two visibility predicates (the right fix for the nowinandroid 0.839 mismatch) is what closed the last gap between them | the denominator comes from `declarations[]`, published by the front end independently of graph construction: callables whose own visibility and whose enclosing declaration's visibility are consumer-nameable, with `unknown` counting IN so a missing fact widens the obligation rather than deleting it. A public callable that never became a node now costs a point, which is the failure the gate exists to catch. Measured: **0.9839 (61 of 62)**, the one miss being `fixtures.interop.Greeter.greet` — a Java-declared method the Kotlin lowering has no body for, a real gap that P9's bytecode tier closes. `PublicApiDenominatorTest` |
| R50 | kosi-bench | **`edge-connectivity` confirmed 62 nodes without traversing a single edge.** A root is reached at distance 0, so it is "connected" with no edge involved; `connectedCount` seeds every root into the visited set before the walk starts. Across the whole corpus **0 of 62** reached nodes sat at distance > 0 — every reached node was a root, in all 56 graph slots — so the 1.000 was a count of roots. The P3 prompt asked specifically that this denominator stop being vacuous; the number got bigger, and stayed vacuous | the denominator is the edge-traversed subset: `reachedViaEdge` (distance > 0) and `connectedViaEdge`, both carried across the bench boundary, with NOT_EVALUATED when it is empty and the detail line naming both figures. The corpus gains `reachable-depth` — one public entry point over a chain of non-public helpers, the only fixture whose reachability is a fact about edges rather than about being declared public. Measured: **1.000 over 3 edge-reached nodes (of 66 reached)**. `CallGraphGateTest.aRunWhoseReachedNodesAreAllRootsIsNotEvaluatedRatherThanPassing` |
| R51 | kosi-graph | `--roots all` matched **every node** — `RootScope.ALL -> true` in the per-node `when`, contradicting the `// filled below from the other scopes` comment two lines under it. Rooting the stdlib and every dependency makes reachability say "everything runs", and hands any connectivity denominator a free pass, since a root needs no edge. Untested in either direction | `all` never matches directly; it is the union of the concrete scopes, as the comment always said. `RootsTest` pins both halves — no non-workspace root, and set equality with the union |
| R53 | build | **the native image could not analyse any fixture containing an `object`.** `MissingReflectionRegistrationError` on `KtObjectDeclaration(ASTNode)` at the resolved tier, exit 3, no report written. The cause is upstream of the metadata file: `make native-metadata` runs the agent over every FIXTURE but only two SLOTS, and P3 added a third. A slot the agent never runs is a code path the image never registers. It survived the phase's own native-vs-JVM sweep because `analyze` writes nothing when it fails, so `cmp` compared the previous fixture's report with itself and reported every fixture identical — the same vacuous-comparison trap the P2 review fell into over empty files, this time hiding a real regression | the agent target runs the `exported` slot (with `--include-stdlib`, so the filter's kept-node path is registered too); 90 new metadata lines, and `sealed-dispatch` and `framework-handlers` analyse in the image again. `docs/BUILD.md`'s determinism recipe now deletes its outputs first, asserts they are non-empty, and normalises `tool.commit`, because a comparison over reused paths passes loudest exactly when the tool is broken |
| R52 | kosi-bench | `everyGateReadableFieldSurvivesTheBaselineFile` compares field by field, so a **newly added** field left at its `null` default passes it vacuously: null in, null out, no evidence the parser ever heard of the field. R44's shape one level up — the guard against unenforced checks, itself unenforced for anything added after it was written | `theSampleLeavesNoFieldAtItsDefault` reflectively requires every persisted field of the sample to carry a distinctive value before the round-trip comparison can claim anything about it |

## Defects found and fixed during the P2 review

| # | Area | Defect | Fix |
|---|------|--------|-----|
| R44 | kosi-bench | **the P1 per-repo ratio gate could not fire against a real baseline.** `FixtureResult.toJson` wrote `resolvedCallRatio`; `BenchResult.fromJson` never read it. Every baseline loaded from disk therefore carried `resolvedCallRatio = null` for every row, and both enforcing arms of `resolvedRatioCheck` — the regression arm and the fell-through-the-target arm — hit `?: continue` on the baseline value and did nothing. The gate reported PASS on a comparison it had not made. Its unit tests missed it because they construct `BenchResult` in memory and never go through the parser. This defect was introduced by the P1 *review* (R26), not by the implementation: the check was written and its round trip was never tested | `fromJson` parses every field the gates read, and `FixtureResultJsonTest.everyGateReadableFieldSurvivesTheBaselineFile` compares the whole data class field by field across write → read, so the next gate-input field cannot go missing the same way |
| R45 | kosi-bench | the P2 lowering gate was measured by hand and enforced nowhere: `stats.loweringFailures` / `stats.functionsLowered` existed in the report but were dropped at the bench boundary, and `Promotion` had no lowering criterion. The lowering could regress from 0.000% to any rate with every check still reading PROMOTE — the same defect as R26, one phase later | `FixtureResult` carries the failures map and the function count; `Promotion` gains a `lowering-failures` check (fixtures must lower cleanly, repos stay under `LOWERING_FAILURE_RATE_MAX = 0.005`), both arms reporting the count over the denominator; `LoweringGateTest` proves each arm fails when the check is disabled |
| R46 | kosi-bench | the bench republished `resolvedCallRatio` with no counts beside it, so the *gate* — which reads its ratios from the bench result, not the report — could not tell 0 of 0 calls from 0 of 400. R25 fixed this in the report and left the harness that consumes it unfixed | `callsTotal` / `callsResolved` travel across the bench boundary, appear in the gate's detail line as `slug=0.9405 (940/1000)`, and a slot with `callsTotal == 0` is excluded from the ratchet instead of manufacturing a regression out of an empty repo |
| R47 | kosi-kir | the CFG validator enforced "no unreachable-but-emitted block" but nothing about instructions *after* a terminator, so unreachable code one level below the block passed clean — the same lowering bug the gate exists to catch, carrying the same stale registers into dataflow, in a block that is itself perfectly reachable. `KirValidatorTest`'s own dead-block fixture happened to contain the malformed shape | a terminator must be its block's last instruction; the finding names the index and how many instructions follow. Also made the reachability walk's fallthrough step O(1) instead of an `indexOf` scan per block |
| R48 | kosi-front | the extracted-JDK cache skipped the *write* but not the *read*: `extractedModuleJars` called `readModuleEntries` unconditionally, reading every entry of every JDK module into memory before the loop discovered that every jar already existed. The cache saved nothing on the warm path it was built for — measured at 0.32 s vs 0.11 s per invocation on `weak-crypto` in the image (pinned toolchain, macOS aarch64), i.e. the reuse path paid ~0.21 s to rediscover what it already had | a `modules.list` manifest, written atomically after every jar is in place, short-circuits the whole read when the set it names is complete |

## Defects found and fixed during the P1 review

| # | Area | Defect | Fix |
|---|------|--------|-----|
| R25 | kosi-schema | `resolvedCallRatio` was published with no denominator, so the resolved slots that print 0.000 could not be told apart: `kmp-jvm-android` and `sealed-when` have zero call sites (vacuous), `android-compose-app` resolved 0 of 1 (a real gap). The same defect P0 fixed for `connectivity` by shipping `sliceCount` | `stats.callsTotal` / `stats.callsResolved` travel with the ratio, asserted equal to it by `theRatioPublishesItsDenominator` |
| R26 | kosi-bench | the P1 gate's per-repo ratio was *reported* but no check enforced it: `Promotion` had no resolved-ratio criterion at all, so a repo could fall from 0.94 to 0.20 and still read PROMOTE | `per-repo-resolved-call-ratio` check, two-way (regression vs baseline, and falling through the 0.90 target), NOT_EVALUATED when there are no repo tiers, with `ResolvedRatioGateTest` covering all five outcomes |
| R27 | kosi-front | `--classpath-file /nonexistent` was silently ignored: the explicit branch set `fromExplicitFlags` and added nothing, producing an empty classpath with no diagnostic — the exact shape of P0's `--compare` defect | the analysis fails with a message naming the file; `aClasspathFileThatDoesNotExistIsAnError` |
| R28 | kosi-front | `modifiers[]` carried `abstract` (and `sealed`) twice, once from the PSI modifier list and once from the symbol's modality: one fact stated as two | `.distinct()`, pinned for every declaration by `modifiersAreNotDuplicatedBetweenPsiAndSymbol` |
| R29 | kosi-front | every resolved annotation was stamped at line 1 column 1 (`positionAt(lines, path, 0)`) — a position that is not where the annotation is | position taken from the declaration's own PSI annotation entry, falling back to the declaration; `annotationsCarryTheirOwnPosition` |
| R30 | kosi-front | every symbol operation was wrapped in `catch (_: Exception)` returning empty evidence, uncounted: an Analysis API breakage would have produced a full-looking report with no JVM evidence and nothing to say why | failures are counted and surfaced as the `symbol-resolution-failed` diagnostic with its count |
| R31 | kosi-front | source files the session's VFS would not open were dropped with `?.let`, while `files[]` kept listing them — resolution silently covering fewer files than the report advertises | counted and reported as `unreadable-source` with a count |
| R32 | kosi-front | the shipped stdlib jar was copied to a fresh temp file on *every* session (60 per `corpusQuick`) and `stdlibJarPath()` copied it again per analysis, none of them deleted | materialized once per process, `deleteOnExit` |
| R33 | kosi-project | `usableArtifact` documented "deterministic path, reused across runs" but called `createTempDirectory`, which returns a fresh unique directory — so every AAR was re-extracted on every run and every copy leaked; `Files.copy` without REPLACE_EXISTING would also have thrown on the reuse path it claimed to take | a fixed `$TMPDIR/kosi-aar/<stamp>` directory, actually reused, with an unreadable AAR falling back to the AAR itself (which the caller then reports as unresolvable) |
| R34 | kosi-project | `packageIndex` broke prefix ties by comparing *purl string lengths* — an ordering on nothing | lexicographically smallest purl, stated in the comment |
| R35 | kosi-project | `packagePrefixOf` sampled the first 4096 packages and broke out, so a large jar yielded a deeper prefix than it has and misattributed imports, with no diagnostic for the truncation | running common prefix over every class entry; no cap, no truncation |
| R36 | kosi-front | `usages[].purl` scanned the whole file map per usage and `declarations` scanned `collected` per declaration — quadratic in file count, invisible on fixtures, dominant on a real repo | indexed once per run |
| R37 | kosi-front | `collectJavaClasses` recursed exactly one level, so a class nested two deep was dropped while `javaCanonicalName` handled arbitrary depth | fully recursive |
| R43 | kosi-cli | `bench --compare <baseline>` computed every promotion criterion and printed none of them: the gate rendered only under `--verbose`, so the documented review command showed a report and no verdict | a baseline comparison always renders the gate, to stderr so stdout stays a parseable report |
| R42 | build | the Makefile resolved the native toolchain from any `JAVA_HOME` that provided `native-image`, preferring it over the pinned release — so the binary being measured need not be the one the pin describes, and on CE 25.0.2 it is a binary whose analysis session cannot start. This review built and judged the wrong artifact because of it | the pin comes first in the resolution order, and every binary rule depends on `native-toolchain-check`, which names the `native-image` version in use and refuses anything but the pinned one unless `GRAAL_ALLOW_ANY=1` |
| R41 | build | `make native`'s binary rules depended only on `native-metadata/kosi/reachability-metadata.json`, so a binary newer than that file was never relinked after a Kotlin source change — `make native` printed a successful build and left the old binary in place (this review measured a stale binary once before catching it) | the rules depend on the fat jar, produced through a PHONY `fat-jar` target so Gradle decides whether it changed and make decides whether to relink |
| R40 | kosi-cli | `kosi version` printed the constant string `"available"` for `backend-syntax` — a component report that never looked at the component, which is why a native binary unable to create a session still reported a working syntax tier | both backends are probed (`probeSyntax` parses a declaration through a real session), so the version output can no longer disagree with what the binary does |
| R39 | build | the PR's headline claim — the resolved tier available in the native image — does not hold, and the same cause takes the syntax tier down with it: the `awt.toolkit` property is consulted *after* `Toolkit.<clinit>` has already failed to load libawt, so the no-op toolkit is never selected | not fixed in this phase; recorded as defect 3, the native resolved run now fails with kosi's own RUNTIME error naming the cause, and it is P2's blocking first item |
| R38 | kosi-cli | `resolvedBackendIsAcceptedSinceP1` accepted `OK` **or** `RUNTIME`, so a resolved tier that could not start at all would have passed the test that exists to prove it starts | asserts OK on a real project and that the report carries the resolved-tier counters |

## Defects found and fixed during the P0 review

Each was caught by this review's gates or by a test added with the fix, and
each has a regression test or a ratchet annotation pinning it:

| # | area | defect | fix |
| --- | --- | --- | --- |
| R1 | kosi-schema | `CallGraphEdge.writeJson` wrote `candidateCount`/`collapsedHops` twice (sentinel `-1` then `null`) — a duplicate-key crash waiting for the first call-graph serialization; `emittedCandidateCount` was never emitted at all | emit each optional once (`ReportSerializationTest`) |
| R2 | kosi-schema | `options` omitted `includeStdlib`, `progressive`, `multiplatformTarget`, violating "every effective option" | serialized; `everyOptionFieldIsSerialized` enumerates the data class so future fields cannot be dropped silently |
| R3 | kosi-schema | `FlowSummary.returnType` was wrapped in an array; map-key iteration (`loweringFailures`, `truncations`, `paramToSink`, `accessPaths`, `summariesByOrigin`) and the `declarations`/`usages` arrays were unsorted — nondeterminism hazards for phase 1+ | string field; all map keys and report arrays sorted at the writer |
| R4 | kosi-project | Maven `kotlin-maven-plugin` settings were scanned with the Gradle brace-block scanner, which can never match XML — `languageVersion`/`apiVersion` discovery silently always null | XML parsed with `XmlElement`; pinned by `MavenDiscoveryTest` and a `kotlin-language-version` corpus annotation on `maven-project` |
| R5 | kosi-project | nested Maven modules stored source roots relative to the module dir, but `SourceCollector` resolves them against the analysis root — a nested module collected the wrong tree (files silently attributed to the parent) | roots carry the module prefix; `nestedModulesAreDiscovered` |
| R6 | repo plumbing | `check-plugin-coverage.sh` listed kosi exemptions but never checked kosi at all (not in `BUILT_PLUGINS`) — dead code, a gate that could not see what it claimed to check | kosi is checked everywhere; named exemptions in the shared `scripts/plugin-platform-support.sh` (used by staging too) actually engage |
| R7 | repo plumbing | `packages/*/build-*.sh` staged kosi on platforms where it cannot exist (ppc64, linux-arm, riscv64) — `stage-built-plugins.sh` would fail the release | stager skips exempt platforms with the named reason |
| R8 | repo plumbing | kosi Makefile lacked the `linux`/`linuxmusl`/`windows`/`darwin` targets the release workflow invokes, and named the darwin binary `aarch64` where packages stage `arm64` | family targets added (host-arch builds, named errors for declared gaps); binary renamed `kosi-darwin-arm64` |
| R9 | kosi-front | the module-boundary test only inspected `import` lines, so fully-qualified compiler references in code bodies escaped the architecture rule (it immediately caught a shaded-path literal in kosi-cli's leftover `--probe-resources` debug code) | boundary test scans all non-comment lines; debug probe removed |
| R10 | kosi-cli | `ParsedArgs.values()` looked up occurrence keys `name.1`, `name.2`, ... and so **dropped the first occurrence**: `--roots main --roots tests` analysed `["tests"]` and a single `--roots tests` analysed the *default* roots while `options.roots` in the report echoed the default — a report describing options that did not run | occurrences kept in order; `repeatedFlagsKeepEveryOccurrence` covers both spellings |
| R11 | kosi-cli | unknown flags were silently ignored, contradicting the documented exit code 2; the previous parser test asserted `AnalyzeOptions()` against itself and could not see it | per-subcommand known/boolean flag vocabularies, unknown flag = exit 2, tests rewritten negative-first |
| R12 | kosi-cli | `--compare <file>` (the spelling in `07-REVIEW-PROTOCOL.md`) was declared a *boolean*, so the file name became a positional and the comparison silently checked nothing | `--compare` is a value flag aliasing `--baseline`; a baseline that does not exist is a runtime error, not an empty comparison |
| R13 | kosi-cli | `commit` fell back to `git rev-parse HEAD` at analysis time, i.e. in the *analysed* project — stamping the analysed repo's commit onto kosi's provenance and spawning a subprocess the threat model forbids | build-time resource only; `unknown` otherwise |
| R14 | kosi-bench | the `TOTAL` row published `Digests.FixtureDigest(..., emptyMap())`, whose combined digest is the SHA-256 of the empty string — a golden-looking value that can never change | totals digest combines every fixture digest |
| R15 | kosi-bench | `Digests.compute` digested an allowlist of 8 sections while its own comment claimed it excluded only volatile fields: `stats`, `crypto`, `services`, `callGraph`, `dataFlow` and every later-phase section were invisible to the goldens | inverted to a named volatile exclusion set (`tool`, `runtime`); goldens regenerated |
| R16 | kosi-bench | `connectivity: 1.0` was published per fixture with no way to tell it apart from a measured 1.0 (it is vacuous while there are no slices) | `sliceCount` travels with it and the promotion gate prints "1.000 over 0 slices"; `fixture-coverage` reads the slot count from `Matrix` instead of hard-coding 2 |
| R17 | kosi-front | `declarations[].receiverType` carried the *return* type (documented as such in `JSON_ATTRIBUTE_REFERENCE.md`) next to `extensionReceiverType` — a v1 field name that means the opposite of what it says | renamed `returnType` in schema and doc |
| R18 | kosi-front | the operator-usage exclusion list was defeated by its own `?:` fallback, so `=`, `&&`, `!!`, `as` and `?:` were emitted as `usages[]` entries no model pattern can ever match; `*=` mapped to `mulAssign` (the Kotlin name is `timesAssign`) | non-callable operators emit nothing (identifier check + keyword set); `timesAssign` fixed |
| R19 | kosi-front | Java sources were listed in `files[]` and skipped without a diagnostic, so their absent declarations looked like a fact about the code | `java-source-not-parsed` warning with a count |
| R20 | kosi-front | `positionAt` rescanned the file prefix per element, making position stamping quadratic in file length | line-start index + binary search (`LineIndex`) |
| R21 | kosi-schema | diagnostic codes were an open string: a corpus `want-not diagnostic code=parse-errors` typo would have passed vacuously forever | `DiagnosticCodes` registry, `Diagnostic` rejects unregistered codes, corpus validates against the same set |
| R22 | kosi-corpus | `usage kind=` / `declaration kind=` were unvalidated, the same vacuity hole as above for negatives | closed vocabularies in `Annotation.validate` |
| R23 | fixtures | `weak-crypto` and `command-exec` negative halves named symbols absent from the file entirely (`SSLContext`, `Runtime.availableProcessors`) — the comment claimed a "clean TLS path" that did not exist | negatives rewritten as near-misses of symbols the file *does* contain, each with the over-broad implementation it would catch |
| R24 | build | `GRAAL_HOME` defaulted to a hard-coded `$HOME/tools` path that no reviewer machine has, and `bootstrap-*` printed a mangled download URL | `JAVA_HOME` with `native-image` is preferred; bootstrap points at the release page and sdkman |
