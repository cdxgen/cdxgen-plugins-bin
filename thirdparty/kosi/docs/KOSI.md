# Kosi phase status and defect registry

Companion to `$HOME/kotlin-plans/07-REVIEW-PROTOCOL.md`: merged phases,
measured numbers, and the numbered defects that `known-fail=<n>` corpus
markers refer to. Defects stay numbered; closing one requires the XPASS
ratchet proof.

## Phases 7+8 — frameworks/endpoints and crypto/CBOM (this branch)

Branch `feat/kosi-p7-p8-endpoints-crypto`, off `feat/kosi` (`be924c9`). Two
roadmap phases, one branch, plus item 1 of the brief: the two transfer
functions unified.

**Item 1 (R65) — ONE transfer.** `TaintEngine`'s reporting analysis and
`SummaryAnalysis` were two ~700-line copies of the same transfer over two
fact types; R62 was found in one of four merges and fixed in two because
the copies had to be compared by eye. `Transfer.kt` now holds the opcode
switch, the merges, the pack classification, the unknown-call default and
the worklist ONCE (`FlowTransfer` + `TransferHost`), generic over the fact
type; each engine supplies callbacks for what genuinely differs — fact
births, sink recording, parameter seeds, escape records, callee summary
application. Two documented disagreements were resolved to the shared
semantics: a suspend boundary is TRANSPARENT in both (the summary engine
dropped the call's result, contradicting its own comment), and a field
write is a STRONG update in both (the summary engine weak-updated,
undocumented). `TransferParityTest` is deleted in the same commit — there
is one copy now. Proof of no change: all 204 pre-existing goldens were
byte-identical on the unification commit and corpusQuick reported 0
failures. (The goldens that moved in THIS branch moved for the options
key and the new sections, not for the unification — the per-section
digests show only `options` changing on every pre-existing fixture.)

**What ships (P7).** `kosi-endpoints` detects inbound endpoints and
outbound services/URLs, driven entirely by the shipped
`endpoints-pack-v0.json` (the framework registry): eight frameworks —
Spring MVC, Spring WebFlux (functional router), Ktor, Micronaut,
Quarkus/JAX-RS, http4k, gRPC (generated `*ImplBase` supertypes) and
Android (manifest components). Every endpoint publishes `foundBy`
(`annotation` | `dsl` | `manifest`). The framework match is on RESOLVED
type identity — a homonym annotation in a foreign package never matches,
which is the framework-handlers rule applied to endpoints, and each
framework fixture carries its lookalike negatives (annotated DTO, private
method with a mapping-shaped name, commented-out route, marker class with
no mapped methods, unregistered activity). DSL handlers resolve to the
EXTRACTED LAMBDA body (ktor `get("/x") { .. }` publishes the lambda's
canonical name); nested route prefixes compose (`route("/metrics") {
get("/count") }` -> `/metrics/count`); an unresolved route shape publishes
`resolution: unresolved` rather than dropping the endpoint. Outbound:
client calls the pack's `outbound[]` shapes name produce `services[]` and
`urls[]` with a `resolution` on every value — `literal`, `folded`
(`const val` + string templates, via the shared `KirValueFolder` in
kosi-kir), `config` (`application.yml`/`.properties`/`BuildConfig`), `env`
(the key is the evidence; kosi never reads the analysed build's
environment), or `unresolved`.

**Endpoint-rooted taint.** `--endpoint-sources` (bench slot `endpoint`)
seeds every endpoint handler's parameters as `untrusted-input` sources at
the synthetic entry site; slices carry the endpoint they enter through
(`ApiEndpoint.sliceIds`/`reachableSources`), and `command-exec` and
`old-language-version` dropped the `readLine()` P4 patched in and are
parameter-shaped again — P4's deviation 1 is retired. The seeded-entry
machinery rides the same `TransferHost` hooks the summary engine uses.

**What ships (P8).** `kosi-crypto` collects the CBOM: `Cipher.getInstance`
transforms parsed for literal, `const val`, string-template and
config-driven forms (each its own gate denominator — `form=` on the
asset), digests, MACs, signatures, KDFs with PBKDF2 iteration floors,
TLS protocol versions, the Android keystore, named EC curves, JWT
`alg=none`, trust-all managers (empty `checkServerTrusted` bodies), and
secret MATERIAL BY NAME — the pack's `literalSources[]` rule births
`hardcoded-secret` facts at material-named stores, so crypto-flow slices
are ordinary slices (material -> `crypto-asset`/`insecure-tls`) counted
from `dataFlow.slices[]`. Every algorithm family, mode, padding, key size,
curve and finding comes from the shipped `crypto-mappings-v0.json` — the
collector invents nothing, and `"AES"` alone is reported as `"AES"`, not
as `"AES/ECB/PKCS5Padding"` (the JCA's defaults are the JCA's business).
The mapping-coverage gate holds every shipped row to at least one
exercising fixture at 1.000 — it FAILed at 0.70 before the
`crypto-algorithms` fixture landed, which is the gate working. The
no-literal-secret gate (`scripts/scan-secrets.sh` +
`NoSecretLeakTest`) proves both directions: a deliberately-broken report
trips on the planted secrets, the real report is clean.

**Gates** (all with both counts, `Promotion.evaluate`): per-framework
endpoint recall (eight frameworks, never pooled, each >= 0.95),
`endpoints-resolved-handler` (handler symbols looked up in the call-graph
node set, 81/81 on the bundled tiers), `endpoint-rooted-slices`,
`config-resolution` (resolved over config-derived; total > 0 with zero
resolved FAILs), `crypto-mapping-coverage` (= 1.000), per-form
mode/padding extraction, and `crypto-flow-slices`.

## Phases 5+6 — interprocedural summaries, coroutines and Flow (this branch)

Branch `feat/kosi-p5-p6-summaries-async`, off `feat/kosi` (`92d0c6e`). Two
roadmap phases, one branch: P6's gate (`flow { emit(tainted) }.map{}.collect
{ sink(it) }`) is unreachable without P5's summaries.

**What ships (P5).** `kosi-flow` computes bottom-up function summaries over
the call graph's SCC condensation (Tarjan, reverse topological order,
callees before callers); each SCC iterates to a fixpoint — recursion
CONVERGES (the `summary-recursive` fixture pins a mutually recursive pair,
0 cap hits) — with a per-SCC iteration budget whose hit stamps the members
`origin=recursive-approx` and is counted over the SCC count
(`stats.sccIterationCapHits` / `stats.sccsProcessed`). At a call site the
order is fixed: the PACK first (authoritative), then the JOIN of the
dispatch targets' computed summaries (virtual sites join per the run's
`--callgraph` mode; vta/auto narrow by receiver construction types on
positive evidence only), then the `--unknown-call` default. Every boundary
move carries its ORIGIN (`computed`, `pack`, `default`,
`recursive-approx`), every slice publishes `origins[]`, and the promotion
gate's `default-origin-share` holds the default-only fraction under 10%.
Summaries are field-sensitive at the boundary: a sink effect records the
access path from the callee's parameter to the sunk value, and the caller
matches its taint on the SAME path — `summary-clean-sibling` (the
interprocedural clean-sibling negative) stays silent, and
`InterproceduralEngineTest` proves the negative BREAKS when access paths
collapse, exactly as P4 did for the intraprocedural one. Higher-order:
standalone lambda values lower into their OWN KIR functions with captures
renamed to `%c` parameters (the P3 `lambda-inlined` deviation closed); a
function-valued parameter's invocation keeps the value on the receiver; and
a callee's invoked-parameter facts apply the PASSED lambda's summary with
captures bound at the call site. Named limitation: invocation ARGUMENT
flows (a callee feeding its own taint through an invoked lambda's
parameter) are not tracked; callable references and local functions emit
`lambda-unresolved` and no summary.

**What ships (P6).** Coroutine builders and flow operators inline their
lambda bodies at LOWERING time, into the caller's context:
`launch`/`withContext`/`runBlocking`/`LaunchedEffect` plainly; `async` with
the body's value AS the call value (so `Deferred.await` — a pack
passthrough — carries it); `flow`/`channelFlow` with `emit`/`send`
assigning into the builder's value register; the flow operators binding the
flow value to the lambda parameter (a sanitizing `map` body sanitizes
everything downstream). `Channel.send` writes the element state;
`Channel.receive` reads it back (a new `elementFlows` pack tuple).
Suspend boundaries are transparent to the may-analysis — an ignored opcode
NOW IGNORED ON PURPOSE, with the comment in the transfer — and
`stats.suspendCrossingSlices` counts the slices whose trace crosses one.
The async tier is a dedicated corpus tier (7 fixtures, each with a negative
half) run by `gradlew corpusAsync` AND by the bench, so `async-recall` has
its own denominator while the sweeps and the native agent still see every
fixture directory.

**Gate, measured (JVM, darwin-aarch64, M4 Pro, fixtures+async tiers):**

- Taint recall: **1.000 (40 of 40)** at target >= 0.90 (raised from 0.85).
- Precision per flow: **1.000 (60 of 60 slices)** across fixtures AND async
  tiers together.
- `async-recall`: **1.000 (16 of 16)** on the async tier's own denominator.
- `summaries-computed`: **288 computed summaries over 88 slots; origins:
  computed=288, pack=52** — more than one producer.
- `default-origin-share`: **0.0000 (0 of 20 summary-crossing slices)**.
- `dependency-crossing-flows` LIVE: **2 cross-module and 2 cross-dependency
  slices** (the `summary-cross-module` fixture), flags computed from the
  slice ends; a baseline that loses all crossings FAILs. Read with the
  caveat the equal counts imply: every Gradle module in the corpus carries
  its own purl, so on this corpus `crossesDependency` is *collinear* with
  `crossesModule` — both flags are computed from real attribution, but no
  slice yet crosses into an EXTERNAL dependency, and that arm stays
  unexercised until P9 analyses dependency code.
- Integrity **0 of 60**; connectivity 1.000; the endpoint-kind check now
  also covers cross-function slices.
- Caps: **0** worklist cap hits over 252 analysed functions; **0** SCC cap
  hits over 286 SCCs.
- Corpus: 876 -> 1088 annotations, 789 -> 1001 evaluated outcomes: 939 pass /
  0 fail / xfail 62 (all scoped `known-fail=syntax:1`) / 0 xpass at the
  fixtures+async tiers; the two-way ratchet re-proven (broken expectation
  FAILs at both resolved slots; `known-fail=resolved:99` on a passing
  expectation XPASSes; restored, exit 0).
- Goldens: **204 pairs** (51 fixtures x 4 slots), 0 problems.
- Determinism: **104 of 104** fixture/slot pairs byte-identical across two
  JVM runs, **104 of 104** in the native image, **104 of 104** native ==
  JVM (`tool.commit` normalised). Native binary 96,140,416 B on the pinned
  GraalVM CE 25.3.4.1; all three components `available`.

**Pinned repos, re-measured (resolved slot, machine idle).** Two machines,
because the review re-ran them and the absolute numbers are not portable —
the ratios are what the gate reads:

| repo | P5/P6 wall (impl. machine) | ratio vs P4 there | review machine | slices | summaries computed |
| --- | --- | --- | --- | --- | --- |
| spring-fu | 10.8 s | 1.20x | 3.6 s | 0 | 1128 |
| anki-android | 237.9 s | **1.84x** | 38.7 s | 0 | 16953 |
| ktor-samples | 14.3 s | 1.12x | 5.0 s | 0 | 2057 |
| nowinandroid | 36.0 s | 1.46x | 3.7 s | 0 | 2424 |
| kampkit | 3.4 s | 1.26x | 0.3 s | 0 | 198 |

Repo slices stay **0** — correct even with summaries: none of the five
calls a pack source in a function whose transitive callees reach a pack
sink (the summaries found 17k functions worth of parameter behaviour on
anki-android alone, and none of it completes a source-to-sink path through
the shipped pack). Cross-dependency taint stays P9's. Lowering failures 0
on all five. `per-repo-flow-counts` and `per-repo-exported-reach` hold
their baselines for the first time on a baseline that carries flow data.

**The wall-clock finding, plainly**: summaries pushed anki-android past the
per-repo 1.5x allowance (1.84x) and nowinandroid near it (1.46x) on the
implementation machine; the median fixture wall is unchanged and four of
five repos are inside 1.5x. The review machine reproduces the same run at
roughly a sixth of the wall (38.7 s for anki-android), so the *ratio*, not
the second count, is the finding, and it is not independently confirmed
here — the P4 side was not re-measured on this hardware. The cost is the
SCC fixpoint re-running each member's analysis; the state budget (R58)
bounds its memory but not its time. The roadmap's P10 (worker parallelism,
`--max-analysis-seconds`, per-phase budgets) exists for exactly this; until
then the per-repo wall-clock check reads the delta against ITS baseline, so
a re-baseline records the cost and a future phase that removes it earns the
improvement back as a measured win.

Both figures come from `./gradlew corpusFull`, which until this review ran
one of the five repos while calling itself the full corpus (R64).

**Deviation 1 revisited (P4's).** `command-exec` and
`old-language-version` KEEP their added `readLine()`: their original flows
are parameter-shaped with no in-repo source, and summaries PROPAGATE
sources — they do not invent entry-point taint. Parameter-shaped flows from
unmodelled entry points stay out of scope until endpoint/entry modelling
(P7); the fixture-patch stands, now next to `summary-param-to-return`,
which pins the same shape where a source exists.

**Defects found and fixed during this phase** (R58-R61 below): the summary
engine's own OOM on a pinned repo; a P2-era implicit-this register that
never connected to the receiver's state; Gradle submodule file attribution
(the R5 twin); and a pack pattern that could never match the operator
rendering it models.

**Defects found and fixed during the review** (R62-R65 below): R54's
per-fact provenance applied to the joins and to neither of the other two
merges; every access path deeper than one field invisible while recall read
1.000, because no fixture in the corpus was ever two levels deep; a
`corpusFull` that measured one of five pinned repos and exited zero; and
the two transfer functions, still a copy of each other, now held in
lockstep by a parity test until a phase unifies them.

## Phase 4 — intraprocedural, field-sensitive taint (this branch)

Branch `feat/kosi-p4-taint`, off `feat/kosi` (`1aecdc0`).

**What ships.** `kosi-flow` (compiler-free: KIR + schema + model-pack types
only) runs forward, field-sensitive taint over every lowered function's CFG,
iterated with a worklist to a real fixpoint — loop-carried flows need the
second rotation and get it (`taint-loop-fixpoint` pins the shape a fixed
pass count silently misses). Sources, sinks, passthroughs, sanitizers and
effects are DATA in the shipped pack (`kosi-models`); the engine hard-codes
no rule about categories. Taint is tracked on access paths `(base, field*)`:
writing `obj.query` does not taint `obj.column` — `field-sensitivity`'s
negative half is golem's most valuable single negative, written before any
positive taint fixture, and `TaintEngineTest`
.aFieldInsensitiveEngineReportsTheCleanSibling proves it fails with access
paths collapsed (the annotation has teeth, not a vacuous pass). `field*` is
a path of up to five elements, not one: `nested-field-path` pins the
two-level positive and the two-level clean sibling, which is the depth the
whole corpus lacked until the P5/P6 review (R63). Scope
functions (let/run/apply/also/with/use) now inline their lambda bodies for
qualified calls too, bind `it` as a local and rebind `this` inside
apply/run/with bodies (`scope-function-flow` pins receiver taint through all
three bindings). `--dataflow reachable` intersects slices with call-graph
reachability; severity is DATA on sink pack entries.

**Lowering defects the new fixtures exposed (fixed, each lowering a shape the
validator or corpus can now see):** `x ?: return` emitted the return
mid-block (the elvis fallback now lowers inside the null arm's block, caught
by `kosi kir dump`'s CFG validation on the loop fixture); `for` loop
parameters read as member accesses on `this` (`isLocalReference` now binds
them); implicit `it` likewise. No `kir` format change.

**Pack entries corrected by executing them for the first time** (the P0 seed
was never run through an engine): `ProcessBuilder.<init>` [1] -> `[0]` and
constructor patterns render as the class FQN (the golem pattern-notation
lesson: `java.lang.ProcessBuilder.<init>` could never match the renderer's
`java.lang.ProcessBuilder`); `Runtime.exec`/`Logger.info`/`readValue`
receiver-vs-argument indexes; `map` passthrough [[1,-1]] -> [[0,-1]];
`MutableList.add` pattern matched to the renderer's owner-class form;
collection/stdlib passthroughs (`listOf`, `split`, `toTypedArray`,
`iterator`/`next`, `component1..5`) and empty-flow entries for the
mechanical calls the lowering itself generates (`isNull`, `equals`,
`iterator`, scope-function evidence edges) so they neither propagate nor
inflate `unknownCallPropagations`.

**Gate, measured (JVM, darwin-aarch64, M4 Pro):**

- Taint recall on the single-function tier: **1.000 (18 of 18 flow
  expectations)** at the resolved slots — target >= 0.85 (`taint-recall`).
- Precision per flow: **1.000 (22 of 22 slices)** — every reported slice was
  asked for by an expectation; target >= 0.95 (`precision-per-flow`, live
  for the first time since P0).
- Slice connectivity **1.000 over 22 slices**, integrity violations **0 of
  22** — and read the two apart. `connectivity` walks the edge list that
  `materialise` builds from consecutive trace nodes, so it is 1.000 **by
  construction**: its value is that it now reads NOT_EVALUATED over 0 slices
  instead of a vacuous pass, not that it can catch a bad trace. R54 is the
  proof — 3 of 11 slices carried a trace that did not start at its source
  while this line read 1.000. The check with teeth is
  `integrity-violations`, which since the R54 fix compares the endpoint node
  KINDS against the materialised node list rather than the trace against
  itself, and which reads 2 of 3 the moment the defect is reintroduced.
- `fixpointCapHits` **0 over 170 analysed functions** across all fixtures
  (`fixpoint-cap`, denominator published).
- Determinism, re-measured in review over **both** graph-bearing slots
  rather than `resolved` alone (R53 generalises: a slot the sweep never runs
  is a slot the sweep proves nothing about, and `exported` is the one whose
  missing reflection entry killed the P3 image): **70 of 70 fixture/slot
  pairs** byte-identical across two runs on the JVM, **70 of 70** in the
  native image, and **70 of 70** native == JVM with `tool.commit`
  normalised. `scripts/determinism-sweep.sh` deletes its outputs first,
  checks exit codes, asserts sizes and prints per-pair slice/node/edge
  counts. Native binary 95,743,696 B on GraalVM CE 25.3.4.1; `kosi version`
  in the image reports all three components `available`.
- Corpus: 876 annotations over 34 fixtures x 4 slots, **789 evaluated
  outcomes**: 765 pass /
  0 fail / 24 xfail / 0 xpass; structural recall 1.000 (411 of 411). The
  xfail count grew 14 -> 24 — every one of the new markers is a flow
  expectation scoped `known-fail=syntax:1` (defect 1 remains open at the
  syntax tier BY DESIGN); the resolved-tier flow xfails went 8 -> 0. The
  two-way ratchet re-proven on this branch (broken expectation FAIL;
  `known-fail=resolved:99` on a passing expectation XPASS at both resolved
  slots; restored, exit 0).
- Goldens: 136 pairs (34 fixtures x 4 slots), 0 problems.
- Repo tiers (all five pinned repos, 4 slots each): 0 failed expectations,
  0 xpass, 0 slices — correct: no repo calls a pack source in a function
  with a pack sink (cross-function flows are P5). Engine cost measured A/B
  on spring-fu: 9.36 s (`--dataflow none`) vs 9.04 s (`security`) — within
  noise; a fixpoint over functions with no facts is one CFG walk. Per-repo
  `resolvedCallRatio` unchanged to four decimals (spring-fu 0.9405, anki
  0.9232, ktor 0.9024, nowinandroid 0.7564, kampkit 0.6639). Per-repo
  exported-reach against the declarations[] denominator, first real
  measurement (pre-R49 figures read a tautological 1.0000): ktor 0.9932
  (441/444), nowinandroid 0.9904 (617/623), kampkit 0.9865 (73/74), anki
  0.9620 (7183/7467), **spring-fu 0.5359 (447/834)** — the gap is dominated
  by public methods DECLARED IN JAVA (the repo's `*Initializer` modules),
  the R49 `Greeter.greet` defect at repo scale, owned by P9's bytecode
  tier. The `exported-reach` check keeps the P3 roadmap's fixture scope for
  its 0.95 bar; the per-repo absolute bar returns with P9, and until then
  `per-repo-exported-reach` (added in review, R56) ratchets the five repo
  fractions against the baseline so an excluded population is still measured
  by something.

**Defect 1 narrowed:** `command-exec` and `old-language-version`'s flow
expectations now read real slices at the resolved tier (each fixture gained a
pack source call — `readLine()` — the flows were parameter-shaped, which is
P5's summaries, not P4's intraprocedural sources); their markers are scoped
`known-fail=syntax:1`. `FlowFoundAcrossLanguageVersionRange` asserts the
fixture's flow PASSES at every accepted language version.

## Phase 3 — the call graph and reachability

Merged 2026-09-10 (`feat/kosi` at `1aecdc0`, squashed).

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
6. **Every kosi JVM runs headless and out of the macOS Dock.** The Analysis
   API brings in intellij-core, which initialises AWT; without
   `-Djava.awt.headless=true -Dapple.awt.UIElement=true` an analyze run
   registers as an application and takes keyboard focus, once per fixture.
   Set in the build for tests and the bench JavaExecs, in
   `org.gradle.jvmargs` for the daemon, in `applicationDefaultJvmArgs` for
   the launcher, and in `main()` for the fat jar and the native image, where
   there is no launcher to set it. (R57)
7. **`dependency-crossing-flows` reports NOT_EVALUATED, not PASS, while the
   engine is intraprocedural.** Both ends of every slice are one function,
   so nothing can violate the criterion; a criterion nothing could have
   violated must not be counted as met. It becomes a real comparison in P5.
   (R55) — it is live since P5, with the collinearity caveat recorded in
   that section: no slice yet crosses into an EXTERNAL dependency.
8. **The two dataflow transfer functions are duplicated, not shared.**
   `TaintEngine`'s and `SummaryAnalysis`'s are the same ~700 lines over two
   fact types. Unification is P7's first item; until then
   `TransferParityTest` fails the build when one learns an opcode the other
   does not. (R65)

## Defects found and fixed during the P5/P6 implementation

| # | Area | Defect | Fix |
|---|------|--------|-----|
| R58 | kosi-flow | **the summary engine crashed the JVM with OutOfMemoryError on a pinned repo** (anki-android): a summary analysis's live state (registers x facts) grows with the body's size and path fan-out, and nothing bounded it — the per-function instruction cap bounded the MAIN analysis but not the summary one, and the first full-repo measurement died instead of degrading. Found by this phase's own per-repo measurement, not by the fixture tier | a deterministic state budget (`maxSummaryStateEntries`, 60k register+fact entries, checked per worklist round): an over-budget summary is DROPPED, never partially published — callers fall to the labelled `origin=default` — and the drop is counted in `stats.truncations{}` (`summary-state-budget`). Functions over the body budget are likewise skipped from summarisation (`summary-oversized-function`), matching the main analysis. A summary that is silently absent is a counted absence |
| R59 | kosi-front | **member reads and writes on the IMPLICIT receiver never saw the receiver's state.** `currentThis()` returned the register `"v this"` (with a space) while the entry parameter store binds `"vthis"` — two names, one receiver, so `fun stage(raw: String) { command = raw }` stored taint into a register nothing would ever read, and P2-era fixtures masked it by using explicit receivers | one naming: the implicit receiver IS the entry store (`v$this` from `bindParameters`). Found by `summary-param-to-receiver`, whose whole flow lives on the implicit this |
| R60 | kosi-project | **files collected under a Gradle submodule were attributed to the root module**: submodule source roots arrive MODULE-RELATIVE (`src/main/kotlin`) but were resolved against the analysis root, so only the root module's inferred sweep collected anything — and its `"."` attribution won `distinctBy(relativePath)`. The Gradle twin of R5 (nested Maven), with the same face: a module boundary the report flattens into a blob | root-relative miss falls back to the module's own directory, and a file reachable from several modules attributes to the MOST SPECIFIC module (longest modulePath). Found by `summary-cross-module`: `crossesModule` read false while the trace visibly crossed modules |
| R61 | kosi-models | **`kotlin.text.plus` could never match the `+` operator rendering.** `"a" + b` with a NON-null receiver resolves to `kotlin.text.plus`, but with a NULLABLE receiver to `kotlin.plus` — the pack modelled only the former, so every nullable `+` chain leaned on the unknown-call default (invisible until the default-origin gate measured it) | both patterns shipped, plus `trim`/`replace`/`lowercase`/`uppercase`/`substring` — the string passthroughs the corpus demonstrated were missing. Data fixed at the pack, not special-cased in the engine (the P4 lesson, twice now) |

## Defects found and fixed during the P5/P6 review

| # | Area | Defect | Fix |
|---|------|--------|-----|
| R62 | kosi-flow | **R54's per-fact provenance was applied to the joins and to nothing else.** Concat, phi and elvis blame the operand that actually carried each fact; the element read (`KirIndexGet`, merging the collection's element state with the collection value) and the unknown-call default (merging the receiver and every argument) still blamed *the first non-empty operand* for every fact they merged — in BOTH transfer functions. Two sources into one unresolvable call is enough: the fact that arrived on the second argument gets a move pointing at the first, the backward walk dead-ends in a register that never held it, and the P4 endpoint net quietly stamps the slice `elided` | per-fact blame at all four sites, matching `joinInto`. Proven by `TaintEngineTest.everyMergeAttributesPerFactNotJustTheJoins`, which fails on the restored defect |
| R63 | kosi-front | **every access path deeper than one field was invisible, and recall read 1.000 anyway.** `AccessPath` has carried `elements: List<Element>` with a depth-5 cap since P2, and both engines join those elements into the state key — but the lowering only ever emitted length-ONE paths. `o.inner.a = readLine()` became `t4 = fieldget vo vo.inner; fieldset t4 t4.a`, while the read `o.inner.a` hung off a *different* temporary: the write and the read never met, intraprocedurally or across a summary. Nothing in 50 fixtures used a two-level path, so `accessPathDepth: 5` was advertised in the options, honoured by the engines, and unreachable — and the P5 clean-sibling negatives were vacuous below depth one | the lowering composes a syntactic `a.b.c` qualifier chain into ONE path off the chain's base register, for reads, writes and compound assignments alike; `AccessPath.of` still collapses past the cap. Both engines are fixed by the one change. New fixture `nested-field-path` carries the positive, the interprocedural positive and the depth-two clean sibling; restoring the defect fails all four (two positives x two slots) |
| R64 | kosi-corpus | **`corpusFull` measured one of the five pinned repos and exited zero.** The task asked for tiers `fixtures,async,small,vuln,ported`: `vuln` and `ported` have never existed in `corpus.toml`, and the four tiers that hold the other repos — `medium`, `android`, `kmp`, `hybrid` — were not named. `select` filtered an unknown tier to nothing and said nothing, so the documented full-corpus command silently covered `ktor-samples` alone. The repo evidence in the P5/P6 report came from ad-hoc `--tier` invocations, not from the command the docs give a reader | the task names every tier the manifest carries, and `select` now REQUIRES each requested tier to exist — a typo'd tier is an error, not a quiet reduction in coverage |
| R65 | kosi-flow | **the two transfer functions are a copy of each other with the fact type changed** (`TaintFact` vs `SummaryFact`): the same joins, field and index handling, unknown-call default and sink matching, ~700 lines each, and they must agree or a summary describes a function differently from the engine consuming it. R62 is what the drift looks like when it is small. Not fixed here — unification is a phase of its own | `TransferParityTest` pins the cheapest observable that catches the likeliest drift: an opcode one transfer learned and the other did not fails the build naming the opcode. Recorded as the first item of P7 |

## Defect registry (numbers referenced by `known-fail=<backend>:<n>`)

| # | backend | defect | status |
| --- | --- | --- | --- |
| 1 | syntax | no flow engine at the syntax tier: no slices, no call graph; the flow expectations of `command-exec`, `old-language-version` and the six P4 taint fixtures carry `known-fail=syntax:1` for their flows. **At the resolved tier this defect is closed (P4): the same expectations are live ratchets there and must pass** | open (syntax tier) — closed at resolved in P4 |
| 2 | syntax | Java sources are listed in `files[]` but not parsed at the syntax tier: their declarations are absent (R19 added the diagnostic; P1 closes the gap at the resolved tier, where Java PSI is parsed through the same symbols). `java-interop` and `empty-classpath` carry `known-fail=syntax:2` on the expectations that need the resolved tier | open (resolved tier: closed) |
| 3 | resolved | the native image attaches no JDK module: `java.home` is unset in an image, so `java.*` symbols go unresolved (reported as `classpath-partial`, and visible in the ratio — `weak-crypto` resolves 0/4 in the image vs 4/4 on the JVM), and `--jdk-home` fails with `ProviderNotFoundException: Provider "jrt" not found` because the image has no jrt filesystem provider for a modular JDK's `lib/modules`. Resolved-tier native output is therefore not byte-identical to JVM output; the syntax tier is unaffected | **closed in P2** — the image reads `lib/modules` through its own jimage reader and attaches per-module jars; `weak-crypto` 4/4 in the image, 8 fixtures byte-identical native vs JVM, `--jdk-home` works or is a usage error (see Phase 2) |

## Defects found and fixed during the P4 review

| # | Area | Defect | Fix |
|---|------|--------|-----|
| R54 | kosi-flow | **3 of 11 fixture slices carried a trace that did not start at the source, and the run reported connectivity 1.000 with 0 integrity violations.** `KirElvis` merged its operands' facts and recorded no provenance move, so the backward walk dead-ended at every `x ?: y` on a taint path — and `readLine() ?: ""` appears in four fixtures. The emitted trace then began wherever the walk happened to stop (`scope-function-flow`'s two slices began at a *field write*), `elided` was null, and nothing caught it: `isConnected` walks the edge list that `materialise` builds from consecutive trace nodes, so it is 1.000 **by construction** and can only catch a defect in id assignment. `everySliceSatisfiesTheTraceInvariants` asserted `sourceId in nodeIds`, which is trivially true — `sourceId` *is* `nodeIds.first()`. The phase's "connectivity is a real check for the first time" is the claim this disproves | three changes, each independent of the others. (1) Elvis records provenance, and concat/phi/elvis now attribute **per fact** to the operand that carried it, through one `joinInto` helper — blaming the first non-empty operand sends the other fact's walk into a register that never held it. (2) `buildSlice` GUARANTEES the endpoints: when the walk does not reach the birth move — cap, cycle, or missing provenance — the source site is prepended and the slice is marked `elided`, so a cut trace looks cut. (3) `invariantsHold` checks the endpoint node KINDS against the materialised node list, which is the one property here not derived from the trace-building code. Measured after the fix: 0 of 22 slices broken, same 22 slices, 4 goldens changed. Proven to have teeth by reintroducing the defect: elvis alone -> 2 of 3 slices marked `elided`; elvis plus the endpoint guarantee removed -> **integrityViolations 2 of 3** where it read 0 before. `anElvisOnTheTaintPathKeepsTheSourceEndpoint`, `aTraceTruncatedByTheCapKeepsItsSourceAndSaysSo`, `aJoinAttributesEachFactToTheOperandThatCarriedIt` |
| R55 | kosi-bench | `dependency-crossing-flows` reported **PASS** on a criterion nothing could have violated. Both ends of an intraprocedural slice are the same function, so `crossesDependency` is false for a structural reason — and the count the gate read back was written as the literal `0` two modules away. R49's shape with a different variable name: a green line that carries no information | the stats field is counted from the slices (`slices.count { it.crossesDependency }`, likewise `reachableSlices`) instead of asserted, and the zero case is **NOT_EVALUATED** naming why nothing could have violated it. Nonzero still FAILs. It becomes a real comparison in P5, when summaries give a slice two ends. `crossDependencyIsCountedFromTheSlicesNotAsserted` |
| R56 | kosi-bench | **`exported-reach`'s population shrank in the same change that would have made it fail.** P3 summed every exported slot; P4 restricted the 0.95 bar to the fixture tier, and the excluded repos include spring-fu at **0.5359**. The reason given is sound — the repo denominators only became honest with R49, and the misses are Java-declared bodies that P9's bytecode tier owns — but "reported in the detail line" is not a check. spring-fu could fall from 0.5359 to 0.05 and every gate would stay green | the fixture bar stands (holding this phase on a named P9 defect would hold it on work it does not own), and the repo figures gain `per-repo-exported-reach`: no absolute bar, but a repo may not DROP more than half a point against its baseline. The same two-way discipline the corpus ratchet uses, and it costs nothing — the numbers were already measured |
| R57 | build | **every `kosi analyze` stole keyboard focus on macOS.** The Analysis API pulls in intellij-core, which initialises AWT; the JVM then registers as a real application, appears in the Dock and takes focus on startup. A corpus run over 35 fixtures does that 35 times and makes the machine unusable while it runs — reported from the far side of a review, which is the only way a defect like this surfaces | `-Djava.awt.headless=true -Dapple.awt.UIElement=true` on every JVM the build starts (`HEADLESS_JVM_ARGS` for tests and the `kosiTask` JavaExecs, `org.gradle.jvmargs` for the daemon, `applicationDefaultJvmArgs` for the installed launcher) and, for the paths that have no launcher — `java -jar kosi-all.jar` and the native image — set in `main()` before anything can touch the toolkit, never overriding a value the caller chose |

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
