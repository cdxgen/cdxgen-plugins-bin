# Kosi phase status and defect registry

Companion to `$HOME/kotlin-plans/07-REVIEW-PROTOCOL.md`: merged phases,
measured numbers, and the numbered defects that `known-fail=<n>` corpus
markers refer to. Defects stay numbered; closing one requires the XPASS
ratchet proof.

## P15 — the engine under a real classpath (this branch)

Branch `feat/kosi-p15-engine-under-load`, off `feat/kosi` (`8e578f6`).

**§1 — the per-class cost of a large attached classpath, measured and
fixed.** The dominant retainer was neither the KIR nor the Analysis API
session nor the summaries' published form — it was kosi's own COMPOSED
summary sink-effects. Measured with a mid-run `GC.class_histogram`
polled every 1.5s while AndroGoat's warmed classpath lowered its whole
wanted closure (fresh JVM, JDK 21):

| deps classes lowered | peak live heap | outcome |
|---|---|---|
| 0 (resolved slot only) | 465 MB | completes, 5.4 s |
| 25 | 494 MB | completes |
| 50 | 903 MB | completes |
| 100 | 1067 MB | completes |
| 200 | > 8 GB | GC death (25 min, killed) |
| 500 (the default cap) | 8.5 GB at OOM | **OOM even on a 12g heap** |

The histogram at the peak: **68,292,827 `SummarySinkEffect` instances
(3.8 GB) + 23M byte[]/String (3.8 GB)** — the KIR itself was 13k KirCall
instances, the PSI/session invisible at this scale. The mechanism:
`recordComposedSinkEffects` re-records every callee effect joined with
every live fact, KEYED BY THE JOINED param path, and `joinPath` is
unbounded — so a recursive cluster composes ever-deeper paths and every
deeper join is a NEW map key. The instrumented run named it:
`androidx.fragment.app.FragmentManagerImpl.moveToState` grew 8k → 1M
effects across SCC iterations while its param paths deepened
`mActive.mChildFragmentManager.mTmpRecords.mIndex` → depth 15. Every one
of those effects is UNFIREABLE: a fact key's path is one LOWERED access
path, and `AccessPath.of` keeps at most five elements and appends `*`
when it cuts — so six segments is the deepest key either engine can
spell, and an effect whose param path is deeper can never match any
fact. (The bound is the lowering's, NOT `Options.accessPathDepth`, which
only switches field sensitivity on and off; reading it off the option
cost a real flow — R91.)

Two bounds, both in `SummaryAnalysis.recordEffect` and both unit-pinned
(`composedParamPathsNoFactKeyCanSpellAreDropped`,
`anEscapeSetPastItsBudgetDropsTheWholeSummary` — each fails with its
bound restored):

1. A composed param path deeper than the deepest path the lowering can
   put on a fact key is DROPPED, exactly — it can never match one at
   application time.
2. The effect map is budgeted like the state (R58's rule):
   `maxSummarySinkEffects` (8192) trips `stateOverBudget`, the summary
   is dropped WHOLE, and the run counts it in `stats.truncations` as
   `summary-effect-budget` (AndroGoat's 500-class closure: 25 trips,
   loudly).

After: AndroGoat's 161-jar classpath lowers its whole 300-class wanted
closure at a **~1 GB peak in ~16 s** (500-class cap never trips; the
closure is 300). `deps_max_classes = 50` is DELETED from corpus.toml and
the corpus JVM heap comes down 8g → **6g** (metaspace stays 1g). The
honest accounting of what the remaining 6g buys: ~500 sessions share one
JVM and the Analysis API's per-session caches accumulate (the pre-P9
note in the build file), and the from-empty warm attaches each repo's
FULL transitive closure — 20-40% more jars than the stale partial lists
P14's 8g run measured against (anki 710 → 1010 coordinates, nowinandroid
918 → 1100). At 3g and at 4g the warmed matrix GC-thrashed without
dying (measured, 20+ minutes of 1000%-CPU full GCs); 6g completes. The
SINGLE-SESSION driver — the 8.5 GB deps-slot spike that pinned the cap —
is gone. Proof the fix changes nothing where nothing exploded:
kosi-vulnerable-service's deps slot is byte-identical pristine-vs-fixed
(`dataFlow` including `summaries`, and `stats`), and the 432 pre-P15
golden digests did not move — the 12 new goldens are this phase's two
new fixtures.

**§2 — the five `unreachable-but-emitted block` findings on InsecureShop,
root-caused as TWO defects.** Reduced to InsecureShop's four functions
(five findings: ChooserActivity.makeTempCopy x2, LoginActivity.onLogin,
SendingDataViaActionActivity.onSendData, Util.verifyUserNamePassword):

1. **Missing exceptional edges (cause A) — NOT harmless.** Catch
   handlers lowered as standalone blocks with NO incoming edge: the CFG
   has no exceptional-edge instruction, so every `catch` body was
   structurally unreachable, never analysed, and taint through it
   silently dropped (onLogin's `catch (e) { throw RuntimeException(e) }`,
   makeTempCopy's `catch { return null }`). Fixed in `lowerTry`: two
   may-edges into a DISPATCH CHAIN over the handlers — from the try
   body's entry (a throw at the first call; the only edge possible when
   the body ends terminated) and from the body's open end — so every
   handler is reachable with the fork's state, no handler flows into
   another (the exception's type picks one at run time; the KIR cannot
   express that, so all are alternatives), and the transfer's
   may-successor treatment of branch arms makes a true-condition branch
   exactly this edge.
2. **Dead tail blocks (cause B) — harmless noise, now not emitted.** An
   all-paths-returned construct (both if/else arms return; try body and
   handler both return) still started its join/continuation block.
   `finish()` now drops unreachable blocks (ids stable, no renumbering)
   and strips their phi inputs.

Success condition met: `kosi kir dump` on InsecureShop validates CLEAN.
Fixture `catch-handler-flow` pins the dropped flow (source before the
try, sink INSIDE the handler — with cause A restored the slice is
absent) and the negatives (sanitized-before-try stays clean; the
handler's clean sibling stays clean). KirLoweringTest pins both causes
through the kir dump's own CFG validation (restored defects: the dump
REFUSES the module). InsecureShop's floor did NOT move (its catch
handlers carry no pack source-to-sink path) — measured, not assumed.

**§3 — nowinandroid's 266 unlocatable coordinates, mapped per cause
before any code.** Of the 266: 1 carried an AAR and 2 carried jars ON
DISK under file names no rule derives (`window-core.aar`,
`Turbine-jvm.jar`, `roborazzi-painter-jvm.jar`) — the Gradle Module
Metadata `.module` beside them declares those names, and Gradle stores
each file under its OWN content hash, so the `.module` and the artifact
sit in different hash directories; 229 had no binary under their own
coordinate but a same-base sibling variant did (`animation-android`'s
alpha carries no AAR anywhere, `animation-jvmstubs` carries the API
jar); 34 have no binary at any variant at that version (never
downloaded). Two rules added to the resolver, each covered by a
`ClasspathResolverTest` case on a synthetic cache layout (P13's
pattern), both failing with their rule restored:

1. `.module`-declared artifact FILE names, searched across the whole
   version directory, metadata/docs-usage variants excluded (a
   kotlin-metadata jar is not a binary root).
2. Same-base variant siblings in preference order — the real JVM code
   first (`-desktop`), then `-jvm`, the umbrella, the JVM API stubs
   (`-jvmstubs`), the Android AAR last — never widening to a different
   library of the same group.

nowinandroid: **0.7564 → 0.8150** (5132/6297), missing 266 → 94 — the 94
are the no-binary-anywhere set, unfixable without downloading (kosi is
offline by design; the warm script's job, not the resolver's). No repo
crossed 0.90, so no gate membership changed.

**§4 — media and auth beyond the four frameworks that had it.** Three
new declaration sites, all pack-driven, each pinned by fixture
`dsl-media-auth` with its negative half (restore-the-defect proven: all
three channels off → every field empty → the wants FAIL):

- **Vert.x**: media sits on the ROUTE OBJECT between the route call and
  the handler (`router.get("/x").produces("application/json").handler {}
  — read from the chained calls (pack `mediaDsl`/`handlerDsl`), folding
  each media argument at its own call site and seeing through the
  SAM-constructor wrapper around the handler lambda.
- **Javalin**: the route builder's vararg RouteRole tail IS the
  requirement (`get("/x", handler, Role.ADMIN)` — pack
  `roleArgumentStart`); the handler is the argument BEFORE the roles,
  which the last-argument read used to lose entirely.
- **web.xml `<security-constraint>`**: the deployment descriptor's own
  authentication requirement, parsed (P13 parsed the element past it)
  and attached per url-pattern with servlet-spec matching — roles
  (`security-constraint(admin,auditor)`), the empty `<auth-constraint/>`
  DENY-ALL, the `*` wildcard, and the transport-only constraint (no
  auth-constraint element) correctly attaching NOTHING.
- **http4k, servlet media, Vert.x auth**: genuinely no declaration site
  in the shapes the KIR can attribute to one route — said so in the
  PACK'S OWN `_p15_comment` rather than leaving the empties ambiguous.

The consumer question: **the SARIF writer now carries the endpoint on
every result that entered through one** (`properties.endpoint`:
authentication/consumes/produces/framework/path, pinned by
`anEndpointLinkedSliceCarriesItsAuthenticationIntoTheExport`) — before
P15 the three fields were facts kosi computed and threw away at the
first export boundary. The cdxgen SaaSBOM arm
(`lib/ecosystems/kosi.js`, cdxgen checkout, `feat/kosi-evinse-tmp`)
still drops `apiEndpoints` entirely — it reads `services[]` only; fixing
that belongs to that repo's branch and is named as the follow-up.

**§5 — the corpus warm, reproducible.** `warm-corpus-classpath.sh`:

- **The monorepo bound**: a merged tree carrying many VERSIONS of the
  same group:artifact (http4k's killed-mid-run state: 10,923 lines,
  1466 of them the IDENTICAL `kotlin-stdlib:2.4.0`, 253 unique
  group:artifact pairs) is collapsed to ONE version per pair — the
  HIGHEST, numeric segment-wise, the rule Gradle's own conflict
  resolution applies — then hard-capped (`KOSI_WARM_MAX_COORDS`, default
  2000, the cut printed). The bound runs BEFORE the artifact pull
  (bounding the resolve input) and AGAIN AFTER (the transitive-closure
  merge re-introduces the other versions).
- **SIGPIPE removed**: the one early-exiting pipe consumer
  (`head -1` after a grep, under `set -o pipefail`) is now `sed -n 1p`.
- **Honest exit codes on every arm**: a multi-repo warm records
  per-repo failures, warms the REST (one broken repo no longer leaves
  the tier's other floors measuring against cold caches), and exits 1
  naming every failure; an Android-shaped classpath whose framework jar
  cannot be fetched FAILS (the floors are measured against it).

Full warm from an EMPTY `.corpus-cache`: every tier re-fetched at its
pinned SHA and warmed clean, exit 0 per tier — per-repo coordinate
counts in the phase report. Those counts were produced BEFORE R92: the
numeric bound never ran and a leftover string comparison pruned the
lists instead, so a handful of coordinates were pinned to a lower
version (`2.4.0` over `2.10.0`). The lists must be re-warmed and the
per-repo counts and ratios re-measured on the corpus machine — named in
the P16 prompt as its first task.


## P14 — real repos, framework generations, and the findings ratchet (this branch)

Branch `feat/kosi-p14-real-repos`, off `feat/kosi` (`0443465`). The one
rule that governed the phase: **a capability no fixture exercises is a
capability you have not shipped, and a number no gate ratchets is a number
that will silently rot.**

**§1 — the five pinned repos re-measured, every classpath warmed from
scratch.** The P1-era ratios were recorded before R81's locator fix, so
every number was measured against a classpath that could not find KMP
artifacts. Re-warmed and re-measured on the PRISTINE branch state (a
worktree at `0443465`, jars fetched from an empty resolve), resolved slot:

| repo | recorded (P1) | re-measured (P14) | note |
|---|---|---|---|
| spring-fu | 0.9405 | 0.9405 (3763/4001) | unchanged; 3 unlocatable: 2 BOMs (no artifact) + junit-jupiter-params:5.8.2 |
| anki-android | 0.9232 | 0.9232 (60644/65692) | unchanged; 149 unlocatable, all AAR/`-android` variants |
| ktor-samples | 0.9024 | 0.9024 (5093/5644) | unchanged; 50 unlocatable, sample-specific deps the resolver failed on |
| nowinandroid | 0.7564 | 0.7564 (4763/6297) | UNCHANGED — see below |
| kampkit | 0.6639 | **0.7551** (447/592) | +0.09: the KMP `-jvm` jars (kotlinx, ktor-client) now attach via R81 |

The honest headline: the R81 fix recovered **kampkit only**. nowinandroid
is unchanged to FOUR DECIMALS, and its gap is what the old paragraph said
it was — now re-derived from the current run instead of copied forward:
266 named unlocatable coordinates, of which 104 are `-android` variants
(on disk as AARs, which no locator rule names), 108 pre-release
alpha/beta AndroidX builds, and the rest parent coordinates whose
on-disk artifact is the AAR. kampkit's remaining 292 are 167 ios/native
variants (no JVM artifact exists — inherent to JVM-tier analysis), 40
`-android` variants, and 85 AndroidX compose parents. No repo crossed the
0.90 target, so no gate membership changed. **R85** records that the
"0.23 -> 1.0" one-app result does not generalise to repos whose misses are
AAR-shaped, not name-shaped.

**§2 — framework GENERATIONS.** The audit of both packs for
generation-encoding FQNs, against the real artifacts (ktor-server-core-jvm
3.0.0, httpclient5 5.3.1, okhttp 4.12.0):

- servlet/JMS/persistence: both generations already modelled;
  HttpClient 4 AND 5 already modelled (P12) — but pinned by no fixture
  until `framework-generations`.
- **Missing, added**: `javax.ws.rs.PATCH` (jakarta twin shipped, javax did
  not), `javax.ws.rs.BeanParam`, `javax.ws.rs.core.UriInfo.getPathParameters`
  (jakarta shipped BOTH readers, javax only one), and OkHttp 4/5's Kotlin
  generation — `okhttp3.HttpUrl.Companion.toHttpUrl`/`toHttpUrlOrNull`
  beside the OkHttp 3 Java static `HttpUrl.parse`.
- **Ktor 3 (checked, no pack change needed)**: the verb builders stay at
  Ktor 2's FQNs (`io.ktor.server.routing.get`, verified against the 3.0.0
  artifact's `RoutingBuilderKt`); what moved is the handler RECEIVER
  (`RoutingContext`, whose `call` is §4's own bare-name accessor shape).
  `RoutingCall.pathParameters` was already modelled. The fixture pins a
  Ktor-3-shaped app end to end.
- **jakarta.mail / Bouncy Castle providers / android.support**: nothing is
  modelled in ANY generation — these families are entirely outside the
  pack's surface (a pack-surface fact, not a generation gap; recorded so
  the next audit does not re-derive it).
- **AndroidX vs support-lib**: every modelled `android.*` API is a
  framework class that never moved; no modelled API has a support-lib
  twin.

Fixtures: `framework-generations` (both JAX-RS generations' routing +
UriInfo readers + media/auth, jakarta servlet, OkHttp 3 and 4/5,
HttpClient 4 and 5, Ktor 3) — six flows and five endpoints, each with its
near-miss. Teeth: stripping the four added pack entries fails exactly
three resolved-slot expectations (the UriInfo twin flow, the PATCH
endpoint, the toHttpUrl sink); restored, all pass.

**§2.3 — a miss is never a WRONG answer.** R84 handed Ktor 1.x routes to
Vert.x; R74's evidence-preference still fell back to first-match when NO
framework's package was present. The fallback is gone: an unevidenced
name-match publishes under the reserved pseudo-framework `unattributed`
(`foundBy = "dsl-unattributed"`, no verb list — a verb would name a
framework's builder, which is exactly the claim that cannot be made).
`unattributed` is a reserved id in the corpus vocabulary, so fixtures can
pin it. Fixture `unattributed-route`: a module with unresolved `get`/`post`
route calls and no framework packages anywhere. Teeth: restoring the
`?: byName.firstOrNull()` fallback fails the resolved slot three ways —
`unattributed /legacy` not found, `unattributed /api/data` not found, and
`javalin /legacy` FOUND (the wrong answer, by pack list order).

**§3 — the findings ratchet.** The vuln tier existed but nothing pinned
what it must FIND: a change could take any deliberately vulnerable app to
zero with a green build, which is how P11 shipped zero findings everywhere.
Now:

- `corpus.toml` carries `min_findings` per vuln-repo entry, and the
  `vuln-finding-floor` promotion check enforces it TWO-WAY over the
  resolved slot: below the floor FAILS; MATERIALLY above it (more than
  max(2 slices, 25%) over) FAILS until the floor is raised, so an
  improvement is recorded rather than absorbed; a DECLARED classpath file
  that is missing FAILS (R73's shape — a floor measured against an empty
  classpath is a floor nobody measured). `VulnFindingFloorGateTest` covers
  all eight outcomes.
- The `vuln-repo` tier (separate from `vuln`, so corpusQuick keeps its
  no-network population): AndroGoat, InsecureShop, and
  `tsp-vulnerable-app-kotlin-ktor` — the single-file Ktor 1.6.7 app that
  exposed R80–R84, pinned as their regression anchor. Measured (bench,
  resolved slot, warmed): androgoat **16** slices / 33 endpoints,
  insecureshop **7** / 12, tsp **2** / 2 — and tsp's ratio is exactly
  **1.0**, reproducing R81's headline on the anchor app. The floors are
  these measurements.
- `warm-corpus-classpath.sh --tier <name>` reads the slugs from
  corpus.toml; a warm that downloads nothing EXITS 1 (R73's silent
  WARNING is gone — measured: androgoat with a broken extraction arm
  fails the script, the fixed arm passes).

**R86 — the textual warming arm's direct-only list (found by §3's own
floor).** The Android vuln repos' builds (AGP 3.x, JDK 8) cannot run their
dependency reports on any JVM this machine has, so the warm script gained
a textual fallback that reads `group:artifact:version` literals from the
build files. The first version listed only DIRECTS — and a direct-only
classpath leaves the transitive tree unattached: InsecureShop's
`AppCompatActivity` degraded with MISSING_DEPENDENCY_SUPERCLASS (its
appcompat needs androidx.fragment/core), and the app measured **0 slices
against a warm-looking classpath** — R73's failure mode, reproduced by a
warmer that worked. The scratch resolver now prints each coordinate's
RESOLVED transitive closure and the script merges it into the list
(InsecureShop's list went 14 -> 184 entries, its findings 0 -> 7 — the
P13 number — and its ratio 0.674 -> 0.915).

**R87 — six colliding `<accessor>` functions (pre-existing since P5,
found promoting InsecureShop).** Every `KtPropertyAccessor` lowered as
`<accessor>` — no name of its own — so a class with several custom
accessors produced N functions with ONE canonical name: InsecureShop's
`Prefs` object carried six `com.insecureshop.util.Prefs.<accessor>`
functions, the KIR validator named the duplicates, and `kir dump` refused
the module outright. Accessors now take the JVM name of the property they
belong to (`getData`/`setData`). Still open on this repo: five
`unreachable-but-emitted block` validation findings (ChooserActivity,
LoginActivity, SendingDataViaActionActivity, Util) — named, not fixed;
nothing in this phase asked for engine work.

**§4 — the bare-name accessor read (R80's sibling).** `resolveProperty`
was wired into `dotChain` only, so a bare-name read of an accessor-backed
property — `call` inside a Ktor route lambda, `parameters` inside an
extension on ApplicationCall — lowered as `fieldget vthis vthis.call`,
invisible to every pack. `reference()` now resolves the reference and
lowers as a call ONLY when the property demonstrably has no backing field
(a member/extension accessor runs against the implicit receiver; a
top-level one is static); a property WITH a backing field keeps its access
path. Fixture `bare-accessor-source` pins the accessor flow (`ApplicationCall.parameters`
read bare through an extension receiver — the pack's own source pattern)
beside the backing-field half (a bare member read through an inlined
`with` receiver still flows through its FIELD path, clean sibling stays
clean). Unit teeth: `aBareNameAccessorReadLowersAsTheCallItIs` fails on
the restored defect; corpus teeth: the fixture's resolved slot fails its
`queryEcho` flow with the defect restored while the field flow keeps
passing. **Corpus slice counts did not move: 480 of 480 fixture/slot pairs
identical between the pristine jar and this branch** (both runs 0 fail /
0 xpass) — R80's proof shape, at P13's fixture count. No findings
improvement is claimed from this item (nothing shipped models such a
property as a source before the fixture).

**§5 — `consumes`, `produces`, `authentication`.** These were
`emptyList()` on every endpoint kosi had ever emitted; all three are
filled from the pack as data, from where the frameworks themselves put
them:

- NAMED annotation arguments (Spring's `@RequestMapping(consumes=..)`) —
  a new named-argument channel through the annotation evidence, because
  the argument's NAME is the only difference between consumes and
  produces. A method-level declaration REPLACES the class default for its
  kind (Spring's own routing rule; the first implementation appended both
  — caught by the fixture, fixed before commit).
- POSITIONAL value arguments (JAX-RS `@Consumes`/`@Produces`, Micronaut).
- Auth annotations on the handler or its class (`@PreAuthorize`,
  `@RolesAllowed`, `@Secured`), value carried: `@PreAuthorize(hasRole('AUDITOR'))`.
- Ktor's `authenticate("basic") { }` — the requirement sits on the
  ENCLOSING nesting call, collected by walking the same lambda links the
  route prefixes use: `authenticate(basic)`.

Fixture `endpoint-media-auth` (Spring, JAX-RS, Micronaut, Ktor in one
tree). Honest empties: servlet has no media/auth annotations to read, and
a bare DSL route declares none — those lists stay empty because nothing
declares them. Teeth: reverting the three fields to `emptyList()` fails
10 resolved-slot expectations; restored, all pass.


**Gate, measured (JVM, darwin-aarch64; corpus classpaths warmed):**

- `test`: green — 250 unit tests, 0 failures, including the 8
  `VulnFindingFloorGateTest` outcomes and the two §4 lowering tests.
- `corpusQuick` (fixtures + frameworks + crypto + async + vuln): **510
  rows** (85 fixtures x 6 slots), **0 fail, 0 XPASS**, pass 2253,
  structural recall **1.0000 (931 of 931)**.
- `corpusFull` including the vuln tier AND the new `vuln-repo` tier:
  **green, 504 rows, 0 fail, 0 XPASS** (39 min at the 8g/1g ceilings).
  Per-repo findings printed by the run and held by the floors:
  **androgoat 16 slices / 33 endpoints (ratio 0.9464), insecureshop 7 /
  12 (0.9147), tsp-vulnerable-app-kotlin-ktor 2 / 2 (ratio 1.0)**;
  kosi-vulnerable-service deps 9 slices / 8 bytecode-origin
  cross-dependency / 2 applied bytecode summaries (the P11 bar holds).
  AndroGoat's deps slot runs at its pinned 50-class cap; http4k keeps its
  documented offline row (its monorepo resolves 16k coordinates — warming
  it is named as future work, not forced).
- `golden`: **432 pairs, 0 problems** after regeneration. Every moved
  pair accounted: 272 `dataFlow` digests are the pack-growth provenance
  shift — proven benign by the slice-count comparison below — 8
  `callGraph` digests are exactly two fixtures (`class-declarations`:
  R87's accessor renames; `ktor-context-semantics`: §4's bare `call`
  reads becoming call nodes), and the 4 `stats` digests ride the same
  two fixtures' counts. **"Goldens regenerated" is not the account — the
  480-of-480 slice-count identity between the pristine jar and this
  branch is.**
- §4's proof the lowering change moved no behaviour: the pristine jar
  (a worktree at `0443465`) and this branch, over the same 80 pre-P14
  fixtures x 6 slots = **480 pairs, identical slice counts in every
  pair** (both runs 0 fail / 0 xpass).
- Determinism: JVM **173/173** byte-identical, native **173/173**
  byte-identical, native == JVM **173/173** (fixtures x both graph
  slots), on the pinned GraalVM CE 25.3.4.1.
- Native metadata: regenerated (+34 lines: `KtImportAlias`,
  `KtCollectionLiteralExpression`, stubs — R89); `native-metadata-check`
  clean after commit.
- Teeth, restored-defect-by-restored-defect: §2's pack entries stripped
  -> 3 resolved-slot expectations fail; §2.3's first-match fallback
  restored -> `javalin /legacy` found (the wrong answer) and both
  `unattributed` routes missing; §5's three fields reverted to
  `emptyList()` -> 10 expectations fail; §4's lowering reverted -> the
  `queryEcho` flow fails while the backing-field flow keeps passing; the
  findings floor's eight outcomes are unit-pinned in both directions;
  the warm script's broken arm fails the script (exit 1, measured on
  androgoat before the per-arm `|| true` fix).


## P11 — cdxgen integration, the release phase, and the red gate closed (this branch)

Branch `feat/kosi-p11-integration`, off `feat/kosi` (`e594c00`).

**The red gate, closed honestly.** P9 left `cross-dependency-bytecode`
FAILing at 0 of 8 repos, correctly: no pinned repo completed a
workspace -> jar-sink path under the shipped pack. The phase brief says
the fix is corpus and modelling work, so first every zero got a named
cause. The deps-slot analysis was re-run per repo (all 8 caches warmed,
R70 fixed, see below):

| repo | classes lowered | functions compiled | applied bytecode summaries | cross-dependency slices | cause |
| --- | --- | --- | --- | --- | --- |
| anki-android | 500 | 6,915 | 0 | 0 | budget cut: 571 wanted classes > 500 cap; `timber.log.*` sorts last and is selected-but-cut (named in the diagnostic) |
| spring-fu | 500 | 9,079 | 0 | 0 | cap trips inside framework plumbing; spring-jdbc's jar-internal chain crosses CONSTRUCTOR-written fields (`QueryStatementCallback.sql`), which the tier's constructor-free summaries cannot see |
| ktor-samples | 500 | 3,847 | 0 | 0 | cap + no pack-modelled sink reachable from the lowered ktor internals (ktor's URI handling crosses jar boundaries the same-jar closure declines) |
| nowinandroid | 500 | 3,375 | 0 | 0 | cap; the repo logs via platform `android.util.Log` from workspace code — a workspace sink call site, not a jar-internal one |
| kampkit | 464 | 2,500 | 0 | 0 | iOS-target references resolve partially (documented P1 gap); no modelled jar-internal sink chain |
| heterogeneous-microservices | 58 | 340 | 0 | 0 | no warm classpath: offline resolution leaves `resolvedCallRatio` at 0.28 and the tier lower 58 classes with no reachable pack sink |
| grpc-kotlin | 0 | 0 | 0 | 0 | no warm classpath at all: the tier lowers nothing |
| http4k | — | — | — | — | pre-existing counted failure row (the Analysis API checker trips before the graph stage; the call-graph guard does not launder it) |

Two structural shapes came out of the diagnosis, both at the tier boundary
rather than the engine's transfer:

1. **R70 (fixed):** the wanted phase (workspace callees -> classes) is
   uncapped by design, but the closure loop's budget guard compared
   `selected.size` against `--deps-max-classes` — so a repo whose wanted
   set ALONE exceeded the budget lowered NOTHING. anki-android shipped
   571 "lowered" classes, 0 compiled functions and one cap diagnostic.
   The budget now bounds the LOWERED set; the cut classes are named
   (`deps-class-limit`, count = classes cut) and carried on the bench row
   (`dependencyFunctions`, `depsCutClasses`). anki-android went 0 ->
   6,915 compiled dependency functions.
2. **Parameter chains only.** A jar-internal sink is reachable only when
   the taint passes as a PARAMETER through owner-visible calls. Timber's
   `Forest.d -> Tree.d -> DebugTree.log -> Log.println` closes; spring-jdbc
   does not (the SQL rides a constructor-written field, and `<init>` is
   excluded from the tier entirely — the body-less rule doing its job).
   commons-dbutils' `query` does not either (`prepareStatement` is
   inherited, and the bytecode owner names the caller's own class, so the
   same-jar closure never finds the declaring class). Both are named
   shapes, not silent gaps.

**The criterion moved with the measurement pasted beside it.** The honest
population for the gate is a repo-tier entry whose vulnerable path runs
through a real published dependency, so the corpus gains the `vuln` tier:
`kosi-vulnerable-service`, a deliberately vulnerable Kotlin service whose
logging flows run through `libs/timber-5.0.1.jar` — the classes.jar inside
the published Timber 5.0.1 AAR, committed byte for byte, never rebuilt,
never fetched. Its deps slot publishes 8 cross-dependency slices with
`origins = [bytecode, pack]` and 2 applied bytecode summaries;
`UserRepository` pins the workspace-side SQL flow and the want-not
negatives; `DriverManager.getConnection` doubles as the services[] row.
The bar lowers 5 -> 1 (`CROSS_DEPENDENCY_BYTECODE_REPOS`): every pinned
repo's zero is named and structural, and 5 was a number nobody could meet
— a gate everyone learns to ignore. At 1 the teeth remain, re-proven:
jar removed -> `FAIL ... kosi-vulnerable-service=0 slice(s), 0 applied
bytecode summar(ies) ... 0 classes lowered`; restored -> PASS.

One more boundary recorded in the fixture: planting the debug tree from
an `init` block keeps the cross-dependency slices from materialising —
the dispatch join needs the `DebugTree` construction site as a workspace
call. A reviewer would assume the two shapes equivalent; they are not.

**The R69 task, as a task.** The fixture tree's set of source constructs
is a coverage denominator nothing measured. Swept the grammar against all
68 fixtures: **29 constructs had never been contained** — annotations with
named arguments, `@Deprecated`, the `@Jvm*` family, `tailrec`, labelled
break/continue/return, `do-while`, ranges with `step`, `out`/`in` variance,
star projections, `where` clauses, annotations on type arguments, `fun
interface`, `value` classes, `init` blocks, `inner` classes, anonymous
objects, `data object`, `lateinit`, custom getters/setters over the backing
field, named arguments, raw strings, `!!`, `as?`, `try` as an expression,
`runCatching`, `::class` and `::fn` literals, and `suspend` lambda types.
Four fixtures close the sweep (`generic-shapes`, `loop-and-labels`,
`class-declarations`, `expressions-and-literals`), each carrying
`lowering-failed` + `parse-error` want-nots so a declined construct is a
corpus failure. `!!` carries a live flow: the assertion must PRESERVE
taint, never cut it. The `as?`-then-sink negative was rewritten during
bring-up: a may-analysis cannot know a cast arm is dead, so the cast
fixture pins no-flow-escapes instead. Native metadata drift after the
sweep: reported with the release numbers below.

**P11 proper — shipped into cdxgen.**

- **SARIF export** (`--sarif-out`): SARIF 2.1.0, one rule per rule id, one
  result per slice; the sink is the result location, the trace the related
  locations in walk order and a `codeFlow`; deterministic bytes. On the
  sample, a cross-dependency result's related locations walk INTO the jar
  (`timber-5.0.1.jar!timber/log/Timber$DebugTree.class:240`).
- **The committed Kotlin sample project** (`examples/kotlin-sample-app`)
  and `scripts/kosi-e2e.sh`: half 1 asserts the report contract offline
  (trace invariants, bytecode origins, reachability, crypto material,
  service row); half 2 — against a cdxgen checkout carrying the kosi
  evinser arm (`CDXGEN_DIR`) — runs cdxgen + `evinse -l kotlin` and asserts
  the BOM carries occurrence, callstack, reachability, data-flow and
  crypto-flow evidence plus services[].
  **The cdxgen-side arm lives in another repository and is not pushed.**
  It is 7 commits on `feat/kosi-evinse-tmp` in the cdxgen checkout on the
  build host (`lib/ecosystems/kosi.js`, the evinser arm, the `kotlin`
  language choice, the plugins entry). Until that branch is pushed, half 2
  runs on exactly one machine and half 1 — the offline report contract — is
  the only part of the integration CI can gate. Pushing it and wiring half 2
  into the workflow with `KOSI_E2E_REQUIRE_CDGEN=1` is the next phase's
  first item.
- **CDXGEN_KOSI_DISABLE=1** (the cdxrs silent-fallback discipline, in the
  cdxgen arm): the run logs once, skips kosi, and the BOM stays valid with
  ZERO kosi artifacts — asserted by the same script.
- **Packaging:** kosi enters `generate-metadata.js` (the
  `plugins-manifest.json` entry and SBOM component); `check-plugin-coverage.sh`
  proves both directions (missing kosi binary FAILs; exempt platforms name
  their reason) and `check-package-size.sh` passes. R66's unpinned-tarball
  defect was not only in kosi-test.yml: all three GraalVM installs in
  native-builds.yml are sha-pinned now (linux-x64 `b2bc38d0...`,
  linux-aarch64 `7e8a3fbc...`, macos-aarch64 `ebfab1d7...`).
  **darwin-amd64 was claimed here and the claim was false (R96)** — see the
  P15 review table; it is a named exemption again, alongside
  windows-amd64/windows-arm64 (no Windows runner job wires the MSVC build;
  the recipe is docs/BUILD.md §6). The JVM-jar fallback covers every
  non-claimed platform.
- **R66 root-caused.** The linux smoke died at startup with
  `NoClassDefFoundError: java/awt/GraphicsEnvironment` inside a JDK native
  library's `JNI_OnLoad`. The cause is in the JDK's natives:
  `Toolkit.<clinit>` loads `libawt` unconditionally before any
  `awt.toolkit` property read (the IntelliJ platform's mock application
  Swing runnable is the path that reaches it), linux `libawt.so` DEFINES a
  `JNI_OnLoad` whose `FindClass` cannot succeed in an image, and darwin
  `libawt.dylib` defines NO `JNI_OnLoad` — same flags, opposite verdicts.
  Fix, verified end-to-end in a local arm64 container running the exact
  CI steps (ubuntu 24.04, the pinned linux-aarch64 GraalVM): JDK 25
  removed the `awt.toolkit` property — linux `createToolkit()` constructs
  XToolkit unconditionally, and XToolkit's `<clinit>` loads libawt. The
  linux targets therefore bake HEADLESS at build time
  (`-Djava.awt.headless=true` + `java.awt.GraphicsEnvironment` in the
  build-time-init list), so libawt's `AWT_OnLoad` reads a baked-true
  `isHeadless()` and dlopens `libawt_headless.so` instead of
  `libawt_xawt.so`; the image JNI-registers `java.awt.GraphicsEnvironment`
  and its `isHeadless()` (a hand-seeded reachability entry the merge
  script preserves, like the P2 jimage entries) so `AWT_OnLoad`'s
  `FindClass`/`GetStaticMethodID` succeed. Container smoke: `kosi version`
  reports all three components available; two analyze runs are
  byte-identical. On darwin the flag stays off — initializing Toolkit at
  build time there bakes a default `LWCToolkit` into the image heap and
  every probe fails (measured); darwin needs no flag because
  `libawt.dylib` defines no `JNI_OnLoad`. The earlier main()-level
  `awt.toolkit` selection stays: it is the mechanism darwin has used
  since P1, harmless on linux, and documents the boundary the listener
  crosses.
**What is NOT measured / declared gaps, in one list:** the five pinned
repos with real vulnerable dependency paths the original bar implied (the
vuln tier holds one; each remaining pinned repo's zero is named above);
spring-jdbc-style field-through-constructor chains and inherited-method
owner closures in the dependency tier (named shapes); windows kosi native
binaries; `--backend compile` (generated sources, unchanged since P10);
and, from the same sweep honesty: the fixture tree STILL does not contain
`reified` type parameters, `contract {}` blocks, the `inc`/`dec`,
`contains`, `rangeTo` and `get`/`set` operator conventions,
`provideDelegate`, `@JvmSynthetic`, `crossinline`/`noinline`, or a
`sealed fun interface` — the next sweep iteration's list. (P14 removed
two from an earlier list's neighbourhood: aliased companion-member
imports and array-valued annotation arguments are now contained — R89.)

## Phases 9+10 — cross-dependency taint, and the gate that can see a regression

Branch `feat/kosi-p9-p10-deps-scale`, off `feat/kosi` (`4579fa6`). Two
roadmap phases, one branch: P6's gate needed P5's summaries; the P10 gate
needed P9's tier to be worth gating on.

**What ships (P9).** `kosi-bytecode` lowers dependency jars into the SAME
KIR the source front end produces, and `kosi-flow` summarises them with
the SAME `Summarizer` — origin `bytecode` — applying them at workspace
call sites exactly like workspace summaries. There is no second transfer
anywhere: the tier is a `KirModule` whose site ids continue after the
workspace's, so ONE trace walks into the jar and back out, and slice
traces render jar frames (`dep-helper.jar!dev/kosi/helper/Db.class:32`).
`--deps` enables the tier; `--dataflow security-deps` implies it. The
demangler reads `@kotlin.Metadata` (JvmProtoBufUtil from
kotlin-compiler-common-for-ide, already shipped — the allowlist did not
grow) and maps JVM names to source callable ids: hash-mangled overloads,
property accessors, `*Kt` facades, `$Companion`/nested classes. Overrides
are resolved inside the lowered set by JVM name+descriptor on selected
supertypes — without it, a jar body calling an abstract supertype method
(Timber's `Tree.log` -> `DebugTree.log`) dies into the unknown default
exactly one hop before the sink.

**Body-less records are ignored ENTIRELY, never concluded about** —
rusi's rule, and the phase's most important sentence. An
abstract/interface/native/stripped method lowers to `body = null`, which
the engine never compiles; each is counted (`stats.bodylessRecords`) with
a `deps-bodyless` diagnostic, and the population is excluded from every
dependency denominator. `dep-taint-through-lib` pins it from both sides:
a flow THROUGH an abstract `Provider.provide` must exist on every backend
(unknown-propagation without the tier, labelled with it), and a
`Db.hashOf` must never sink.

**The tier's summaries keep `origin=bytecode` even when an SCC hits the
iteration budget.** The `recursive-approx` relabel is guarded on the
workspace origin, because the label is what the gate reads to tell a
jar-derived summary from a workspace one — losing that would hide which
summaries come from jars at all. An under-converged tier stays visible in
`stats.sccIterationCapHits` over `stats.sccsProcessed` instead. The tier
runs on the SAME per-SCC budget as the workspace: it briefly carried a 4x
one justified as protecting that label, which the label never needed.

**crossesDependency stops being collinear with crossesModule** (the P5/P6
caveat): it is now set when the TRACE enters a jar the tier lowered —
dependency purls are the marker set — and stays false for a
workspace-module crossing, however many purls differ between the ends.
The fixture that existed to make the P5 gate nonzero (`summary-cross-module`)
keeps its crossModule flags and loses its crossDependency ones, which is
the point: the flags answer different questions now.

**Excluded shapes, named** (the R63 clause for this phase): JDK and
Android platform APIs are excluded by prefix (`java.`, `kotlin.`,
`android.`, ...) and stay pack-modeled; `@JvmName`-renamed facades and
multi-file facades are found only through the call closure; overload
summaries collapse per canonical name (the workspace CallIndex has the
same collapse; Kotlin vararg bridge descriptors never match raw JVM ones
so descriptors disambiguate nothing); AARs are read through their
extracted `classes.jar` (the resolver's, reused); `suspend` state machines
lower as ordinary control flow with the transfer treating the artifacts
conservatively; cross-jar closure is unbounded on fat classpaths, so the
closure is same-jar and budget-capped (`--deps-max-classes`, 500, a
`deps-class-limit` diagnostic when it trips).

**Gate, determinism (this branch, re-measured after the tier landed).**
Native binary 97,611,856 B on the pinned GraalVM CE 25.3.4.1 (+1.47 MB
over P7/P8: the ASM tree API and the metadata reader); all three
components `available`; `nativeImage: true`. Determinism:
`scripts/determinism-sweep.sh` grew the deps slot (R53: a slot the sweep
never runs proves nothing) over the dep fixture — **135 of 135**
fixture/slot pairs byte-identical across two JVM runs, **135 of 135** in
the native image, **135 of 135** native == JVM with `tool.commit`
normalised; the deps rows show the tier producing the same 4 slices on
both binaries. `make native-metadata` re-ran the agent loop (now covering
the deps slot) and produced no drift for the TIER — it is reflection-free
(direct ASM + protobuf calls), which is why the image needed no new
registrations to run it. It did produce three, for the KDoc PSI types
R69 names: a defect of the fixture tree's construct coverage, not of this
phase's code, and the reason the review added a fixture carrying KDoc.

**What ships (P10).** `--max-analysis-seconds` and `--max-rss-mb` DEGRADE
the run: between SCCs, between functions, and at stage boundaries a
tripped budget emits `analysis-time-budget`/`rss-budget` and the partial
report still ships — golem's `guardAlgorithm` lesson is pinned twice, in
the budgets and in the call-graph guard (`callgraph-failed`, severity
error: a graph crash names itself and the evidence report survives; the
http4k failure row still fails — the guard sits AFTER the resolution
stage that throws). An already-exceeded RSS budget trips synchronously at
construction (an absurd budget must degrade deterministically, not race
the sampler). `--dataflow-workers` parallelises the per-function
analysis behind synchronized context mutations and a compiled-order fold:
evidence is identical at widths 1/4/8 (`WorkerDeterminismTest`). The
bench records a per-row RSS window (samples bracketing the slot) and the
promotion gate adds the real-repo criteria: `per-repo-rss` (1.5x vs the
baseline row, FAIL naming the repo), `deps-delta` (per-repo wall and RSS
ratios of the deps slot against the resolved slot, measured in the same
session — recorded, published, not a bar), and `cross-dependency-bytecode`
(P9's gate: at least 5 pinned repos with cross-dependency slices whose
origins carry `bytecode` and applied bytecode summaries; FAIL names the
zero repos).

`--backend compile` is a DECLARED GAP: kosi cannot execute the analysed
build offline to obtain generated sources (KSP/Compose/Room), so the flag
runs the resolved tier and stamps `compile-backend-gap` on the report —
the gap is named where a consumer sees it, and no report claims generated
sources were analysed.

**The pack grew one family for the tier to be real:** `android.util.Log`
(v/d/i/w/e/wtf/println, log-injection). Real Android dependencies sink
through Log (Timber's chain bottoms out in `DebugTree.log` ->
`Log.println`), and a jar-internal boundary the models cannot see is a
boundary the tier cannot measure. The rows are validated by the same
pattern-notation test as every other row; no bundled JVM fixture
exercises them (android.jar is not on fixture classpaths) — the pinned
Android repos are their exercising corpus, and until a repo completes a
flow through one, they are measured by nothing at repo scale.

**Gate, measured (darwin-arm64, M4 Pro, one session, both sides
re-measured).** The P9 gate — cross-dependency slices with
`origin=bytecode` on >= 5 pinned repos — is implemented, armed, and
FAILS today, honestly:

```
FAIL   cross-dependency-bytecode  0 of 8 repo(s) qualify (< 5):
       measured: anki-android=0 slice(s), 0 applied bytecode summar(ies),
       grpc-kotlin=..., heterogeneous-microservices=..., http4k=..., ...
```

The engine is proven where a source->jar-sink path EXISTS: the committed
`dep-taint-through-lib` fixture's deps slot publishes 4 slices, 3 of them
cross-dependency with `origins=[bytecode, pack]` (workspace readLine ->
`Db.runQuery` -> `Statement.executeQuery` inside the jar; jar-side
`Console.readLine` -> workspace `ProcessBuilder`); a synthetic probe
against the real Timber 5.0.1 AAR publishes 4 cross-dependency
`log-injection` slices whose trace walks `Timber.Forest.d` ->
`Timber$Tree.d` -> `DebugTree.log` -> `Log.println` with `origins=
[bytecode, pack]`. But NO pinned repo completes a source -> jar-sink
path under the shipped models: entry-point seeding exists on the deps
slot (P7 handlers), and no seeded fact reaches a jar-internal sink — the
same finding P5/P6 recorded for workspace flows ("none of the five calls
a pack source in a function whose transitive callees reach a pack
sink"), now measured one boundary further out. Closing it is corpus and
model work (a vulnerable Kotlin service fixture; per-repo source/sink
modeling), not engine work — manufacturing per-repo pack entries to
make the gate pass would be inventing reach, which the standing rules
forbid. The gate stays FAIL and names every zero repo until then.

What the tier DOES measure at repo scale (deps slot, same-session deltas
against the resolved slot — the `deps-delta` record):

| repo | classes lowered | wall resolved -> deps | delta |
| --- | --- | --- | --- |
| anki-android | 571 (cap 500 + closure) | 226.0s -> 220.8s | 0.98x |
| spring-fu | <= 500 + closure | 9.8s -> ~20s | ~2x |
| nowinandroid | <= 500 + closure | 34.4s -> ~44s | ~1.3x |
| ktor-samples | <= 500 + closure | 16.2s -> ~18s | ~1.1x |
| kampkit | <= 500 + closure | 2.9s -> ~4s | ~1.3x |
| heterogeneous-microservices | 58 | 0.20s -> 0.26s | 1.31x |

(Anki's row is the one re-measured after the cap moved to 500 — the class
cap exists because a 2000-class tier OOMed the pinned 2 GiB corpus JVM
(`ExitOnOutOfMemoryError` fired: loud, but dead); the other rows are the
2000-cap run's walls, quoted as ~ until re-measured. The caps bound the
tier's memory: the corpus JVM must survive the whole matrix.)

grpc-kotlin's cache carries no warm classpath (its tier resolves empty —
offline resolution, gaps diagnosed); http4k stays a counted failure row
(a pasted-failure investigation, see P7/P8) — the call-graph guard does
NOT launder it: its Analysis API checker trips before the graph stage.
Three repos hit the `--deps-max-classes` cap (at the 2000 it then
carried; the default is 500 now, so more repos will) with
`deps-class-limit` naming it; spring-fu's 6093 body-less records are the
tier's largest excluded population. All 48 corpus rows: 0 failed
expectations, 0 XPASS.

**What is NOT measured / declared gaps, in one list:** the 5-repo
cross-dependency-bytecode criterion (above); `--backend compile`
(generated sources — named gap, `compile-backend-gap`); platform-API
jar bodies (JDK/Android excluded by prefix — pack-modeled); `@JvmName`
facades, multi-file facades, overload-disambiguated jar summaries
(canonical-collapse, same as workspace); per-row peak-RSS windows are
process-cumulative-contaminated on long single-JVM runs (the bench runs
~390 sessions in one JVM), so the deps-vs-resolved DELTA in the same
session and isolated single-slot runs are the meaningful readings; the
native image's deps slot is exercised by the agent over the dep fixture
only.

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
  `Toolkit.<clinit>` loads its natives before the toolkit is chosen.
  **The `awt.toolkit` route never worked on the pinned build either — see
  R71.** This paragraph previously claimed it did, and retracted an earlier
  verdict that "the mechanism cannot work on JDK 25". That earlier verdict
  was right: JDK 25's `getDefaultToolkit()` reads no property at all. What
  the episode did expose is that the Makefile resolved the
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

## Defects found and fixed during the P15 review

| # | Area | Defect | Fix |
|---|------|--------|-----|
| R91 | kosi-flow (review of P15) | **§1's composed-path bound was read off `Options.accessPathDepth`, which NOTHING enforces.** That option only switches field sensitivity on and off; a fact key's path is one lowered `AccessPath`, which `AccessPath.of` cuts at five elements and marks with `*` — so `job.a.b.c.d.e.f` is the key `a.b.c.d.e.*`, SIX segments, formable on both sides of a call. Capping composed paths at the option's 5 dropped that escape and lost the flow with it; GLM's own unit test pinned the wrong bound (it asserted a depth-3 path is unfireable at `accessPathDepth = 2`, which the lowering never made true) | the cap is `AccessPath.DEFAULT_DEPTH + 1` — the deepest path the lowering can spell — with the lost flow pinned by `aCollapsedAccessPathEscapeStillFiresAcrossTheBoundary` (it fails against the shipped bound) and the bound test rewritten to grow a composed path one field per level until it passes six. The effect BUDGET, which is what actually bounds the heap, is depth-independent and unchanged |
| R92 | scripts (review of P15) | **§5's monorepo bound never ran, and the dedup that did run was the one §5 said it was replacing.** `grep -E "$coord_re" "$out" \|\| true \| awk ...` parses as `grep \|\| (true \| awk ...)`: on a SUCCESSFUL grep the awk never runs, so `bound_coordinates` wrote back the unbounded list. The pruning actually in force was a leftover inline block comparing versions as STRINGS — it keeps `2.4.0` over `2.10.0`, the exact defect the new numeric `vercmp` was written for, and it also mangles the jar-path lines the function preserves | the coordinate and non-coordinate halves are split into files before filtering, the numeric bound applied to the coordinate half only, and the leftover inline block deleted. Checked on a list holding `kotlin-stdlib` at 1.9.0/2.4.0/2.10.0 plus a jar path: 2.10.0 survives, the jar path passes through |
| R93 | scripts (review of P15) | the per-repo failure list was a bash ARRAY read as `${#failed[@]}` under `set -u` — on bash 3.2 (still the system bash on macOS) an empty array is an unbound variable, so the arm that reports failures would itself abort the script on the happy path | a plain string accumulator, checked with `[ -n "${failed# }" ]` |
| R94 | kosi-export (review of P15) | the endpoint-per-slice map said "the first (lowest id) wins deterministically" and did the opposite: `.toMap()` keeps the LAST pair, so ascending order left the HIGHEST id | sorted descending so the lowest id survives, pinned by a test that writes the same two endpoints in both orders and asserts identical bytes |
| R95 | cdxgen (the §4 consumer question, completed here) | kosi's `apiEndpoints` — the whole INBOUND route surface, with the authentication P14/P15 worked to model — was dropped by cdxgen's SaaSBOM arm: `collectKosiServices` reads only the OUTBOUND `services[]` rows | `collectKosiApiEndpoints` in `lib/ecosystems/kosi.js`, wired into evinser beside the services collector: one service per route, named as `detectServicesFromOpenAPI` names its own so a spec and a kosi run converge on one entry, with `authenticated`/`x-trust-boundary` set only when a requirement was DECLARED (an empty list is "nothing declared", not "open") and the framework, handler and media types as properties |
| R96 | `.github/workflows/native-builds.yml`, `scripts/plugin-platform-support.sh` | The darwin-amd64 kosi native was "graduated to a claimed platform" by a job that had never once run (R53). Its GraalVM URL 404s — GraalVM ships NO macOS x64 build for JDK 25, in Community or Oracle — and the sha256 it was pinned to, `0019dfc4…`, is the hash of GitHub's nine-byte `Not Found` body, so the pin VERIFIED the error page and `tar: Unrecognized archive format` was the first complaint, on PR #93 | The build and publish steps deleted, darwin-amd64 a named exemption again with its true reason, the release's oras pull loop no longer asking for a tag nothing produces, and every GraalVM download in all three workflows moved to `curl -fsSL` so an HTTP error fails at the download instead of being pinned and unpacked |

## Defects found and fixed during P14

| # | Area | Defect | Fix |
|---|------|--------|-----|
| R85 | kosi-bench / docs (found by §1's re-measurement) | **the recorded per-repo ratios were stale in the direction everyone assumed: re-warming changed ONE repo of five.** R81's locator fix took a real Ktor app 0.23 -> 1.0, and the P13-era writeup implied nowinandroid and kampkit's below-target ratios were partly the same bug's fault. Re-measured on the pristine branch state with every classpath warmed from scratch: kampkit 0.6639 -> **0.7551** (the KMP `-jvm` jars attach), and spring-fu 0.9405, anki 0.9232, ktor-samples 0.9024, nowinandroid 0.7564 all UNCHANGED to four decimals — the one-app result does not generalise to repos whose misses are AAR-shaped (104 `-android` variants, 108 alpha/beta AndroidX builds) rather than name-shaped. The docs paragraph was rewritten from the current run's named unlocatable coordinates, not copied forward | the docs paragraph and this row; no locator change was warranted (the remaining misses name AAR/variant shapes, which is the recorded follow-up lever) |
| R86 | scripts (P14, found by §3's own floor) | **the textual warming arm listed only DIRECT coordinates, and a direct-only classpath measures zero against a warm-looking cache.** InsecureShop's AGP-3.x build cannot run its dependency report on any JVM this machine has, so the new textual fallback extracted the build file's literals — 14 coordinates, no transitives. The jars for appcompat's own dependencies never attached, every activity degraded with MISSING_DEPENDENCY_SUPERCLASS, and the app published **0 slices** with the floor green-lighted by a classpath file that existed and resolved — R73's failure mode reproduced by a warmer that worked | the scratch resolver prints each coordinate's RESOLVED transitive closure and the script merges it into the list (InsecureShop 14 -> 184 entries: findings 0 -> 7, the P13 number; ratio 0.674 -> 0.915). The P13-era "InsecureShop 7 / AndroGoat 17" ad-hoc measurements are now bench rows anyone can ratchet |
| R87 | kosi-front (pre-existing since P5, found promoting InsecureShop into the corpus) | **every custom property accessor lowered as the same function name.** `KtPropertyAccessor` has no PSI name, so the lowering used the constant `<accessor>` — a class with N accessor-bodied properties produced N functions with ONE canonical name. InsecureShop's `Prefs` object carried six `com.insecureshop.util.Prefs.<accessor>` functions; the KIR validator named the duplicates and `kir dump` refused the module. Nothing in fifty fixtures had two custom accessors on one class | accessors take the JVM name of their property (`getData`/`setData`), which is unique per class and matches what the JVM actually calls them. Still open on the same repo, named: five `unreachable-but-emitted block` findings in four functions |
| R90 | kosi-front (review of P14) | **a top-level EXTENSION property read by bare name lowered without its receiver.** §4's fix sent the implicit `this` only when the property's `callableId` named a class, so a member accessor carried its receiver and a top-level extension accessor did not — and extension properties are how Ktor spells most of its request readers (`val ApplicationRequest.uri`). Taint arriving on the receiver stopped at every such accessor; no fixture had one, so 432 goldens and 510 corpus rows held either way | the call carries the implicit receiver whenever the symbol has one, while its `CallKind` stays STATIC (the JVM getter is static, but it reads the receiver). Two unit tests added for capabilities P14 shipped without one: this receiver, and R87's accessor renaming (six colliding `<accessor>` functions had no test at all) — both proven by restoring their defect |
| R89 | native image (found by §2/§5's own fixtures) | **two source constructs the fixture tree had never contained made the image refuse to analyse the new fixtures** — R53's fourth instance, found this time before any green run could hide it: `import okhttp3.HttpUrl.Companion.toHttpUrl` creates a `KtImportAlias` PSI node (a companion-MEMBER import, never written in 82 fixtures), and `@RequestMapping(consumes = ["application/json"])` — §5's own input syntax — creates a `KtCollectionLiteralExpression`. The native sweep failed both fixtures' resolved slots with `MissingReflectionRegistrationError` until the agent re-ran | `make native-metadata` re-traced the fixture tree (34 metadata lines), the image rebuilt, and both fixtures analyse natively (framework-generations: 5 endpoints, 6 slices, identical to the JVM). The construct-sweep list in the P11 section gains both entries | 
| R88 | build + corpus (found by §1's own corpusFull, three times) | **warmed classpaths outgrew the corpus JVM's memory ceilings.** First death: 65 minutes in, at report time, `NoClassDefFoundError` naming a class that was always on the classpath — the 512m `MaxMetaspaceSize` ceiling (set in P9 for a different failure) ran out as every resolved session attached far more dependency classes; every slot had already completed, so the measurement existed and was lost. Second death: once the vuln-repo tier's TRANSITIVE classpaths attached (R86's fix), AndroGoat's deps slot filled the whole 3g heap — with `ExitOnOutOfMemoryError` the JVM terminated instead of letting runSlot catch it as a named failure row, and 3g -> 4g -> 6g all died the same way | metaspace 512m -> 1g, heap 3g -> 8g, both causes recorded beside the flags; and the corpus manifest gained a per-entry `deps_max_classes` — AndroGoat's deps slot is the tier's known heavyweight (161 attached coordinates against an uncapped wanted phase, R70's design), and MEASURED: a 50-class lowering fits, 150 fills an 8g heap — so the entry pins 50 and the `deps-class-limit` diagnostic names what was cut. The engine's per-class cost over a large attached classpath is named as the next phase's own |

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
| R66 | CI (inherited, pre-existing on `feat/kosi` at `4579fa6`) | **the kosi-test linux on-demand native job fails at the binary smoke on the untouched base branch too**: the linux-amd64 image builds (same Makefile flags, jar and metadata as the green darwin build) then aborts at startup with `NoClassDefFoundError: java/awt/GraphicsEnvironment` raised inside a JDK native library's `JNI_OnLoad` — an AWT-natives signature, on a job whose GraalVM tarball sha was never pinned ("record at the first successful run" — a first successful run never happened). Control run: dispatching `kosi-test.yml` on `feat/kosi` fails the identical step. Not caused by and not fixable within this phase; the four-arch release path (`native-builds`) is green on this branch | fix belongs to CI/toolchain: pin the linux GraalVM sha, then root-cause the linux AWT registration difference against the green darwin build |
| R67 | kosi-flow | **an unresolved CONSTRUCTOR stopped being an unresolved call, in the summary engine only.** The dependency-tier fallback was added to `SummaryAnalysis` under `targets.isEmpty() && kind != CONSTRUCTOR`, which also flipped the pre-P9 behaviour of the arm it guarded: an unresolved constructor now reported *handled* and SUPPRESSED the conservative unknown-call default, silently dropping the parameter-to-return passthrough it used to publish — on every backend, not just the deps tier, since the tier never lowers `<init>` at all. Nothing failed: no annotation named the shape, and the goldens were regenerated over the eight pairs it moved. The comment above the condition described the dependency fallback and said nothing about constructors | the two hosts now consult the tier under ONE condition (no workspace summary applies), stated once, with the carve-out gone: a constructor simply misses, because `<init>` is never in the tier. New fixture `unresolved-constructor` puts the unresolved constructor inside a CALLEE, so the flow can only survive through that function's summary — an inline one would pass either way on the caller's own default. Restoring the carve-out fails it on `resolved` and `deps` |
| R68 | kosi-front | **the P2 lowering gate's numerator grew a population its denominator does not have.** Dependency-tier misses were folded into `stats.loweringFailures` under a `bytecode:` prefix, and the gate reads that map over `stats.functionsLowered` — which counts WORKSPACE functions only. The fixtures arm demands the map be empty, so one unreadable jar record would have failed a gate about workspace lowering; the repo arm would have rationed jar records against a workspace denominator. R49/R54's shape, and a silent change to what a shipped gate means | the merge is gone; `loweringFailures` is workspace lowering again. The tier's misses were already carried, with their own breakdown and count, by the `bytecode-unlowered` diagnostic |
| R70 | kosi-bytecode | **the `--deps` cap zeroed the tier when the wanted set alone exceeded it.** The wanted phase (workspace callees -> classes) is uncapped by design, but the closure loop's guard compared `selected.size` — filled by that unbounded phase — against `--deps-max-classes`, so a repo naming more than 500 classes lowered NOTHING: anki-android shipped 571 selected classes, 0 compiled functions and one cap diagnostic, and every gate passed. R68's family (a boundary the tier's own bookkeeping gets wrong), found by re-running the deps slot per repo while diagnosing the red gate | the budget bounds the LOWERED set; cut classes are a named row (`deps-class-limit`, count = classes cut, first few named in the message) carried on the bench row as `depsCutClasses` beside `dependencyFunctions`. `BytecodeLowererTest` proves a cap under the wanted set still lowers exactly `maxClasses` deterministically. anki-android: 0 -> 6,915 compiled functions |
| R69 | native image (pre-existing, found by this review) | **the native binary could not analyse any Kotlin file containing a KDoc comment.** `/** ... */` anywhere in a source made `createForResolved` throw `ExceptionInInitializerError` wrapping `RuntimeException: Must have a constructor with ASTNode` — the PSI factory reflectively looking up `KDocSection`/`KDocName`/`KDocTag`, none of which the image had registered. The JVM build was unaffected, so every gate passed. This is R53's THIRD instance and its worst: R53 was a matrix SLOT the agent never ran (`exported`, and `KtObjectDeclaration`), P9 added the `deps` slot for the same reason — but here the untraced thing is a SOURCE CONSTRUCT. The agent's real denominator is the set of constructs the fixture tree contains, and not one of 53 fixtures had ever carried a doc comment, in a language whose every real repository is full of them | the `unresolved-constructor` fixture (added for R67) carries KDoc; `make native-metadata` then traced the three missing types and the image runs it. Native sweeps re-measured at **135/135** JVM, **135/135** native, **135/135** native == JVM. The error message that hid it is fixed too: session failures render their whole CAUSE CHAIN (`describeFailure`, applied at all three sites that had the shape), because "ExceptionInInitializerError: no message" named nothing and pointed the reader at `kosi version`, where the answer could never be |
| R71 | kosi-front / kosi-cli (pre-existing since phase 1, found by this review) | **the mechanism that was supposed to keep AWT out of the image had never once run.** `KosiNoopToolkit` was selected by setting the `awt.toolkit` system property, at two sites, and P11 added a third in `main()` when the linux image still died. JDK 25's `Toolkit.getDefaultToolkit()` reads NO property — it calls `PlatformGraphicsInfo.createToolkit()`, which branches on `isHeadless()` alone — so the no-op toolkit was never installed, on any platform, on the pinned toolchain. Measured directly: with the property set to the class name, `getDefaultToolkit()` still returns `LWCToolkit`. An earlier review reached this verdict correctly, then RETRACTED it in `docs/KOSI.md` after a mis-built comparison, and the retraction stood for eleven phases; P11's own root-cause note ("JDK 25 removed the property") contradicted the retraction in the same tree without removing the code or the claim, and `docs/BUILD.md` still told the reader the route "remains darwin's mechanism". The inert property is precisely what made R66's real fix look unnecessary for so long | the class and all three property sites are deleted. `java.awt.headless=true`, set in `main` and baked at image-build time for linux, is now the only AWT steering kosi has, stated once in `main` and once on the Makefile's linux rule; the superseded narrative block above that rule is gone, and both docs are corrected |
| R76 | kosi-flow / kosi-endpoints | **every endpoint handler's parameters were seeded alike, whatever the framework meant by them.** `--endpoint-sources` tainted every value parameter of a detected handler. For a CONTEXT framework that is wrong twice over: a servlet's `doGet(request, response)` had its RESPONSE object tainted as hard as its request, so anything derived from the response was reported as attacker-controlled; and a Ktor handler, whose call is a receiver, got nothing at all. The three real shapes — the signature NAMES its transports (Spring, JAX-RS, Micronaut), the handler receives a request CONTEXT (servlet, Ktor, Javalin, Vert.x, http4k), or the parameter IS the payload (gRPC, Lambda, Android) — need three seedings | `FrameworkModel.handlerInput` states which, per framework. `annotated` seeds exactly the annotated parameters, `context` seeds none and relies on the context's reader methods (57 of which were added to the security pack, so the surface is complete), `all` keeps the previous behaviour. Fixture `handler-input-semantics` asserts that a servlet's request reader is a source AND that nothing derived from its response is reported |
| R77 | kosi-endpoints | **three route shapes the detector could not express, so it silently reported nothing for them.** (a) A route declared on the CLASS with convention-named handlers — `@WebServlet("/run")` with `doGet` — fits neither the mapping-on-the-function rule nor any other; a servlet published no endpoint. (b) A route whose path is on a TYPE — Ktor's `get<Article> { }` with `@Resource("/articles")` — has no path argument at all, and the registered builders published the raw register name as the path, which looks handled and is worse than unsupported. (c) `WEB-INF/web.xml` maps URLs to servlet classes with no annotation anywhere in the source, which is how most inherited JVM applications still route | `classMappingAnnotations` + `handlerMethodNames` for the class-declared shape; `resourceAnnotations` plus TYPE ARGUMENTS carried through the KIR (`KirCall.typeArguments`) for typed routing, with nested `@Resource` classes composing; and `WebXmlParser`, whose mappings join to the handler methods the class actually declares, so a servlet implementing only `doGet` publishes only GET. Fixtures `handler-input-semantics`, `ktor-resources`, `descriptor-routes` |
| R78 | kosi-endpoints | **reported routes were spelled in whatever syntax their framework uses, and gRPC coroutine services were named after a service that does not exist.** The same route is written four ways on the JVM — `{id:[0-9]+}`, `{id: \\d+}`, `:id`, `{id?}` — so two frameworks' routes could not be matched against each other, against traffic or against an allowlist without re-implementing every framework's path syntax. Separately, grpc-kotlin emits `GreeterCoroutineImplBase`, and stripping only `ImplBase` named the service `GreeterCoroutine`, giving an RPC path that matches no proto | one normal form (`{name}`, `*`, `**`) applied at every publication point, with the regex constraint dropped from the template and the variable still named in `pathParameters`; and the longest supertype suffix wins, falling back to the enclosing `<Service>GrpcKt` holder. Fixtures `path-normalisation` and the extended `grpc-service` |
| R79 | kosi-endpoints | **routes that exist without a handler were invisible.** Spring Data REST exposes every repository interface as a collection resource with the full verb set and no controller; Spring Boot Actuator and springdoc publish their trees because the artifact is on the classpath. These are among the most probed paths on any Spring deployment, so a scanner that reads only handlers reports an attack surface missing exactly the parts an attacker looks for first — and says nothing about the omission | `repositorySupertypes` derive collections from repository interfaces (pluralised the way Spring's own inflector does for the regular cases, never guessing an irregular plural), and `dependencyMarkers` + `implicitRoutes` publish dependency-implied trees from the RESOLVED classpath. Both carry `foundBy = "implicit"`, so a consumer can tell a route read from code from one inferred from a dependency. Actuator's base path is substituted, not prefixed (`/ops/health`, never `/ops/actuator/health`). Fixture `implicit-routes` |
| R80 | kosi-front (pre-existing since phase 2) | **Ktor had no working taint sources at all.** The security pack shipped eight of them — `ApplicationCall.parameters`, `ApplicationRequest.queryParameters`, `.headers`, `receiveText` — and every one was dead. Ktor declares its readers as ABSTRACT properties, and R72 lowered only SYNTHETIC JAVA properties as calls; a Kotlin property read stayed a `fieldget` whose path is the LOCAL VARIABLE's name (`vcall.parameters`). Model packs match callees, so no Ktor application could produce a single taint slice, on the most widely used Kotlin server framework. Nothing failed: the patterns existed, so the capability looked shipped | `KirLowering.resolveProperty` also resolves a `KaKotlinPropertySymbol` and, when it has NO BACKING FIELD (an `abstract val` or a custom getter — a method call on the JVM), emits a `KirCall` to the property's own callableId, which is the name the packs already carry. A property WITH a backing field stays a field access, so P4/P5 field sensitivity is untouched — 486 corpus pairs moved zero slices. Fixture `ktor-context-semantics`; on the real vulnerable Ktor app `tsp-vulnerable-app-kotlin-ktor`, 0 slices -> 2 (both the app's documented reflected XSS) |
| R81 | kosi-project (pre-existing since P3) | **every Kotlin multiplatform dependency was reported as unlocatable with the jar already in the cache.** Gradle files a KMP library's JVM artifact under the PARENT's directory: `io.ktor:ktor-server-core` resolves to `ktor-server-core-jvm-1.6.7.jar` sitting in `ktor-server-core/1.6.7/<hash>/`. `gradleHashDirs` looked only for `<artifact>-<version>.jar`, so it missed all of Ktor and all of kotlinx — most of the modern Kotlin ecosystem. A real Ktor app analysed against a fully warmed classpath resolved 23% of its calls because its own framework was missing, and the `classpath-partial` diagnostic named the coordinates without anyone asking why jars that were present could not be found | the platform-suffixed name is accepted for Kotlin's own target suffixes (`jvm`, `android`, `androidRelease`) and ONLY when the exact name is absent, so a neighbouring `-sources` jar is never picked up. Two `ClasspathResolverTest` cases, one per direction. On the real Ktor app: resolvedCallRatio 0.23 -> 1.0 |
| R82 | kosi-endpoints (pre-existing since P7) | **`route("/hello") { get { .. } }` published a REGISTER NAME as a path segment.** Ktor's verb builders have a pathless overload whose route is entirely the enclosing prefix; `detectRouteCall` read the first argument as the path regardless, folded the LAMBDA register, failed, and fell into the unresolved-path branch that renders the register — publishing `/hello/t7`, a URL that exists nowhere, on the most common Ktor nesting idiom. The `ktor-app` fixture only used the `get("/path") { }` form, so nothing caught it | a single-argument route call whose one argument resolves to a workspace lambda takes the enclosing prefix as its whole path. Fixture `ktor-context-semantics` pins the composed path and pins the absence of a register-named segment |
| R83 | kosi-endpoints | **`<filter-mapping>` was not read, and a context handler declared no parameters.** Two halves of the same omission. A filter mapped in `web.xml` sees every request before any servlet does and reads the same `HttpServletRequest`, and kosi reported only the servlets. Separately, `ParameterAnnotation.kind` — the transport slot — was loaded by the pack and read by nothing, so `queryParameters` was hard-coded to the empty list for EVERY endpoint of every framework, and a context framework (Ktor, Javalin, Vert.x, Spark, servlet, http4k, WebFlux) declared no parameters anywhere a signature could carry them | `WebXmlParser` joins `<filter>`/`<filter-mapping>`, resolving the `<servlet-name>` indirection to the wrapped servlet's patterns; a filter's handler is `doFilter` and it pins no verb. `FrameworkModel.contextReaders` names each reader's transport and where the parameter's NAME sits — a call argument (`ctx.pathParam("id")`) or the index of a get against a returned map (`call.parameters["id"]`) — folded through the same `KirValueFolder` the route paths use. Ktor's and the servlet API's merged maps are split by the ROUTE: a name the template declares as `{name}` is a path parameter, one it does not could only have come from the query string. Corpus gains `pathparam=`/`queryparam=`. Fixtures `ktor-context-semantics`, `descriptor-routes` |
| R84 | kosi-endpoints | **Ktor 1.x was entirely unmodelled, and its routes were attributed to Vert.x.** Every pack pattern named Ktor 2's packages (`io.ktor.server.routing.get`), and the suffix rule cannot match a 1.x symbol (`io.ktor.routing.get`) against them. A Ktor 1.x app therefore produced no sources, no sinks — and its `route(...)` calls fell through to name-only attribution, where Vert.x's own `route` claimed them: kosi reported a Ktor application's endpoints under the wrong framework with no HTTP methods | the 1.x package layout (`io.ktor.routing`, `io.ktor.application`, `io.ktor.request`, `io.ktor.response`) is added to both packs' routing, reader, source and sink entries |
| R74 | kosi-endpoints (pre-existing since P7) | **only ONE framework per detection kind was ever consulted.** `detectGrpc` read `pack.frameworks.firstOrNull { it.kind == "supertype" }`. With gRPC the only supertype framework in the pack the bug was invisible; the moment a second one (AWS Lambda's `RequestHandler`) was added it took gRPC's place and every gRPC endpoint disappeared — caught by the corpus, which is what the corpus is for. Separately, an UNRESOLVED route call (`get("/x") { .. }` where the receiver type never resolved) was attributed to whichever framework sat first in the pack, because the match is on the bare NAME: Ktor, Javalin, Spark and Vert.x all declare a `get`, so sorting the pack alphabetically silently re-attributed every Ktor route to Javalin | the supertype kind iterates every supertype framework, and name-matched attribution now prefers the framework whose package this module demonstrably uses, evidenced by a RESOLVED callee fqn, falling back to first-match only when nothing is present. List order no longer decides a reported fact |
| R75 | kosi-endpoints (pre-existing since P7) | **reported route URLs omitted the deployment base path.** `@GetMapping("/orders")` in an application configured with `server.servlet.context-path=/api/v2` is served at `/api/v2/orders`; kosi reported `/orders`. That is a WRONG url, not a partial one — a consumer matching it against traffic, an allowlist or a scanner's target list gets no hit and no warning. The value was already in the config table the endpoint detector loads | routes compose the configured context path (`server.servlet.context-path`, `spring.webflux.base-path`, `micronaut.server.context-path`, `quarkus.http.root-path`, `ktor.deployment.rootPath`), Android excepted. Fixture `endpoint-base-path` asserts the composed path AND asserts the application-relative one is not reported |
| R72 | kosi-front (pre-existing since phase 2) | **a Kotlin read of a Java getter lowered as a FIELD READ, so no model pack could ever see it.** `editText.text` is `editText.getText()` on the JVM, and `intent.data` is `getData()` — but `dotChain` decided "plain name selector means field access" SYNTACTICALLY, without consulting what the name resolved to. The emitted instruction was `fieldget ve ve.text`: the path is the LOCAL VARIABLE's name, carrying neither the declaring type nor the fact that a method runs. Packs match callee symbols, so every getter-backed API in every Java library was invisible to the taint engine. This is how input enters an Android application, and it is why two intentionally-vulnerable Kotlin apps (AndroGoat, InsecureShop) produced **zero** findings while the engine happily computed 17k summaries and 39k dispatch joins on a third. Nothing failed: no fixture read a Java getter into a sink, and the corpus' own sources are all plain calls | `KirLowering.resolveProperty` resolves the selector and, for a `KaSyntheticJavaPropertySymbol` ONLY, emits a `KirCall` to the Java getter with its real JVM descriptor (`android.widget.EditText.getText` / `()Landroid/text/Editable;`). Kotlin property reads still lower as field accesses — the field sensitivity in P4/P5 keys on those paths. Fixture `android-taint` pins four Android shapes against a 5KB committed stub jar, two of which (`intent.dataString`, `intent` itself) exist only through this rule, each with the near-miss negative a collapsing implementation would report on |
| R73 | scripts (pre-existing since P9) | **the corpus' artifact warming downloaded nothing, silently, for every repo.** `warm-corpus-classpath.sh`'s synthetic resolve project put `import org.gradle.api.attributes.Attribute` UNDER `plugins {}`; Kotlin requires imports first, so the script never compiled, `resolveAll` never ran, and both the `|| true` and the `grep -E "downloaded"` filter swallowed the failure — the coordinate list was written, so the step looked like it worked. Every pinned repo then analysed against jars that were never fetched, which is the "no warm classpath" cause P11 recorded for grpc-kotlin and heterogeneous-microservices without finding why | the import moves above `plugins {}`, and a resolve that produces no `downloaded N` line is now a named WARNING naming the repo and tailing the log, instead of silence |

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
