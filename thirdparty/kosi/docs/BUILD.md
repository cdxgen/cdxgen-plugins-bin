# Building and shipping kosi

Phase 0 (P0) numbers and commands, measured on the host platform
(darwin-aarch64, Apple M4 Pro, 64 GB, macOS 26). Re-measure at every phase
gate; a change that grows the binary by more than 10% has to say why
(05-BUILD-DIST.md §3).

## 1. Primary path: GraalVM native-image — WORKS

JetBrains build a native image of `kotlin-compiler-embeddable` themselves
(`prepare/compiler-native-image`), which makes feasibility a fact, not a bet.
kosi copies their recipe with two adjustments recorded below.

Measured P0 numbers:

| Artifact | Size |
| --- | --- |
| deterministic fat jar (`kosi-all.jar`) | 68,608,874 bytes (65.4 MiB) |
| native binary `kosi-darwin-arm64` | 53,185,568 bytes (50.7 MiB) |
| native build wall clock | 31 s (M4 Pro, `--gc=serial -Os`, peak RSS 3.3 GB) |
| cold start, `kosi version` | < 10 ms (below `/usr/bin/time` resolution) |
| `java -jar kosi-all.jar version` | ~60 ms |
| `kosi analyze` (native), 16-fixture sweep | all succeed, byte-identical across runs **and** byte-identical to the JVM build |
| UPX-LZMA (`--force-macos`) | 35 MB -> 12 MB, **binary segfaults: NOT USED** |

**Toolchain: the pin is part of the contract, not a preference.** kosi builds
against GraalVM CE 25.3.4.1 (`native-image 25.0.4.1`, GraalVM for JDK 25):

```bash
# sdkman's own 25.3.4+1.r25-graalce candidate fails to repackage on macOS,
# so install the release directly, under the path the Makefile pins:
mkdir -p ~/tools && cd ~/tools
curl -LO https://github.com/graalvm/graalvm-ce-builds/releases/download/graal-25.3.4.1/graalvm-community-jdk-25i3-25.0.4.1_macos-aarch64_bin.tar.gz
shasum -a 256 -c <<<"ebfab1d74420f355a459076162012d6835fa6068bd9d2f230f1fcaf7ee0dd923  graalvm-community-jdk-25i3-25.0.4.1_macos-aarch64_bin.tar.gz"
tar -xzf graalvm-community-jdk-25i3-25.0.4.1_macos-aarch64_bin.tar.gz
# optional: expose it through sdkman as a local candidate
sdk install java 25.0.4.1-gce ~/tools/graalvm-community-25.3.4.1+1.1/Contents/Home
```

Other GraalVM builds are not interchangeable: on **CE 25.0.2** the same
sources produce a binary that cannot create the analysis session at all
(`UnsatisfiedLinkError: Can't load library: awt` — that JDK's
`Toolkit.<clinit>` loads its natives before reading the `awt.toolkit`
property, so kosi's no-op toolkit is never selected), and it is 12 MB
larger. So `GRAAL_HOME` resolves in order: an explicit override, **the pinned
release** under `$HOME/tools`, then a `JAVA_HOME` that provides
`native-image` — and every binary rule depends on `native-toolchain-check`,
which prints the `native-image` version in use and refuses anything but the
pin unless `GRAAL_ALLOW_ANY=1`:

```
$ make native-toolchain-check
kosi: native-image 25.0.4.1 (pinned) at /Users/you/tools/graalvm-community-25.3.4.1+1.1/Contents/Home
```

**Binary size is toolchain-specific, so record the GraalVM build alongside
every number.** P1 on the pin: 93,709,760 bytes (89.4 MiB); the same sources
on CE 25.0.2: 106,000,640 bytes. The plan's
"most binaries land 120-260 MB uncompressed" budget is beaten by an order of
magnitude because the P0 closed world is small: the syntax tier touches the
frontend/PSI only, never the compiler *backends*.

Reproduce:

```bash
cd thirdparty/kosi
make bootstrap-darwin   # verifies the pinned GraalVM is installed
make native             # fat jar + native image + sha256 sidecar
./build/kosi-darwin-arm64 version
rm -f /tmp/a.json /tmp/b.json   # a failed run leaves the OLD file in place
set -e                          # ...and `cmp` would then compare it with itself
./build/kosi-darwin-arm64 analyze --dir fixtures/weak-crypto --out /tmp/a.json
./build/kosi-darwin-arm64 analyze --dir fixtures/weak-crypto --out /tmp/b.json
test -s /tmp/a.json && test -s /tmp/b.json
cmp /tmp/a.json /tmp/b.json
```

The two lines before the runs are not decoration. `analyze` writes nothing
when it fails, so a comparison over reused paths passes loudest exactly when
the tool is broken — an empty-vs-empty match, or last run's report against
itself. R53 reached the P3 gate that way: the image could not analyse any
fixture containing an `object`, and the phase's own native-vs-JVM sweep
reported every fixture identical. P4 turned the recipe into a script that
cannot be run wrong — outputs deleted before every run, exit codes checked,
sizes asserted, `tool.commit` normalised, and the per-fixture slice/node/edge
counts printed so the sweep shows what it compared:

```bash
scripts/determinism-sweep.sh --jar modules/kosi-cli/build/dist/kosi-all.jar JVM
scripts/determinism-sweep.sh build/kosi-darwin-arm64 native
scripts/native-vs-jvm.sh build/kosi-darwin-arm64 \
  modules/kosi-cli/build/dist/kosi-all.jar
```

### When this is worth running

The native pass costs roughly 35 minutes end to end on an M-series laptop:
~13 min to build the image, ~6 min for the native sweep, ~7 min for
native-vs-JVM, ~9 min for a metadata check. Running all of it after every
change is waste, and waste that gets skipped under time pressure is worse
than a rule nobody pretends to follow. Run what the change can actually
break:

| the change | what to run |
|---|---|
| model packs, `corpus.toml`, docs — DATA only | nothing native. The image cannot be affected: it holds no pack. |
| new fixtures, or any new Kotlin SOURCE CONSTRUCT | `make native-metadata-check` alone. Drift is the whole signal (R69), and it needs no image. |
| lowering, KIR shape, reflection, resources, `native-image` flags, the CLI entry | the full pass: rebuild, both sweeps, and the metadata check. |
| a squash-merge that touched none of those | nothing native. |

**`native-vs-jvm.sh` is the expensive one and it is NOT a per-merge gate.**
Every divergence it has ever caught — R53 (an image that could not analyse
an `object`), R69 (one that could not analyse a KDoc comment), R66 (one that
could not start on linux) — was a REFLECTION or RESOURCE failure, and
`native-metadata-check` sees that class of problem from a trace, with no
image build, for a fraction of the cost. So metadata drift is the routine
gate; the comparison runs only when the change is in the image's own
surface (the row above), and otherwise on a release build. Running it after
a data or fixture change buys nothing and costs half an hour.

The discipline is real — a green JVM suite has repeatedly shipped a broken
image — but it is a reason to watch reflection metadata, not a reason to
rebuild an image after editing a JSON file.

Both sweeps run **both** graph-bearing slots (`resolved` and `--roots
exported`), not `resolved` alone: R53's lesson is that a slot nobody runs is
a code path nobody proves anything about, and `exported` is precisely the
slot whose missing reflection entry killed the P3 image. 35 fixtures x 2
slots = 70 pairs; at P4 all three sweeps read 70 of 70.

The native-vs-JVM comparison is a script and not a paragraph for the same
reason: it was prose in P3 ("cmp the outputs per fixture"), and it is the
step R53 walked straight through.

When comparing a native report against a JVM one, normalise `tool.commit`:
the image bakes in the commit it was built from, the JVM run reads the one
its jar was built from, and the two differ whenever either is stale.

### The committed symbol-evidence extract and the pack liveness gate (P19)

Two tests gate the endpoints pack itself, not the engine:

- `EndpointsPackSymbolEvidenceTest` (kosi-bytecode) checks every modelled
  symbol against COMMITTED evidence —
  `modules/kosi-bytecode/src/test/resources/symbol-evidence/endpoints-pack-symbols.json`,
  ~32 KB of class kinds, member tables and facade statics derived from the
  pinned artifacts (http4k sources at the pinned SHA, vertx-web 5.1.7,
  ktor 3.5.2, spring 5.3.18, micronaut 4.10.23, the jakarta/aws/azure
  jars), never the jars. The pack-vs-extract check runs on EVERY machine
  (R109/R112/R113/R114's shape fails anywhere); where the pinned evidence
  is held, the extract is re-derived and must equal the committed bytes.
  Regenerate after a deliberate pack or evidence-pin change:

      KOSI_UPDATE_SYMBOL_EVIDENCE=1 ./gradlew :kosi-bytecode:test \
          --tests 'io.cdxgen.kosi.bytecode.EndpointsPackSymbolEvidenceTest'

  The verdict table counts per framework — checked vs committed, gaps
  recorded with reasons; a framework nobody can check says so, never
  KIND-CHECKED.

- `EndpointsPackLivenessTest` (kosi-bench) is the R63 gate the pack never
  had: it removes every pack entry in turn (identity-based, so whole
  name-classes compose) over one captured front-end analysis per bundled
  fixture and classifies each entry LIVE (some fixture's detection result
  changed — the whole `Endpoints.Result`, source handlers and config
  counts included, so a verdict is never an artefact of which fields the
  gate compared), ALIAS-COVERED (a same-name sibling of
  another generation carries the channel) or INERT. An inert entry fails
  unless `inertAllowance()` in the test records a one-line reason for it —
  the reviewed-in-diff exit, not a CI suppressor. The sweep takes ~15 s
  (the front end runs once per fixture; only detection re-runs per entry).

### The gate-cost policy: corpusChanged, and corpusFull ONCE (P20 §5)

`corpusFull` is the most expensive thing anyone runs here (~50 minutes, a
warmed cache, one machine), and by P20 it had become the routine answer to
every question. The policy is now, on evidence:

- **`corpusChanged` (`scripts/corpus-changed.sh [base-ref]`) is the
  development loop's tier.** The bundled tiers always (they are
  corpusQuick), the vuln-repo floors always, plus any repo row whose
  declared `capabilities` intersect a capability token the change mentions
  — the token vocabulary is read FROM `corpus.toml`, so the mapping is
  data-driven. `--only` takes a comma-separated slug list;
  `./gradlew kosiRepoRows -Pkosi.only=...` runs the selected rows.
- **`corpusFull` runs ONCE per phase**, at the end, on the corpus machine,
  and its result is what the phase report quotes. Not per commit, not per
  question.
- **CI stays the fast deterministic subset** it is today (`kosi-test.yml`:
  unit tests, corpusQuick, goldens). Bigger tiers stay local — that is the
  standing instruction and it does not change.
- **What corpusChanged deliberately does NOT see**, and the gates that do:
  cross-environment and cache effects (`scripts/two-environment-proof.sh`),
  bundled-fixture digest drift (`./gradlew golden`), pack-symbol rotness
  and inert entries (the two liveness sweeps), and repo-tier movement on
  repos the change's capability tokens do not name (corpusFull, once).

The evidence for the tier boundary (P20 §5, measured over goldens/ and the
tracker's history): every one of the 17 commits that ever touched goldens
is a phase squash, and the bundled fixtures' gates caught every movement —
the bundled tier is the population whose digest history is dense. The REPO
tier has no goldens at all; its recorded numbers (the floors, the
per-repo ratios) have moved four times in twenty phases (P14's floors, P14
kampkit, P16 nowinandroid, P12's pack growth), each time through a warm,
a resolver, or a pack change — which is exactly the population the
capability matching selects.

### What no corpus tier answers: is this code reachable from any input we have (P21)

`corpusChanged` and `corpusFull` both answer one question: **did a
behaviour move.** Neither answers the question R131 turned up: **is this
code reachable from any input we have.** R131's cross-block fold — 460
lines of dominator walk with a green unit test — ran GREEN through every
corpus tier at any cost, because the corpus held no input that reached the
code: no bundled fixture had ever asked the folder for a local's value, so
there was nothing for any bench row to move on. No tier, at any price,
fixes that; a warm cache does not invent inputs.

The gate that answers it is a FIXTURE, and the phase rule is the policy:
**every capability ships with its fixture that reaches it through
`Analyzer.analyze`, in the same change** — and every failure reason the
folder can name stays non-zero in the committed depth report
(`DepthReportTest.everyFoldFailureBucketIsNonZeroInTheCommittedReport`), so
a new reason must arrive with an input that reaches it or not ship.

The replay, measured (P21 §4) by restoring each defect one at a time:

| defect | corpusChanged | what actually catches it |
|---|---|---|
| R129 — no fixture makes a sanitizer load-bearing | GREEN: an absence moves no bench row (measured: the bundled bench is green with `sanitizer-gallery` deleted) | the depth-report golden + the security-pack liveness sweep, both in `./gradlew test`, which runs in every loop |
| R130 — the name matcher reads golden file names | FLOODS: the tier's vocabulary fills with fixture slugs mirrored by golden names (measured on this phase's own diff: 0 → 6 tokens; on P20's 164 regenerated goldens it selected every repo row and ran 45 minutes) | nothing automated can see a tier degenerate into corpusFull; the fix is the filter and the review of it |
| R131 — the fold cannot see a local's value | GREEN at `cd71886`, where the defect shipped (measured: corpusQuick 0 fail, androgoat floor green, with the store arm absent and no fixture reaching the code). RED at P21 with the same defect restored — `cross-block-values/resolved` fails 2 wants. The difference is the FIXTURE, not the tier | the fixture (R63), which is the phase rule |
| R132 — the content matcher diffs the whole tree | same flood as R130 through the other door (measured: 0 → 9 tokens) | same |

A corollary the replay surfaced: `depth-cap-chain` pins the VALUE outcome
(the chain stays unresolved) but not the failure REASON — the restored R131
also produces an unresolved value there, by a different route. Reasons live
in the depth-report golden, values in the corpus; the two gates hold
different halves, and neither substitutes for the other.

### The reachability table past the bundled tier (P21 §3, schema closed P22 §2)

The depth report's third table (complete / partial / symbol-only) is a
bundled-corpus golden; on the corpus machine it has been run over the three
pinned vuln repos at the bench's own slot options, and the numbers are:
androgoat 16 findings (16 complete, 0 partial, 0 symbol-only, ratio
0.9546), insecureshop 7 (7/0/0, ratio 0.9147), tsp 2 (2/0/0, ratio 1.0) —
identical at the `resolved` and `exported` slots, so on these apps every
published finding rides a COMPLETE entrypoint→sink path and the fraction
that means only "exists" (the exported roots' honest meaning, P20 §4) is
zero. P22 §2 closed the schema gap that paragraph used to warn about: the
distinction is now a FIELD on every slice (`pathKind`: complete | partial |
symbol-only, pinned by `SlicePathKindVocabularyTest`), the constant-false
`reachableFromRoots` flag and the always-null `rootWitness` are deleted
(a field that never varies is not a fact, it is a schema lie — R117's
rule), and the elided-trace fixture drives PARTIAL so no vocabulary value
is undriven. The historical zero on the repos rests on a defect P22 found
and fixed (R135): the summaries published their sink effects with the
composed site paths stripped, so a composed trace could never outgrow the
trace cap and PARTIAL was unrepresentable anywhere — the repo numbers
above are unchanged by the fix (the same findings, now with real traces),
which is what makes them a measurement instead of an artefact.

### The option matrix (P23 §0)

The corpus picks FIXTURES and SLOTS. Until P23 nothing picked option
COMBINATIONS, and that is where R137 lived: `--dataflow reachable` paired
with `--callgraph none` published a `reachableSlices` count claiming every
slice reachable, on a run that had built no graph to intersect with. It
survived 522 golden pairs, a 600-row `corpusQuick`, a full corpus and a
two-environment proof, because not one of them runs `reachable` mode at
all.

`OptionMatrixTest` walks the accepted product of the option enums over one
small project and asserts each cell's contract. It costs seconds and no
corpus tier, which is the point: the cheapest gate in the repo covers the
axis the expensive ones do not. Two properties make it a gate rather than a
sample — it is EXHAUSTIVE over the enums (a new `DataflowMode` or
`CallGraphMode` with no declared contract fails it), and the diagnostics it
expects come from `AnalyzeOptions.degradations()`, the same predicate the
CLI refuses from, so a report and a refusal cannot describe different sets.

| pairing | before P23 | now |
| --- | --- | --- |
| `--backend syntax` + any `--dataflow` (THE DEFAULT) | no `dataFlow`, no diagnostic naming it; the only hint spoke about `resolvedCallRatio` | `dataflow-not-run` names it, run proceeds |
| `--backend syntax` + any `--callgraph` | no `callGraph`, silently | `callgraph-not-run` names it, run proceeds |
| `--dataflow reachable` + `--callgraph none` | accepted; published every slice as reachable (R137) | CLI REFUSES; the library names `reachable-without-callgraph` and reports 0 |
| `--deps` + `--dataflow none` | the tier was lowered and summarised, then discarded | `deps-without-dataflow` names it |
| `--dataflow crypto` | published every security slice, unfiltered (R139) | publishes only crypto flows, by the predicate the bench already counted them with |
| `--dataflow all` | a synonym of `security` that nothing said was one | asserted to be a declared alias, in one line |

The `all` SLOT is gone with it. It ran the syntax backend, which runs no
dataflow, so `--dataflow all` could change nothing but the echo of the flag:
across all 87 fixtures the `all` and `security` goldens differed in exactly
one section, `options`, and no fixture carried a single `mode=all`
annotation. 87 golden pairs — a sixth of every corpus run, every golden
check and both legs of the two-environment proof — pinning the fact that the
CLI echoes its own flag (R53).

### Merges: a set, a witness, or a fact (P23 §1)

R138 was a type error wearing a data structure's clothes: eight fields of a
`FunctionSummary` are sets of effects and one is a witness path, and the
deps-tier JOIN unioned all nine. Every merge in the analysis is now
classified, and the classification is the discipline:

| merge | kind | rule |
| --- | --- | --- |
| `FlowState.addFacts` / `mergeFrom` | SET | union; a fact either side has, the join has |
| `Transfer.joinInto` (phi, concat, elvis) | SET + per-fact WITNESS | facts union; the blame register is CHOSEN (first operand carrying it), never merged (R54/R62) |
| `FunctionSummary.join` (deps tier, by name) | SET ×8 | may-union across the overloads of one name |
| `FunctionSummary.join`, `sourceReturns` | WITNESS | shortest path, lexicographic tie-break — the joined path IS one of its inputs (R138) |
| `SummaryAnalysis.toSummary` escape dedup | WITNESS | one shortest-path witness per canonical (R135) |
| `KirValueFolder` phi / dominator join | FACT | arms that disagree REFUSE; no arm is preferred |
| `KirValueFolder` workspace return sites | FACT | every return site of every candidate must agree, or refuse |
| `ConstTable.fromSources` (`const val` names) | FACT | a name holding two values is refused, never guessed |
| `ConfigResolver.load` (config keys) | FACT | **was a PICK** — first file in sorted-path order won and was published as `resolution=config`. Now refuses: known key, null value (R140) |
| `BytecodeLowerer.classIndex` | PICK, declared | a shaded class keeps the last jar, mirroring the resolver's own one-artifact-per-coordinate pick |

### The two-environment proof (P18)

`scripts/two-environment-proof.sh [<commit>]` (default HEAD) is the scripted
form of the check that found R108: the same commit checked out TWICE (two
git worktrees, different absolute paths), the same kosi jar, and two Gradle
cache states — leg A with the machine's caches as the runner left them,
leg B with `HOME` and `-Duser.home` pointed at an empty directory, so the
offline resolver reads `user.home/.gradle` and `user.home/.m2` and finds
nothing. Each leg runs `kosi golden --update-goldens` into its own
directory; the script diffs the two legs' digest files (naming the sections
that differ, per file) and each leg against the CHECKED-IN goldens at that
commit. Any difference exits 1.

Run it per phase and before a release; it takes a few minutes (one fat-jar
build plus two golden passes). Requirements: a clean working tree (the
proof compares a commit, not a dirty tree), git, a JDK, and either a warm
Gradle build cache or network for the one jar build — the analysis itself
never touches the network. On a machine whose Gradle modules-2 cache is
already empty the cache axis degenerates (the script prints a note) but the
checkout-location axis still runs; the corpus machine gives the full
warm-vs-scrubbed contrast.

Its teeth, measured 2026-09-16: against `feat/kosi-part2` (`2a6d232`) the
proof PASSES — 450 digest files identical across both legs and matching the
checked-in goldens, i.e. zero environment dependence found; against P16
(`d317c78`), where the async fixtures were still unpinned, it FAILS exactly
the way the P17 review's second machine did — the six coroutines fixtures
differ between the legs (`callGraph, diagnostics, stats` sections: the warm
cache attaches jars the scrubbed leg cannot), and `async-android-scopes`
additionally disagrees with its own checked-in goldens (`callGraph,
diagnostics, imports, stats`), which is R104 verbatim. The golden gate's
in-run portability check (§ above) covers the checkout-location axis on
every `kosi golden` run; this script adds the cache axis and the
against-the-pin comparison.

## 2. Handled pitfalls (05-BUILD-DIST.md §1 table, with outcomes)

| Pitfall | Handling | Status |
| --- | --- | --- |
| Shaded JLine ships `META-INF/native-image/org.jline/...` properties pointing at absent files (KT-68829) | `kosiFatJar` strips `META-INF/native-image/org.jline/**` and `org/jline/**` (the REPL/daemon classes kosi never calls) | fixed |
| intellij-core registers services/extension points via ServiceLoader + XML; the 2.4.0 environment locates its own jar via `PathUtil.getResourcePathForClass`, which cannot work in an image | the compiler's `META-INF/extensions/*.xml` descriptors ship as image resources (`kosi-ext/`), are materialized to a temp dir at run time, and `CLIConfigurationKeys.INTELLIJ_PLUGIN_ROOT` points there — the configuration key the 2.4.0 code checks *before* the jar lookup | fixed |
| IntelliJ `EventDispatcher`/`Proxy` dynamic proxies | `native-metadata/proxy-config.json` registers one proxy group per listener interface; note this GraalVM wants the **array-of-interface-arrays** proxy config format, and reachability-metadata `proxy` entries passed via `-H:ConfigurationFileDirectories` did **not** register (see deviations) | fixed |
| `kotlin-reflect` retention | no `kotlin-reflect` anywhere; hand-rolled JSON writer/reader and arg parser | avoided by design |
| build-time class-init clashes | `--initialize-at-run-time=...EarlyAccessRegistry`; `--trace-class-initialization` documents any further clashes | minimal list, grows on evidence |
| reachability drift when the Kotlin pin bumps | `make native-metadata` re-runs the tracing agent over every fixture and deterministically re-merges (`scripts/merge-agent-metadata.py`); `make native-metadata-check` fails CI on drift | wired |

## 3. Reachability metadata provenance (rewritten at P1)

P1 moved the substrate from the shaded `kotlin-compiler-embeddable` to the
unrelocated `-for-ide` artifacts plus the unrelocated IntelliJ platform
(02-ARCHITECTURE.md §1 amendment). The JetBrains seed metadata described the
SHADED class names (`org.jetbrains.kotlin.com.intellij.*`) and cannot apply;
the whole surface is now re-derived from our own runs:

- `native-metadata/kosi/reachability-metadata.json` — the GraalVM tracing
  agent over ALL fixtures with BOTH backends (every fixture at the syntax
  backend plus every fixture again at `--backend resolved`, so the Analysis
  API session's ServiceLoader, reflection and proxy surface is recorded),
  merged by `scripts/merge-agent-metadata.py` (deterministic union; CI diffs
  the checked-in file via `make native-metadata-check`).
- `native-metadata/proxy-config.json` (P0's hand-maintained relocated
  proxies) and the JetBrains seed (`native-metadata/jetbrains/`) are retired;
  proxy groups arrive through the agent's reachability metadata now.
- The fat jar carries the kotlin-stdlib JAR FILE as a resource
  (`kosi-libs/kotlin-stdlib.jar`): the native resolved tier materializes it
  to a temp jar at run time as the module provider's stdlib binary root —
  an image has no classpath jars on disk.

## 4. Size levers still available (05-BUILD-DIST.md §3, in order)

1. `-Os`, `--gc=serial` — applied. `-H:-IncludeMethodData` not yet needed.
2. shadowJar minimisation (drop compiler backends, daemon, JLine) — partially
   applied (`org/jline/**` dropped wholesale); further trimming is phase 3+
   work measured against the corpus.
3. UPX-LZMA — **rejected at P0**: `upx --force-macos --lzma` packs 35 MB to
   12 MB but the packed binary segfaults on macOS; unpacked it is identical
   output. Per the plan, kosi ships uncompressed rather than risk a
   platform-specific segfault. Re-evaluate per platform on linux/windows at
   the release phase.
4. Own npm package / ORAS-only distribution — not needed while the binary is
   ~45 MB; revisit if phase 3+ (resolved tier, more of FIR) pushes past the
   budget.

## 5. Fallback (jlink) — not needed at P0

The jlink runtime image fallback (05-BUILD-DIST.md §5) was not required: the
primary path builds and runs. If a later phase breaks native-image (for
example the Analysis API standalone platform wiring in P2 dragging in more of
intellij-core), the fallback order stands: jlink image first, `kosi-portable.jar`
for ppc64/arm32 regardless.

## 6. Platform matrix claim at P0

Native-image is claimed for darwin-arm64 (proven here) and, by the same
recipe, linux-amd64/linux-arm64 and musl static builds on the release
runners. ppc64 and 32-bit arm remain declared gaps with a documented JVM-jar
fallback (see `docs/KOSI.md`); riscv64 stays best-effort per the plan.
Windows follows at the release phase with the MSVC toolchain.

Binary names use the package fragments (`kosi-darwin-arm64`,
`kosi-linux-amd64`, ...) so `stage-built-plugins.sh` finds them without a
mapping. The Makefile carries the same family targets the release workflow
invokes for the other plugins — `linux`, `linuxmusl` (needs `musl-gcc`,
`apt install musl-tools`), `windows`, `darwin` — and because native-image
cannot cross-compile, each builds for the host it runs on and errors with a
named message otherwise (including the declared gaps: ppc64le, 32-bit arm,
riscv64). The per-platform exemption table shared by staging and coverage
lives in `scripts/plugin-platform-support.sh`; exemptions are printed
wherever they apply, never silent.

CI: `.github/workflows/kosi-test.yml` runs one job on every change — unit
tests, the fixture-tier corpus ratchet (`corpusQuick`, both modes) and the
digest goldens, a few minutes end to end. Everything heavier is
`workflow_dispatch`-only and belongs to the phase gate run locally: the
darwin-arm64 and linux-amd64 native builds, and `corpusFull`. The rule is
deliberate — big measurements run on the machine that can hold them, and
the small deterministic subset guards every push.

`corpusFull` is `workflow_dispatch`-only for the same reason it always
should have been: the pinned-repo matrix does not fit a hosted runner.
Measured 2026-09-15 on `ubuntu-latest`: the WARM step alone ran 52 minutes
(http4k's monorepo 42 of them) and the job was killed (exit 143) 56 minutes
in, during nowinandroid's warm, before a single bench row ran. The gate
itself has not moved — `corpusFull` is run per phase on the corpus machine,
with rows, fail/XPASS counts, the vuln finding floors and every repo's
resolvedCallRatio recorded in that phase's tracker section. A red
tick nobody can make green is not a gate; the phase report is. The linux-amd64 GraalVM
tarball sha256 has been pinned since R66 (the job downloaded an unpinned
tarball because its first successful run never happened):

```
b2bc38d0c4141426eb44d0eefa3cc172c96faf92727d703b61541699128b6fc7  graalvm-community-jdk-25i3-25.0.4.1_linux-x64_bin.tar.gz
```

### The linux AWT startup failure (R66, root-caused)

The linux-amd64 smoke aborted at image startup with
`NoClassDefFoundError: java/awt/GraphicsEnvironment` raised inside a JDK
native library's `JNI_OnLoad`, while the same jar, flags and metadata built
and ran green on darwin. The cause is in the JDK's own natives:

- `java.awt.Toolkit`'s `<clinit>` (`initStatic()` → `loadLibraries()`)
  calls `System.loadLibrary("awt")` UNCONDITIONALLY, before any
  `awt.toolkit` property read. The path that reaches it is the IntelliJ
  platform's mock application scheduling one Swing runnable while the
  analysis environment is created — the same finding the P1 no-op toolkit
  works around.
- linux `libawt.so` defines a `JNI_OnLoad` that calls
  `FindClass("java/awt/GraphicsEnvironment")` at load; an image ships no
  AWT classes, so the load is fatal.
- darwin `libawt.dylib` defines **no `JNI_OnLoad`** (`nm -D
  --defined-only`), so the identical path is harmless there. The
  "registration difference" between the platforms was never in kosi's
  flags.

The fix, verified in a local arm64 container running the exact CI recipe,
is THREE facts (linux targets only, via `KOSI_AWT_FLAG` in the Makefile):

1. JDK 25 removed the `awt.toolkit` property: linux
   `PlatformGraphicsInfo.createToolkit()` constructs XToolkit
   unconditionally, whose `<clinit>` calls `getLocalGraphicsEnvironment()`
   -> `X11GraphicsEnvironment.<clinit>` -> `System.loadLibrary("awt")`,
   and libawt.so's `AWT_OnLoad` does
   `FindClass("java/awt/GraphicsEnvironment")` + `GetStaticMethodID
   isHeadless` in an image that ships no AWT classes — fatal.
2. `-Djava.awt.headless=true` at BUILD time plus
   `java.awt.GraphicsEnvironment` in the build-time-init list bakes
   `isHeadless() == true`, so `AWT_OnLoad` dlopens `libawt_headless.so`
   instead of `libawt_xawt.so` — no X11, and the event queue works.
3. The image JNI-registers `java.awt.GraphicsEnvironment` + `isHeadless()`
   (a hand-seeded reachability entry `scripts/merge-agent-metadata.py`
   preserves) so `AWT_OnLoad`'s lookups succeed.

The flags are deliberately NOT applied to darwin: baking Toolkit at build
time there ships a default `LWCToolkit` in the image heap and every probe
fails (measured). Darwin needs no flag — its `libawt.dylib` has no
`JNI_OnLoad`, so nothing there is fatal; `java.awt.headless=true`, set in
`main`, is the whole of its mechanism. (It was believed to be a no-op
`Toolkit` selected through `awt.toolkit`; JDK 25 never reads that property
— see R71.) To reproduce the verification locally:
`docker run --platform linux/arm64 ubuntu:24.04` + the pinned
linux-aarch64 GraalVM + `zlib1g-dev`, then the `native-image` command from
the Makefile's linux rule against the checked-in fat jar and metadata.
