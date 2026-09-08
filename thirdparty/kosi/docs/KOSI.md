# Kosi phase status and defect registry

Companion to `$HOME/kotlin-plans/07-REVIEW-PROTOCOL.md`: merged phases,
measured numbers, and the numbered defects that `known-fail=<n>` corpus
markers refer to. Defects stay numbered; closing one requires the XPASS
ratchet proof.

## Phase 1 — resolved front end (this branch)

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
- **Native image carries the resolved tier.** `kosi version` in the
  `kosi-darwin-arm64` binary reports all three components available and
  `--backend resolved` runs end-to-end, byte-identical across runs. The
  image needed three recorded fixes: the K1 application environment is
  seeded once per process with a configuration pointing
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
- Binary: 93,627,264 bytes (89.3 MiB) on GraalVM CE 25.0.4.1, up from P0's
  53,185,568 — the unrelocated IntelliJ platform + FIR + Analysis API is
  the closed world now. Determinism holds: native output byte-identical
  across runs and byte-identical to the JVM build.
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
  bytecode tier which reads dependency jars directly.
  result.

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
