# Kosi phase status and defect registry

Companion to `$HOME/kotlin-plans/07-REVIEW-PROTOCOL.md`: merged phases,
measured numbers, and the numbered defects that `known-fail=<n>` corpus
markers refer to. Defects stay numbered; closing one requires the XPASS
ratchet proof.

## Phase 0 — measurement harness + native-image spike (this branch)

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
  `build/kosi-darwin-aarch64` (44.7 MiB); numbers and pitfalls in
  `docs/BUILD.md`.

Measured (host: darwin-aarch64, M4 Pro):

| Metric | value |
| --- | --- |
| fixtures | 16, ×2 slots = 32 corpus cases |
| annotations | 202 (126 positive / 76 negative) |
| recall (fixtures tier, per slot) | 1.000 (124/124 non-known-fail positives) |
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
   gap as a `resolve-capability` diagnostic; the resolved tier (P2) must
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
| 1 | syntax | no flow engine at the syntax tier: no slices, no call graph; `command-exec` carries `known-fail=1` for `flow source=untrusted-input sink=process-exec` | open |
