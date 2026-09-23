# Kosi threat model

Same discipline as rusi's, applied to a Kotlin front end.

## Trust boundaries

- **Untrusted input to kosi**: the target project's sources and build files.
  kosi's default tiers never execute them: no Gradle, no Maven, no
  kapt/KSP/annotation processors, no build-logic evaluation. Gradle/Maven/AGP
  build files are parsed as *text* (balanced-brace block extraction plus
  anchored regexes in `kosi-project`); anything dynamic is reported unknown,
  never guessed and never run. The only processes kosi spawns are
  `git` (to fetch SHA-pinned corpus repos, explicitly requested) and `ps`
  (peak-RSS self-measurement on darwin).
- **kosi output**: internal until reviewed. Reports never contain literal
  secret values, environment values, command output or file contents. They do
  contain absolute paths (`runtime.workingDirectory`), internal service names,
  endpoint paths and symbol names — treat reports as evidence artifacts for
  the analyst, not as publishable documents.

## Hard rules

1. **Read-only tiers are read-only.** `--backend syntax` (and later
   `resolved`/`+deps`) touch the filesystem only to read. The opt-in
   `--backend compile` tier would execute the target build and will
   carry rusi's compiler-backend warning; it is never the default.
2. **No silent degradation.** A missing classpath, a failed lowering, a hit
   cap, a timeout, an unsupported Kotlin version — each produces a
   `diagnostics[]` entry with a code and a counter. A small plausible graph
   with no explanation is the worst possible output because it reads like a
   fact about the analysed code.
3. **Secrets are never copied.** Material records carry names/positions only
   (`crypto.materials`), never values; env-derived URLs resolve to a
   `resolution: env` marker, not the value.
4. **No build execution on untrusted input by default.** `corpus.toml` fetch
   jobs are operator-invoked, pin exact SHAs, and cache under
   `.corpus-cache/`; fixture analysis never touches the network.
5. **Deterministic output is a security property.** Two runs on the same tree
   are byte-identical (`cmp`-verified), so a diff between runs is always a
   real signal, and report artifacts can be integrity-checked.
6. **Dependencies are allowlisted.** kotlin-stdlib, the unrelocated
   `-for-ide` Analysis API artifacts plus the IntelliJ platform modules the
   standalone session needs, kotlin-test for
   tests. The native image is built with a pinned GraalVM CE 25 toolchain —
   every CI install is sha-pinned — and SHA-256 sidecars; no UPX
   (packed binaries segfault on macOS — docs/BUILD.md §4). The image
   initialises `java.awt.Toolkit` at build time: a JDK native library's
   `JNI_OnLoad` must never run at image startup, where AWT classes are
   absent.
7. **Committed third-party binaries are pinned and provenance-named.** The
   dependency-tier fixtures and the sample app commit real published jars
   (e.g. Timber 5.0.1's `classes.jar`). Each is documented next to its
   `classpath.txt`, never rebuilt and never fetched at analysis time; the
   corpus tier that reads them runs offline.
8. **The evinse bridge inherits the cdxrs discipline.** cdxgen spawns kosi
   read-only (`analyze` never executes the analysed build), honours
   `CDXGEN_KOSI_DISABLE=1` by skipping kosi entirely (a valid BOM without
   any kosi artifact — asserted by `scripts/kosi-e2e.sh`), and never lets a
   kosi failure abort SBOM generation.

## What kosi will never do

- Execute or evaluate `build.gradle(.kts)`/`pom.xml` logic.
- Run at image startup any code path that needs AWT (the
  `Toolkit` static initializer loads `libawt`, whose linux `JNI_OnLoad`
  requires classes an image does not ship — see docs/BUILD.md).
- Send any data anywhere (no telemetry, no network in default tiers).
- Copy source file contents into reports.
- Report findings without positions, or slices without connected witness
  paths (`kosi golden` asserts `sourceId ∈ nodeIds`, `sinkId ∈ nodeIds`,
  connected `edgeIds` on every slice).

## Known limits (stated, not hidden)

- **Import-based resolution is a spoofing surface, by design bounded.**
  An annotation or supertype the classpath cannot resolve is read at the
  FQN its file's explicit `import` names. A star import counts only when
  exactly one star package holds a pack-modelled FQN of that name. This is
  how endpoints survive a run with no jars. It also means a hostile source
  tree can declare `import org.springframework.web.bind.annotation.GetMapping`
  with no Spring on the classpath and get a route published. The effect is
  limited to ADDING attack surface to the report: it never hides an
  endpoint, never executes anything, and never changes what a resolved
  symbol means. A class the classpath does resolve always wins over the
  import. Every such run carries the `annotation-import-resolved` diagnostic
  with a count, so the report says the endpoints rest on imports and not
  types.
- **Implicit routes rest on declared dependencies and config, read as
  text.** Spring Data REST resources, Actuator endpoints and springdoc
  paths are published from a dependency coordinate in a build file or
  `classpath.txt`, plus `application.*` keys. They are published with
  `foundBy: implicit`. A key kosi cannot prove, for example one set only in
  a non-default profile, yields `pathUnresolved` and is never a guessed
  value.

- The syntax tier resolves nothing: `resolvedCallRatio` is 0.0 by
  construction and says so (`syntax-backend-no-resolution`).
- Java sources are discovery evidence at the syntax tier; Java PSI parsing
  arrives with the resolved tier.
- The Analysis API standalone session cannot be constructed from the
  allowlisted artifacts alone (unrelocated IntelliJ platform classes are
  missing; KSP2 fat-jars thousands of them). `kosi version` reports this as
  `analysis-api-standalone: unavailable: ...` — a `resolve-capability`
  diagnostic, not a pretend capability. Closing it is a deliberate, recorded
  decision.
