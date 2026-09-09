# Kosi (Kotlin Source Inspector)

kosi is a Kotlin code analysis engine for evidence collection — the Kotlin
sibling of `golem` (Go) and `rusi` (Rust). It answers, for a Kotlin project:

- which Kotlin/Java sources, modules and source sets exist (Gradle, Maven,
  Android variants, Kotlin Multiplatform), and their declared/effective
  language versions
- which imports, declarations and library calls occur (canonical, sorted,
  byte-identical output)
- which packages/purls the evidence attaches to

Phase 0 ships the **syntax tier** (`--backend syntax`): PSI-only parsing via
`kotlin-compiler-embeddable`, with **no classpath and no build execution**.
The resolved tier (typed call graph, interprocedural taint, crypto/services
evidence) lands in later phases on the same report contract
(`schemaVersion: kosi/1`).

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
kosi kir dump --dir .                               # KIR dump (resolved tier), round-trip + CFG validated
kosi bench --tier fixtures                          # corpus ratchet, both modes
kosi bench --tier fixtures --write-baseline baseline.json
kosi bench --tier fixtures --baseline baseline.json --fail-unless-promotable
kosi golden                                         # digest goldens, trace invariants
kosi version                                        # versions, compiler band, capabilities
```

Exit codes: `0` success, `1` expectations failed (ratchet/golden/bench),
`2` usage error, `3` runtime error.

## What kosi reads

- `settings.gradle(.kts)`, `build.gradle(.kts)`, `gradle.properties` — member
  list, plugins, compiler settings, Android build types/flavors, KMP source
  sets. **Parsed as text, never executed.**
- `pom.xml` — Maven modules, coordinates, kotlin-maven-plugin settings.
- `.kt` sources under discovered source roots (PSI parse); `.java` sources as
  discovery evidence (Java PSI parsing arrives with the resolved tier).
- `corpus.toml` for the evaluation harness; annotations (`kosi:want`,
  `kosi:want-not`) in fixture sources; SHA-pinned upstream repos fetched into
  `.corpus-cache/` for the small/medium tiers.

### Syntax tier (default)

- Parses without classpath or JDK; unresolved things stay unresolved **and
  are reported** (`syntax-backend-no-resolution`, `parse-error`, ...).
- Emits `modules`, `packages`, `files`, `imports`, `declarations`, `usages`
  (by name, dotted receiver form), `diagnostics`, `stats`.
- Version policy (08-VERSION-POLICY.md): the analysable band comes from the
  bundled compiler's `LanguageVersion` constants at runtime — on Kotlin
  2.4.0 that is 2.0–2.4 with `FIRST_NON_DEPRECATED` 2.2. Projects declaring
  older versions are clamped with a `kotlin-language-version` diagnostic;
  newer declarations get `kotlin-version`. Reports carry
  `runtime.kotlinVersion` and `runtime.languageVersionRange`.

## Development

```bash
./gradlew build        # unit tests, all modules
./gradlew corpusQuick  # fixture-tier ratchet, security + all modes
./gradlew corpusFull   # fixtures + pinned real-repo tiers (network)
./gradlew golden       # digest goldens for every fixture/slot
make native            # GraalVM native image (see docs/BUILD.md)
make size              # staged binary sizes
```

The corpus is a two-way ratchet: a regressed expectation fails the build and
a `known-fail` that starts passing fails the build (XPASS). Scoped markers
(`known-fail=syntax:1`) describe per-backend defects; the numbers reference
`docs/KOSI.md` §defects.

See `docs/BUILD.md` for the native-image spike numbers,
`JSON_ATTRIBUTE_REFERENCE.md` for the report contract, `THREAT_MODEL.md` for
the security model, and `docs/KOSI.md` for phase status and defects.
