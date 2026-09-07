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
| deterministic fat jar (`kosi-all.jar`) | 68,596,677 bytes (65.4 MiB) |
| native binary `kosi-darwin-aarch64` | 46,893,264 bytes (44.7 MiB) |
| native build wall clock | 30 s (M4 Pro, `--gc=serial -Os`) |
| cold start, `kosi version`, median of 20 | < 10 ms (`/usr/bin/time` resolution) |
| `java -jar kosi-all.jar version` | ~60 ms |
| `kosi analyze` (native), 16-fixture sweep | all succeed, byte-identical output |
| UPX-LZMA (`--force-macos`) | 35 MB -> 12 MB, **binary segfaults: NOT USED** |

Toolchain: GraalVM Community Edition **JDK 25.0.4.1** (release
`graal-25.3.4.1`), pinned in the `Makefile` (`GRAAL_HOME`). The plan's
"most binaries land 120-260 MB uncompressed" budget is beaten by an order of
magnitude because the P0 closed world is small: the syntax tier touches the
frontend/PSI only, never the compiler *backends*.

Reproduce:

```bash
cd thirdparty/kosi
make bootstrap-darwin   # verifies the pinned GraalVM is installed
make native             # fat jar + native image + sha256 sidecar
./build/kosi-darwin-aarch64 version
./build/kosi-darwin-aarch64 analyze --dir fixtures/weak-crypto --out /tmp/a.json
./build/kosi-darwin-aarch64 analyze --dir fixtures/weak-crypto --out /tmp/b.json
cmp /tmp/a.json /tmp/b.json
```

## 2. Handled pitfalls (05-BUILD-DIST.md §1 table, with outcomes)

| Pitfall | Handling | Status |
| --- | --- | --- |
| Shaded JLine ships `META-INF/native-image/org.jline/...` properties pointing at absent files (KT-68829) | `kosiFatJar` strips `META-INF/native-image/org.jline/**` and `org/jline/**` (the REPL/daemon classes kosi never calls) | fixed |
| intellij-core registers services/extension points via ServiceLoader + XML; the 2.4.0 environment locates its own jar via `PathUtil.getResourcePathForClass`, which cannot work in an image | the compiler's `META-INF/extensions/*.xml` descriptors ship as image resources (`kosi-ext/`), are materialized to a temp dir at run time, and `CLIConfigurationKeys.INTELLIJ_PLUGIN_ROOT` points there — the configuration key the 2.4.0 code checks *before* the jar lookup | fixed |
| IntelliJ `EventDispatcher`/`Proxy` dynamic proxies | `native-metadata/proxy-config.json` registers one proxy group per listener interface; note this GraalVM wants the **array-of-interface-arrays** proxy config format, and reachability-metadata `proxy` entries passed via `-H:ConfigurationFileDirectories` did **not** register (see deviations) | fixed |
| `kotlin-reflect` retention | no `kotlin-reflect` anywhere; hand-rolled JSON writer/reader and arg parser | avoided by design |
| build-time class-init clashes | `--initialize-at-run-time=...EarlyAccessRegistry`; `--trace-class-initialization` documents any further clashes | minimal list, grows on evidence |
| reachability drift when the Kotlin pin bumps | `make native-metadata` re-runs the tracing agent over every fixture and deterministically re-merges (`scripts/merge-agent-metadata.py`); `make native-metadata-check` fails CI on drift | wired |

## 3. Reachability metadata provenance

- Seed: JetBrains' own compiler image config, pinned to
  `JetBrains/kotlin@4d1f6aaf3c0e2e47b2da9f7829ccdf551774bd26`,
  file `prepare/compiler-native-image/resources/META-INF/native-image/org/jetbrains/kotlin/kotlin-compiler-embeddable/reachability-metadata.json`
  (checked in at `native-metadata/jetbrains/`). **Deviation, recorded:** the
  `prepare/compiler-native-image` module does not exist at the `v2.4.0` tag —
  it only exists on master — so the pin is a master commit, not the release
  tag.
- Refined by the GraalVM tracing agent over all 16 fixtures
  (`native-metadata/kosi/reachability-metadata.json`, regenerated with
  `make native-metadata`; deterministic merge so CI can diff it).
- Hand-maintained proxy groups: `native-metadata/proxy-config.json`.

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
fallback (see `docs/KOSI.md` and `scripts/check-plugin-coverage.sh`); riscv64
stays best-effort per the plan. Windows follows at the release phase with the
MSVC toolchain. CI: `.github/workflows/kosi-test.yml` runs the JVM gates on
every change and the native build on demand (runner RAM allowing).
