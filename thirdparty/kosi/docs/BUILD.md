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

Toolchain: GraalVM Community Edition JDK 25 (`native-image` from
`$GRAAL_HOME`). The numbers above were re-measured at review time with
GraalVM CE 25.0.2 (`sdk install java 25-graalce`), which is why the binary is
~6 MB larger than the first measurement on CE 25.0.4.1 — **binary size is
toolchain-specific, so record the GraalVM build alongside the number.**
`GRAAL_HOME` resolves in order: an explicit override, a `JAVA_HOME` that
already provides `native-image`, then the pinned release under
`$HOME/tools`. The plan's
"most binaries land 120-260 MB uncompressed" budget is beaten by an order of
magnitude because the P0 closed world is small: the syntax tier touches the
frontend/PSI only, never the compiler *backends*.

Reproduce:

```bash
cd thirdparty/kosi
make bootstrap-darwin   # verifies the pinned GraalVM is installed
make native             # fat jar + native image + sha256 sidecar
./build/kosi-darwin-arm64 version
./build/kosi-darwin-arm64 analyze --dir fixtures/weak-crypto --out /tmp/a.json
./build/kosi-darwin-arm64 analyze --dir fixtures/weak-crypto --out /tmp/b.json
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

CI: `.github/workflows/kosi-test.yml` runs the JVM gates on every change and
the darwin-arm64 native build on every change; a `workflow_dispatch`-only
`make linux` job exercises the linux-amd64 path. Record the linux-amd64
GraalVM tarball sha256 here at its first successful run so it can be pinned
like the macOS one.
