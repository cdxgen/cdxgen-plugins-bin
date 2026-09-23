# kosi: Kotlin source inspector

kosi analyses a Kotlin/Java project and emits one deterministic JSON report: module and source inventory, a call graph with reachability, taint slices, inbound endpoints and outbound services, and crypto evidence. It is the Kotlin sibling of [golem](GOLEM.md) (Go) and [rusi](RUSI.md) (Rust), and it is what cdxgen calls to put Kotlin evidence into a BOM.

The deep operator's guide lives with the tool: [thirdparty/kosi/docs/KOSI.md](../thirdparty/kosi/docs/KOSI.md). The README tours the capabilities, the JSON attribute reference pins the report contract, and the build doc records the native-image gate policy.

## Two tiers, one report

Everything kosi reports is produced at one of two tiers, and the tier decides what is knowable:

- **syntax** (the default) parses sources with the embedded Kotlin compiler's PSI. No classpath and no build execution — build files are read as text and never run. It yields modules, packages, files, imports, declarations and name-level usages, and reports rather than hides what it cannot resolve.
- **resolved** runs the Kotlin Analysis API in standalone mode against a real classpath. The call graph, reachability, taint, endpoints, services and crypto evidence come from this tier, and their quality is bounded by the classpath it is given.

Both tiers emit the same report contract (`schemaVersion: kosi/1`), so a consumer can upgrade a run from syntax to resolved without changing how it reads the report.

## Running it

```bash
kosi analyze --dir /path/to/project --out report.json
kosi analyze --dir . --backend resolved --roots exported --callgraph auto
kosi analyze --dir . --backend resolved --dataflow all --endpoint-sources
kosi --version
```

Classpaths come from Gradle or Maven discovery, or from an explicit pin:

```bash
kosi analyze --dir . --backend resolved --classpath-file classpath.txt
```

## Exit codes and output

Exit codes follow the suite convention: `0` success, `1` expectations failed (the bench and golden gates), `2` usage error, `3` runtime error. Unknown flags are usage errors, never silently dropped options. `--out <file>` (alias `--output`) writes the report to a file; `--pretty` indents it.

## Memory and stack

The analysis holds the whole project's PSI, KIR and summaries in memory. A repository of a few thousand source files wants **16 GB of heap or more** (`-Xmx16g`); below that the JVM tends to die at whichever class it needed next, so a `NoClassDefFoundError` naming a kosi class is usually starvation rather than a corrupt build — kosi recognises that shape and says so. Deeply nested sources are a *stack* question: the analysis runs on a 512 MB stack and bounds every PSI walk per file (`psi-depth-cap`, `stack-overflow-skipped`), so an overflow that still reaches the CLI names the file that caused it.

## Platforms

kosi ships as a GraalVM native image for linux-amd64, linux-arm64, linuxmusl-amd64 and darwin-arm64. Where a native image cannot exist — 32-bit arm, and the architectures no longer packaged here — consumers get cdxgen's own JS-side structural Kotlin analysis and, with a JDK 21+ present, the `kosi-portable.jar` fallback. Windows is a declared exemption until a Windows runner job wires the MSVC-toolchain build; the jar fallback covers Windows consumers in the meantime.
