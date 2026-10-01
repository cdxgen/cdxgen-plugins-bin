# Lesson 8: Kotlin evidence with kosi, and the eight rules the engine taught

## Learning objective

Run the kosi plugin end to end: analyze a Kotlin project (plus its
dependency jars), read the evidence kinds cdxgen/evinse consumes, export
SARIF, and understand the eight standing rules kosi's phases learned the
hard way, every one of them the scar of a shipped defect.

## Pre-requisites

- Lesson 7 (how binaries are built, staged and published; kosi rides the
  same pipeline).
- A built kosi binary for your platform (`make -C thirdparty/kosi native`)
  or the fat jar (`thirdparty/kosi/modules/kosi-cli/build/dist/kosi-all.jar`).
- For the end-to-end half: a cdxgen checkout carrying the kosi evinser arm.

## The pipeline in one picture

```mermaid
flowchart LR
  src[Your Kotlin project] --> kosi
  deps[Dependency jars<br/>--deps] --> kosi
  kosi[kosi analyze<br/>one IR, one summariser] --> report[kosi/1 JSON report]
  report --> sarif[--sarif-out<br/>SARIF 2.1.0]
  report --> evinse[cdxgen/evinse -l kotlin]
  evinse --> bom[BOM: occurrence, callstack,<br/>reachability, data-flow,<br/>crypto-flow, services[]]
```

## Analyze a project

```bash
cd thirdparty/kosi
./gradlew :kosi-cli:kosiFatJar          # or: make native
java -jar modules/kosi-cli/build/dist/kosi-all.jar analyze \
  --backend resolved --dataflow all --deps --endpoint-sources \
  --dir /path/to/project --out report.json --sarif-out report.sarif
```

`--deps` lowers dependency jars into the SAME KIR the source front end
produces and summarises them with `origin=bytecode`; a slice whose trace
walks into a jar and back out is marked `crossesDependency` with the jar's
purl. `CDXGEN_KOSI_DISABLE=1` makes cdxgen skip all of it and still emit a
valid BOM: the silent-fallback discipline from cdxrs.

## What the taint engine now follows

The engine's appetite was widened gap by gap, and the idioms it learned
are worth knowing because they are exactly the ones real services use:

- A vararg's written arguments sit at adjacent positions, so
  `ProcessBuilder("sh", "-c", cmd)` watches `cmd` and not only `"sh"`. URL
  watches its host argument, and the multi-argument URI constructors are
  SSRF sinks.
- NIO paths are traversal sinks where they are used: the `Files`
  operations, the `kotlin.io.path` I/O extensions, and the
  `FileInputStream`, `FileReader` and `RandomAccessFile` constructors.
  Construction stays a passthrough, so `normalize()` and
  `getCanonicalPath()` still clear taint.
- A bare `append(raw)` inside `apply {}`, `with(sb) {}` or an extension
  lambda is a call on the lambda's receiver, and `buildString` and its
  siblings are inlined as their definitions. A template renders a
  builder's or a collection's contents, and `joinToString` reads a list's
  elements.
- A handler parameter the framework converted to a scalar (`n: Int`,
  `id: UUID`, `BigDecimal`) arrives parsed, and the pack's sanitizer for
  that conversion clears it as it clears `text.toInt()`. Boolean parses
  are sanitizers too.
- A classpath-less framework call records the callee its file's imports
  name, and when the pack has an entry for it the flow engine reads the
  call as that entry: `jdbc.queryForList(sql)` without the Spring jar is a
  SQL sink again. `call-import-resolved` lists every callee read that way,
  and `taint-unresolved-call` names the unresolved classes that carried
  taint by the unknown-call default, which is the blind spot surfaced on
  purpose.
- State that outlives a call: object, companion and top-level properties
  lower to one canonical static base however they are spelled, and a
  container singleton's fields join them. One handler's store into a
  static reaches another handler's exec, and the slice names
  `static <field> written in <function>`.

## The eight rules, in the order they were learned

1. **Never let a numerator and a denominator come from the same producer.**
   R49's `exported-reach` read 1.0000 everywhere because the denominator was
   the graph's own nodes; R68 folded dependency-tier misses into a
   workspace denominator; R70's cap guarded a count a different phase had
   filled. Every rate in a report names both of its parents.
2. **A capability no fixture exercises is a capability you have not
   shipped.** R69: the native binary could not parse any file with a KDoc
   comment because not one fixture had one, and every gate was green. P11
   swept the grammar and found 29 constructs the fixture tree had never
   contained; the sweep is now four fixtures with `lowering-failed`
   want-nots, and it runs on every change.
3. **Before you state a metric, say what is NOT in the population.** The
   red gate's "0 of 8" was honest precisely because each zero got a named
   cause; "5 repos qualify" with unexplained zeros would have been noise.
4. **Grep for the shape, not the line.** R62's provenance defect lived at
   four sites; R70's guard had exactly one. The commit says which, and
   the number of other sites is part of the answer.
5. **Prove every gate has teeth by making it fail.** The cross-dependency
   gate's FAIL output is pasted next to its PASS in docs/KOSI.md; the
   two-way corpus ratchet is re-proven every phase.
6. **A crash is a counted row, never a silent zero and never a hang.** R58
   (the summary OOM), R70 (the tier that lowered nothing behind a cap
   diagnostic): the failure mode is a named diagnostic plus a counter, and
   the partial result still ships.
7. **A behaviour change is never a golden regeneration.** R67 flipped what
   an unresolved constructor does and eight goldens moved silently. Any
   regeneration names, per changed pair, WHAT changed and why; P11's
   regeneration moved 24 pairs, all NEW files, zero modified.
8. **A passing reproducer is not a closed issue.** The #113 reproducers
   all passed after the first fix, and a 64-case probe corpus of their
   idiomatic neighbours was still open: varargs that watched only their
   first argument, builders whose receivers went missing inside `apply {}`,
   static state no carrier modelled. The probe corpus is the regression
   suite now; an issue closes when its neighbourhood passes, not its
   reproducer.

## Verify

```bash
scripts/kosi-e2e.sh                    # report contract + evinse half (with CDXGEN_DIR)
make -C thirdparty/kosi golden         # digest goldens, trace invariants
make -C thirdparty/kosi corpusQuick    # the two-way ratchet, all bundled tiers
```

Next: [Lesson 9, flows that only a fixpoint finds](LESSON9.md).
