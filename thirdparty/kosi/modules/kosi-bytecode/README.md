# kosi-bytecode

P9: the dependency-jar tier (`--deps`). Reads class files from the resolved
classpath with the allowlisted ASM, demangles Kotlin names through
`@kotlin.Metadata` (the protobuf reader shipped inside
`kotlin-compiler-common-for-ide` — no new dependencies), and lowers method
bodies into the SAME KIR the source front end produces. The engine in
`kosi-flow` never learns that a function came from a class file: one IR, one
summariser.

## What it guarantees

- **Body-less records are ignored entirely, never concluded about.** An
  abstract/interface/native/stripped method is emitted with `body = null` —
  which kosi-flow never compiles or summarises — and counted
  (`stats.bodylessRecords`). An empty body is indistinguishable from a
  no-op; summarising one as "no flow" would invent a sanitiser.
- **Canonical names match the workspace renderer.** Demangling maps JVM
  names (hash-mangled overloads, `get`/`is`/`set` accessors, `*Kt` file
  facades, `$Companion`/nested classes) to the source callable ids the
  workspace KIR and the model packs use; a summary a workspace call site
  can never look up is a capability the report silently lacks.
- **Everything is bounded and counted.** Selection lowers the workspace's
  callee classes plus a bounded same-jar call closure, capped by
  `--deps-max-classes` with a diagnostic. Every declined construct is
  itemised; a method the lowering aborts on is treated as body-less, never
  summarised from a half-body.

## Named limitations (see docs/KOSI.md for the full list)

- `@JvmName`-renamed file facades and multi-file facades are found only
  through the call closure, never by name.
- Overload summaries collapse per canonical name (the same collapse the
  workspace CallIndex has always had); Kotlin `vararg` bridge descriptors
  never match raw JVM ones, so descriptors disambiguate nothing.
- Only classes in the resolved classpath jars are lowered; JDK and Android
  platform APIs are excluded by prefix and modeled by the shipped pack.
- `suspend` state machines lower as ordinary control flow; the state
  machine's artifacts are visible to the transfer, which treats them
  conservatively.
