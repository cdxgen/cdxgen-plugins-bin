# kosi-vulnerable-service

The `vuln` tier entry: a deliberately vulnerable Kotlin service whose
taint crosses a REAL published dependency, making it the honest repo-tier
population for the `cross-dependency-bytecode` gate.

- `libs/timber-5.0.1.jar` is the `classes.jar` inside the published Timber
  5.0.1 AAR, committed byte for byte. It is never rebuilt and never fetched.
- `AuditService` logs request-derived strings through Timber; the sink
  (`android.util.Log.println`) is called INSIDE the jar, at the end of
  `Timber.d -> Forest.d -> Tree.d -> DebugTree.log`. Only the `--deps` tier
  can lower that chain and apply its summaries at the workspace call site
  (`origins = [bytecode, pack]`).
- `UserRepository` keeps the same service's JDBC flows INSIDE the workspace:
  the near-miss negatives a collapsing implementation would report on, and
  the slice the plain `resolved` slot must find identically with and without
  `--deps` (rusi's rule).
- `DriverManager.getConnection` doubles as the service's outbound
  `services[]` evidence.

Named boundary, recorded because it looks equivalent but is not: planting
the tree from an `init` block instead of `initLogging()` keeps the
cross-dependency slices from materialising — the dispatch join that resolves
`Tree.log` to the planted `DebugTree` needs the construction site as a
workspace call.
