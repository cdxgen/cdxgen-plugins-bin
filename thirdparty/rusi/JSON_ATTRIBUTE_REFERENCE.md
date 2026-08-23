# Rusi JSON attribute reference

This document describes the report emitted by `rusi`. Field names map directly to the schema in `crates/rusi-schema/src/lib.rs`.

## Output format

- **Minified by default.** The report (`--out`) and the graph exports
  (`--callgraph-out`/`--dataflow-out` with `--callgraph-export-format json` /
  `--dataflow-export-format json`) are written as compact, single-line JSON.
  Pass `--pretty` to get indented, human-readable output instead.
- **Deterministic.** Collections are emitted in a stable, sorted order, so
  re-running the analyzer on unchanged input produces byte-identical output.
- **No duplicated evidence.** Import/declaration/usage/security-signal evidence
  is emitted once, in the canonical top-level arrays; the matching per-file
  arrays inside `FileEvidence` are omitted (see [`FileEvidence`](#fileevidence)).

## Top-level report

| Field              | Type                       | Meaning                                                                                                          |
| ------------------ | -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `schema_version`   | `string`                   | Schema identifier for the report format.                                                                         |
| `tool`             | object                     | Information about the analyzer binary that produced the report.                                                  |
| `runtime`          | object                     | Toolchain/runtime metadata for the analysis environment.                                                         |
| `options`          | object                     | Effective analysis options used for the run.                                                                     |
| `modules`          | array of `ModuleRef`       | Workspace/module inventory derived from Cargo metadata.                                                          |
| `packages`         | array of `PackageEvidence` | Package-level summary records.                                                                                   |
| `files`            | array of `FileEvidence`    | Per-file evidence (path/package/purl/crypto). See the note below on the per-file collection fields.              |
| `imports`          | array of `ImportUsage`     | **Canonical** flattened import list across all files.                                                            |
| `declarations`     | array of `Declaration`     | **Canonical** flattened declarations across all files.                                                           |
| `usages`           | array of `LibraryUsage`    | **Canonical** flattened API/library usage evidence across all files.                                             |
| `security_signals` | array of `SecuritySignal`  | **Canonical** flattened non-flow security-relevant signals across all files.                                     |
| `crypto`           | `CryptoEvidence \| null`   | Aggregated cryptographic evidence used for CBOM-oriented review.                                                 |
| `call_graph`       | `CallGraph \| null`        | Call graph output when enabled.                                                                                  |
| `data_flow`        | `DataFlowEvidence \| null` | Data-flow output when enabled.                                                                                   |
| `api_endpoints`    | array of `ApiEndpoint`     | HTTP endpoints discovered in the source code. Empty when the workspace doesn't import a supported web framework. |
| `diagnostics`      | array of `Diagnostic`      | Analysis warnings, backend notes, and completeness clues.                                                        |
| `stats`            | object                     | Precomputed counters for high-level report contents.                                                             |

## Common utility objects

### `Position`

| Field      | Type     | Meaning                                           |
| ---------- | -------- | ------------------------------------------------- |
| `filename` | `string` | Report-relative file path or diagnostic filename. |
| `line`     | `number` | 1-based line number.                              |
| `column`   | `number` | 1-based column number.                            |

### `ToolInfo`

| Field         | Type     | Meaning                          |
| ------------- | -------- | -------------------------------- |
| `name`        | `string` | Tool name, currently `rusi`.     |
| `version`     | `string` | Analyzer version.                |
| `description` | `string` | Human-readable tool description. |

### `RuntimeInfo`

| Field               | Type     | Meaning                                                    |
| ------------------- | -------- | ---------------------------------------------------------- |
| `rustc_version`     | `string` | Captured `rustc -Vv` or toolchain-specific version output. |
| `cargo_version`     | `string` | Captured Cargo version.                                    |
| `host`              | `string` | Host triple or host approximation.                         |
| `working_directory` | `string` | Canonical analysis root directory.                         |

### `AnalysisOptions`

| Field                 | Type      | Meaning                                                                                      |
| --------------------- | --------- | -------------------------------------------------------------------------------------------- |
| `directory`           | `string`  | Analyzed root directory.                                                                     |
| `backend`             | `string`  | `stable` or `compiler`.                                                                      |
| `analysis_scope`      | `string`  | Report scope, currently `default` or `cryptos`.                                              |
| `call_graph_mode`     | `string`  | Requested call-graph mode.                                                                   |
| `data_flow_mode`      | `string`  | Requested data-flow mode.                                                                    |
| `include_tests`       | `boolean` | Whether tests were included in file discovery / compiler runs.                               |
| `max_call_candidates` | `number`  | Ceiling on call-graph edges emitted per ambiguous call site (`0` means no cap). Default `8`. |

> When dependency analysis is on (`--deps`), `packages` and `modules` include the
> resolved dependency crates, each with `module.workspace_member: false`. Their
> declarations, imports, impls, and usage evidence are present; their function
> bodies are analyzed only under the `security-deps` data-flow mode, so
> dependency-side data-flow summaries appear only in that mode.

### `ModuleRef`

| Field              | Type      | Meaning                                    |
| ------------------ | --------- | ------------------------------------------ |
| `name`             | `string`  | Cargo package/module name.                 |
| `version`          | `string`  | Cargo package version.                     |
| `manifest_path`    | `string`  | Path to the package manifest.              |
| `workspace_member` | `boolean` | Whether the package is a workspace member. |

## Package and file evidence

### `PackageEvidence`

| Field           | Type        | Meaning                                         |
| --------------- | ----------- | ----------------------------------------------- |
| `id`            | `string`    | Stable identifier for the package record.       |
| `name`          | `string`    | Cargo package name.                             |
| `package_path`  | `string`    | Rust crate/package path used inside the report. |
| `purl`          | `string`    | Package URL when derivable.                     |
| `manifest_path` | `string`    | Manifest path for the package.                  |
| `module`        | `ModuleRef` | Module metadata associated with the package.    |
| `files`         | `string[]`  | Files discovered for that package.              |

### `FileEvidence`

| Field              | Type                     | Meaning                                         |
| ------------------ | ------------------------ | ----------------------------------------------- |
| `path`             | `string`                 | Relative file path.                             |
| `package_name`     | `string`                 | Cargo package name.                             |
| `package_path`     | `string`                 | Rust crate/package path.                        |
| `purl`             | `string`                 | Package URL associated with the file's package. |
| `imports`          | `ImportUsage[]`          | Omitted in the report (see note below).         |
| `declarations`     | `Declaration[]`          | Omitted in the report (see note below).         |
| `usages`           | `LibraryUsage[]`         | Omitted in the report (see note below).         |
| `security_signals` | `SecuritySignal[]`       | Omitted in the report (see note below).         |
| `crypto`           | `CryptoEvidence \| null` | File-scoped crypto evidence, if any.            |

> **Per-file collections are not serialized.** Earlier report versions repeated
> each file's `imports`/`declarations`/`usages`/`security_signals` both inside
> `FileEvidence` and in the canonical top-level `imports`/`declarations`/
> `usages`/`security_signals` arrays — duplicating the same data (tens of MB on
> large workspaces). These four fields are now cleared before serialization and
> omitted from the JSON (`skip_serializing_if`), so a `FileEvidence` object
> typically contains only `path`, `package_name`, `package_path`, `purl`, and
> `crypto`.
>
> **Consume the top-level arrays instead.** To reconstruct a per-file view,
> read the canonical top-level collections and group by each item's
> `position.filename` (and `file_path` on `Declaration`), which match
> `FileEvidence.path`. The fields remain in the schema type so they may carry
> data in intermediate, pre-finalized artifacts (e.g. the compiler backend's
> per-crate evidence), but the finalized report always omits them.

## Structural evidence

### `ImportUsage`

| Field          | Type             | Meaning                                                    |
| -------------- | ---------------- | ---------------------------------------------------------- |
| `path`         | `string`         | Imported path as written after flattening grouped imports. |
| `alias`        | `string \| null` | Import alias if present.                                   |
| `package_path` | `string`         | Package path for the analyzed crate.                       |
| `purl`         | `string`         | PURL for the referenced package when derivable.            |
| `position`     | `Position`       | Import location.                                           |

### `Declaration`

| Field            | Type             | Meaning                                                                                                                                                                                                                                    |
| ---------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`             | `string`         | Stable declaration ID.                                                                                                                                                                                                                     |
| `name`           | `string`         | Short declaration name.                                                                                                                                                                                                                    |
| `qualified_name` | `string`         | Fully qualified symbol name.                                                                                                                                                                                                               |
| `canonical_name` | `string`         | Normalized, generic-free, hash-free join key (`crate::module::Type::method`).                                                                                                                                                              |
| `kind`           | `string`         | Declaration kind such as `function`, `method`, `module`, `struct`, or `trait`.                                                                                                                                                             |
| `package_path`   | `string`         | Owning package path.                                                                                                                                                                                                                       |
| `purl`           | `string`         | Package URL of the owning package.                                                                                                                                                                                                         |
| `file_path`      | `string`         | Relative file containing the declaration.                                                                                                                                                                                                  |
| `signature`      | `string`         | Captured signature or declaration text.                                                                                                                                                                                                    |
| `receiver`       | `string \| null` | Receiver type for methods when known.                                                                                                                                                                                                      |
| `position`       | `Position`       | Declaration location.                                                                                                                                                                                                                      |
| `cfg_gate`       | `string \| null` | `#[cfg(...)]` predicate this declaration sits behind, as written (for example `feature = "tls"`). Omitted when the declaration is unconditional. Declarations whose gate is inactive in the analyzed configuration are not emitted at all. |

> `qualified_name` is rooted at the **Cargo target's** crate, not the package:
> each `bin`, `example`, and `test` target is its own crate, so `src/bin/a.rs`
> and `src/bin/b.rs` yield `a::main` and `b::main`. `package_path` remains the
> owning package, so grouping and purl resolution are unaffected. A declaration
> `id` additionally covers the signature and the implemented trait, because one
> type can carry several same-named, same-shaped trait methods
> (`impl Section for T` and `impl ComponentSection for T` both defining
> `fn id(&self) -> u8`).

### `LibraryUsage`

| Field                   | Type                    | Meaning                                                                                                           |
| ----------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `id`                    | `string`                | Stable usage ID.                                                                                                  |
| `kind`                  | `string`                | Usage category such as `call` or `method-call`.                                                                   |
| `name`                  | `string`                | Captured callee or symbol name.                                                                                   |
| `package_path`          | `string`                | Owning package path.                                                                                              |
| `purl`                  | `string`                | PURL associated with the usage package when derivable.                                                            |
| `enclosing_declaration` | `string \| null`        | Declaration ID containing the usage.                                                                              |
| `position`              | `Position`              | Usage location.                                                                                                   |
| `properties`            | `object<string,string>` | Extra metadata such as receiver text, dispatch confidence, resolved symbol, specialization key, or semantic tags. |

### `SecuritySignal`

| Field          | Type             | Meaning                                                                                                              |
| -------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------- |
| `id`           | `string`         | Stable signal ID.                                                                                                    |
| `category`     | `string`         | Signal family, for example `unsafe-code`, `async-model`, or `native-interop`.                                        |
| `severity`     | `string`         | Coarse severity label.                                                                                               |
| `confidence`   | `string`         | Coarse confidence label.                                                                                             |
| `description`  | `string`         | Human-readable explanation.                                                                                          |
| `package_path` | `string`         | Owning package path.                                                                                                 |
| `purl`         | `string`         | PURL associated with the signal package when derivable.                                                              |
| `file_path`    | `string`         | Relative file path.                                                                                                  |
| `position`     | `Position`       | Signal location.                                                                                                     |
| `cfg_gate`     | `string \| null` | `#[cfg(...)]` predicate this signal sits behind, as written. Omitted when unconditional. See `Declaration.cfg_gate`. |

## Crypto / CBOM evidence

### `CryptoEvidence`

| Field        | Type                    | Meaning                                                              |
| ------------ | ----------------------- | -------------------------------------------------------------------- |
| `libraries`  | `CryptoLibrary[]`       | Crypto-relevant libraries or namespaces observed.                    |
| `components` | `CryptoComponent[]`     | Individual crypto components or API uses.                            |
| `materials`  | `CryptoMaterial[]`      | Secret- or material-like identifiers such as keys, salts, or nonces. |
| `findings`   | `CryptoFinding[]`       | Crypto review findings such as weak primitive usage.                 |
| `properties` | `object<string,string>` | Reserved for aggregate crypto metadata.                              |

### `CryptoLibrary`

| Field          | Type                    | Meaning                                                                |
| -------------- | ----------------------- | ---------------------------------------------------------------------- |
| `id`           | `string`                | Stable crypto-library ID.                                              |
| `path`         | `string`                | Library/provider path, such as `sha2` or `rustls`.                     |
| `family`       | `string`                | High-level crypto family such as `hash`, `aead`, `kdf`, or `protocol`. |
| `package_path` | `string`                | Owning package path.                                                   |
| `file_path`    | `string`                | Relative file path.                                                    |
| `position`     | `Position`              | Evidence location.                                                     |
| `properties`   | `object<string,string>` | Extra metadata such as detection source or confidence.                 |

### `CryptoComponent`

| Field          | Type                    | Meaning                                                                        |
| -------------- | ----------------------- | ------------------------------------------------------------------------------ |
| `id`           | `string`                | Stable crypto-component ID.                                                    |
| `kind`         | `string`                | Component family such as `hash`, `aead`, `mac`, `kdf`, `token`, or `protocol`. |
| `algorithm`    | `string`                | Classified algorithm label such as `SHA-256`, `AES-GCM`, or `TLS`.             |
| `provider`     | `string`                | Library/provider name.                                                         |
| `operation`    | `string`                | Operation such as `digest`, `derive`, `key-init`, or `config-builder`.         |
| `symbol`       | `string`                | Canonical symbol label used by the classifier.                                 |
| `package_path` | `string`                | Owning package path.                                                           |
| `file_path`    | `string`                | Relative file path.                                                            |
| `position`     | `Position`              | Evidence location.                                                             |
| `properties`   | `object<string,string>` | Detection metadata, for example heuristic/source provenance.                   |

### `CryptoMaterial`

| Field          | Type                    | Meaning                                                  |
| -------------- | ----------------------- | -------------------------------------------------------- |
| `id`           | `string`                | Stable crypto-material ID.                               |
| `kind`         | `string`                | Material category such as `key` or `nonce`.              |
| `name`         | `string`                | Identifier name; the secret value itself is not emitted. |
| `package_path` | `string`                | Owning package path.                                     |
| `file_path`    | `string`                | Relative file path.                                      |
| `function`     | `string`                | Enclosing function, when known.                          |
| `confidence`   | `string`                | Confidence label for the heuristic match.                |
| `position`     | `Position`              | Evidence location.                                       |
| `properties`   | `object<string,string>` | Reserved extension metadata.                             |

### `CryptoFinding`

| Field          | Type                    | Meaning                                  |
| -------------- | ----------------------- | ---------------------------------------- |
| `id`           | `string`                | Stable crypto-finding ID.                |
| `category`     | `string`                | Finding category, such as `weak-crypto`. |
| `severity`     | `string`                | Severity label.                          |
| `confidence`   | `string`                | Confidence label.                        |
| `summary`      | `string`                | Short human-readable finding summary.    |
| `package_path` | `string`                | Owning package path.                     |
| `file_path`    | `string`                | Relative file path.                      |
| `position`     | `Position`              | Finding location.                        |
| `properties`   | `object<string,string>` | Reserved extension metadata.             |

## Call graph

### `CallGraph`

| Field         | Type              | Meaning                           |
| ------------- | ----------------- | --------------------------------- |
| `mode`        | `string`          | Call-graph mode used for the run. |
| `nodes`       | `CallGraphNode[]` | Call-graph nodes.                 |
| `edges`       | `CallGraphEdge[]` | Call-graph edges.                 |
| `diagnostics` | `Diagnostic[]`    | Call-graph-specific diagnostics.  |
| `stats`       | `GraphStats`      | Node/edge counts.                 |

### `CallGraphNode`

| Field            | Type             | Meaning                                                         |
| ---------------- | ---------------- | --------------------------------------------------------------- |
| `id`             | `string`         | Stable node ID.                                                 |
| `name`           | `string`         | Short function/method name.                                     |
| `qualified_name` | `string`         | Fully qualified symbol name.                                    |
| `canonical_name` | `string`         | Normalized, generic-free, hash-free join key.                   |
| `kind`           | `string`         | Node kind.                                                      |
| `package_path`   | `string`         | Package path associated with the node.                          |
| `purl`           | `string`         | PURL for the node package when derivable.                       |
| `file_path`      | `string`         | Relative file path.                                             |
| `local`          | `boolean`        | Whether the node belongs to the analyzed workspace/package set. |
| `external`       | `boolean`        | Whether the node is synthetic/external.                         |
| `receiver`       | `string \| null` | Receiver type when known.                                       |
| `position`       | `Position`       | Node position.                                                  |

### `CallGraphEdge`

Edges are **normalized against `CallGraphNode`**: an endpoint's name, purl, and
file are read from the referenced node instead of being repeated on every edge.
Those repeated fields were the single largest part of a report — 61 MB of 132 MB
of edge bytes on wasm-tools 1.247.0 — and each was byte-identical to a field
already present on the node.

| Field                     | Type      | Meaning                                                                                                                                               |
| ------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                      | `string`  | Stable edge ID, unique within a report.                                                                                                               |
| `source_id`               | `string`  | Source node ID.                                                                                                                                       |
| `target_id`               | `string`  | Target node ID.                                                                                                                                       |
| `call_type`               | `string`  | How the target was resolved (see below). `confidence` is a function of this and is not stored per edge.                                               |
| `line`                    | `number`  | Call-site line, 1-based, within the **source** node's `file_path`.                                                                                    |
| `column`                  | `number`  | Call-site column, 1-based.                                                                                                                            |
| `callee_text`             | `string?` | Callee path as written at the call site, after import resolution. Omitted when unknown.                                                               |
| `receiver`                | `string?` | Receiver expression text, for method calls.                                                                                                           |
| `method`                  | `string?` | Bare method name, for method calls.                                                                                                                   |
| `candidate_count`         | `number?` | Total local candidates the call site resolved to, when more than one. Always the true count, even when capped.                                        |
| `emitted_candidate_count` | `number?` | Edges actually emitted for this site. **Present only when the site was capped**, so its presence means these edges are a sample of `candidate_count`. |
| `properties`              | `object?` | Backend-specific extras (compiler-backend dispatch metadata). Omitted when empty.                                                                     |

**Reading an edge.** Index `call_graph.nodes` by `source_id` / `target_id`:

| You want           | Read                                                            |
| ------------------ | --------------------------------------------------------------- |
| source symbol name | source node's `qualified_name`                                  |
| target symbol name | target node's `qualified_name`                                  |
| source/target purl | the nodes' `purl`                                               |
| call-site file     | **source** node's `file_path` (with the edge's `line`/`column`) |

`call_type` values: `static`, `receiver-typed`, `trait-impl`, `static-overapprox`,
`trait-overapprox`, `higher-order`, `external`, plus compiler-backend dispatch
labels (`dyn-dispatch-exact`, `trait-static-bounded`, `async-logical`, ...).
Confidence follows from it. For the stable backend: `high` for `static`,
`trait-impl`, and `higher-order`; `medium` for `receiver-typed`; `low`
otherwise. A compiler-backend label carries the resolved target count as a
suffix, and that suffix decides: `-exact` is `high`, `-bounded` is `medium`,
`-unknown` is `low`.

> **Ambiguous call sites are capped by default.** An unresolved bare method name
> matches every same-named candidate in the workspace, and emitting the full
> cross product dominates report size and peak memory (on wasm-tools 1.247.0:
> 97% of 1.15M edges) without adding information a candidate count does not
> already carry. Only the over-approximating call types (`static-overapprox`,
> `trait-overapprox`) are capped; `static`, `receiver-typed`, `trait-impl`,
> `higher-order`, and `external` edges are always emitted in full. Surviving
> candidates are ordered targets-in-the-caller's-crate first, then by
> qualified name, so the sample is deterministic. Pass
> `--max-call-candidates 0` for the full candidate set, and see the aggregate
> `resolution` diagnostic in `call_graph.diagnostics` for how many sites were
> truncated.

### `GraphStats`

| Field        | Type     | Meaning                       |
| ------------ | -------- | ----------------------------- |
| `node_count` | `number` | Number of nodes in the graph. |
| `edge_count` | `number` | Number of edges in the graph. |

## Data flow

### `DataFlowPattern`

| Field                | Type       | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `target`             | `string`   | Pattern role: `source`, `sink`, or `passthrough`. When reading custom JSON it may be omitted and inferred from the containing array.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `pattern`            | `string`   | Pattern text used for matching.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `category`           | `string`   | Category assigned when the pattern matches. Common categories for sources: `env`, `cli`, `file`, `http-request`, `secret`, `crypto-material`. For sinks: `process-exec`, `filesystem-write`, `filesystem-delete`, `network-connect`, `network-request`, `sql-query`, `html-response`. For passthroughs: `value-wrapper`, `smart-pointer`, `lock-accessor`, `iterator-adapter`, `channel-io`, `linker-accessor`, `string-format`, `ffi-wrapper`, `sql-builder`, `pointer-arithmetic`, `auto-discovered-passthrough`. Crypto-specific: `crypto-digest`, `crypto-key`, `crypto-keygen`, `tls`, `jwt`. |
| `relevant_arguments` | `number[]` | Argument indexes used by the rule. Defaults to `[]` for custom JSON. For a method call, index 0 is the receiver, so the first real argument is 1.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `receiver_type`      | `string?`  | Restricts the rule to a method call whose receiver resolves to this type, so a rule named after a common method (`arg`, `write_all`) does not fire on every type that has one. Omitted when the rule matches on the callee alone; a rule that has it never fires on an unresolved receiver.                                                                                                                                                                                                                                                                                                        |

### `DataFlowPatternSet`

| Field          | Type                | Meaning                                                                                                                                                                                                                   |
| -------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sources`      | `DataFlowPattern[]` | Source patterns. Defaults to `[]` when omitted in custom JSON.                                                                                                                                                            |
| `sinks`        | `DataFlowPattern[]` | Sink patterns. Defaults to `[]` when omitted in custom JSON.                                                                                                                                                              |
| `passthroughs` | `DataFlowPattern[]` | Passthrough patterns. Defaults to `[]` when omitted in custom JSON. Patterns with category `auto-discovered-passthrough` were inferred from workspace methods with accessor-like signatures rather than being hard-coded. |

### `DataFlowNode`

| Field             | Type                    | Meaning                                               |
| ----------------- | ----------------------- | ----------------------------------------------------- |
| `id`              | `string`                | Stable node ID.                                       |
| `kind`            | `string`                | Node role, typically `source` or `sink`.              |
| `name`            | `string`                | Captured symbol or parameter name.                    |
| `package_path`    | `string`                | Package path.                                         |
| `purl`            | `string`                | PURL for the node package when derivable.             |
| `function`        | `string`                | Enclosing function qualified name.                    |
| `position`        | `Position`              | Node position.                                        |
| `source`          | `boolean`               | Whether the node is a source.                         |
| `sink`            | `boolean`               | Whether the node is a sink.                           |
| `category`        | `string`                | Data-flow category.                                   |
| `parameter_index` | `number \| null`        | Parameter index when the node represents a parameter. |
| `type_name`       | `string \| null`        | Type name when known.                                 |
| `properties`      | `object<string,string>` | Extra node metadata.                                  |

### `DataFlowEdge`

| Field        | Type                    | Meaning                                                |
| ------------ | ----------------------- | ------------------------------------------------------ |
| `id`         | `string`                | Stable edge ID.                                        |
| `source_id`  | `string`                | Source node ID.                                        |
| `target_id`  | `string`                | Target node ID.                                        |
| `kind`       | `string`                | Edge kind, currently used for internal trace modeling. |
| `properties` | `object<string,string>` | Extra edge metadata.                                   |

### `DataFlowSlice`

| Field                    | Type                    | Meaning                                           |
| ------------------------ | ----------------------- | ------------------------------------------------- |
| `id`                     | `string`                | Stable slice ID.                                  |
| `source_id`              | `string`                | Source node ID.                                   |
| `sink_id`                | `string`                | Sink node ID.                                     |
| `source_name`            | `string`                | Source name.                                      |
| `sink_name`              | `string`                | Sink name.                                        |
| `source_function`        | `string`                | Source function qualified name.                   |
| `sink_function`          | `string`                | Sink function qualified name.                     |
| `source_package_path`    | `string`                | Source package path.                              |
| `sink_package_path`      | `string`                | Sink package path.                                |
| `sourcePurl`             | `string`                | Source package PURL.                              |
| `targetPurl`             | `string`                | Sink package PURL.                                |
| `purls`                  | `string[]`              | Deduplicated union of slice endpoint PURLs.       |
| `source_category`        | `string`                | Source category.                                  |
| `sink_category`          | `string`                | Sink category.                                    |
| `node_ids`               | `string[]`              | Trace node IDs used in the slice.                 |
| `edge_ids`               | `string[]`              | Trace edge IDs used in the slice.                 |
| `path_length`            | `number`                | Count of trace nodes/steps retained in the slice. |
| `source_parameter_index` | `number \| null`        | Source parameter index when applicable.           |
| `sink_parameter_index`   | `number \| null`        | Sink parameter index when applicable.             |
| `source_type_name`       | `string \| null`        | Source type name when known.                      |
| `sink_type_name`         | `string \| null`        | Sink type name when known.                        |
| `rule_name`              | `string`                | Human-readable rule name.                         |
| `description`            | `string`                | Short slice description.                          |
| `properties`             | `object<string,string>` | Extra slice metadata.                             |

> **Witness paths are bounded.** A slice records one representative
> source-to-sink witness (`node_ids`/`edge_ids`), not every possible route.
> Interprocedural taint propagation can otherwise produce a combinatorial number
> of paths; to keep memory bounded the analyzer caps the witness set per value
> (default 32), deduplicates witnesses sharing an origin and node sequence, and
> drops pathologically long chains (default >64 steps). A slice still proves the
> flow exists — `source_id`/`sink_id` and the categories are exact — but
> `node_ids`/`edge_ids`/`path_length` reflect the retained witness rather than an
> exhaustive enumeration.

### `DataFlowMethodSummary`

| Field             | Type                      | Meaning                                                                 |
| ----------------- | ------------------------- | ----------------------------------------------------------------------- |
| `function_id`     | `string`                  | Declaration ID for the summarized function.                             |
| `function`        | `string`                  | Qualified function name.                                                |
| `package_path`    | `string`                  | Package path.                                                           |
| `purl`            | `string`                  | PURL for the package when derivable.                                    |
| `parameter_names` | `string[]`                | Parameter names in order.                                               |
| `parameter_types` | `string[]`                | Parameter types in order.                                               |
| `return_type`     | `string`                  | Return type text.                                                       |
| `param_to_return` | `number[]`                | Parameter indexes that may flow to the return value.                    |
| `param_to_sink`   | `object<string,number[]>` | Map from sink category to parameter indexes that may flow to that sink. |
| `source_returns`  | `string[]`                | Source categories returned by the function.                             |
| `properties`      | `object<string,string>`   | Extra summary metadata.                                                 |

### `DataFlowStats`

| Field           | Type     | Meaning                        |
| --------------- | -------- | ------------------------------ |
| `source_count`  | `number` | Number of source nodes.        |
| `sink_count`    | `number` | Number of sink nodes.          |
| `slice_count`   | `number` | Number of materialized slices. |
| `node_count`    | `number` | Number of data-flow nodes.     |
| `edge_count`    | `number` | Number of data-flow edges.     |
| `summary_count` | `number` | Number of method summaries.    |

### `DataFlowEvidence`

| Field         | Type                      | Meaning                             |
| ------------- | ------------------------- | ----------------------------------- |
| `mode`        | `string`                  | Data-flow mode used for the run.    |
| `patterns`    | `DataFlowPatternSet`      | Pattern pack actually used.         |
| `nodes`       | `DataFlowNode[]`          | Data-flow nodes.                    |
| `edges`       | `DataFlowEdge[]`          | Data-flow edges.                    |
| `slices`      | `DataFlowSlice[]`         | Materialized source-to-sink slices. |
| `summaries`   | `DataFlowMethodSummary[]` | Per-function summaries.             |
| `diagnostics` | `Diagnostic[]`            | Data-flow-specific diagnostics.     |
| `stats`       | `DataFlowStats`           | Data-flow counters.                 |

> The `patterns` sets and `diagnostics` are emitted in a stable, sorted order so
> the field is byte-reproducible across runs (see _Output format_ below).

## API endpoints

The `api_endpoints` array carries one entry per HTTP endpoint that the
api-discovery pass was able to resolve. The pass runs automatically when
the workspace imports a supported framework crate; supported frameworks
today are **axum**, **actix-web**, and **rocket**. Warp is planned but
not yet implemented. Workspaces with no HTTP framework imports get an
empty array and zero overhead.

Path prefixes from `Router::nest("/api/v1", …)` (axum),
`web::scope("/api/v1").service(…)` (actix-web), and
`.mount("/api", routes![…])` (rocket) are composed into the final path
before emission, so each entry contains the fully-qualified URL a client
would call.

### `ApiEndpoint`

| Field               | Type                  | Meaning                                                                                                                                                                      |
| ------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                | `string`              | Stable deterministic identifier.                                                                                                                                             |
| `method`            | `string`              | HTTP method in uppercase: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, `TRACE`.                                                                               |
| `path`              | `string`              | Fully-resolved URL path including any prefixes from nested routers/scopes/mounts. Placeholders use the framework's native syntax (axum `:id`, actix `{id}`, rocket `<id>`).  |
| `framework`         | `string`              | The framework that owns this endpoint: `axum`, `actix-web`, or `rocket`.                                                                                                     |
| `handler`           | `string`              | Fully-qualified path to the handler function.                                                                                                                                |
| `package_path`      | `string`              | Crate (package) path.                                                                                                                                                        |
| `purl`              | `string`              | Package URL when derivable; empty otherwise.                                                                                                                                 |
| `file_path`         | `string`              | Source file the registration call lives in (not necessarily the handler's file).                                                                                             |
| `position`          | `Position`            | Source position of the registration call.                                                                                                                                    |
| `parameters`        | `EndpointParameter[]` | Path and query parameters parsed from the handler's signature. Path parameters synthesize one entry per placeholder in the route; query parameters carry the extractor type. |
| `request_body_type` | `string \| null`      | Type of the deserialized request body when the handler uses a body extractor (axum `Json<T>`, actix `web::Json<T>` / `web::Form<T>`, rocket `Json<T>` / `Form<T>`).          |
| `response_type`     | `string \| null`      | The application-level response type. Wrappers like `Result<…, _>` and `Json<…>` are unwrapped so the type names the data the handler returns.                                |
| `properties`        | `Map<string,string>`  | Extension map for future enrichments; empty today.                                                                                                                           |

### `EndpointParameter`

| Field       | Type     | Meaning                                                                                                                              |
| ----------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `name`      | `string` | Parameter name as it appears in the route path or in the handler's parameter pattern.                                                |
| `location`  | `string` | Either `path` or `query`.                                                                                                            |
| `type_name` | `string` | Rust type spelled as written, e.g. `i32`, `String`, `Option<bool>`. For path parameters, this is the type inside the path extractor. |

## Diagnostics and stats

### `Diagnostic`

| Field          | Type               | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kind`         | `string`           | Diagnostic class. Common values: `parse`, `resolution`, `backend`, `missing-passthrough`, `module-resolution`, `import-resolution`. `missing-passthrough` diagnostics indicate method calls where taint tracking was lost; the message suggests adding the method as a passthrough pattern. `module-resolution` reports a `mod` declaration that could not be resolved, or a file no crate root reaches (analyzed with a module path derived from its file path). `import-resolution` reports a glob import whose target module is outside the workspace, so names imported through it stay unresolved. `macro` reports a macro whose body could not be recovered as Rust (including every `macro_rules!` definition, which is deliberately not walked), naming the files it appears in so the blind spot is visible. |
| `message`      | `string`           | Human-readable diagnostic text.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `package_path` | `string \| null`   | Package path if the diagnostic is package-scoped.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `file_path`    | `string \| null`   | File path if file-scoped.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `position`     | `Position \| null` | Position when available.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

### `Stats`

| Field                    | Type     | Meaning                                     |
| ------------------------ | -------- | ------------------------------------------- |
| `package_count`          | `number` | Number of package records.                  |
| `file_count`             | `number` | Number of file records.                     |
| `import_count`           | `number` | Total imports in the flattened report.      |
| `declaration_count`      | `number` | Total declarations in the flattened report. |
| `usage_count`            | `number` | Total library-usage records.                |
| `security_signal_count`  | `number` | Total security signals.                     |
| `crypto_library_count`   | `number` | Total crypto-library records.               |
| `crypto_component_count` | `number` | Total crypto-component records.             |
| `crypto_material_count`  | `number` | Total crypto-material records.              |
| `crypto_finding_count`   | `number` | Total crypto findings.                      |
| `call_graph_node_count`  | `number` | Call-graph node count.                      |
| `call_graph_edge_count`  | `number` | Call-graph edge count.                      |
| `data_flow_node_count`   | `number` | Data-flow node count.                       |
| `data_flow_edge_count`   | `number` | Data-flow edge count.                       |
| `data_flow_slice_count`  | `number` | Data-flow slice count.                      |
| `api_endpoint_count`     | `number` | Number of `ApiEndpoint` records emitted.    |

## Notes

- `purl`, and the `sourcePurl`/`targetPurl` on `DataFlowSlice`, may be empty when a package URL cannot be derived. Call-graph **edges** carry no purls: read them from the nodes the edge references (see `CallGraphEdge`).
- `crypto`, `call_graph`, and `data_flow` are optional and may be `null` when disabled or when no evidence was produced.
- Backend-specific metadata is commonly stored in `properties` maps rather than top-level schema changes.
- For semantics and operational caveats, also read `README.md` and `THREAT_MODEL.md`.
