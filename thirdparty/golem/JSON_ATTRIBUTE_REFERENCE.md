# Golem JSON Attribute Reference

This document explains the JSON report emitted by Golem with a focus on call graph, data-flow, and crypto evidence. It is designed for engineering teams that consume Golem output in automation, dashboards, and triage workflows.

The canonical schema lives in `internal/model/model.go`.

## Scope and option behavior

Golem always emits a report envelope and core source evidence. Call graph and data-flow sections are optional. Crypto evidence is always collected from parsed source and type information.

| Invocation option          | Allowed values                                                                                              | JSON sections affected                    | What changes in output                                                                                                                                      |
| -------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--callgraph`              | `none`, `static`, `cha`, `rta`, `vta`                                                                       | `callGraph`, `stats.callGraph*`           | When not `none`, `callGraph` contains graph nodes, edges, diagnostics, and stats.                                                                           |
| `--dataflow`               | `none`, `security`, `crypto`, `all`                                                                         | `dataFlow`, `stats.dataFlow*`             | When not `none`, `dataFlow` contains taint slices, nodes, edges, summaries, diagnostics, and stats.                                                         |
| `--dataflow-callgraph`     | `none`, `static`, `cha`, `rta`, `vta`                                                                       | `dataFlow.diagnostics`, slice quality     | Controls dynamic summary replay for data-flow interprocedural propagation.                                                                                  |
| `--taint-engine`           | `seam` (default), `legacy`                                                                                  | `dataFlow.engine`                         | Selects the taint engine. `seam` is the default structured-model SCC-fixpoint engine; `legacy` is the older engine, kept as an escape hatch.                |
| `--dataflow-pattern-packs` | `all`, `base`, `http`, `frameworks`, `data`, `filesystem`, `process`, `crypto`, `native`, `config`, `cloud` | `dataFlow.patterns` and downstream slices | Changes which sources, sinks, passthroughs, and sanitizers can match.                                                                                       |
| `--include-stdlib`         | boolean                                                                                                     | `callGraph`, `dataFlow`, core usages      | Includes standard library nodes/usages when enabled.                                                                                                        |
| `--include-local`          | boolean                                                                                                     | `callGraph`, `dataFlow`, core usages      | Controls whether local module symbols are included.                                                                                                         |
| `--include-all-flows`      | boolean                                                                                                     | `callGraph`, `dataFlow`                   | Alias for `--dependency-detail=full`.                                                                                                                       |
| `--dependency-detail`      | `drop`, `collapse`, `full`                                                                                  | `callGraph`, `dataFlow`                   | How much dependency interior to show. `collapse` (default) replaces interior chains with one annotated edge; the boundary into a dependency is always kept. |
| `--roots`                  | `main`, `init`, `exported`, `tests`, `handlers`, `all`, `symbol:<regex>`                                    | `callGraph.roots`, `callGraph`            | Entry points for reachability. Defaults to `main`/`init` plus framework registrations.                                                                      |
| `--reachable-symbols`      | file path                                                                                                   | `callGraph.reachability.paths`            | Emit shortest witness paths for the listed symbols.                                                                                                         |

## Report envelope

The top-level `Report` carries metadata plus optional analysis sections.

| JSON path                                                | Type                       | Purpose                                         | Typical use case                                 |
| -------------------------------------------------------- | -------------------------- | ----------------------------------------------- | ------------------------------------------------ |
| `schemaVersion`                                          | string                     | Versioned schema URL for compatibility checks.  | Contract gating in ingestion pipelines.          |
| `tool.name`                                              | string                     | Producer tool name.                             | Multi-tool provenance in merged evidence.        |
| `tool.version`                                           | string                     | Producer version string.                        | Drift analysis and reproducibility.              |
| `runtime.*`                                              | object                     | Host/runtime context used during analysis.      | Explain platform-specific evidence differences.  |
| `options.*`                                              | object                     | Effective analysis options persisted in report. | Auditing and replay of analysis behavior.        |
| `packages`, `files`, `imports`, `declarations`, `usages` | arrays                     | Core source and symbol evidence.                | Occurrence evidence and code ownership mapping.  |
| `securitySignals`                                        | array                      | Security API pattern observations.              | Lightweight risk surfacing before taint review.  |
| `crypto`                                                 | object, optional           | Crypto-focused evidence extracted from source.  | CBOM-like enrichment and crypto policy checks.   |
| `callGraph`                                              | object, optional           | Call graph section when enabled.                | Reachability and blast radius analysis.          |
| `dataFlow`                                               | object, optional           | Data-flow section when enabled.                 | Source-to-sink triage and exploitability review. |
| `diagnostics`                                            | array                      | Global diagnostic messages.                     | Handling partial analysis gracefully.            |
| `nativeBoundary[]`                                       | array of `NativeCall`      | cgo Go↔C boundary records.                      | Hybrid-project boundary auditing.                |
| `buildShapeDeltas[]`                                     | array of `BuildShapeDelta` | Files excluded by build constraints.            | Diagnose CGO_ENABLED skew.                       |
| `stats`                                                  | object                     | Aggregate counters across evidence sections.    | Dashboards, trend baselining, quality checks.    |

## `options` object details

`options` is useful when reports are stored long-term and reviewed out of band.

| JSON path                       | Type    | Purpose                                    | Typical use case                                     |
| ------------------------------- | ------- | ------------------------------------------ | ---------------------------------------------------- |
| `options.directory`             | string  | Absolute analysis root used by Golem.      | Correlate evidence paths to source checkout.         |
| `options.patterns[]`            | string  | `go/packages` patterns analyzed.           | Explain missing packages due to narrowed scope.      |
| `options.buildTags[]`           | string  | Build tags applied at load time.           | Compare prod versus test build surfaces.             |
| `options.tests`                 | boolean | Test variants included or not.             | Separate runtime evidence from test-only evidence.   |
| `options.noRecurse`             | boolean | Recursive module discovery disabled flag.  | Multi-module repository behavior auditing.           |
| `options.includeAllFlows`       | boolean | External-only flow filtering control.      | Keep or suppress third-party-only call/flow paths.   |
| `options.callGraphMode`         | string  | Effective call graph mode.                 | Precision versus performance tuning.                 |
| `options.dataFlowMode`          | string  | Effective data-flow mode.                  | Security-only or broad taint modeling.               |
| `options.dataFlowCallGraphMode` | string  | Dynamic summary replay mode for data-flow. | Improve interprocedural coverage in large codebases. |
| `options.dataFlowPacks[]`       | string  | Active pattern packs.                      | Validate expected source and sink coverage.          |

`options.noRecurse` and `options.includeAllFlows` are always emitted, including `false`, so downstream tooling can reliably audit effective defaults.

## Call graph JSON reference

The `callGraph` section exists only when `--callgraph` is not `none`.

### `callGraph` section

| JSON path                   | Type                     | Purpose                              | Typical use case                              |
| --------------------------- | ------------------------ | ------------------------------------ | --------------------------------------------- |
| `callGraph.mode`            | string                   | Requested mode.                      | Verify requested algorithm path.              |
| `callGraph.algorithm`       | string                   | Effective algorithm used internally. | Debug mode coercions or fallback behavior.    |
| `callGraph.nodes[]`         | array of `CallGraphNode` | Function-level graph vertices.       | API fan-in and fan-out exploration.           |
| `callGraph.edges[]`         | array of `CallGraphEdge` | Caller to callee relations.          | Reachability and impact tracing.              |
| `callGraph.roots[]`         | array of `CallGraphRoot` | Resolved analysis entry points.      | Explain why a symbol is or is not reachable.  |
| `callGraph.reachability`    | object, optional         | Per-node reachability and witnesses. | Reachability triage without re-walking edges. |
| `callGraph.diagnostics[]`   | array                    | Call graph construction issues.      | Explain graph sparsity or unsupported shapes. |
| `callGraph.stats.nodeCount` | integer                  | Number of graph nodes emitted.       | Sanity checks and trend monitoring.           |
| `callGraph.stats.edgeCount` | integer                  | Number of graph edges emitted.       | Graph density checks over time.               |

### `callGraph.nodes[]` fields

| Field           | Type    | Purpose                                          | Typical use case                            |
| --------------- | ------- | ------------------------------------------------ | ------------------------------------------- |
| `id`            | string  | Stable node id, generally SSA function identity. | Join key for edge processing.               |
| `name`          | string  | Function short name.                             | Human-readable graph labels.                |
| `label`         | string  | Expanded function label.                         | Disambiguate overload-like patterns.        |
| `kind`          | string  | Node kind, usually `function`.                   | Future compatibility checks.                |
| `packagePath`   | string  | Go package path.                                 | Package-level aggregation and ownership.    |
| `packageName`   | string  | Package short name.                              | UI grouping convenience.                    |
| `module`        | object  | Module metadata for this node.                   | Internal versus external module decisions.  |
| `purl`          | string  | Package URL for dependency mapping.              | Component evidence linking in SBOM.         |
| `standard`      | boolean | Standard library classification.                 | Filter stdlib-heavy fan-outs.               |
| `local`         | boolean | Local module classification.                     | Focus on first-party execution paths.       |
| `external`      | boolean | External dependency classification.              | Third-party reachability insights.          |
| `synthetic`     | boolean | Synthetic SSA function indicator.                | Exclude compiler-generated nodes in UX.     |
| `syntheticKind` | string  | Kind of synthetic function, from SSA.            | Distinguish thunks from generic wrappers.   |
| `visibility`    | string  | `local`, `dependency`, `stdlib`, or `synthetic`. | Scope filtering without re-deriving origin. |
| `signature`     | string  | Function signature text.                         | Method shape and call-compatibility review. |
| `receiver`      | string  | Receiver type for methods.                       | OO-like method dispatch analysis.           |
| `position.*`    | object  | Source location for function definition.         | Jump-to-code from graph nodes.              |

### `callGraph.edges[]` fields

| Field           | Type         | Purpose                                          | Typical use case                                  |
| --------------- | ------------ | ------------------------------------------------ | ------------------------------------------------- |
| `id`            | string       | Stable edge id.                                  | De-duplication and graph diffs.                   |
| `sourceId`      | string       | Caller node id.                                  | Upstream traversal.                               |
| `targetId`      | string       | Callee node id.                                  | Downstream traversal.                             |
| `sourceName`    | string       | Caller function text.                            | Fast context in logs/UI.                          |
| `targetName`    | string       | Callee function text.                            | Fast context in logs/UI.                          |
| `sourcePurl`    | string       | Caller package URL.                              | Component-level stack evidence.                   |
| `sinkPurl`      | string       | Callee package URL.                              | Component-level stack evidence.                   |
| `purls[]`       | string array | Combined purls seen on edge.                     | Dependency evidence enrichment.                   |
| `callType`      | string       | Dispatch kind, see below.                        | Confidence scoring and triage order.              |
| `static`        | boolean      | Static callsite marker.                          | Precision-oriented filtering.                     |
| `collapsed`     | boolean      | Edge stands in for a path through omitted nodes. | Distinguish a direct call from a summarised path. |
| `collapsedHops` | integer      | Hops folded into a collapsed edge.               | Judge how indirect a collapsed path is.           |
| `via[]`         | string array | Packages traversed by a collapsed edge.          | Show what a collapsed path went through.          |
| `position.*`    | object       | Source location of callsite.                     | File and line call stack rendering.               |
| `description`   | string       | Optional edge description.                       | Custom narratives in future exporters.            |
| `properties`    | object       | Optional edge metadata map.                      | Extended analytics without schema churn.          |

`callType` is one of `static`, `interface`, `func-value`, `bound method wrapper`,
`generic wrapper`, `defer`, `go`, `reflect`, `cgo`, or `synthetic-root`. The
`static` boolean remains true only for statically resolved calls, so existing
consumers keep their previous meaning.

### `callGraph.roots[]` fields

| Field        | Type   | Purpose                             | Typical use case                                                                                          |
| ------------ | ------ | ----------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `id`         | string | Root node id.                       | Join to `callGraph.nodes[]`.                                                                              |
| `function`   | string | Root function text.                 | Human-readable entry point list.                                                                          |
| `rootReason` | string | Why the function was chosen a root. | Distinguish `main` from `exported`, and either from `escaped-func-value`, which is an over-approximation. |

### `callGraph.reachability` fields

| JSON path                                 | Type         | Purpose                                | Typical use case                            |
| ----------------------------------------- | ------------ | -------------------------------------- | ------------------------------------------- |
| `reachability.nodes[].nodeId`             | string       | Node the entry describes.              | Join to `callGraph.nodes[]`.                |
| `reachability.nodes[].reachableFromRoots` | boolean      | Whether any root reaches the node.     | Drop findings in unreachable code.          |
| `reachability.nodes[].minDepth`           | integer      | Shortest distance from a root.         | Rank findings by how directly they are hit. |
| `reachability.nodes[].rootIds[]`          | string array | Roots that reach the node.             | Explain reachability per entry point.       |
| `reachability.paths[].symbol`             | string       | Symbol the witness path targets.       | Requested via `--reachable-symbols`.        |
| `reachability.paths[].nodeIds[]`          | string array | Nodes along the shortest witness path. | Render a call stack for a reachable symbol. |
| `reachability.paths[].edgeIds[]`          | string array | Edges along the witness path.          | Attribute each hop to a call site.          |
| `reachability.paths[].depth`              | integer      | Length of the witness path.            | Sort witnesses shortest-first.              |

Reachability is computed on the complete graph, before any view filtering, so a
node omitted from `callGraph.nodes[]` never leaves a dangling reference behind:
entries and witness paths referring to omitted nodes are removed with it.

## Data-flow JSON reference

The `dataFlow` section exists only when `--dataflow` is not `none`.

### `dataFlow` section

| JSON path                | Type                     | Purpose                                                                                                                                                                                                                        | Typical use case                                                        |
| ------------------------ | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| `dataFlow.engine`        | string                   | Producing taint engine: `seam` (default) or `legacy`. Tells a consumer which engine produced a report, so the `known-fail` ratchet, the model set in force, and the precision/recall expectations can be attributed correctly. | Differential triage; consumer-side gating on engine-specific behaviour. |
| `dataFlow.mode`          | string                   | Effective data-flow mode.                                                                                                                                                                                                      | Confirm security versus all-mode operation.                             |
| `dataFlow.nodes[]`       | array of `DataFlowNode`  | Taint graph nodes.                                                                                                                                                                                                             | Interactive path inspection.                                            |
| `dataFlow.edges[]`       | array of `DataFlowEdge`  | Taint transitions between nodes.                                                                                                                                                                                               | Explain propagation hops.                                               |
| `dataFlow.slices[]`      | array of `DataFlowSlice` | Source-to-sink traces selected for output.                                                                                                                                                                                     | Triage and evidence export.                                             |
| `dataFlow.patterns`      | `DataFlowPatternSet`     | Active source/sink/sanitizer patterns.                                                                                                                                                                                         | Explain why a flow was or was not matched.                              |
| `dataFlow.summaries[]`   | `DataFlowMethodSummary`  | Interprocedural summary models.                                                                                                                                                                                                | Debug summary replay quality.                                           |
| `dataFlow.diagnostics[]` | array                    | Data-flow analysis diagnostics.                                                                                                                                                                                                | Understand truncation and skipped coverage.                             |
| `dataFlow.stats.*`       | object                   | Counts, performance, and quality metrics.                                                                                                                                                                                      | Capacity planning and confidence scoring.                               |

### `dataFlow.patterns` fields

| Field            | Type                       | Purpose                        | Typical use case                        |
| ---------------- | -------------------------- | ------------------------------ | --------------------------------------- |
| `sources[]`      | array of `DataFlowPattern` | Source match rules.            | Validate ingress coverage for APIs.     |
| `sinks[]`        | array of `DataFlowPattern` | Sink match rules.              | Validate dangerous boundary coverage.   |
| `passthroughs[]` | array of `DataFlowPattern` | Propagation helpers.           | Reduce false negatives in wrappers.     |
| `sanitizers[]`   | array of `DataFlowPattern` | Taint reduction or stop rules. | Suppress known-safe transformed flows.  |
| `packs[]`        | string array               | Enabled pattern packs.         | Confirm profile-level policy selection. |

### `DataFlowPattern` fields

| Field                   | Type            | Purpose                                                     | Typical use case                              |
| ----------------------- | --------------- | ----------------------------------------------------------- | --------------------------------------------- |
| `target`                | string          | Pattern target class: source, sink, passthrough, sanitizer. | Rule routing and UI labeling.                 |
| `kind`                  | string          | Match domain such as function, package, type, parameter.    | Fine-grained matching behavior.               |
| `match`                 | string          | Match operator: contains, exact, prefix, suffix, regex.     | Rule precision tuning.                        |
| `pattern`               | string          | Pattern value.                                              | Library and symbol matching.                  |
| `category`              | string          | Security/flow category.                                     | Severity and policy mapping.                  |
| `purl`                  | string          | Optional purl override for rule.                            | Explicit dependency attribution.              |
| `description`           | string          | Human rule description.                                     | Reviewer context and documentation.           |
| `taintKinds[]`          | string array    | Taint labels to propagate.                                  | Data classification and policy filtering.     |
| `removesTaintKinds[]`   | string array    | Taint kinds removed by sanitizer.                           | Safe-transform modeling.                      |
| `sanitizesCategories[]` | string array    | Sink categories suppressed after sanitization.              | Category-aware sink suppression.              |
| `relevantArguments[]`   | integer array   | Sink argument indexes to inspect.                           | Accurate sink targeting for APIs.             |
| `receiverRelevant`      | boolean         | Whether method receiver is sink-relevant.                   | Receiver-side taint checks.                   |
| `ruleId`, `ruleName`    | strings         | Rule metadata attached to slices.                           | Findings normalization and suppression logic. |
| `severity`, `riskScore` | string, integer | Priority metadata for matched sink rules.                   | Sort and threshold in triage queues.          |
| `confidence`            | string          | Confidence hint for pattern evidence.                       | Review prioritization.                        |

### `dataFlow.nodes[]` fields

| Field                    | Type         | Purpose                                                 | Typical use case                         |
| ------------------------ | ------------ | ------------------------------------------------------- | ---------------------------------------- |
| `id`                     | string       | Stable node id.                                         | Joining nodes, edges, and slices.        |
| `kind`                   | string       | Node role such as source, sink, call, store, sanitizer. | Visual graph styling and filtering.      |
| `name`, `symbol`, `type` | strings      | Symbolic detail for node.                               | Analyst-readable path details.           |
| `packagePath`            | string       | Node package path.                                      | Package ownership mapping.               |
| `module`                 | object       | Module metadata at node level.                          | Internal versus external filtering.      |
| `purl`                   | string       | Dependency mapping anchor.                              | SBOM evidence linking.                   |
| `functionId`, `function` | strings      | Function context.                                       | Grouping and call-path explanation.      |
| `position.*`             | object       | Source location of node event.                          | Code navigation from findings.           |
| `source`                 | boolean      | Marks source node.                                      | Ingress counts and source filtering.     |
| `sink`                   | boolean      | Marks sink node.                                        | Egress counts and sink filtering.        |
| `category`               | string       | Node category, often sink/source type.                  | Policy and severity mapping.             |
| `taintKinds[]`           | string array | Active taint labels at node.                            | Security and data-classification checks. |
| `fieldPath`              | string       | Aggregate field/index context.                          | Struct and collection taint debugging.   |
| `confidence`             | string       | Node confidence hint.                                   | Prioritization in review tooling.        |
| `properties`             | object       | Extra metadata map.                                     | Rule and sanitizer metadata transport.   |

### `dataFlow.edges[]` fields

| Field                  | Type    | Purpose                                           | Typical use case                         |
| ---------------------- | ------- | ------------------------------------------------- | ---------------------------------------- |
| `id`                   | string  | Stable edge id.                                   | Graph diff and dedupe.                   |
| `sourceId`, `targetId` | strings | Node ids connected by transition.                 | Path traversal.                          |
| `kind`                 | string  | Transition kind such as call-return, store, sink. | Explain propagation mechanism.           |
| `label`                | string  | Optional edge label.                              | Parameter or channel context display.    |
| `position.*`           | object  | Location associated with transition.              | Trace review and auditing.               |
| `properties`           | object  | Optional extensible metadata.                     | Advanced telemetry without schema churn. |

### `dataFlow.slices[]` fields

A slice is the key triage record. It points to source and sink nodes and preserves ordered path identifiers.

| Field                                  | Type                     | Purpose                                        | Typical use case                        |
| -------------------------------------- | ------------------------ | ---------------------------------------------- | --------------------------------------- |
| `id`                                   | string                   | Stable slice id.                               | Deduplication and suppression keys.     |
| `sourceId`, `sinkId`                   | strings                  | Endpoint node ids for the trace.               | Fast source-to-sink joins.              |
| `flowKey`                              | string                   | Stable grouping key for similar flows.         | Duplicate group collapsing.             |
| `duplicateOf`, `duplicateIndex`        | string, integer          | Duplicate flow linkage.                        | UI compaction and de-noising.           |
| `nodeIds[]`, `edgeIds[]`               | string arrays            | Ordered path node and edge ids.                | Multi-hop call stack rendering.         |
| `edgeKinds[]`                          | string array             | Aggregated transition kinds in path.           | Quick path-shape filtering.             |
| `sanitizerNodeIds[]`                   | string array             | Sanitizer nodes on path.                       | Sanitized-flow review and policy logic. |
| `pathLength`                           | integer                  | Number of edges in path.                       | Complexity and confidence heuristics.   |
| `sourceCategory`, `sinkCategory`       | strings                  | Classified endpoints.                          | Rule routing and severity policy.       |
| `sourceName`, `sinkName`               | strings                  | Symbol short names.                            | Human-readable triage context.          |
| `sourceSymbol`, `sinkSymbol`           | strings                  | Symbol identities.                             | API-level sink/source mapping.          |
| `sourceFunction`, `sinkFunction`       | strings                  | Function-level endpoint context.               | Ownership and remediation routing.      |
| `sourcePackagePath`, `sinkPackagePath` | strings                  | Package-level endpoint context.                | Team-level routing.                     |
| `sourcePurl`, `sinkPurl`, `purls[]`    | strings and string array | Dependency attribution for endpoints and path. | SBOM evidence and dependency policy.    |
| `sinkArgument`, `sinkArgumentIndex`    | string, integer          | Sink argument context.                         | Precision remediation at callsite.      |
| `taintKinds[]`                         | string array             | Taint labels observed in path.                 | Data-class and policy checks.           |
| `fieldPaths[]`                         | string array             | Aggregate field-level path context.            | Object-graph taint debugging.           |
| `crossesDependency`                    | boolean                  | Taint left the module under analysis.          | Dependency risk and blast radius.       |
| `dependencyHops`                       | integer                  | Dependency boundaries the flow crossed.        | Ranking flows by distance from the app. |
| `ruleId`, `ruleName`                   | strings                  | Rule metadata from sink classification.        | Stable issue keys in ticketing systems. |
| `severity`, `riskScore`                | string, integer          | Priority metadata.                             | Sorting and threshold gating.           |
| `sourceScope`, `sinkScope`             | strings                  | Runtime/test/example scope context.            | Ignore test-only findings in CI.        |
| `sourceCriticality`, `sinkCriticality` | strings                  | Criticality hints by category.                 | Prioritized review queues.              |
| `confidence`                           | string                   | Slice confidence.                              | Automated triage ranking.               |
| `description`                          | string                   | Human explanation of flow.                     | Analyst-friendly finding summary.       |
| `properties`                           | object                   | Extensible metadata map.                       | Pipeline-specific enrichment.           |

### `dataFlow.summaries[]` fields

| Field                    | Type    | Purpose                                  | Typical use case                           |
| ------------------------ | ------- | ---------------------------------------- | ------------------------------------------ |
| `functionId`, `function` | strings | Function identity and label for summary. | Traceability for interprocedural behavior. |
| `packagePath`            | string  | Package context for summary.             | Grouping by ownership.                     |
| `paramToReturn[]`        | array   | Parameter-to-return taint propagation.   | Wrapper and adapter behavior modeling.     |
| `paramToSink[]`          | array   | Parameter-to-sink category propagation.  | Hidden sink exposure through wrappers.     |
| `receiverToReturn`       | boolean | Receiver-to-return passthrough flag.     | Fluent API taint modeling.                 |
| `passthrough`            | boolean | Generic passthrough marker.              | Fast-path propagation logic.               |
| `confidence`             | string  | Summary confidence hint.                 | Summary quality tracking.                  |
| `properties`             | object  | Extra summary metadata.                  | Debug and tuning metadata.                 |

### `dataFlow.stats` fields

| Field                                        | Type           | Purpose                                      | Typical use case                    |
| -------------------------------------------- | -------------- | -------------------------------------------- | ----------------------------------- |
| `sourceCount`, `sinkCount`, `sliceCount`     | integers       | Core flow counts.                            | Coverage and trend KPIs.            |
| `nodeCount`, `edgeCount`                     | integers       | Graph size.                                  | Capacity and complexity monitoring. |
| `summaryCount`                               | integer        | Number of inferred summaries.                | Interprocedural model footprint.    |
| `candidateFunctionCount`, `functionCount`    | integers       | Candidate and analyzed function counts.      | Understand analysis narrowing.      |
| `skippedFunctionCount`                       | integer        | Functions skipped by safeguards.             | Large-repo tradeoff visibility.     |
| `instructionCount`                           | integer        | Approximate SSA instruction workload.        | Capacity planning.                  |
| `workerCount`                                | integer        | Worker parallelism used.                     | Performance tuning.                 |
| `elapsedMillis`                              | integer        | End-to-end data-flow runtime.                | SLA and runtime budgeting.          |
| `truncated`                                  | boolean        | Slice truncation flag.                       | Warn when output is incomplete.     |
| `truncationReasons[]`                        | string array   | Human-readable truncation reasons.           | Automatic retry with higher limits. |
| `uniqueFlowCount`                            | integer        | Unique flow groups by `flowKey`.             | Noise ratio measurements.           |
| `duplicateSliceCount`, `duplicateGroupCount` | integers       | Duplicate metrics.                           | UI collapse and dedupe tuning.      |
| `maxPathLength`, `averagePathLength`         | integer, float | Path complexity metrics.                     | Risk heuristics and trend analysis. |
| `sanitizedSliceCount`                        | integer        | Number of slices with sanitizer involvement. | Sanitizer effectiveness reporting.  |

## Crypto JSON reference

The `crypto` section is populated from core analysis and does not require `--dataflow`. Data-flow can still add crypto-relevant slices and metadata in `dataFlow`.

### `crypto` section

| JSON path             | Type                       | Purpose                                           | Typical use case                                |
| --------------------- | -------------------------- | ------------------------------------------------- | ----------------------------------------------- |
| `crypto.libraries[]`  | array of `CryptoLibrary`   | Crypto package/library imports and usage context. | Dependency-level crypto inventory.              |
| `crypto.assets[]`     | array of `CryptoAsset`     | Detected algorithms and certificates.             | Crypto primitive and asset classification.      |
| `crypto.operations[]` | array of `CryptoOperation` | Concrete crypto operation usage records.          | Encryption/signing/decryption pathway auditing. |
| `crypto.materials[]`  | array of `CryptoMaterial`  | Key and secret material indicators.               | Sensitive material handling governance.         |
| `crypto.protocols[]`  | array of `CryptoProtocol`  | Protocol usage like TLS.                          | Transport security posture analysis.            |
| `crypto.findings[]`   | array of `CryptoFinding`   | Rule-based crypto findings.                       | Policy violation reporting and gating.          |
| `crypto.properties`   | object                     | Optional extensible metadata.                     | Custom pipeline enrichment.                     |

### `CryptoLibrary` fields

| Field         | Type    | Purpose                       | Typical use case                              |
| ------------- | ------- | ----------------------------- | --------------------------------------------- |
| `id`          | string  | Stable record id.             | Deduplication and cross-run comparison.       |
| `path`        | string  | Import path.                  | Library policy checks and allowlists.         |
| `family`      | string  | Crypto family classification. | Portfolio-level cryptography mapping.         |
| `standard`    | boolean | Standard library indicator.   | Third-party crypto dependency identification. |
| `usageScope`  | string  | Runtime/test scope.           | Runtime-only security review.                 |
| `packagePath` | string  | Package where usage appears.  | Ownership mapping.                            |
| `range.*`     | object  | Source range of evidence.     | Jump-to-code review.                          |
| `properties`  | object  | Optional metadata.            | Extended analytics.                           |

### `CryptoAsset` fields

| Field                                 | Type    | Purpose                                       | Typical use case                             |
| ------------------------------------- | ------- | --------------------------------------------- | -------------------------------------------- |
| `id`                                  | string  | Stable asset id.                              | Joins with operations and findings.          |
| `name`                                | string  | Asset name, often algorithm name.             | Human-readable inventory.                    |
| `assetType`                           | string  | Asset class such as algorithm or certificate. | Category-based policy controls.              |
| `primitive`                           | string  | Primitive family when known.                  | Primitive governance and migration planning. |
| `strength`                            | string  | Strength indicator when inferable.            | Weak crypto tracking.                        |
| `standard`                            | string  | Referenced standard metadata.                 | Compliance reporting.                        |
| `oid`                                 | string  | Algorithm or certificate OID when available.  | Accurate cryptographic normalization.        |
| `packagePath`, `symbol`, `usageScope` | strings | Context metadata for source origin.           | Ownership and triage routing.                |
| `range.*`                             | object  | Source range.                                 | Code navigation from findings.               |
| `properties`                          | object  | Optional metadata map.                        | Context enrichment.                          |

### `CryptoOperation` fields

| Field                                 | Type    | Purpose                                         | Typical use case                      |
| ------------------------------------- | ------- | ----------------------------------------------- | ------------------------------------- |
| `id`                                  | string  | Stable operation id.                            | Change detection and diffing.         |
| `operationType`                       | string  | Operation class such as encrypt, decrypt, sign. | Operation-specific policy checks.     |
| `algorithm`                           | string  | Algorithm name if inferred.                     | Algorithm usage metrics.              |
| `assetId`                             | string  | Linked `CryptoAsset` id.                        | Graphing operation-to-asset relation. |
| `packagePath`, `symbol`, `usageScope` | strings | Code context metadata.                          | Team-level remediation routing.       |
| `range.*`                             | object  | Source range.                                   | Source inspection from reports.       |
| `properties`                          | object  | Optional metadata.                              | Pipeline-specific augmentation.       |

### `CryptoMaterial` fields

| Field                                 | Type    | Purpose                                   | Typical use case                  |
| ------------------------------------- | ------- | ----------------------------------------- | --------------------------------- |
| `id`                                  | string  | Stable material id.                       | Deduplication and trend analysis. |
| `type`                                | string  | Material type such as key, secret, nonce. | Sensitive data policy mapping.    |
| `name`                                | string  | Material identifier when available.       | Human triage context.             |
| `packagePath`, `symbol`, `usageScope` | strings | Source context.                           | Ownership and prioritization.     |
| `range.*`                             | object  | Source range.                             | Review navigation.                |
| `properties`                          | object  | Optional metadata.                        | Additional context transport.     |

### `CryptoProtocol` fields

| Field                                 | Type    | Purpose                          | Typical use case               |
| ------------------------------------- | ------- | -------------------------------- | ------------------------------ |
| `id`                                  | string  | Stable protocol id.              | Diffs and historical tracking. |
| `name`                                | string  | Protocol name.                   | Inventory and policy checks.   |
| `type`                                | string  | Protocol category.               | Grouped compliance reporting.  |
| `version`                             | string  | Protocol version when inferable. | Legacy protocol detection.     |
| `packagePath`, `symbol`, `usageScope` | strings | Source context.                  | Ownership-aware remediation.   |
| `range.*`                             | object  | Source range.                    | Jump-to-source workflow.       |
| `properties`                          | object  | Optional metadata.               | Extended reporting.            |

### `CryptoFinding` fields

| Field                                  | Type    | Purpose                                | Typical use case                       |
| -------------------------------------- | ------- | -------------------------------------- | -------------------------------------- |
| `id`                                   | string  | Stable finding id.                     | Deduplication and suppression control. |
| `ruleId`                               | string  | Rule identifier.                       | Policy rule mapping.                   |
| `severity`                             | string  | Finding severity.                      | Prioritized triage queues.             |
| `confidence`                           | string  | Evidence confidence.                   | Auto-triage quality scoring.           |
| `summary`, `recommendation`            | strings | Human explanation and action guidance. | Developer-facing remediation output.   |
| `packagePath`, `usageScope`            | strings | Context metadata.                      | Runtime-only gating and ownership.     |
| `assetId`, `operationId`, `materialId` | strings | Links to crypto evidence records.      | Graph-based triage workflows.          |
| `range.*`                              | object  | Source range.                          | Editor jump links.                     |
| `properties`                           | object  | Optional metadata.                     | Extended pipeline integrations.        |

## Practical consumption patterns

### 1. Build a component call stack table

Use `dataFlow.slices[*].nodeIds` and `callGraph.edges[*].position` to collect ordered file and line entries by resolved purl. Favor slices first, then enrich with call graph edges for broader coverage.

### 2. Separate runtime and test evidence

Use `sourceScope`, `sinkScope`, and `usageScope` fields. For CI gate decisions, drop findings where both source and sink are test-like scopes.

### 3. Prioritize by confidence and impact

Sort slices by `severity`, `riskScore`, `confidence`, then `pathLength`. For crypto, combine `crypto.findings[*].severity` with linked `assetId` and operation context.

### 4. Detect incomplete runs

Check `dataFlow.stats.truncated`, `dataFlow.stats.truncationReasons`, and section diagnostics. If truncated, rerun with larger slice budget or narrower patterns.

## Native boundary reference

The `nativeBoundary[]` section records crossing points between Go and C, in both
directions: `_Cfunc_*` wrappers for calls into C, and `//export`ed Go functions
for calls out of it. Records are derived from source and SSA; no C compiler is
invoked.

`direction` is the direction data moves, not the direction of the call. That
matters for the conversion functions cgo generates for itself: `C.GoString` is
`c->go` even though Go calls it. Those functions carry `properties.cgoHelper`
and have no `cSymbol`, because there is no C declaration to point at - reporting
one named `GoString` would send a reader looking for something that does not
exist.

### `NativeCall` fields

| Field             | Type                          | Purpose                                                                                                              |
| ----------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `id`              | string                        | Stable record identifier.                                                                                            |
| `goSymbol`        | string                        | Go-side cgo wrapper symbol (`_Cfunc_*`).                                                                             |
| `cSymbol`         | string                        | Resolved C function name. Absent for cgo-generated conversions.                                                      |
| `direction`       | string                        | `go->c` or `c->go`.                                                                                                  |
| `headerFile`      | string                        | The preamble's `#include`, when the package has exactly one. Ambiguous preambles are left blank rather than guessed. |
| `libraries[]`     | string array                  | Linked libraries from `#cgo LDFLAGS`.                                                                                |
| `argumentRoles[]` | array of `NativeArgumentRole` | Per-argument role classification.                                                                                    |
| `position.*`      | object                        | Source location from SSA function.                                                                                   |
| `confidence`      | string                        | Evidence confidence.                                                                                                 |
| `evidence[]`      | string array                  | Raw `#cgo` directive text supporting the entry.                                                                      |
| `packagePath`     | string                        | Go package owning the cgo function.                                                                                  |
| `goFunctionId`    | string                        | SSA function identity.                                                                                               |
| `goFunctionName`  | string                        | Human-readable function qualified name.                                                                              |
| `properties`      | object                        | `cgoHelper` and `role` for cgo's own conversions.                                                                    |

### `NativeArgumentRole` fields

| Field      | Type    | Purpose                                          |
| ---------- | ------- | ------------------------------------------------ |
| `index`    | integer | Zero-based argument index.                       |
| `role`     | string  | Semantic role (e.g. pointer, c-string, integer). |
| `type`     | string  | Go type string of the argument.                  |
| `variadic` | boolean | True when this is a variadic argument.           |

## Build shape delta reference

The `buildShapeDeltas[]` section lists Go files present in the tree that took no
part in the analysis. A single `packages.Load` picks one build configuration, so
on a hybrid repository whole files - the `CGO_ENABLED=0` fallbacks, the other
platform's syscalls - are invisible; this section is what says so.

Note that a cgo package's `CompiledGoFiles` are generated files in the build
cache rather than its sources, so the check is made against `GoFiles` too.

### `BuildShapeDelta` fields

| Field        | Type   | Purpose                                                                                                                        |
| ------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------ |
| `path`       | string | File system path to the excluded file.                                                                                         |
| `reason`     | string | `excluded-by-build-constraint`, `test-only`, or `not-in-any-loaded-package`.                                                   |
| `constraint` | string | The file's parsed `//go:build` expression, or the constraint implied by its name (`GOOS=windows`). Empty when neither applies. |

## Notes on compatibility

Field names in JSON use lower camel case as defined in model tags. Any unknown fields should be ignored by consumers for forward compatibility.
