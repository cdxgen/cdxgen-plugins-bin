# Rusi threat model

This document describes the operational security assumptions for `rusi`, with emphasis on the difference between the default stable backend and the opt-in compiler backend.

## Scope

`rusi` analyzes Rust source trees and produces review-oriented JSON evidence:

- package/module/file structure
- imports, declarations, and resolved library usage clues
- security-sensitive API signals
- cryptographic evidence for CBOM-oriented review
- optional call graph and data-flow evidence

It is not a sandbox, exploit detector, or formal verifier.

## Assets worth protecting

When running `rusi`, the main assets are:

1. the host running the analysis
2. the confidentiality of local source code and path metadata
3. CI/CD credentials and network-accessible secrets in the environment
4. the integrity of the generated report
5. analyst trust in the absence or presence of findings

## Trust boundaries

### Stable backend

The default `stable` backend:

- runs `cargo metadata`
- reads `Cargo.toml` and workspace metadata
- reads and parses local Rust source files with `syn`
- does **not** intentionally execute the analyzed crate's Rust code, tests, examples, or binaries
- does **not** intentionally run `build.rs`, procedural macros, or `cargo check`

For untrusted repositories, this is the lower-risk mode and should be preferred when source-evidence, structural review, and heuristic CBOM extraction are sufficient.

### Compiler backend

The `compiler` backend is different.

It ultimately runs:

- `cargo check --all-targets`
- with a custom `RUSTC_WRAPPER`
- against a nightly toolchain with `rustc-dev`/`rust-src`

That means the compiler backend inherits the execution model of Cargo and `rustc`, including repository-controlled behavior such as:

- `build.rs`
- procedural macros
- dependency resolution and target-specific build logic
- environment-sensitive compilation behavior

For that reason, the compiler backend should be treated as **trusted-input or isolated-environment only**. Use a disposable worker, container, or VM if the repository is not already trusted.

## Untrusted input assumptions

Rusi assumes the analyzed repository may be malicious, malformed, or intentionally expensive to analyze.

Possible attacker goals include:

- causing analysis failure or extreme slowdown
- abusing compiler-backend execution surfaces
- generating confusing identifiers, paths, or symbols in reports
- exhausting disk, memory, or process limits via huge workspaces or generated code
- inducing false negatives through dynamic behavior, reflection-like macro expansion, or unsupported language patterns

## Main risks

### 1. Host compromise through compiler-backend execution

This is the highest-impact risk.

If you run `--backend compiler` on an untrusted project, Cargo may execute project-controlled build-time logic. Treat that as code execution risk.

### 2. Resource exhaustion

Large or adversarial repositories may cause:

- long parse times
- large call graphs
- many data-flow candidates
- high memory usage
- large intermediate build directories in compiler mode

Mitigations:

- prefer `--backend stable` first
- use `--callgraph none` or `--dataflow none` when structure is enough
- isolate compiler runs
- enforce external CPU, wall-clock, and memory limits in CI

### 3. Sensitive metadata exposure in reports

Rusi reports include:

- file paths relative to the analysis root
- package names and package paths
- symbol names and signatures
- package URLs when available

Even when raw secret values are avoided, this metadata may still be sensitive.

Mitigations:

- treat reports as internal artifacts unless intentionally published
- scrub or post-process if repository structure is sensitive
- store outputs in controlled locations

### 4. False confidence from static analysis limits

Rusi is intentionally practical, not complete.

Possible failure modes include:

- missed flows through macros, generated code, or unsupported patterns
- over-approximate call edges
- heuristic crypto classification without semantic validation
- inability to prove runtime reachability or exploitability

Mitigations:

- read diagnostics before interpreting absence of evidence
- combine `stable` and `compiler` backend results when appropriate
- treat findings as review candidates, not exploit proof

## Data handling expectations

Rusi aims to keep output reviewable and compact.

Current design goals:

- do not copy raw file contents into reports
- do not intentionally emit environment variable values
- do not intentionally emit raw secret literals as findings
- report secret-like material by identifier name and source location, not by secret value

Still, analysts should assume the following can appear in reports:

- secret-looking identifier names such as `app_secret` or `api_token`
- relative file paths
- crate/module names
- function names and signatures

## Supply-chain considerations

The stable backend depends on Cargo metadata resolution and local manifests.
The compiler backend additionally depends on:

- the selected toolchain
- nightly `rustc_private` components
- the embedded wrapper build
- dependency graph build behavior

Operationally, that means compiler-backend output can vary with:

- toolchain version
- target platform
- enabled features and targets
- workspace layout
- dependency graph state

For reproducible review workflows, record the tool/runtime fields from the JSON report.

## Recommended operating modes

### For untrusted repositories

Use:

```bash
cargo run -p rusi-cli -- analyze \
  --dir /path/to/repo \
  --backend stable \
  --callgraph static \
  --dataflow security \
  --out rusi.json
```

If you only need structural evidence or CBOM-oriented crypto evidence, reduce scope further:

```bash
cargo run -p rusi-cli -- analyze \
  --dir /path/to/repo \
  --backend stable \
  --callgraph none \
  --dataflow none \
  --out rusi-structure.json
```

### For trusted or isolated repositories

Use compiler mode only when you want type-resolved and MIR-informed evidence and you accept Cargo build-time execution semantics:

```bash
cargo run -p rusi-cli -- analyze \
  --dir /path/to/repo \
  --backend compiler \
  --toolchain nightly \
  --callgraph static \
  --dataflow security \
  --out rusi-compiler.json
```

## Non-goals

Rusi does not currently try to:

- sandbox Cargo or rustc
- verify cryptographic protocol correctness
- prove exploitability
- guarantee complete call-graph or data-flow precision
- determine whether all weak primitives are security-relevant in context

## Practical summary

- Prefer `stable` for first-pass and untrusted-repo analysis.
- Treat `compiler` as higher-fidelity but higher-risk.
- Consider reports sensitive metadata.
- Use diagnostics and runtime metadata when interpreting completeness.
