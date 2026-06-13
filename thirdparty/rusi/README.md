# Rusi (Rust Source Inspector)

Rusi is a Rust code analysis engine for evidence collection. It is designed to help downstream tooling and reviewers answer questions such as:

- What packages, files, symbols, and imports exist in this Rust repository?
- Which APIs look security-sensitive?
- Which cryptographic libraries and components appear relevant for CBOM-style review?
- What does an approximate call graph look like?
- Which practical source-to-sink flows are present for common security categories?

## Quick start

Build or run Rusi from this directory:

```bash
cargo run -p rusi-cli -- analyze --dir /path/to/rust/project --out rusi.json
```

Useful variants:

```bash
cargo run -p rusi-cli -- analyze --dir . --backend stable --callgraph static --dataflow security --out rusi-stable.json
cargo run -p rusi-cli -- analyze --dir . --backend compiler --toolchain nightly --callgraph static --dataflow security --out rusi-compiler.json
cargo run -p rusi-cli -- analyze --dir . --dataflow security --patterns ./rusi-patterns.json --out rusi-custom.json
cargo run -p rusi-cli -- analyze --dir . --callgraph static --callgraph-out callgraph.graphml --callgraph-export-format graphml --out rusi.json
cargo run -p rusi-cli -- analyze --dir . --dataflow security --dataflow-out dataflow.gexf --dataflow-export-format gexf --out rusi.json
cargo run -p rusi-cli -- cryptos --dir . --callgraph static --dataflow security --out rusi-cryptos.json
cargo run -p rusi-cli -- analyze --dir . --callgraph none --dataflow none --out rusi-structure.json
```

## What Rusi reads

Rusi always starts from Cargo workspace/package discovery via `cargo metadata`.

### Stable backend

The default `stable` backend:

- discovers Rust files from the workspace/package layout
- parses source with `syn`
- records imports, declarations, library/API usage clues, and security signals
- constructs a deterministic source-level call graph
- performs a lightweight interprocedural data-flow analysis
- emits heuristic crypto/CBOM evidence from imports, syntax-level API usage, and secret-looking identifiers

This mode is the safest and fastest option for most first-pass analysis.

### Compiler backend

The optional `compiler` backend uses an embedded nightly `rustc` wrapper and MIR/HIR-derived evidence. It can add:

- type-resolved call evidence
- dispatch metadata for traits, dyn dispatch, closures, and specialization-like patterns
- native interop evidence
- richer crypto evidence when calls resolve cleanly through the compiler
- MIR-informed data-flow evidence

This backend is higher fidelity, but it runs Cargo/rustc for the target repository and therefore inherits Cargo build-time execution semantics. Read [`THREAT_MODEL.md`](./THREAT_MODEL.md) before using it on untrusted repositories.

#### `--toolchain` in compiler mode

`--toolchain` selects the Rust toolchain used for compiler-backed analysis. It is only meaningful with `--backend compiler`.

- `--toolchain auto` is the default. Rusi asks `rustup` for installed toolchains, prefers a nightly toolchain when one is available, and otherwise falls back to stable capability checks.
- `--toolchain nightly` runs the compiler backend through `cargo +nightly ...`.
- A fully named toolchain such as `--toolchain nightly-2026-06-01` or `--toolchain stable` is passed through to Cargo/rustup in the same way.

The embedded MIR/HIR collector requires a nightly toolchain with the `rustc-dev` and `rust-src` components installed. A typical setup is:

```bash
rustup toolchain install nightly --component rustc-dev --component rust-src
```

When embedded compiler collection is available, Rusi builds its local `rusi-rustc-wrapper` with the resolved toolchain and then runs the target repository with:

```bash
cargo +<resolved-toolchain> check
```

under a Rusi `RUSTC_WRAPPER`. This is where most compiler-mode time is spent on real repositories. Test targets are skipped by default. Add `--tests` to opt into test/example/bench target analysis, which makes compiler mode run:

```bash
cargo +<resolved-toolchain> check --all-targets
```

Use `--debug` to print progress to stderr without changing the JSON report. In compiler mode this includes the driver passes, wrapper build, Cargo check invocation, and rustc-wrapper file/function progress where available:

```bash
cargo run -p rusi-cli -- analyze \
  --dir /path/to/rust/project \
  --backend compiler \
  --toolchain nightly \
  --callgraph static \
  --dataflow security \
  --debug \
  --out rusi-compiler.json
```

If output appears to pause around `pass=embedded-compiler-backend`, Rusi is usually building the wrapper or waiting for Cargo to finish `cargo check` for the analyzed repository. With `--tests`, it may spend additional time on test targets such as `<crate>(test)`.

By default, compiler mode collects HIR/MIR bodies only for crates whose source files live under `--dir`. Calls into dependencies are still represented as resolved or modeled external calls where rustc provides the target information, but Rusi does not fully traverse Cargo registry/git dependency bodies. This keeps normal application analysis focused on the repository under review and avoids large debug logs from generated or table-heavy dependency files.

Use `--dataflow security-deps` to opt into full dependency/external crate body collection. In that mode Rusi also emits evidence for crates compiled from Cargo's registry/git/path dependency cache, which can improve whole-program dependency-body review but is substantially slower and can produce much larger JSON/GraphML reports:

```bash
target/debug/rusi analyze \
  --dir /path/to/rust/project \
  --backend compiler \
  --toolchain nightly \
  --callgraph static \
  --dataflow security-deps \
  --debug \
  --out rusi-compiler-with-deps.json
```

Pre-building the repository with ordinary `cargo build` usually does **not** make compiler-mode Rusi much faster. Rusi uses an isolated target directory under the analyzed repository and runs `cargo check`, not `cargo build`, so normal `target/debug` build artifacts are not reused. It can still help to run `cargo fetch` or a normal build/check once if dependencies have not been downloaded yet, because Cargo's registry and git caches are shared globally.

For example, to analyze `mini-redis`:

```bash
git clone https://github.com/tokio-rs/mini-redis.git /tmp/mini-redis
cd /tmp/mini-redis
cargo +nightly fetch

cd /path/to/rusi
cargo build -p rusi-cli
mkdir -p /tmp/mini-redis-rusi
target/debug/rusi analyze \
  --dir /tmp/mini-redis \
  --backend compiler \
  --toolchain nightly \
  --callgraph static \
  --dataflow security \
  --debug \
  --out /tmp/mini-redis-rusi/rusi-report.json \
  --callgraph-out /tmp/mini-redis-rusi/callgraph.graphml \
  --callgraph-export-format graphml \
  --dataflow-out /tmp/mini-redis-rusi/dataflow.graphml \
  --dataflow-export-format graphml
```

## Output model

The main report format is JSON. At a high level, a report contains:

- tool/runtime/options metadata
- workspace modules and packages
- file-level evidence
- flattened imports, declarations, usages, and security signals
- optional aggregated crypto evidence
- optional call graph
- optional data-flow evidence
- diagnostics and summary counts

The complete field reference is in [`JSON_ATTRIBUTE_REFERENCE.md`](./JSON_ATTRIBUTE_REFERENCE.md).

## Call graphs

Rusi currently exposes a practical call-graph model rather than a theorem of runtime reachability.

- `stable` builds a source-level graph from parsed functions and observed call text.
- `compiler` can add more precise edges and metadata for trait calls, dyn dispatch, closures, async boundaries, and candidate targets.

Call graphs can be exported as GraphML or GEXF:

```bash
cargo run -p rusi-cli -- analyze \
  --dir . \
  --callgraph static \
  --callgraph-out callgraph.graphml \
  --callgraph-export-format graphml \
  --out rusi.json
```

## Data-flow analysis

Rusi's data-flow engine is intentionally pragmatic.

The stable engine uses:

- syntax-level source/sink/passthrough pattern packs
- per-function summaries computed via fixpoint interprocedural analysis
- simple interprocedural replay
- concrete slice materialization for reviewable source-to-sink traces
- **automatic passthrough discovery** from workspace methods with accessor-like signatures (e.g. `fn get(&self) -> &T`)
- **struct field-level taint tracking** through struct construction, field assignment, and field access
- **trait method resolution** for `impl Trait for Type` blocks, enabling call-graph edges to concrete trait implementations
- **missing-passthrough diagnostics** that flag method calls where taint was lost, suggesting patterns to add

Current built-in security modeling includes, among other areas:

- environment, CLI, file, and HTTP sources
- process execution, filesystem write/delete, network request/connect, SQL, and HTML-response sinks
- sanitizer handling for HTML escaping and parameterized SQL APIs
- broad HTTP framework/source heuristics
- broad SQL sink coverage across popular Rust DB ecosystems

Example:

```bash
cargo run -p rusi-cli -- analyze \
  --dir . \
  --backend stable \
  --callgraph static \
  --dataflow security \
  --dataflow-out dataflow.graphml \
  --dataflow-export-format graphml \
  --out rusi-security.json
```

### Custom JSON sources and sinks

Rusi can merge custom JSON modeling with the built-in stable data-flow pack:

```bash
cargo run -p rusi-cli -- analyze \
  --dir . \
  --dataflow security \
  --patterns ./rusi-patterns.json \
  --out rusi-custom.json
```

The file is a JSON object with optional `sources`, `sinks`, and `passthroughs` arrays. Each entry maps directly to `DataFlowPattern` and supports:

- `pattern` — symbol/callee text to match
- `category` — category emitted in nodes, slices, and summaries
- `relevant_arguments` — argument indexes used by a sink or passthrough rule
- `target` — optional; if omitted, Rusi infers it from the containing array

Minimal example:

```json
{
  "sources": [
    {
      "pattern": "mycrate::config::read_key",
      "category": "custom-source"
    }
  ],
  "sinks": [
    {
      "pattern": "mycrate::shell::run",
      "category": "custom-command",
      "relevant_arguments": [0]
    }
  ]
}
```

Custom patterns are merged with built-in modeling instead of replacing it. In compiler mode, Rusi still keeps compiler-backed call/data-flow evidence, then merges the stable pattern-driven slices into the final report so custom JSON remains visible.

### `cryptos` command

`cryptos` runs the normal analysis pipeline but narrows the reported data-flow and callgraph output to cryptography-related slices and graph paths.

- data-flow output keeps crypto-oriented sources/sinks such as secret material, digests, key initialization, KDFs, JWT signing keys, and TLS builders
- callgraph output keeps crypto-relevant nodes plus caller paths leading into those nodes
- the top-level `crypto` evidence section is still preserved for CBOM-style review

Example:

```bash
cargo run -p rusi-cli -- cryptos \
  --dir . \
  --backend stable \
  --callgraph static \
  --dataflow security \
  --out rusi-cryptos.json \
  --callgraph-out rusi-cryptos.graphml \
  --dataflow-out rusi-cryptos-dataflow.graphml \
  --callgraph-export-format graphml \
  --dataflow-export-format graphml
```

The report records this narrowed mode under `options.analysis_scope = "cryptos"`.

## Crypto evidence and CBOM use

Rusi emits crypto evidence in the `crypto` section of the JSON report.

The current model is intended for CBOM-oriented review, not protocol verification.

It records four kinds of evidence:

1. `libraries` — crypto-relevant providers or namespaces such as `sha2`, `aes_gcm`, `argon2`, `rustls`, or `jsonwebtoken`
2. `components` — concrete crypto API uses classified into algorithm, provider, kind, and operation
3. `materials` — secret-like identifiers such as keys, tokens, salts, and nonces without copying raw secret values
4. `findings` — review findings such as weak primitive usage (`MD5`, `SHA-1`)

### Current CBOM-oriented strengths

The stable backend recognizes common real-world families such as:

- hashes: `sha2`, `sha1`, `md5`, `blake3`
- AEAD: `aes-gcm`, `chacha20poly1305`
- MAC/KDF/password hashing: `hmac`, `pbkdf2`, `argon2`
- asymmetric and key material: `rsa`, `ed25519-dalek`, plus import-level coverage for `x25519-dalek`, `p256`, `p384`, and `k256`
- token/protocol libraries: `jsonwebtoken`, `rustls`
- component-level `ring` digest/AEAD coverage plus import-level crypto library evidence for additional families such as `openssl`, `native_tls`, and `x509`-related crates

### Current CBOM-oriented limitations

Rusi is not yet a full cryptographic protocol analyzer. In particular, it is weaker at:

- proving which algorithm variant a generic wrapper resolves to when the syntax is ambiguous
- validating TLS configuration correctness end to end
- distinguishing all security-relevant uses of weak hashes from non-security checksum contexts
- following custom wrapper layers or macro-generated crypto abstractions exhaustively

The stable engine also tracks crypto source-to-sink flows through common method chains (`.as_bytes()`, `.trim()`, `.to_lowercase()`, etc.) via built-in and auto-discovered passthrough patterns. Crypto data-flow slices are emitted in `cryptos` scope when an environment or file source flows into a classified crypto sink.

### Reproducible CBOM sample evaluation

Curated real-crate sample apps live under `fixtures/cbom-real-*` and can be evaluated with:

```bash
cargo build -p rusi-cli
python3 scripts/evaluate-cbom-samples.py
python3 scripts/evaluate-cbom-samples.py --backend compiler --timeout-seconds 90 fixtures/cbom-real-asymmetric-app
```

The timeout option is especially useful for compiler-backed real-crate probes because it bounds the run and cleans up spawned Cargo/wrapper subprocesses if the timeout is reached.

That harness currently exercises real crate manifests and source examples covering:

- `sha2`, `md5`, `blake3`
- `aes-gcm`, `chacha20poly1305`
- `argon2`, `pbkdf2`, `hmac`
- `jsonwebtoken`, `rustls`
- `ring` digest/AEAD coverage
- `rsa` and `ed25519-dalek`

## SQL and HTTP modeling

The built-in stable security pack intentionally covers common Rust web and data stacks.

### SQL

Modeled SQL/raw-query ecosystems currently include:

- `sqlx`
- `diesel`
- `postgres` / `tokio-postgres`
- `rusqlite`
- `mysql` / `mysql_async`
- `tiberius`
- `sea-orm` / `sea-query`

Parameterized-query helpers such as `bind`, `push_bind`, `push_values`, `params`, and `params_from_iter` are treated as sanitizing boundaries.

The remaining generic-method false-positive risk has been reduced by requiring SQL context for ambiguous method names such as `query`, `execute`, `load`, and `prepare` before they are treated as SQL sinks.

### HTTP

Modeled request/response ecosystems include:

- `actix-web`
- `axum`
- `warp`
- `rocket`
- `hyper`
- `poem`
- `tide`
- `salvo`
- `iron`
- `gotham`
- `rouille`
- `ntex`
- `dropshot`
- `thruster`
- `nickel`
- common outbound client stacks such as `reqwest`, `surf`, `ureq`, and `isahc`

## Strengths

- Works on stable Rust by default.
- Produces deterministic, review-friendly JSON.
- Keeps structural, graph, flow, and crypto evidence in one schema.
- Includes package URLs where derivable.
- Offers both safe/faster (`stable`) and richer/higher-risk (`compiler`) backends.
- Ships with fixtures, regression tests, and evaluation scripts.
- Trait method resolution for `impl Trait for Type` blocks in the stable backend.
- Auto-discovered passthrough patterns reduce manual pattern curation.
- Struct field-level taint tracking for projection and builder patterns.
- Missing-passthrough diagnostics guide pattern refinement.

## Weaknesses and assumptions

- Static analysis is approximate; absence of evidence is not proof of absence.
- Stable call resolution is text/syntax driven; trait dispatch is limited to known `impl` blocks.
- Compiler mode is dependent on nightly toolchain availability and Cargo build behavior.
- Crypto evidence is classification-oriented, not a proof of secure protocol design.
- Data flow is practical and bounded rather than path-perfect.

## Documentation map

- [`THREAT_MODEL.md`](./THREAT_MODEL.md): trust boundaries and operational security guidance
- [`JSON_ATTRIBUTE_REFERENCE.md`](./JSON_ATTRIBUTE_REFERENCE.md): field-by-field JSON schema guide

## Build and test

Run the workspace tests:

```bash
cargo test --all-targets
```

Build the CLI:

```bash
cargo build -p rusi-cli
cargo build --release -p rusi-cli
```

## Benchmarking

The stable analysis path parallelizes file analysis, summary inference, and per-function materialization. Set `RUSI_THREADS=<n>` to override automatic worker selection during benchmarking.

Example benchmark commands:

```bash
cargo build --release -p rusi-cli
python3 scripts/benchmark-real-world.py --rusi-bin ./target/release/rusi --include-auto --threads 1 /absolute/path/to/repo
python3 scripts/benchmark-real-world.py --rusi-bin ./target/release/rusi --suite popular --suite large --include-auto --threads 1
```

## Packaging and release builds

The local `Makefile` produces packaged binaries such as:

- `rusi-linux-amd64`
- `rusi-linuxmusl-arm64`
- `rusi-windows-amd64.exe`
- `rusi-darwin-arm64`

It also emits `*.sha256` sidecars and a post-build CycloneDX SBOM.

Common packaging commands:

```bash
make bootstrap-linux
make linux linuxmusl windows sbom

make bootstrap-darwin
make darwin sbom
```

`make all` builds the targets supported by the current host.
