# Lesson 3: Rust evidence with rusi

## Learning objective

Run rusi over a Rust workspace with both backends, write a custom source-to-sink pattern, and extend analysis into dependency crates.

## Pre-requisites

- Rust stable toolchain (and nightly for the compiler backend)
- a Rust project; this lesson uses rusi's own workspace as the sample

## Build and take the default pass

```bash
cd thirdparty/rusi
cargo build --release -p rusi-cli
target/release/rusi analyze --dir . --out /tmp/rusi.json
```

The default run uses the stable backend: `cargo metadata` for workspace discovery, `syn` for parsing, `#[cfg]` evaluation against the active target and resolved features. That last part is worth a pause. Code behind a `#[cfg(target_os = "windows")]` gate on a Linux analysis is not reported as if it were active; conditional code carries its gate in a `cfg_gate` field. Reports that pretend platform-specific code is universal are how false positives get shipped.

## Read the structure evidence

```bash
jq 'keys' /tmp/rusi.json
jq -r '.packages[] | [.name, .version] | @tsv' /tmp/rusi.json | head
```

The report answers inventory questions first: which packages, crates, files, symbols, and imports exist. Security signals mark APIs that look sensitive with locations attached.

## Receiver-typed resolution in practice

The stable backend resolves method calls by receiver type, following `self`, struct fields, smart pointers, `let` annotations, return types through `Result` and `Option`, and method chains. The practical effect is visible when two traits or impls define the same method name: rusi picks the one the receiver type calls for, or marks the call external, instead of fanning out to every same-named method. Sink matching uses the same discipline, which is why `Command::new(..).arg(tainted)` is a process-execution sink while another type's `arg` is not.

## Turn on the call graph and data flow

```bash
target/release/rusi analyze --dir . \
  --callgraph static --callgraph-out /tmp/rusi-callgraph.graphml --callgraph-export-format graphml \
  --dataflow security --out /tmp/rusi-full.json
jq '.dataFlow.flows | length' /tmp/rusi-full.json
```

Flows run from environment, CLI, file, and HTTP sources into process execution, filesystem write or delete, network, SQL, and HTML-response sinks. Export the flow graph alongside the report when you want to render it:

```bash
target/release/rusi analyze --dir . --dataflow security \
  --dataflow-out /tmp/flows.gexf --dataflow-export-format gexf --out /tmp/rusi-full.json
```

## Custom patterns

Teams have their own frameworks. If your crate reads secrets through `mycrate::config::read_key` and runs commands through `mycrate::shell::run`, teach rusi in a JSON file and merge it with the built-in pack:

```json
{
  "sources": [
    { "pattern": "mycrate::config::read_key", "category": "custom-source" }
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

```bash
target/release/rusi analyze --dir . --dataflow security \
  --patterns ./rusi-patterns.json --out /tmp/rusi-custom.json
```

`relevant_arguments` restricts a sink to the arguments that matter, so a logger's formatting arguments do not trigger a command-execution finding.

## Taint through dependencies

By default rusi analyzes your workspace and treats dependencies as boundaries. `--deps` crosses it, and `security-deps` keeps dependency bodies so taint flows through them:

```bash
target/release/rusi analyze --dir . --deps --dataflow security-deps --out /tmp/rusi-deps.json
```

This costs time on large dependency trees, so run it when a first-pass flow terminates suspiciously at a dependency edge and you want to know whether the taint really dies there.

## The compiler backend

The stable backend is syntax and receiver typing. The compiler backend embeds a nightly rustc wrapper and lifts MIR and HIR evidence: type-resolved call edges, trait and `dyn` dispatch metadata, native interop facts, richer crypto attribution, and MIR-informed flows.

```bash
rustup toolchain install nightly
target/release/rusi analyze --dir . --backend compiler --toolchain nightly \
  --callgraph static --dataflow security --out /tmp/rusi-compiler.json
```

Use it when dispatch precision matters more than setup cost. A CBOM pass over a crypto-heavy crate is a good candidate; the `cryptos` subcommand filters everything else out:

```bash
target/release/rusi cryptos --dir . --callgraph static --dataflow security --out /tmp/rusi-cryptos.json
```

## What you learned

- the stable backend needs no toolchain and respects `cfg` gates, which keeps reports honest about the target
- receiver-typed resolution means one method name produces one answer, not a fan-out
- custom patterns let house frameworks participate in the same flow analysis as stdlib and popular crates
- dependency taint and the compiler backend are escalation paths: reach for them when the stable answer is not enough
