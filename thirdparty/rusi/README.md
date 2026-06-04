# Rusi (Rust Source Inspector)

Rusi is a Rust code analysis engine for evidence collection. It is designed to help downstream tooling and reviewers answer questions about what packages, files, symbols, and imports exist in a Rust repository, which APIs look security-sensitive, and what cryptographic libraries appear relevant for CBOM-style review.

Rusi operates in two modes:

- **Stable mode**: Uses the `syn` parser to analyze Rust source code without requiring a nightly compiler or rustc. This mode is stable, fast, and suitable for CI environments.
- **Compiler mode**: Uses an embedded nightly rustc wrapper and MIR/HIR-derived evidence for type-resolved call evidence, dispatch metadata for traits and dyn dispatch, native interop evidence, richer crypto evidence, and MIR-informed data-flow evidence.

## Quick Start

Build or run Rusi from this directory:

```bash
# Stable mode (no nightly required)
cargo run --bin rusi -- analyze --dir /path/to/rust/project --format json --out rusi.json

# Compiler mode (requires nightly rustc)
cargo run --bin rusi -- analyze --dir /path/to/rust/project --format json --out rusi-compiler.json --backend rustc
```

## What Rusi Reads

### Stable Mode

Rusi uses the `syn` crate to parse Rust source code. It walks the AST and records:

- **Imports**: Module paths, glob imports, and use statements
- **Declarations**: Functions, structs, enums, and trait definitions
- **Library/API usage**: Type-resolved function calls and trait implementations
- **Security signals**: Patterns that indicate security-sensitive operations (e.g., process execution, network access, file I/O)
- **Cryptographic evidence**: Recognized crypto library imports and API usage

### Compiler Mode

Rusi uses an embedded nightly rustc wrapper to access MIR (Mid-level IR) and HIR (High-level IR) for deeper analysis. This mode provides:

- Type-resolved call evidence
- Dispatch metadata for traits and dyn dispatch
- Native interop evidence (FFI bindings)
- Richer crypto evidence from MIR analysis
- MIR-informed data-flow evidence

## Cryptographic Evidence

Rusi recognizes common crypto families and classifies them:

- **sha2** - SHA-2 hash functions
- **sha1** - SHA-1 hash functions (weak primitive)
- **md5** - MD5 hash function (weak primitive)
- **blake3** - BLAKE3 hash function
- **aes-gcm** - AES-GCM encryption
- **chacha20poly1305** - ChaCha20-Poly1305 encryption
- **hmac** - HMAC keyed hash
- **pbkdf2** - Password-based key derivation
- **argon2** - Argon2 password hashing
- **rsa** - RSA public-key cryptography
- **ed25519-dalek** - Ed25519 signatures
- **rustls** - TLS library
- **jsonwebtoken** - JWT library

## Data-Flow Analysis

Rusi tracks source-to-sink flows for security analysis. Built-in patterns cover:

### Sources

- **Environment** - `std::env`, environment variables
- **CLI** - Command-line arguments
- **File** - File read operations
- **HTTP** - HTTP request/response APIs

### Sinks

- **Process execution** - `std::process::Command`, shell execution
- **Filesystem write/delete** - File write and delete operations
- **Network request/connect** - Network connection and request APIs
- **SQL** - Database query execution
- **HTML response** - HTML content generation

### Passthroughs

Functions that pass data from sources to sinks without modification. For example, a function that reads an environment variable and passes it directly to a process execution call.

### Sanitizers

Functions that transform or validate data before it reaches a sink. For example, a function that validates a command string before passing it to process execution.

## Custom Pattern Support

Rusi can merge custom JSON modeling with the built-in stable data-flow pack. Use the `--patterns` flag to provide a JSON file with custom sources, sinks, passthroughs, and sanitizers:

```bash
cargo run --bin rusi -- analyze --dir . --patterns custom-patterns.json --out rusi-custom.json
```

Example custom pattern file:

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
  ],
  "passthroughs": [
    {
      "pattern": "mycrate::transform::sanitize_path",
      "input_index": 0,
      "output_index": 0
    }
  ]
}
```

## Output Formats

- `json` - Complete report with evidence, call graph, and data-flow data
- `graphml` - Call graph export in GraphML format (requires `--callgraph`)
- `gexf` - Call graph export in GEXF format (requires `--callgraph`)

## Build and Test

```bash
# Run tests
cargo test

# Build stable mode binary
cargo build --release --bin rusi

# Build compiler mode binary (requires nightly)
cargo +nightly build --release --bin rusi
```

## Threat Model

Threat model notes live in [THREAT_MODEL.md](THREAT_MODEL.md). Rusi treats the analyzed repository as untrusted input and does not execute code. Source paths, package names, and symbols can still be sensitive metadata.
