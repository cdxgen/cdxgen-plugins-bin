# cdxrs

Rust-native CycloneDX BOM tooling, shipped inside
`@cdxgen/cdxgen-plugins-bin` and invoked by cdxgen as an optional accelerator.

## What it is for

cdxrs is an **optimisation, not a requirement**. cdxgen carries a JavaScript
implementation of everything cdxrs does and falls back to it whenever the
binary is unavailable — missing, wrong major version, disabled, or failed. The
fallback is silent by design, and
`contrib/rs-disable-golden-test.js` in the cdxgen repository asserts that
`CDXGEN_RS_DISABLE=all` produces byte-identical output, which is what makes
taking it silently safe.

That constraint shapes what belongs here: a subcommand is worth adding only
when it measurably beats the JavaScript path on a real corpus. Several
candidates were measured and rejected — the registry-fetch speedup turned out
to be concurrency rather than Rust, and evinse is 89–99.7% atom, leaving under
0.6% for anything a port could touch.

## Commands

```
cdxrs [OPTIONS] [COMMAND]

  info            Print BOM summary statistics
  schema-version  Print the supported CycloneDX spec versions
  validate        Validate a CycloneDX BOM (schema + semantic checks)
  fetch           Fetch a batch of registry URLs in parallel, with an on-disk cache

  -i, --input <INPUT>              Input file path ("-" for stdin) [default: -]
  -o, --output <OUTPUT>            Output file path ("-" or omitted for stdout)
      --max-input-bytes <BYTES>    Maximum input size (default: 2 GB)
```

Of these, cdxgen currently routes only `validate` and `fetch` through the
binary. `info` and `schema-version` exist for direct use and for the bridge's
version probe.

### validate

Schema validation against the vendored CycloneDX schemas, plus semantic rules
that the schema cannot express (purl well-formedness, SPDX expressions,
metadata completeness). Output is a JSON findings document:

```console
$ cdxrs validate --input bom.json
{
  "valid": true,
  "specVersion": "1.7",
  "findings": [
    {
      "id": "metadata.component-version-missing",
      "severity": "warning",
      "path": "/metadata/component/version",
      "message": "Version is missing for metadata.component. ..."
    }
  ],
  "summary": { "error": 0, "warning": 1, "info": 0 }
}
```

`valid` is false only when at least one `error` finding is present. Warnings
never make a BOM invalid. The rule catalogue is documented in
`docs/VALIDATION_RULES.md` in the cdxgen repository, which is the contract both
implementations satisfy.

### fetch

Batched registry metadata GETs with per-host concurrency limits, an on-disk
cache bounded by TTL and an LRU byte ceiling, rate-limit awareness, and
credential redaction. Reads a batch request on stdin and writes responses to
stdout.

## Spec version support

1.6 and 1.7. Schemas are vendored under `schemas/` and guarded against drift by
`tests/schema_drift.rs`, which pins their hashes — an accidental schema swap
fails the build rather than silently changing what validates.

CycloneDX 1.7 additions that are explicitly covered:

- root-level `citations`, including the schema's `oneOf` on
  `pointers`/`expressions` and its `anyOf` on `attributedTo`/`process`
- `algorithmFamily` and `ellipticCurve` on cryptographic assets
- `metadata.distributionConstraints.tlp`

A 1.6 document carrying a 1.7-only element is rejected. That is what makes
cdxgen's downgrade strip load-bearing rather than cosmetic, so it is tested in
both directions.

## Round-trip guarantee

The I/O path uses `serde_json::Value` rather than the typed model, so unknown
fields survive and key order is deterministic (`BTreeMap`, alphabetically
sorted, 2-space indent, trailing newline). This matches the normalisation
cdxgen's golden harness applies, which is what allows byte-identical
comparison between the Rust and JavaScript paths.

The typed structs in `src/bom/model.rs` are hand-written rather than generated,
and every one carries `#[serde(flatten)] extra` so type-safe field access never
costs unknown-field preservation. The reasoning is recorded at the top of that
file.

## Protocol

stdin and stdout carry JSON. **stderr carries NDJSON log records only** — never
human-readable text, because cdxgen parses it. Exit codes:

| Code | Meaning                                      |
| ---- | -------------------------------------------- |
| 0    | Success                                      |
| 1    | Operational failure (I/O, parse, size limit) |
| 2    | Bad usage (invalid arguments)                |
| 3    | Validation found error-severity findings     |

The full protocol, including the JS bridge API and every fallback reason, is in
`docs/CDXRS_PROTOCOL.md` in the cdxgen repository.

## Version contract

cdxgen's bridge pins a **major** version (`CDXRS_VERSION_MAJOR` in
`lib/inventory/cdxrs.js`). A mismatch is not an error: the bridge logs once and
uses the JavaScript path. Release plugins-bin before cdxgen when bumping it,
otherwise every existing install quietly drops to the fallback on upgrade.

## Building

```shell
make bootstrap-linux    # or bootstrap-darwin
make all                # cross-builds every target supported by the host OS
make test
```

A Linux host builds the linux, linuxmusl and windows targets; darwin targets
require a macOS host. Cross-building needs `cargo-zigbuild` and `zig`.

## Development

```shell
cargo test              # unit and integration tests
cargo test --test validate citations   # one area
cargo clippy --all-targets -- -D warnings
```

Snapshot tests use `cargo-insta`. `tests/fetch.rs` runs against a local mock
server and makes no outbound requests.
