# cdxrs: Rust-native BOM validation and fetch

cdxrs is an optimization, not a requirement. It is a Rust binary that cdxgen routes two operations through when present: BOM validation and batched registry metadata fetch. cdxgen carries a JavaScript implementation of both and falls back to it whenever the binary is unavailable: missing, wrong major version, disabled, or failed.

The fallback is silent by design, and cdxgen's golden test asserts that `CDXGEN_RS_DISABLE=all` produces byte-identical output, which is what makes taking it silently safe. That constraint shapes the tool: a subcommand earns its place only when it measurably beats the JavaScript path on a real corpus.

## Install

```bash
cd thirdparty/cdxrs
cargo build --release
target/release/cdxrs --help
```

Or point cdxgen at a custom build with `CDXRS_CMD`.

## Command surface

```
cdxrs [OPTIONS] [COMMAND]

  info            Print BOM summary statistics
  schema-version  Print the supported CycloneDX spec versions
  validate        Validate a CycloneDX BOM (schema + semantic checks)
  fetch           Fetch a batch of registry URLs in parallel, with an on-disk cache

  -i, --input <INPUT>           Input file path ("-" for stdin) [default: -]
  -o, --output <OUTPUT>         Output file path ("-" or omitted for stdout)
      --max-input-bytes <BYTES> Maximum input size (default: 2 GB)
```

cdxgen routes only `validate` and `fetch`. The other two exist for direct use and for the bridge's version probe.

## validate

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

Validation has two layers. Schema validation runs against vendored CycloneDX 1.6 and 1.7 schemas. Semantic rules then check what a schema cannot express: purl well-formedness, SPDX license expressions, metadata completeness. The catalogue of rules is documented in cdxgen's `docs/VALIDATION_RULES.md`, which is the contract both the Rust and JavaScript implementations satisfy.

`valid` is false only when at least one `error` finding exists. Warnings never invalidate a BOM, so the field can gate CI without warning noise becoming a build break.

Coverage includes the CycloneDX 1.7 additions cdxgen emits: root-level `citations`, `algorithmFamily` and `ellipticCurve`, and `metadata.distributionConstraints.tlp`.

## fetch

`fetch` takes a batch of registry URLs and fetches them in parallel with per-host concurrency limits, a TTL- and size-bounded on-disk cache, and credential redaction. It exists because registry metadata is a large fraction of scan wall time and most of the latency is waiting on sockets, which is exactly where a small native process with tight connection handling wins.

## Byte-identical round-trips

The I/O path uses untyped JSON values, so unknown fields survive and key order stays deterministic. A BOM that goes through cdxrs validate comes out the same BOM. This is a hard requirement for a tool that sits inside a generation pipeline: an accelerator that rewrites the document it was asked to check is a bug factory.

## Version pinning and fallback behavior

cdxgen pins cdxrs by major version. On a mismatch the bridge logs once and uses JavaScript; it does not error. Operationally that sets a release order: publish the plugins package before releasing a cdxgen version that expects a new cdxrs major, and nothing anywhere will complain.

If you suspect the accelerator never ran, do not look for errors, look for the absence of speed:

```bash
CDXGEN_RS_DISABLE=all cdxgen -t pnpm -o /tmp/a.json .
cdxgen -t pnpm -o /tmp/b.json .
cmp /tmp/a.json /tmp/b.json   # identical output, different wall time
```
