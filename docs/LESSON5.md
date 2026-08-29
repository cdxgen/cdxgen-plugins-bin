# Lesson 5: BOM validation with cdxrs

## Learning objective

Validate a CycloneDX BOM with cdxrs directly, read its findings document, understand the two-layer validation model, and know exactly what happens in cdxgen when the binary is present or absent.

## Pre-requisites

- Rust toolchain for the build
- a BOM to validate; any cdxgen output works

## Build and validate

```bash
cd thirdparty/cdxrs
cargo build --release
target/release/cdxrs validate --input /path/to/bom.json
```

Output is a JSON findings document:

```json
{
  "valid": true,
  "specVersion": "1.7",
  "findings": [
    {
      "id": "metadata.component-version-missing",
      "severity": "warning",
      "path": "/metadata/component/version",
      "message": "Version is missing for metadata.component."
    }
  ],
  "summary": { "error": 0, "warning": 1, "info": 0 }
}
```

`valid` is false only when at least one finding has severity `error`. Warnings describe a BOM that will pass schema but embarrass you in a consumer, like a metadata component without a version. That split is what makes the field CI-safe: gate on `valid`, report warnings, and a noisy warning never becomes a red build by accident.

## The two validation layers

Layer one is schema. cdxrs validates against vendored CycloneDX 1.6 and 1.7 schemas, so the check is version-aware and offline. Layer two is semantics, the rules a JSON schema cannot express: purl well-formedness, SPDX license expressions, metadata completeness, and coverage of the 1.7 additions cdxgen emits such as root-level `citations` and `algorithmFamily`. Every rule has a stable id, and the catalogue is documented in cdxgen's `docs/VALIDATION_RULES.md`, which is the contract that both the Rust and the JavaScript implementations satisfy.

Check the supported versions and a quick summary without writing a pipeline:

```bash
target/release/cdxrs schema-version
target/release/cdxrs info --input /path/to/bom.json
```

## Round-trip safety

A validator that rewrites what it validates is a bug factory, so cdxrs parses with untyped JSON values: unknown fields survive, key order is deterministic, and the byte-identical round-trip property holds. You can verify on your own BOM:

```bash
target/release/cdxrs info --input bom.json --output /tmp/roundtrip.json
cmp bom.json /tmp/roundtrip.json   # only meaningful for info paths that re-emit
```

The property that actually matters is guaranteed upstream: cdxgen's golden test asserts `CDXGEN_RS_DISABLE=all` produces byte-identical output, so the accelerator changes speed, never content.

## What cdxgen does with it

cdxgen routes its `validate` and `fetch` stages through cdxrs when the binary resolves, and falls back to its JavaScript implementation otherwise. The fallback triggers on a missing binary, a failed run, a disabled flag, or a major version mismatch, because cdxgen pins cdxrs by major. On mismatch the bridge logs once and moves on; it does not fail the scan.

That design has one operational consequence: when a cdxrs release changes its major version, publish the plugins package before the cdxgen release that expects it. Get the order wrong and nothing errors, your scans simply run on the slower path with a single log line you never read.

To measure what the accelerator is worth on your project:

```bash
time CDXGEN_RS_DISABLE=all cdxgen -t pnpm -o /tmp/a.json /path/to/project
time cdxgen -t pnpm -o /tmp/b.json /path/to/project
cmp /tmp/a.json /tmp/b.json && echo "identical output"
```

## The fetch half

The other routed stage is registry metadata fetch. `fetch` takes a batch of registry URLs, fetches them in parallel with per-host concurrency limits, caches on disk with TTL and size bounds, and redacts credentials. It exists because scan wall time is dominated by socket waits on license and registry metadata, which is a concurrency problem more than a language problem, and the native implementation earns its keep precisely there.

## What you learned

- findings documents separate errors from warnings, and only errors invalidate
- two layers, schema and semantics, with a stable rule catalogue shared across implementations
- round-trips are byte-identical, and the fallback guarantee is tested, not assumed
- version pinning is by major, which sets a publish order rather than an error condition
