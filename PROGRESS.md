# PROGRESS — cdxgen-plugins-bin

## D05 — cdxrs scaffold, protocol, JS bridge, cross-build

- Version bump 2.6.0 → 3.0.0 across package.json (root + 11 platform packages), package-lock.json, cdxui Cargo.toml/Cargo.lock, rusi Cargo.toml/Cargo.lock (5 sub-crates), golem main.go default var. All remaining 2.6.0 are third-party deps (trivy go modules) or test fixtures (schema_tests.rs "12.6.0").
- cdxrs crate created: one crate, one binary, cdxui shape. Hand-written CycloneDX 1.6/1.7 serde model with BTreeMap extras for unknown-field preservation. I/O path uses serde_json::Value (BTreeMap-backed) for guaranteed byte-identical round-trip on golden BOMs.
- cdxrs info subcommand: reads BOM, prints {specVersion, componentCount, dependencyCount, serviceCount, vulnerabilityCount, hasEvidence, bomFormat, cdxrsVersion}. Also ships --version and schema-version.
- 10 golden BOMs vendored into testdata/. Round-trip property test passes byte-identical on all. Large-BOM check (pubspec-smoke 311KB, cargo-smoke 230KB) verified. Fuzz guard on bom::read.
- cargo test (10 tests), clippy -D warnings, fmt --check all clean.
- cdxrs added to build.sh and all 11 packages/*/build-*.sh.
- Cross-build: darwin-amd64 (479K) and darwin-arm64 (443K) built with sha256 sidecars. Linux/musl/windows require Linux host (zig is Linux ELF on this machine).
