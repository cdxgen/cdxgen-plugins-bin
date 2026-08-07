# BLOCKERS — cdxgen-plugins-bin

## Open

Nothing blocking the 3.0.0 release.

## Resolved

### cdxrs was never wired into the release pipeline

`cdxrs` was added to `build.sh` and to every `packages/*/build-*.sh` in the same
commit that bumped versions to 3.0.0, but no CI job ever built it: it appeared
zero times in `release.yml`, `test.yml` and `native-builds.yml`. Because the
last release predates that commit, the pipeline had never run with cdxrs in it.

The failure would have been loud rather than silent, though not obviously so.
With no prebuilt artifacts, `build.sh` takes the `make all` branch, and the
`pkg` runner installs no zig, rustup or cargo — so the first cross-build target
aborts with "zig is required to cross-build linux-amd64" and `set -e` fails the
release.

Fixed by adding `cdxrs_linux_prebuild` and `cdxrs_darwin_prebuild` to both
`release.yml` and `test.yml`, mirroring the existing rusi and cdxui jobs, and
downloading their artifacts in the `pkg` job. The Linux prebuild is required,
not a convenience: the `pkg` runner has no Rust toolchain, so the binaries must
arrive as artifacts.

### A missing plugin binary passed silently

`scripts/stage-built-plugins.sh` printed a warning and returned 0 when it found
no binary for the platform it was staging, so an incomplete package looked
identical to a complete one. Two changes:

- staging now fails when a built plugin has no binary for the platform, and
  reports what it did find;
- `scripts/check-plugin-coverage.sh` re-checks the finished packages before
  `check-package-size.sh` runs, catching a plugin dropped from a build script's
  list or a package that was never staged at all.

Only *built* plugins are checked. `dosai` and `osquery` are downloaded from
upstream projects that publish no binaries for some architectures, and their
absence on riscv64, ppc64le and arm is expected — verified against the
published 2.6.0 packages.

### cdxrs had no CI test run

The crate's 96 tests never ran in CI. `cdxrs-test.yml` now runs `cargo test`,
`cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` on every
change under `thirdparty/cdxrs/`, plus a release build and smoke test on Linux,
macOS and Windows so a broken build surfaces before the slow release job.

## Host limitations, not defects

- **Cross-builds cannot all be produced on a macOS development machine.** A
  Linux host with `cargo-zigbuild` and `zig` builds the five linux-gnu, two
  linuxmusl and two windows flavours; the two darwin flavours need macOS. The
  Makefiles enforce this with a clear error rather than producing a broken
  binary, and CI covers both hosts.
