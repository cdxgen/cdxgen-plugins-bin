#!/usr/bin/env bash
#
# Shared, named per-platform plugin exemptions. Sourced by
# stage-built-plugins.sh (skip staging, print the reason) and
# check-plugin-coverage.sh (skip the coverage assertion, print the reason) so
# the two scripts cannot drift apart.
#
# `kosi` is a GraalVM native image (thirdparty/kosi/docs/BUILD.md,
# 05-BUILD-DIST.md §2). GraalVM does not build for every architecture this
# repository packages, and native-image cannot cross-compile, so the gaps are
# declared here rather than hidden:
#   - ppc64le / linux-arm (32-bit): not Native Image platforms at all.
#     Consumers get cdxgen's own JS-side structural Kotlin analysis and,
#     with a JDK 21+ present, the kosi-portable.jar fallback
#     (thirdparty/kosi/docs/KOSI.md).
#   - linux-riscv64: best-effort LLVM-backend cross-build per the plan; no
#     artifact at this phase.
#   - windows-amd64 / windows-arm64 / darwin-amd64: build jobs land with the
#     release phase (MSVC toolchain / macos-intel runner; docs/BUILD.md §6).
#
# Keys are the binary filename fragments (after scripts/check-plugin-coverage.sh
# maps the ppc64 package directory to ppc64le).

# Usage: plugin_platform_exemption <plugin> <platform-fragment>
# Prints the reason and returns 0 when the plugin is exempt on that platform;
# returns 1 (printing nothing) when it is not.
plugin_platform_exemption() {
  local plugin="$1" platform="$2"
  if [[ "$plugin" != "kosi" ]]; then
    return 1
  fi
  case "$platform" in
    ppc64le)
      echo "not a GraalVM Native Image platform; JVM-jar fallback documented in docs/KOSI.md"
      return 0
      ;;
    linux-arm)
      echo "not a GraalVM Native Image platform (32-bit); JVM-jar fallback documented in docs/KOSI.md"
      return 0
      ;;
    linux-riscv64)
      echo "best-effort LLVM-backend cross-build; no artifact at this phase"
      return 0
      ;;
    windows-amd64|windows-arm64)
      echo "MSVC-toolchain build lands with the release phase (docs/BUILD.md §6)"
      return 0
      ;;
    darwin-amd64)
      echo "macos-intel release runner lands with the release phase (docs/BUILD.md §6)"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}
