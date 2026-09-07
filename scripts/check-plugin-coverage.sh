#!/usr/bin/env bash
#
# Assert that every platform package carries a binary for every built plugin.
#
# Usage:
#   check-plugin-coverage.sh <package-dir> [<package-dir> ...]
#
# `stage-built-plugins.sh` already fails when it cannot find a binary for the
# platform it is staging, so this is the second line of defence: it inspects
# the finished packages rather than the staging step, and so also catches a
# plugin dropped from a build script's plugin list, or a package directory that
# was never staged at all.
#
# Only *built* plugins are checked. `dosai` and `osquery` are downloaded from
# upstream projects that do not publish for every architecture, so their
# absence on riscv64, ppc64le and arm is expected and not a build failure.
#
# `kosi` is checked like every other built plugin, with per-platform
# exemptions that are NAMED, never silent: where kosi cannot exist (ppc64le,
# 32-bit arm) or is not built yet (riscv64, windows, darwin-amd64), the
# exemption table prints its reason and the platform is skipped. On every
# other platform a missing kosi binary fails this check exactly like a
# missing golem or rusi binary. The table is shared with
# stage-built-plugins.sh (scripts/plugin-platform-support.sh).

#shellcheck source=plugin-platform-support.sh
source "$(dirname "$0")/plugin-platform-support.sh"

set -euo pipefail

# Plugins built from source in this repository.
readonly BUILT_PLUGINS=(trivy trustinspector golem rusi kosi cdxui cdxrs)

# Package directory name -> the filename fragment its binaries carry.
platform_fragment() {
  case "$1" in
    ppc64) echo "ppc64le" ;;
    *) echo "$1" ;;
  esac
}

main() {
  if [[ $# -lt 1 ]]; then
    echo "Usage: check-plugin-coverage.sh <package-dir> [<package-dir> ...]" >&2
    exit 1
  fi

  local failures=0
  local exempt_notes=0
  local package_dir package_name fragment plugin reason found

  for package_dir in "$@"; do
    if [[ ! -d "$package_dir" ]]; then
      echo "Error: package directory not found: $package_dir" >&2
      failures=$((failures + 1))
      continue
    fi
    package_name="$(basename "$package_dir")"
    fragment="$(platform_fragment "$package_name")"

    for plugin in "${BUILT_PLUGINS[@]}"; do
      reason="$(plugin_platform_exemption "$plugin" "$fragment" || true)"
      if [[ -n "$reason" ]]; then
        echo "Note: $package_name has no $plugin binary — exempt: $reason" >&2
        exempt_notes=$((exempt_notes + 1))
        continue
      fi
      # `|| true` matters: under `set -o pipefail` a find over a missing
      # directory fails the pipeline and would abort the script before it can
      # report which plugin is absent, which is the whole point of this check.
      found=""
      if [[ -d "$package_dir/plugins/$plugin" ]]; then
        found="$(find "$package_dir/plugins/$plugin" -maxdepth 1 -type f \
          -name "*${fragment}*" ! -name '*.sha256' 2>/dev/null | head -n 1 || true)"
      fi
      if [[ -z "$found" ]]; then
        echo "Error: $package_name is missing a $plugin binary (looked for *${fragment}*)" >&2
        failures=$((failures + 1))
      fi
    done
  done

  if [[ "$failures" -gt 0 ]]; then
    echo "" >&2
    echo "$failures missing plugin binary/binaries. A package that ships without a" >&2
    echo "plugin looks identical to one where the plugin is merely optional, so" >&2
    echo "this fails the release rather than letting it out." >&2
    exit 1
  fi

  echo "Plugin coverage OK: ${#BUILT_PLUGINS[@]} plugins present across $# package(s) ($exempt_notes named exemption(s))."
}

main "$@"
