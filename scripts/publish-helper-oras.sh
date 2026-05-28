#!/usr/bin/env bash
set -euo pipefail

print_usage() {
  cat <<'EOF'
Usage:
  publish-helper-oras.sh <repository> <tool-dir> [binary-glob]

Examples:
  publish-helper-oras.sh ghcr.io/cdxgen/cdxgen-plugins-bin ./plugins/golem 'golem-*'
  publish-helper-oras.sh ghcr.io/cdxgen/cdxgen-plugins-bin ./thirdparty/trustinspector/build 'trustinspector-cdxgen-linuxmusl-*'
EOF
}

publish_artifacts() {
  local repository="$1"
  local tool_dir="$2"
  local binary_glob="${3:-*}"
  local sbom_file=""
  local published=0

  if [[ ! -d "$tool_dir" ]]; then
    echo "Tool directory not found: $tool_dir" >&2
    exit 1
  fi

  if ! command -v oras >/dev/null 2>&1; then
    echo "oras CLI is required but was not found in PATH" >&2
    exit 1
  fi

  sbom_file="$(find "$tool_dir" -maxdepth 1 -type f -name 'sbom-*.cdx.json' -print -quit || true)"

  local candidates=()
  while IFS= read -r -d '' candidate; do
    candidates+=("$candidate")
  done < <(find "$tool_dir" -maxdepth 1 -type f -name "$binary_glob" -print0)

  for binary_path in "${candidates[@]}"; do
    [[ -f "$binary_path" ]] || continue
    case "$(basename "$binary_path")" in
      *.sha256|*.json)
        continue
        ;;
    esac

    local binary_name sha_path tag
    binary_name="$(basename "$binary_path")"
    sha_path="${binary_path}.sha256"
    tag="${binary_name%.exe}"

    if [[ ! -f "$sha_path" ]]; then
      echo "Missing SHA-256 sidecar for $binary_path" >&2
      exit 1
    fi

    local oras_args=(
      push "${repository}:${tag}"
      --artifact-type application/vnd.cdxgen.plugins.binary.v1+json
      "${binary_path}:application/vnd.cdxgen.plugins.layer.v1+tar"
      "${sha_path}:application/vnd.cdxgen.plugins.layer.v1+tar"
    )

    if [[ -n "$sbom_file" ]]; then
      oras_args+=("${sbom_file}:sbom/cyclonedx+json")
    fi

    oras "${oras_args[@]}"
    published=$((published + 1))
  done

  if [[ "$published" -eq 0 ]]; then
    echo "No helper binaries matched ${binary_glob} in ${tool_dir}" >&2
    exit 1
  fi
}

main() {
  if [[ $# -lt 2 || $# -gt 3 ]]; then
    print_usage >&2
    exit 1
  fi

  publish_artifacts "$1" "$2" "${3:-*}"
}

main "$@"
