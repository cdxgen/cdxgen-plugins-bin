#!/usr/bin/env bash
set -euo pipefail

print_usage() {
  cat <<'EOF'
Usage:
  stage-built-plugins.sh <source-dir> <destination-dir> <platform-fragment> [exclude-fragment]
EOF
}

stage_plugin_files() {
  local source_dir="$1"
  local destination_dir="$2"
  local platform_fragment="$3"
  local exclude_fragment="${4:-}"
  local plugin_name
  local staged_binary=0

  plugin_name="$(basename "$source_dir")"
  mkdir -p "$destination_dir"

  if [[ ! -d "$source_dir" ]]; then
    echo "Warning: No files found for $plugin_name in $source_dir/" >&2
    return 0
  fi

  while IFS= read -r -d '' file_path; do
    if [[ -n "$exclude_fragment" ]] \
      && [[ "$(basename "$file_path")" == *"$exclude_fragment"* ]]; then
      continue
    fi
    cp -f "$file_path" "$destination_dir/"
    if [[ "$(basename "$file_path")" == *"$platform_fragment"* ]] \
      && [[ "$(basename "$file_path")" != sbom* ]] \
      && [[ "$(basename "$file_path")" != *.sha256 ]]; then
      staged_binary=1
    fi
  done < <(
    find "$source_dir" -maxdepth 1 -type f \
      \( -name "*${platform_fragment}*" -o -name 'sbom*' \) -print0
  )

  if [[ "$staged_binary" -eq 0 ]]; then
    echo "Warning: No files found for $plugin_name in $source_dir/" >&2
  fi
}

main() {
  if [[ $# -lt 3 || $# -gt 4 ]]; then
    print_usage >&2
    exit 1
  fi

  stage_plugin_files "$1" "$2" "$3" "${4:-}"
}

main "$@"
