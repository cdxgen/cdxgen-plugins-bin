#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/github-smoke.sh"

bash -n "$SCRIPT"

if [[ "${RUSI_RUN_GITHUB_SMOKE:-0}" == "1" ]]; then
  RUSI_GITHUB_REPOS="${RUSI_GITHUB_REPOS:-https://github.com/rust-random/getrandom.git}" \
    "$SCRIPT"
fi
