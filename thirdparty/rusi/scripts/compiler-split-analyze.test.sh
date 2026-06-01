#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/compiler-split-analyze.py"

python3 -m py_compile "$SCRIPT"
"$SCRIPT" --help >/dev/null
