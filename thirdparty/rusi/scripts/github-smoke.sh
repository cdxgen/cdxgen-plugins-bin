#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUSI_BIN="${RUSI_BIN:-$ROOT_DIR/target/debug/rusi}"
WORK_DIR="${RUSI_GITHUB_SMOKE_DIR:-$(mktemp -d)}"
KEEP_WORK_DIR="${RUSI_GITHUB_KEEP_DIR:-0}"
REPOS=(
  "https://github.com/rust-random/getrandom.git"
  "https://github.com/tokio-rs/mini-redis.git"
)

if [[ -n "${RUSI_GITHUB_REPOS:-}" ]]; then
  IFS=' ' read -r -a REPOS <<<"${RUSI_GITHUB_REPOS}"
fi

cleanup() {
  if [[ "$KEEP_WORK_DIR" != "1" ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

mkdir -p "$WORK_DIR"

if [[ ! -x "$RUSI_BIN" ]]; then
  cargo +nightly build -p rusi-cli --manifest-path "$ROOT_DIR/Cargo.toml"
fi

printf 'Running GitHub smoke analyses in %s\n' "$WORK_DIR"
for repo in "${REPOS[@]}"; do
  name="$(basename "$repo" .git)"
  target_dir="$WORK_DIR/$name"
  rm -rf "$target_dir"
  git clone --depth 1 "$repo" "$target_dir" >/dev/null 2>&1
  report_path="$target_dir/rusi-github-smoke.json"
  printf 'Analyzing %s\n' "$repo"
  "$RUSI_BIN" analyze \
    --dir "$target_dir" \
    --backend compiler \
    --callgraph static \
    --dataflow security \
    > "$report_path"
  python3 - <<'PY' "$report_path" "$repo"
import json,sys
report_path, repo = sys.argv[1], sys.argv[2]
with open(report_path) as fh:
    report = json.load(fh)
call_graph_edges = len((report.get("call_graph") or {}).get("edges", []))
data_flow_slices = len((report.get("data_flow") or {}).get("slices", []))
crypto_components = len((report.get("crypto") or {}).get("components", []))
print(f"  report ok for {repo}: edges={call_graph_edges} slices={data_flow_slices} crypto={crypto_components}")
PY
done
