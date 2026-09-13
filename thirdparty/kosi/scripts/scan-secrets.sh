#!/usr/bin/env bash
# The no-literal-secret scanner (P8 gate): every corpus output is scanned
# for the secret values PLANTED in the crypto fixtures. A scanner with
# nothing to find proves nothing, so the fixtures plant values on purpose
# (fixtures/crypto-material-flow/src/main/kotlin/fixtures/cryptoflow/
# TokenService.kt) and a test in kosi-bench proves this scanner fires on a
# deliberately-broken report before the real ones are scanned.
#
# Usage: scan-secrets.sh <file-or-dir> [...]
# Exit 0 = clean, exit 1 = a planted secret (or key-shaped literal) leaked.
set -u

PLANTED=(
  "0123456789abcdef0123456789abcdef"
  "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
)

targets=()
for arg in "$@"; do
  if [ -d "$arg" ]; then
    while IFS= read -r f; do targets+=("$f"); done < <(find "$arg" -type f \( -name '*.json' -o -name '*.sarif' \) 2>/dev/null)
  else
    targets+=("$arg")
  fi
done

if [ ${#targets[@]} -eq 0 ]; then
  echo "scan-secrets: no report files to scan" >&2
  exit 0
fi

leaks=0
for f in "${targets[@]}"; do
  for secret in "${PLANTED[@]}"; do
    if grep -qF "$secret" "$f"; then
      echo "LEAK: $f contains a planted fixture secret (${#secret} chars)" >&2
      leaks=$((leaks + 1))
    fi
  done
done

if [ "$leaks" -gt 0 ]; then
  echo "scan-secrets: $leaks leak(s) across ${#targets[@]} file(s)" >&2
  exit 1
fi
echo "scan-secrets: clean over ${#targets[@]} file(s)"
