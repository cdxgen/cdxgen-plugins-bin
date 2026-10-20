#!/usr/bin/env bash
# Capture the macOS host trust-store fixtures from THIS Mac (read-only):
#
#   testdata/capture-macos.sh
#
# Writes:
#   testdata/macos-system-keychain.pem        `security find-certificate -a -p /Library/Keychains/System.keychain`
#   testdata/macos-systemroots-keychain.pem   `security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain`
#   testdata/macos-dump-trust-settings.txt    `security dump-trust-settings -d` (admin trust settings)
#
# The PEM output contains public certificates only. The trust-settings dump
# is captured for reference (per-Certificate trust settings are only parsed if
# the format proves stable; see the report).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

security find-certificate -a -p /Library/Keychains/System.keychain \
  > "$HERE/macos-system-keychain.pem"
security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain \
  > "$HERE/macos-systemroots-keychain.pem"
security dump-trust-settings -d > "$HERE/macos-dump-trust-settings.txt" 2>&1 || true

for file in macos-system-keychain.pem macos-systemroots-keychain.pem; do
  count=$(grep -c "BEGIN CERTIFICATE" "$HERE/$file" || true)
  echo "$file: $count certificates"
done
echo "macos-dump-trust-settings.txt: $(wc -l < "$HERE/macos-dump-trust-settings.txt") lines"
