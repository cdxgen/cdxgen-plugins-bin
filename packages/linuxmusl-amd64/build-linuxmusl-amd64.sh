#!/usr/bin/env bash
set -e  # Exit on error

# Remove old plugin directories to ensure a clean build
rm -rf plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

bash ../../scripts/thirdparty-downloads.sh install-dosai linuxmusl-amd64 plugins/dosai/dosai
sha256sum plugins/dosai/dosai > plugins/dosai/dosai.sha256

# trivy stages from ../../plugins/trivy like every other plugin: the trivy
# Makefile's `all` builds the linuxmusl flavours (CGO_ENABLED=0, static), so
# the package carries a real musl binary instead of the glibc linux-amd64
# artifact an older draft pulled from the ghcr image here. A missing binary
# is a loud staging failure, never a quiet swap.
# kosi natives are staged into ../../plugins/kosi by build.sh, from
# thirdparty/kosi/build - built there (test.yml's kosi_*_prebuild jobs) or
# pulled from the ghcr cache (release.yml). This script no longer races a
# concurrent native-builds run for a cache tag; a missing binary is a loud
# failure here and in check-plugin-coverage.sh, never a quiet omission.
[ -f "../../plugins/kosi/kosi-linuxmusl-amd64" ] || {
  echo "kosi-linuxmusl-amd64 missing from plugins/kosi; the caller must stage it first" >&2
  exit 1
}

for plug in trivy trustinspector golem rusi kosi cdxui cdxrs
do
  mkdir -p "plugins/$plug"
  bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "linuxmusl-amd64"
  # Compress like every other flavour's package loop; `|| true` keeps the
  # package build alive where upx declines a binary it cannot shrink.
  while IFS= read -r -d '' file; do
    if [[ "$file" != *.sha256 ]]; then
      upx -9 --lzma "$file" || true
      sha256sum "$file" > "${file}.sha256"
    fi
  done < <(find "plugins/$plug" -maxdepth 1 -type f -name '*linuxmusl-amd64*' -print0)
done
node ../../scripts/generate-metadata.js ./plugins
