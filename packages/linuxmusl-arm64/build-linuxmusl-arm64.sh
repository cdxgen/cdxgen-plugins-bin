#!/usr/bin/env bash
set -e  # Exit on error

# Remove old plugin directories to ensure a clean build
rm -rf plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

bash ../../scripts/thirdparty-downloads.sh install-dosai linuxmusl-arm64 plugins/dosai/dosai
sha256sum plugins/dosai/dosai > plugins/dosai/dosai.sha256

# No kosi native here: GraalVM does not support musl static images on
# linux-aarch64, a declared exemption in scripts/plugin-platform-support.sh;
# these consumers get the kosi-portable.jar fallback.
# trivy stages from ../../plugins/trivy like every other plugin: the trivy
# Makefile's `all` builds the linuxmusl flavours (CGO_ENABLED=0, static), so
# the package carries a real musl binary instead of the glibc linux-arm64
# artifact an older draft pulled from the ghcr image here. A missing binary
# is a loud staging failure, never a quiet swap.
for plug in trivy trustinspector golem rusi kosi cdxui cdxrs
do
  mkdir -p "plugins/$plug"
  bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "linuxmusl-arm64"
  # Compress like every other flavour's package loop; `|| true` keeps the
  # package build alive where upx declines a binary it cannot shrink.
  while IFS= read -r -d '' file; do
    if [[ "$file" != *.sha256 ]]; then
      upx -9 --lzma "$file" || true
      sha256sum "$file" > "${file}.sha256"
    fi
  done < <(find "plugins/$plug" -maxdepth 1 -type f -name '*linuxmusl-arm64*' -print0)
done
node ../../scripts/generate-metadata.js ./plugins
