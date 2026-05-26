#!/usr/bin/env bash
set -e  # Exit on error

# Remove old plugin directories to ensure a clean build
rm -rf plugins/trivy plugins/dosai plugins/trustinspector plugins/golem
mkdir -p plugins/trivy plugins/dosai plugins/trustinspector plugins/golem

bash ../../scripts/thirdparty-downloads.sh install-dosai linuxmusl-arm64 plugins/dosai/dosai
sha256sum plugins/dosai/dosai > plugins/dosai/dosai.sha256

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-arm64 -o plugins/trivy/
rm -f plugins/trivy/sourcekitten*
ls -l plugins/trivy/

bash ../../scripts/stage-built-plugins.sh ../../plugins/trustinspector plugins/trustinspector linux-arm64
bash ../../scripts/stage-built-plugins.sh ../../plugins/golem plugins/golem linux-arm64
node ../../scripts/generate-metadata.js ./plugins
