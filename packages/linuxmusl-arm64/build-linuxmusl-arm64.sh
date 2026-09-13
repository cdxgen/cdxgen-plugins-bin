#!/usr/bin/env bash
set -e  # Exit on error

# Remove old plugin directories to ensure a clean build
rm -rf plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

bash ../../scripts/thirdparty-downloads.sh install-dosai linuxmusl-arm64 plugins/dosai/dosai
sha256sum plugins/dosai/dosai > plugins/dosai/dosai.sha256

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-arm64 -o plugins/trivy/
# kosi natives ride the oras cache (native-builds.yml builds them on
# kosi PRs and workflow dispatch); the release consumes this cache.
rm -f plugins/trivy/sourcekitten*
ls -l plugins/trivy/

for plug in trustinspector golem rusi kosi cdxui cdxrs
do
  bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "linuxmusl-arm64"
done
node ../../scripts/generate-metadata.js ./plugins
