#!/usr/bin/env bash
set -e  # Exit on error

# Remove old plugin directories to ensure a clean build
rm -rf plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

bash ../../scripts/thirdparty-downloads.sh install-dosai linuxmusl-amd64 plugins/dosai/dosai
sha256sum plugins/dosai/dosai > plugins/dosai/dosai.sha256

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-amd64 -o plugins/trivy/
# kosi natives ride the oras cache (native-builds.yml builds them on
# kosi PRs and workflow dispatch); the release consumes this cache.
# Retry while the concurrent native-builds run pushes the cache tag.
for attempt in 1 2 3 4 5 6; do
  oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:kosi-linuxmusl-amd64 -o plugins/kosi/ && break
  echo "kosi cache tag kosi-linuxmusl-amd64 not ready (attempt $attempt)"; sleep 60
done
oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:kosi-linuxmusl-amd64 -o plugins/kosi/
# tolerate nested layer paths from older cache pushes
find plugins/kosi -mindepth 2 -type f -name "kosi-*" -exec mv {} plugins/kosi/ \; 2>/dev/null || true
rm -f plugins/trivy/sourcekitten*
ls -l plugins/trivy/

for plug in trustinspector golem rusi kosi cdxui cdxrs
do
  bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "linuxmusl-amd64"
done
node ../../scripts/generate-metadata.js ./plugins
