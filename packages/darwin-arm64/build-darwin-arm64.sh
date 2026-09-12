#!/usr/bin/env bash

set -euo pipefail

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
rm -rf plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:darwin-arm64 -o plugins/sourcekitten/
# kosi natives ride the oras cache (native-builds.yml builds them on
# kosi PRs and workflow dispatch); the release consumes this cache.
for attempt in 1 2 3 4 5 6; do
  oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:kosi-darwin-arm64 -o plugins/kosi/ && break
  echo "kosi cache tag kosi-darwin-arm64 not ready (attempt $attempt)"; sleep 60
done
oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:kosi-darwin-arm64 -o plugins/kosi/

bash ../../scripts/thirdparty-downloads.sh install-osquery darwin-arm64 plugins/osquery/osqueryi-darwin-arm64.app

bash ../../scripts/thirdparty-downloads.sh install-dosai darwin-arm64 plugins/dosai/dosai-darwin-arm64
sha256sum plugins/dosai/dosai-darwin-arm64 > plugins/dosai/dosai-darwin-arm64.sha256

for plug in trivy trustinspector golem rusi kosi cdxui cdxrs
do
  mkdir -p "plugins/$plug"
  bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "darwin-arm64"
done

rm -rf private
node ../../scripts/generate-metadata.js ./plugins
