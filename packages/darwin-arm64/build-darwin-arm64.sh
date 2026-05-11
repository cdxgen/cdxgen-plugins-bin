#!/usr/bin/env bash

set -euo pipefail

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
rm -rf plugins/trustinspector
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten plugins/trustinspector

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:darwin-arm64 -o plugins/sourcekitten/

bash ../../scripts/thirdparty-downloads.sh install-osquery darwin-arm64 plugins/osquery/osqueryi-darwin-arm64.app

bash ../../scripts/thirdparty-downloads.sh install-dosai darwin-arm64 plugins/dosai/dosai-darwin-arm64
sha256sum plugins/dosai/dosai-darwin-arm64 > plugins/dosai/dosai-darwin-arm64.sha256

for plug in trivy trustinspector
do
  mkdir -p "plugins/$plug"
  bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "darwin-arm64"
done

rm -rf private
node ../../scripts/generate-metadata.js ./plugins
