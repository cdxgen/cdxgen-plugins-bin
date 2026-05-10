#!/usr/bin/env bash

set -euo pipefail

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:darwin-arm64 -o plugins/sourcekitten/

bash ../../scripts/thirdparty-downloads.sh install-osquery darwin-arm64 plugins/osquery/osqueryi-darwin-arm64.app

curl -L https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai-osx-arm64 -o plugins/dosai/dosai-darwin-arm64
chmod +x plugins/dosai/dosai-darwin-arm64
sha256sum plugins/dosai/dosai-darwin-arm64 > plugins/dosai/dosai-darwin-arm64.sha256

plug="trivy"
mkdir -p "plugins/$plug"
mv ../../plugins/$plug/*darwin-arm64* "plugins/$plug/"
cp ../../plugins/$plug/sbom* "plugins/$plug/"

rm -rf private
node ../../scripts/generate-metadata.js ./plugins
