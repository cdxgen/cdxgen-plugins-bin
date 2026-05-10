#!/usr/bin/env bash

set -euo pipefail

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
mkdir -p plugins/osquery plugins/dosai

bash ../../scripts/thirdparty-downloads.sh install-osquery windows-amd64 plugins/osquery/osqueryi-windows-amd64.exe
upx -9 --lzma plugins/osquery/osqueryi-windows-amd64.exe
sha256sum plugins/osquery/osqueryi-windows-amd64.exe > plugins/osquery/osqueryi-windows-amd64.exe.sha256

curl -L https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai.exe -o plugins/dosai/dosai-windows-amd64.exe
sha256sum plugins/dosai/dosai-windows-amd64.exe > plugins/dosai/dosai-windows-amd64.exe.sha256

plug="trivy"
mkdir -p "plugins/$plug"
mv ../../plugins/$plug/*windows-amd64* "plugins/$plug/"
cp ../../plugins/$plug/sbom* "plugins/$plug/"
node ../../scripts/generate-metadata.js ./plugins
