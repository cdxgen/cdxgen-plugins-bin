#!/usr/bin/env bash

set -euo pipefail

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/trustinspector plugins/golem plugins/rusi
mkdir -p plugins/osquery plugins/dosai plugins/trustinspector plugins/golem plugins/rusi

bash ../../scripts/thirdparty-downloads.sh install-osquery windows-arm64 plugins/osquery/osqueryi-windows-arm64.exe
sha256sum plugins/osquery/osqueryi-windows-arm64.exe > plugins/osquery/osqueryi-windows-arm64.exe.sha256

bash ../../scripts/thirdparty-downloads.sh install-dosai windows-arm64 plugins/dosai/dosai-windows-arm64.exe
sha256sum plugins/dosai/dosai-windows-arm64.exe > plugins/dosai/dosai-windows-arm64.exe.sha256

for plug in trivy trustinspector golem rusi
do
  mkdir -p "plugins/$plug"
  bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "windows-arm64"
done
node ../../scripts/generate-metadata.js ./plugins
