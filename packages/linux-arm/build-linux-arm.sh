#!/usr/bin/env bash

set -e

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/trustinspector
mkdir -p plugins/osquery plugins/dosai plugins/trustinspector

bash ../../scripts/thirdparty-downloads.sh install-dosai linux-arm plugins/dosai/dosai-linux-arm
sha256sum plugins/dosai/dosai-linux-arm > plugins/dosai/dosai-linux-arm.sha256

for plug in trivy trustinspector
do
    mkdir -p plugins/$plug
    bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "linux-arm" "linux-arm64"
    while IFS= read -r -d '' file; do
        if [[ "$file" != *.sha256 ]]; then
            upx -9 --lzma "$file" || true
            sha256sum "$file" > "${file}.sha256"
        fi
    done < <(find "plugins/$plug" -maxdepth 1 -type f -name '*linux-arm*' ! -name '*linux-arm64*' -print0)
done
node ../../scripts/generate-metadata.js ./plugins
