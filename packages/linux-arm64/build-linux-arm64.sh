#!/usr/bin/env bash

set -euo pipefail

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
rm -rf plugins/trustinspector
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten plugins/trustinspector

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-arm64 -o plugins/sourcekitten/
rm -f plugins/sourcekitten/trivy-cdxgen-*
ls -l plugins/sourcekitten/

bash ../../scripts/thirdparty-downloads.sh install-osquery linux-arm64 plugins/osquery/osqueryi-linux-arm64
upx -9 --lzma plugins/osquery/osqueryi-linux-arm64
sha256sum plugins/osquery/osqueryi-linux-arm64 > plugins/osquery/osqueryi-linux-arm64.sha256

curl -L https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai-linux-arm64 -o plugins/dosai/dosai-linux-arm64
chmod +x plugins/dosai/dosai-linux-arm64
sha256sum plugins/dosai/dosai-linux-arm64 > plugins/dosai/dosai-linux-arm64.sha256

for plug in trivy trustinspector
do
    mkdir -p "plugins/$plug"
    if [ -d "../../plugins/$plug" ] && [ "$(ls -A ../../plugins/$plug/*linux-arm64* 2>/dev/null)" ]; then
        mv ../../plugins/$plug/*linux-arm64* "plugins/$plug/"
        cp ../../plugins/$plug/sbom* "plugins/$plug/"
        for file in "plugins/$plug"/*linux-arm64*; do
            if [[ "$file" != *.sha256 ]]; then
                upx -9 --lzma "$file" || true
                sha256sum "$file" > "${file}.sha256"
            fi
        done
    else
        echo "Warning: No files found for $plug in ../../plugins/$plug/"
    fi
done
node ../../scripts/generate-metadata.js ./plugins
