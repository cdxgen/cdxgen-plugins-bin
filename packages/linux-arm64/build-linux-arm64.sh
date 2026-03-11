#!/usr/bin/env bash

set -e

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-arm64 -o plugins/sourcekitten/
rm -f plugins/sourcekitten/trivy-cdxgen-*
ls -l plugins/sourcekitten/

wget https://github.com/osquery/osquery/releases/download/5.22.1/osquery-5.22.1_1.linux_aarch64.tar.gz
tar -xf osquery-5.22.1_1.linux_aarch64.tar.gz
cp opt/osquery/bin/osqueryd plugins/osquery/osqueryi-linux-arm64
upx -9 --lzma plugins/osquery/osqueryi-linux-arm64
sha256sum plugins/osquery/osqueryi-linux-arm64 > plugins/osquery/osqueryi-linux-arm64.sha256
rm -rf etc usr var opt
rm osquery-5.22.1_1.linux_aarch64.tar.gz

curl -L https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai-linux-arm64 -o plugins/dosai/dosai-linux-arm64
chmod +x plugins/dosai/dosai-linux-arm64
sha256sum plugins/dosai/dosai-linux-arm64 > plugins/dosai/dosai-linux-arm64.sha256

for plug in trivy
do
    mkdir -p plugins/$plug
    if [ -d "../../plugins/$plug" ] && [ "$(ls -A ../../plugins/$plug/*linux-arm64* 2>/dev/null)" ]; then
        mv ../../plugins/$plug/*linux-arm64* plugins/$plug/
        cp ../../plugins/$plug/sbom* plugins/$plug/
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
