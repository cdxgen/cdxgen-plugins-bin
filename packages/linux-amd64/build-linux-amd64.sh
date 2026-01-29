#!/usr/bin/env bash
set -e  # Exit on error

# Remove old plugin directories to ensure a clean build
rm -rf plugins/trivy plugins/osquery plugins/sourcekitten plugins/dosai
mkdir -p plugins/trivy plugins/osquery plugins/sourcekitten plugins/dosai

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-amd64 -o plugins/sourcekitten/
sha256sum plugins/sourcekitten/sourcekitten > plugins/sourcekitten/sourcekitten.sha256
rm -f plugins/sourcekitten/trivy-cdxgen-*
ls -l plugins/sourcekitten/

wget https://github.com/osquery/osquery/releases/download/5.21.0/osquery-5.21.0_1.linux_x86_64.tar.gz
tar -xf osquery-5.21.0_1.linux_x86_64.tar.gz
cp opt/osquery/bin/osqueryd plugins/osquery/osqueryi-linux-amd64
upx -9 --lzma plugins/osquery/osqueryi-linux-amd64
./plugins/osquery/osqueryi-linux-amd64 --help
sha256sum plugins/osquery/osqueryi-linux-amd64 > plugins/osquery/osqueryi-linux-amd64.sha256
rm -rf etc usr var opt
rm osquery-5.21.0_1.linux_x86_64.tar.gz

# Download the Dosai binary
curl -L https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai-linux-amd64 -o plugins/dosai/dosai-linux-amd64
chmod +x plugins/dosai/dosai-linux-amd64
sha256sum plugins/dosai/dosai-linux-amd64 > plugins/dosai/dosai-linux-amd64.sha256

for plug in trivy; do
    mkdir -p plugins/$plug
    if [ -d "../../plugins/$plug" ] && [ "$(ls -A ../../plugins/$plug/*linux-amd64* 2>/dev/null)" ]; then
        mv ../../plugins/$plug/*linux-amd64* plugins/$plug/
        upx -9 --lzma plugins/$plug/*linux-amd64* || true
    else
        echo "Warning: No files found for $plug in ../../plugins/$plug/"
    fi
done
