#!/usr/bin/env bash

set -e

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:darwin-arm64 -o plugins/sourcekitten/

wget https://github.com/osquery/osquery/releases/download/5.21.0/osquery-5.21.0_1.macos_arm64.tar.gz
tar -xf osquery-5.21.0_1.macos_arm64.tar.gz
cp -rf opt/osquery/lib/osquery.app plugins/osquery/osqueryi-darwin-arm64.app
rm -rf etc usr var opt
rm osquery-5.21.0_1.macos_arm64.tar.gz

curl -L https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai-osx-arm64 -o plugins/dosai/dosai-darwin-arm64
chmod +x plugins/dosai/dosai-darwin-arm64
sha256sum plugins/dosai/dosai-darwin-arm64 > plugins/dosai/dosai-darwin-arm64.sha256

for plug in trivy
do
    mkdir -p plugins/$plug
    mv ../../plugins/$plug/*darwin-arm64* plugins/$plug/
done

rm -rf private
