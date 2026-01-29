#!/usr/bin/env bash

set -e

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
mkdir -p plugins/osquery plugins/dosai

wget https://github.com/osquery/osquery/releases/download/5.21.0/osquery-5.21.0.windows_x86_64.zip
unzip osquery-5.21.0.windows_x86_64.zip
cp "osquery-5.21.0.windows_x86_64/Program Files/osquery/osqueryi.exe" plugins/osquery/osqueryi-windows-amd64.exe
upx -9 --lzma plugins/osquery/osqueryi-windows-amd64.exe
sha256sum plugins/osquery/osqueryi-windows-amd64.exe > plugins/osquery/osqueryi-windows-amd64.exe.sha256
rm -rf osquery-5.21.0.windows_x86_64
rm osquery-5.21.0.windows_x86_64.zip

curl -L https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai.exe -o plugins/dosai/dosai-windows-amd64.exe
sha256sum plugins/dosai/dosai-windows-amd64.exe > plugins/dosai/dosai-windows-amd64.exe.sha256

for plug in trivy
do
    mkdir -p plugins/$plug
    mv ../../plugins/$plug/*windows-amd64* plugins/$plug/
done
