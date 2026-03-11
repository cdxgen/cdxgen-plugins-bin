#!/usr/bin/env bash

set -e

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
mkdir -p plugins/osquery plugins/dosai

curl -L https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai-linux-arm -o plugins/dosai/dosai-linux-arm
chmod +x plugins/dosai/dosai-linux-arm
sha256sum plugins/dosai/dosai-linux-arm > plugins/dosai/dosai-linux-arm.sha256

for plug in trivy
do
    mkdir -p plugins/$plug
    if [ -d "../../plugins/$plug" ] && [ "$(ls -A ../../plugins/$plug/*linux-arm* 2>/dev/null)" ]; then
          mv ../../plugins/$plug/*linux-arm* plugins/$plug/
          cp ../../plugins/$plug/sbom* plugins/$plug/
          for file in "plugins/$plug"/*linux-arm*; do
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
