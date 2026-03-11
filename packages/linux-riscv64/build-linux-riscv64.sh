#!/usr/bin/env bash

set -e

rm -rf plugins/trivy

for plug in trivy
do
    mkdir -p plugins/$plug
    if [ -d "../../plugins/$plug" ] && [ "$(ls -A ../../plugins/$plug/*linux-riscv64* 2>/dev/null)" ]; then
        mv ../../plugins/$plug/*linux-riscv64* plugins/$plug/
        cp ../../plugins/$plug/sbom* plugins/$plug/
        for file in "plugins/$plug"/*linux-riscv64*; do
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
