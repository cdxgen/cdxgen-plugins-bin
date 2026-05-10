#!/usr/bin/env bash

set -e

rm -rf plugins/trivy
rm -rf plugins/trustinspector

for plug in trivy trustinspector
do
    mkdir -p plugins/$plug
    bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "ppc64"
    while IFS= read -r -d '' file; do
        if [[ "$file" != *.sha256 ]]; then
            upx -9 --lzma "$file" || true
            sha256sum "$file" > "${file}.sha256"
        fi
    done < <(find "plugins/$plug" -maxdepth 1 -type f -name '*ppc64*' -print0)
done
node ../../scripts/generate-metadata.js ./plugins
