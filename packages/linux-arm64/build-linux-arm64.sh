#!/usr/bin/env bash

set -euo pipefail

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
rm -rf plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-arm64 -o plugins/sourcekitten/
# kosi natives ride the oras cache (native-builds.yml builds them on
# kosi PRs and workflow dispatch); the release consumes this cache.
# Retry while the concurrent native-builds run pushes the cache tag.
for attempt in 1 2 3 4 5 6; do
  oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:kosi-linux-arm64 -o plugins/kosi/ && break
  echo "kosi cache tag kosi-linux-arm64 not ready (attempt $attempt)"; sleep 60
done
oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:kosi-linux-arm64 -o plugins/kosi/
rm -f plugins/sourcekitten/trivy-cdxgen-*
ls -l plugins/sourcekitten/

bash ../../scripts/thirdparty-downloads.sh install-osquery linux-arm64 plugins/osquery/osqueryi-linux-arm64
upx -9 --lzma plugins/osquery/osqueryi-linux-arm64
sha256sum plugins/osquery/osqueryi-linux-arm64 > plugins/osquery/osqueryi-linux-arm64.sha256

bash ../../scripts/thirdparty-downloads.sh install-dosai linux-arm64 plugins/dosai/dosai-linux-arm64
sha256sum plugins/dosai/dosai-linux-arm64 > plugins/dosai/dosai-linux-arm64.sha256

for plug in trivy trustinspector golem rusi kosi cdxui cdxrs
do
    mkdir -p "plugins/$plug"
    bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "linux-arm64"
    while IFS= read -r -d '' file; do
        if [[ "$file" != *.sha256 ]]; then
            upx -9 --lzma "$file" || true
            sha256sum "$file" > "${file}.sha256"
        fi
    done < <(find "plugins/$plug" -maxdepth 1 -type f -name '*linux-arm64*' -print0)
done
node ../../scripts/generate-metadata.js ./plugins
