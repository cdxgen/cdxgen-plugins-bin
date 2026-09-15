#!/usr/bin/env bash

set -euo pipefail

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
rm -rf plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-arm64 -o plugins/sourcekitten/
# kosi natives are staged into ../../plugins/kosi by build.sh, from
# thirdparty/kosi/build - built there (test.yml's kosi_*_prebuild jobs) or
# pulled from the ghcr cache (release.yml). This script no longer races a
# concurrent native-builds run for a cache tag; a missing binary is a loud
# failure here and in check-plugin-coverage.sh, never a quiet omission.
[ -f "../../plugins/kosi/kosi-linux-arm64" ] || {
  echo "kosi-linux-arm64 missing from plugins/kosi; the caller must stage it first" >&2
  exit 1
}
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
