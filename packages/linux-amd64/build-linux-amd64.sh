#!/usr/bin/env bash
set -euo pipefail

# Remove old plugin directories to ensure a clean build
rm -rf plugins/trivy plugins/osquery plugins/sourcekitten plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxrs
mkdir -p plugins/trivy plugins/osquery plugins/sourcekitten plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxrs

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-amd64 -o plugins/sourcekitten/
# kosi natives are staged into ../../plugins/kosi by build.sh, from
# thirdparty/kosi/build - built there (test.yml's kosi_*_prebuild jobs) or
# pulled from the ghcr cache (release.yml). This script no longer races a
# concurrent native-builds run for a cache tag; a missing binary is a loud
# failure here and in check-plugin-coverage.sh, never a quiet omission.
[ -f "../../plugins/kosi/kosi-linux-amd64" ] || {
  echo "kosi-linux-amd64 missing from plugins/kosi; the caller must stage it first" >&2
  exit 1
}
sha256sum plugins/sourcekitten/sourcekitten > plugins/sourcekitten/sourcekitten.sha256
rm -f plugins/sourcekitten/trivy-cdxgen-*
ls -l plugins/sourcekitten/

bash ../../scripts/thirdparty-downloads.sh install-osquery linux-amd64 plugins/osquery/osqueryi-linux-amd64
upx -9 --lzma plugins/osquery/osqueryi-linux-amd64
./plugins/osquery/osqueryi-linux-amd64 --help
sha256sum plugins/osquery/osqueryi-linux-amd64 > plugins/osquery/osqueryi-linux-amd64.sha256

bash ../../scripts/thirdparty-downloads.sh install-dosai linux-amd64 plugins/dosai/dosai-linux-amd64
sha256sum plugins/dosai/dosai-linux-amd64 > plugins/dosai/dosai-linux-amd64.sha256

for plug in trivy trustinspector golem rusi kosi cdxui cdxrs
do
    mkdir -p "plugins/$plug"
    bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "linux-amd64"
    while IFS= read -r -d '' file; do
        if [[ "$file" != *.sha256 ]]; then
            upx -9 --lzma "$file" || true
            sha256sum "$file" > "${file}.sha256"
        fi
    done < <(find "plugins/$plug" -maxdepth 1 -type f -name '*linux-amd64*' -print0)
done

node ../../scripts/generate-metadata.js ./plugins