#!/usr/bin/env bash
set -euo pipefail

# Remove old plugin directories to ensure a clean build. There is no
# sourcekitten on Linux: SourceKitten links the Swift runtime of the
# toolchain that built it, and Linux Swift has no stable ABI, so a prebuilt
# binary only runs next to that exact toolchain (cdxgen-plugins-bin#119).
# cdxgen's container images build it against their own Swift instead.
rm -rf plugins/trivy plugins/osquery plugins/sourcekitten plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/trivy plugins/osquery plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

# kosi natives are staged into ../../plugins/kosi by build.sh, from
# thirdparty/kosi/build - built there (test.yml's kosi_*_prebuild jobs) or
# pulled from the ghcr cache (release.yml). This script no longer races a
# concurrent native-builds run for a cache tag; a missing binary is a loud
# failure here and in check-plugin-coverage.sh, never a quiet omission.
[ -f "../../plugins/kosi/kosi-linux-amd64" ] || {
  echo "kosi-linux-amd64 missing from plugins/kosi; the caller must stage it first" >&2
  exit 1
}

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