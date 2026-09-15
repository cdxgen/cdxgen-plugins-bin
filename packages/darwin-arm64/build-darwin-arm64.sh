#!/usr/bin/env bash

set -euo pipefail

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
rm -rf plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:darwin-arm64 -o plugins/sourcekitten/
# kosi natives are staged into ../../plugins/kosi by build.sh, from
# thirdparty/kosi/build - built there (test.yml's kosi_*_prebuild jobs) or
# pulled from the ghcr cache (release.yml). This script no longer races a
# concurrent native-builds run for a cache tag; a missing binary is a loud
# failure here and in check-plugin-coverage.sh, never a quiet omission.
[ -f "../../plugins/kosi/kosi-darwin-arm64" ] || {
  echo "kosi-darwin-arm64 missing from plugins/kosi; the caller must stage it first" >&2
  exit 1
}

bash ../../scripts/thirdparty-downloads.sh install-osquery darwin-arm64 plugins/osquery/osqueryi-darwin-arm64.app

bash ../../scripts/thirdparty-downloads.sh install-dosai darwin-arm64 plugins/dosai/dosai-darwin-arm64
sha256sum plugins/dosai/dosai-darwin-arm64 > plugins/dosai/dosai-darwin-arm64.sha256

for plug in trivy trustinspector golem rusi kosi cdxui cdxrs
do
  mkdir -p "plugins/$plug"
  bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "darwin-arm64"
done

rm -rf private
node ../../scripts/generate-metadata.js ./plugins
