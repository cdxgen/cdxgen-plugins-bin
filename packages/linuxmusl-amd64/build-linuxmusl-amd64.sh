#!/usr/bin/env bash
set -e  # Exit on error

# Remove old plugin directories to ensure a clean build
rm -rf plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi
mkdir -p plugins/trivy plugins/dosai plugins/trustinspector plugins/golem plugins/rusi plugins/cdxui plugins/cdxrs plugins/kosi

bash ../../scripts/thirdparty-downloads.sh install-dosai linuxmusl-amd64 plugins/dosai/dosai
sha256sum plugins/dosai/dosai > plugins/dosai/dosai.sha256

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-amd64 -o plugins/trivy/
# kosi natives are staged into ../../plugins/kosi by build.sh, from
# thirdparty/kosi/build - built there (test.yml's kosi_*_prebuild jobs) or
# pulled from the ghcr cache (release.yml). This script no longer races a
# concurrent native-builds run for a cache tag; a missing binary is a loud
# failure here and in check-plugin-coverage.sh, never a quiet omission.
[ -f "../../plugins/kosi/kosi-linuxmusl-amd64" ] || {
  echo "kosi-linuxmusl-amd64 missing from plugins/kosi; the caller must stage it first" >&2
  exit 1
}
rm -f plugins/trivy/sourcekitten*
ls -l plugins/trivy/

for plug in trustinspector golem rusi kosi cdxui cdxrs
do
  bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "linuxmusl-amd64"
done
node ../../scripts/generate-metadata.js ./plugins
