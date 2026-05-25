#!/usr/bin/env bash

set -e

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
rm -rf plugins/trustinspector plugins/golem
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten plugins/trustinspector plugins/golem

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:darwin-amd64 -o plugins/sourcekitten/

bash ../../scripts/thirdparty-downloads.sh install-dosai darwin-amd64 plugins/dosai/dosai-darwin-amd64
sha256sum plugins/dosai/dosai-darwin-amd64 > plugins/dosai/dosai-darwin-amd64.sha256

for plug in trivy trustinspector golem
do
    mkdir -p plugins/$plug
    bash ../../scripts/stage-built-plugins.sh "../../plugins/$plug" "plugins/$plug" "darwin-amd64"
done

node ../../scripts/generate-metadata.js ./plugins
