#!/usr/bin/env bash
set -e  # Exit on error

# Remove old plugin directories to ensure a clean build
rm -rf plugins/trivy plugins/dosai
mkdir -p plugins/trivy plugins/dosai

# Download the Dosai binary
curl -L https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai-linux-musl-x64 -o plugins/dosai/dosai
chmod +x plugins/dosai/dosai
sha256sum plugins/dosai/dosai > plugins/dosai/dosai.sha256

oras pull ghcr.io/cdxgen/cdxgen-plugins-bin:linux-amd64 -o plugins/trivy/
rm -f plugins/trivy/sourcekitten*
ls -l plugins/trivy/
node ../../scripts/generate-metadata.js ./plugins
