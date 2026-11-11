#!/usr/bin/env bash
set -e

pushd .
cd thirdparty/sourcekitten
rm -rf SourceKitten
wget https://github.com/jpsim/SourceKitten/releases/download/0.39.0/SourceKitten-0.39.0.tar.gz
# The tarball builds arbitrary Swift on the host, so its bytes are pinned:
# sha256 of the 0.39.0 release archive, verified before anything extracts.
echo "b586d6f951d9436a3c1445fb0fe12a4d95439c046540e737d79205a498f41d9e  SourceKitten-0.39.0.tar.gz" | shasum -a 256 -c -
tar -xf SourceKitten-0.39.0.tar.gz
rm SourceKitten-0.39.0.tar.gz
mv SourceKitten-0.39.0 SourceKitten
cd SourceKitten
swift build -c release
chmod +x .build/release/sourcekitten
./.build/release/sourcekitten --help
shasum -a 256 .build/release/sourcekitten > .build/release/sourcekitten.sha256 || true
cdxgen -t swift --required-only -o .build/release/sbom-sourcekitten-postbuild.cdx.json
popd
