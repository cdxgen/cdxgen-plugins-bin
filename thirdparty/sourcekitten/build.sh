#!/usr/bin/env bash
set -e

pushd .
cd thirdparty/sourcekitten
rm -rf SourceKitten
wget https://github.com/jpsim/SourceKitten/releases/download/0.38.0/SourceKitten-0.38.0.tar.gz
# The tarball builds arbitrary Swift on the host, so its bytes are pinned:
# sha256 of the 0.38.0 release archive, verified before anything extracts.
echo "7eaf0b7acaa2ae4bebf49c686641f9e50b0044c1a91d3c75121ecf698d7fbb91  SourceKitten-0.38.0.tar.gz" | shasum -a 256 -c -
tar -xf SourceKitten-0.38.0.tar.gz
rm SourceKitten-0.38.0.tar.gz
mv SourceKitten-0.38.0 SourceKitten
cd SourceKitten
swift build -c release
chmod +x .build/release/sourcekitten
./.build/release/sourcekitten --help
shasum -a 256 .build/release/sourcekitten > .build/release/sourcekitten.sha256 || true
cdxgen -t swift -o .build/release/sbom-sourcekitten-postbuild.cdx.json
popd
