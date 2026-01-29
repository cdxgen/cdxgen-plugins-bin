#!/usr/bin/env bash

pushd .
cd thirdparty/sourcekitten
rm -rf SourceKitten
wget https://github.com/jpsim/SourceKitten/releases/download/0.37.2/SourceKitten-0.37.2.tar.gz
tar -xf SourceKitten-0.37.2.tar.gz
rm SourceKitten-0.37.2.tar.gz
mv SourceKitten-0.37.2 SourceKitten
cd SourceKitten
swift build -c release
chmod +x .build/release/sourcekitten
./.build/release/sourcekitten --help
shasum -a 256 .build/release/sourcekitten > .build/release/sourcekitten.sha256 || true
popd
