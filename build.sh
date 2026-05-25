#!/usr/bin/env bash
set -e

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
rm -rf plugins/trustinspector plugins/golem
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten plugins/trustinspector plugins/golem

for plug in trivy trustinspector golem
do
    mkdir -p plugins/$plug
    pushd thirdparty/$plug
    make all
    chmod +x build/*
    cp -rf build/* ../../plugins/$plug/
    rm -rf build
    popd
done

upx -9 --lzma ./plugins/trivy/trivy-cdxgen-linux-amd64
./plugins/trivy/trivy-cdxgen-linux-amd64 -v

for flavours in windows-amd64 linux-amd64 linux-arm64 linuxmusl-amd64 linuxmusl-arm64 linux-riscv64 linux-arm windows-arm64 darwin-arm64 darwin-amd64 ppc64
do
    chmod +x packages/$flavours/build-$flavours.sh
    pushd packages/$flavours
    ./build-$flavours.sh
    popd
done
