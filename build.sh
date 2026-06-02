#!/usr/bin/env bash
set -e

rm -rf plugins/trivy
rm -rf plugins/osquery
rm -rf plugins/dosai
rm -rf plugins/sourcekitten
rm -rf plugins/trustinspector plugins/golem plugins/rusi
mkdir -p plugins/osquery plugins/dosai plugins/sourcekitten plugins/trustinspector plugins/golem plugins/rusi

for plug in trivy trustinspector golem rusi
do
    mkdir -p plugins/$plug
    pushd thirdparty/$plug
    if [[ "$plug" == "rusi" ]] && find build -maxdepth 1 -type f -name 'rusi-*' ! -name '*.sha256' -print -quit >/dev/null 2>&1; then
        make sbom
    else
        make all
    fi
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

bash ./scripts/check-package-size.sh \
    packages/windows-amd64 \
    packages/linux-amd64 \
    packages/linux-arm64 \
    packages/linuxmusl-amd64 \
    packages/linuxmusl-arm64 \
    packages/linux-riscv64 \
    packages/linux-arm \
    packages/windows-arm64 \
    packages/darwin-arm64 \
    packages/darwin-amd64 \
    packages/ppc64
