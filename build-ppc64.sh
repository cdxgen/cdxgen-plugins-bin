#!/usr/bin/env bash

rm -rf plugins/trivy
rm -rf plugins/osquery
mkdir -p plugins/osquery

for plug in trivy
do
    mkdir -p plugins/$plug
    pushd thirdparty/$plug
    make build/linux_ppc64le sbom
    chmod +x build/*
    cp -rf build/* ../../plugins/$plug/
    rm -rf build
    popd
done

./plugins/trivy/trivy-cdxgen-linux-ppc64le -v

chmod +x packages/ppc64/build-ppc64.sh
pushd packages/ppc64
./build-ppc64.sh
popd

