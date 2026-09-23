#!/usr/bin/env bash

rm -rf plugins/trivy
rm -rf plugins/osquery plugins/rusi
mkdir -p plugins/osquery plugins/rusi

for plug in trivy rusi
do
    mkdir -p plugins/$plug
    pushd thirdparty/$plug
    if [[ "$plug" == "rusi" ]]; then
        if find build -maxdepth 1 -type f -name 'rusi-linux-ppc64le' ! -name '*.sha256' -print -quit >/dev/null 2>&1; then
            make sbom
        else
            make build/rusi-linux-ppc64le sbom
        fi
    else
        make build/linux_ppc64le sbom
    fi
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

