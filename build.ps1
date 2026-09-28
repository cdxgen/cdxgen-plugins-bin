New-Item -ItemType Directory -Path plugins\osquery -Force
New-Item -ItemType Directory -Path plugins\dosai -Force
New-Item -ItemType Directory -Path plugins\trivy -Force
New-Item -ItemType Directory -Path plugins\trustinspector -Force
New-Item -ItemType Directory -Path plugins\golem -Force

$upxVersion = "5.2.1"
$upxArchive = "upx-$upxVersion-win64.zip"
$upxArchiveSha256 = "eabc6792a347d45e945be7748423e7868fd01b0d2bcaa2f4b1031fd71ff69bda"
$osqueryVersion = "5.23.1"
$osqueryArchive = "osquery-$osqueryVersion.windows_x86_64.zip"
$osqueryArchiveSha256 = "7bd411050ef6b5aae1b23956aec0dc5ce6e800c5656f0cd463ac70a6e1bdf30b"
$dosaiVersion = "4.1.0"
$dosaiArchive = "Dosai.exe"
$dosaiArchiveSha256 = "c804961ed46675a43718553bee5cbf1b74dbe90c318658b6df75f6aedc6aa36c"
# The version the Go tools stamp via -X main.version; the Makefiles read the
# same file, so a Windows binary and a Make-built binary of one commit always
# agree.
$pluginVersion = (Get-Content package.json -Raw | ConvertFrom-Json).version

function Assert-Sha256 {
  param(
	[Parameter(Mandatory = $true)][string]$Path,
	[Parameter(Mandatory = $true)][string]$ExpectedHash
  )

  $actualHash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualHash -ne $ExpectedHash.ToLowerInvariant()) {
	Remove-Item $Path -Force -ErrorAction SilentlyContinue
	throw "SHA-256 mismatch for $Path. Expected $ExpectedHash but got $actualHash"
  }
}

Invoke-WebRequest -Uri "https://github.com/upx/upx/releases/download/v$upxVersion/$upxArchive" -UseBasicParsing -OutFile $upxArchive
Assert-Sha256 -Path $upxArchive -ExpectedHash $upxArchiveSha256
Expand-Archive -Path $upxArchive -DestinationPath . -Force

Invoke-WebRequest -Uri "https://github.com/osquery/osquery/releases/download/$osqueryVersion/$osqueryArchive" -UseBasicParsing -OutFile $osqueryArchive
Assert-Sha256 -Path $osqueryArchive -ExpectedHash $osqueryArchiveSha256
Expand-Archive -Path $osqueryArchive -DestinationPath . -Force
copy "osquery-$osqueryVersion.windows_x86_64\Program Files\osquery\osqueryi.exe" plugins\osquery\osqueryi-windows-amd64.exe
& ".\upx-$upxVersion-win64\upx.exe" -9 --lzma plugins\osquery\osqueryi-windows-amd64.exe
plugins\osquery\osqueryi-windows-amd64.exe --help

Invoke-WebRequest -Uri "https://github.com/owasp-dep-scan/dosai/releases/download/v$dosaiVersion/$dosaiArchive" -UseBasicParsing -OutFile plugins/dosai/dosai-windows-amd64.exe
Assert-Sha256 -Path plugins/dosai/dosai-windows-amd64.exe -ExpectedHash $dosaiArchiveSha256

cd thirdparty\trivy
# Mirror the Makefile's GOPIN: trivy v0.74.0 targets encoding/json/v2 as Go
# 1.26 exposed it under GOEXPERIMENT=jsonv2. Go 1.27 stabilised the package
# with a changed API (json.SkipFunc is gone), so pin the toolchain here too.
$env:GOTOOLCHAIN = "go1.26.8"
$env:GOEXPERIMENT = "jsonv2"
$env:CGO_ENABLED = "0"
# Mirror the Makefile's slim build: vendor the dependencies, apply
# overlay/patches to the vendored Trivy and build through the overlay. A patch
# that no longer applies must stop the build, not fall back to a full one.
go mod vendor
if ($LASTEXITCODE -ne 0) { throw "go mod vendor failed for trivy-cdxgen" }
go run ./overlay
if ($LASTEXITCODE -ne 0) { throw "overlay/patches no longer apply to the vendored Trivy" }
# Mirror the Makefile's trivy_version: the Trivy release from go.mod, with a
# -cdx suffix because this is the patched wrapper, not Trivy itself.
$trivyRequire = Select-String -Path go.mod -Pattern '^\s*github\.com/aquasecurity/trivy v(\S+)' | Select-Object -First 1
if (-not $trivyRequire) { throw "go.mod does not require github.com/aquasecurity/trivy" }
$trivyVersion = $trivyRequire.Matches[0].Groups[1].Value + "-cdx"
# Quoted: PowerShell splits an unquoted native argument at "=." and would
# pass ".overlay/overlay.json" to go as a package path.
go build -mod=vendor "-overlay=.overlay/overlay.json" -trimpath -buildvcs=false -ldflags "-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=$trivyVersion -extldflags=-Wl,-z,now,-z,relro" -o build\trivy-windows-amd64.exe
if ($LASTEXITCODE -ne 0) { throw "go build failed for trivy-cdxgen" }
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma build\trivy-windows-amd64.exe
copy build\* ..\..\plugins\trivy\
Remove-Item build -Recurse -Force
cd ..\..

# golem and trustinspector require Go 1.27; drop the trivy-only pins.
Remove-Item Env:GOTOOLCHAIN -ErrorAction SilentlyContinue
Remove-Item Env:GOEXPERIMENT -ErrorAction SilentlyContinue


cd thirdparty\golem
$env:CGO_ENABLED = "0"
go test ./...
go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$pluginVersion -extldflags=-Wl,-z,now,-z,relro" -o build\golem-windows-amd64.exe .\cmd\golem
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma build\golem-windows-amd64.exe
copy build\* ..\..\plugins\golem\
Remove-Item build -Recurse -Force
cd ..\..

cd thirdparty\trustinspector
$env:CGO_ENABLED = "0"
go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$pluginVersion -extldflags=-Wl,-z,now,-z,relro" -o build\trustinspector-cdxgen-windows-amd64.exe
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma build\trustinspector-cdxgen-windows-amd64.exe
copy build\* ..\..\plugins\trustinspector\
Remove-Item build -Recurse -Force
cd ..\..

New-Item -ItemType Directory -Path plugins\rusi -Force
cd thirdparty\rusi
cargo build -p rusi-cli --release --locked
copy target\release\rusi.exe ..\..\plugins\rusi\rusi-windows-amd64.exe
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma ..\..\plugins\rusi\rusi-windows-amd64.exe
cd ..\..

New-Item -ItemType Directory -Path plugins\cdxui -Force
cd thirdparty\cdxui
cargo build --release --locked
copy target\release\cdxui.exe ..\..\plugins\cdxui\cdxui-windows-amd64.exe
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma ..\..\plugins\cdxui\cdxui-windows-amd64.exe
cd ..\..

# kosi is NOT built here on purpose: Windows is a declared kosi exemption
# (scripts/plugin-platform-support.sh) until a Windows runner job wires the
# MSVC-toolchain native-image build; the kosi-portable.jar fallback covers
# Windows consumers in the meantime.
New-Item -ItemType Directory -Path plugins\cdxrs -Force
cd thirdparty\cdxrs
cargo build --release --locked
copy target\release\cdxrs.exe ..\..\plugins\cdxrs\cdxrs-windows-amd64.exe
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma ..\..\plugins\cdxrs\cdxrs-windows-amd64.exe
cd ..\..

node .\scripts\generate-metadata.js .\plugins

Remove-Item "osquery-$osqueryVersion.windows_x86_64" -Recurse -Force
Remove-Item $osqueryArchive -Recurse -Force
Remove-Item "upx-$upxVersion-win64" -Recurse -Force
Remove-Item $upxArchive -Recurse -Force
