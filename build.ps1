New-Item -ItemType Directory -Path plugins\osquery -Force
New-Item -ItemType Directory -Path plugins\dosai -Force
New-Item -ItemType Directory -Path plugins\trivy -Force
New-Item -ItemType Directory -Path plugins\trustinspector -Force
New-Item -ItemType Directory -Path plugins\golem -Force

$upxVersion = "5.2.0"
$upxArchive = "upx-$upxVersion-win64.zip"
$upxArchiveSha256 = "b471ebf1b7f20f4a89150264ed9a008a2a5bfd247f3c6d1184a75bb59ca08f5d"
$osqueryVersion = "5.23.1"
$osqueryArchive = "osquery-$osqueryVersion.windows_x86_64.zip"
$osqueryArchiveSha256 = "7bd411050ef6b5aae1b23956aec0dc5ce6e800c5656f0cd463ac70a6e1bdf30b"
$dosaiVersion = "4.0.0"
$dosaiArchive = "Dosai.exe"
$dosaiArchiveSha256 = "8d4ed9585068cf2df6975e75fa981c39ea35a597e6b79572137dfa0dab28d31d"
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
go build -trimpath -buildvcs=false -ldflags "-s -w -extldflags=-Wl,-z,now,-z,relro" -o build\trivy-windows-amd64.exe
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
