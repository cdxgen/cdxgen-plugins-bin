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
$dosaiVersion = "3.0.5"
$dosaiArchive = "Dosai.exe"
$dosaiArchiveSha256 = "34fbbe401a6d62d127516ff1c1e145923a494698e788c0f0c2088e22a391aabc"

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
$env:GOEXPERIMENT = "jsonv2"
$env:CGO_ENABLED = "0"
go build -ldflags "-s -w" -o build\trivy-windows-amd64.exe
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma build\trivy-windows-amd64.exe
copy build\* ..\..\plugins\trivy\
Remove-Item build -Recurse -Force
cd ..\..


cd thirdparty\golem
$env:CGO_ENABLED = "0"
go test ./...
go build -trimpath -ldflags "-s -w" -o build\golem-windows-amd64.exe .\cmd\golem
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma build\golem-windows-amd64.exe
copy build\* ..\..\plugins\golem\
Remove-Item build -Recurse -Force
cd ..\..

cd thirdparty\trustinspector
$env:CGO_ENABLED = "0"
go build -ldflags "-s -w" -o build\trustinspector-cdxgen-windows-amd64.exe
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma build\trustinspector-cdxgen-windows-amd64.exe
copy build\* ..\..\plugins\trustinspector\
Remove-Item build -Recurse -Force
cd ..\..

New-Item -ItemType Directory -Path plugins\rusi -Force
cd thirdparty\rusi
cargo build -p rusi-cli --release --locked
copy target\release\rusi.exe ..\..\plugins\rusi\rusi-windows-amd64.exe
cd ..\..

New-Item -ItemType Directory -Path plugins\cdxui -Force
cd thirdparty\cdxui
cargo build --release --locked
copy target\release\cdxui.exe ..\..\plugins\cdxui\cdxui-windows-amd64.exe
cd ..\..

node .\scripts\generate-metadata.js .\plugins

Remove-Item "osquery-$osqueryVersion.windows_x86_64" -Recurse -Force
Remove-Item $osqueryArchive -Recurse -Force
Remove-Item "upx-$upxVersion-win64" -Recurse -Force
Remove-Item $upxArchive -Recurse -Force
