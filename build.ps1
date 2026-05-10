New-Item -ItemType Directory -Path plugins\osquery -Force
New-Item -ItemType Directory -Path plugins\dosai -Force
New-Item -ItemType Directory -Path plugins\trivy -Force
New-Item -ItemType Directory -Path plugins\trustinspector -Force

$upxVersion = "5.1.1"
$upxArchive = "upx-$upxVersion-win64.zip"
$upxArchiveSha256 = "fa5380bca4c2718547aaa0134bc0d8a7fa27e102f0ac6371573d60d1c21d64de"
$osqueryVersion = "5.23.0"
$osqueryArchive = "osquery-$osqueryVersion.windows_x86_64.zip"
$osqueryArchiveSha256 = "5ddb8e1c23fd870838ef4ff47c0d2e5a080f22a6944fc4870d726e7b20e962a4"

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

Invoke-WebRequest -Uri https://github.com/owasp-dep-scan/dosai/releases/latest/download/Dosai.exe -UseBasicParsing -OutFile plugins/dosai/dosai-windows-amd64.exe

cd thirdparty\trivy
$env:GOEXPERIMENT = "jsonv2"
$env:CGO_ENABLED = "0"
go build -ldflags "-H=windowsgui -s -w" -o build\trivy-windows-amd64.exe
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma build\trivy-windows-amd64.exe
copy build\* ..\..\plugins\trivy\
Remove-Item build -Recurse -Force
cd ..\..

cd thirdparty\trustinspector
$env:CGO_ENABLED = "0"
go build -ldflags "-H=windowsgui -s -w" -o build\trustinspector-cdxgen-windows-amd64.exe
& "..\..\upx-$upxVersion-win64\upx.exe" -9 --lzma build\trustinspector-cdxgen-windows-amd64.exe
copy build\* ..\..\plugins\trustinspector\
Remove-Item build -Recurse -Force
cd ..\..

node .\scripts\generate-metadata.js .\plugins

Remove-Item "osquery-$osqueryVersion.windows_x86_64" -Recurse -Force
Remove-Item $osqueryArchive -Recurse -Force
Remove-Item "upx-$upxVersion-win64" -Recurse -Force
Remove-Item $upxArchive -Recurse -Force
