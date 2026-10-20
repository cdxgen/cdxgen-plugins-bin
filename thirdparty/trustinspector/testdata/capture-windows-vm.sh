#!/usr/bin/env bash
# Capture the Windows certificate-store fixture from the shared win11-vm
# (rule 10: read-only for stores, only write inside hbom-work/cbom01):
#
#   testdata/capture-windows-vm.sh
#
# Cross-compiles trustinspector for Windows (amd64 + arm64), runs the cert
# store enumeration PowerShell script on the VM, and captures its JSON as
# testdata/windows-certstores.json. Also runs `trustinspector ... host` on the
# VM and stores its full report as testdata/windows-host-report.json for the
# live check counts.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MODULE="$HERE/.."
VM_NAME=cbom01
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

echo "cross-compiling trustinspector (windows amd64 + arm64)..."
(cd "$MODULE" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o "$SCRATCH/trustinspector-cdxgen.exe" .)
(cd "$MODULE" && CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -o "$SCRATCH/trustinspector-cdxgen-arm64.exe" .)

# The enumeration script must be identical to windowsCertStorePowerShellScript
# in host.go; keep them in sync.
cat > "$SCRATCH/capture-certstores.ps1" <<'PS'
$results = @()
foreach ($store in @('Root', 'CA', 'AuthRoot', 'Disallowed')) {
  try {
    $certs = Get-ChildItem -LiteralPath ('Cert:\LocalMachine\' + $store) -ErrorAction Stop
    foreach ($cert in $certs) {
      $results += [pscustomobject]@{
        store = $store
        rawData = [convert]::ToBase64String($cert.RawData)
      }
    }
  } catch {
    $results += [pscustomobject]@{
      store = $store
      error = [string]$_.Exception.Message
    }
  }
}
$results | ConvertTo-Json -Depth 6 -Compress
PS

bash "$HOME/work/cdx-hbom-windows/tools/vm-sync.sh" "$SCRATCH" "$VM_NAME"
echo "running the cert store capture on the VM..."
# vm-run executes inside hbom-work/<name>; use a relative path. The fixture
# is replaced only when the capture produced valid JSON.
bash "$HOME/work/cdx-hbom-windows/tools/vm-run.sh" "$VM_NAME" \
  powershell -NoProfile -ExecutionPolicy Bypass -File capture-certstores.ps1 \
  | tr -d '\r' > "$SCRATCH/windows-certstores.json"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$SCRATCH/windows-certstores.json"
mv "$SCRATCH/windows-certstores.json" "$HERE/windows-certstores.json"

count=$(python3 -c "import json,sys;data=json.load(open('$HERE/windows-certstores.json'));print(len(data) if isinstance(data,list) else 1)")
echo "windows-certstores.json: $count entries"

echo "running trustinspector host on the VM..."
bash "$HOME/work/cdx-hbom-windows/tools/vm-run.sh" "$VM_NAME" \
  trustinspector-cdxgen.exe host | tr -d '\r' > "$HERE/windows-host-report.json" || true
python3 - "$HERE/windows-host-report.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
materials = data.get("materials") or []
stores = {}
for material in materials:
    for store in material.get("hostStores") or []:
        stores[store] = stores.get(store, 0) + 1
print("host materials per store:", stores)
PY
