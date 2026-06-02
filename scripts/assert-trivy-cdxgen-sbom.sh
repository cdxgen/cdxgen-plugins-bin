#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 SBOM_JSON [LABEL]" >&2
  exit 2
fi

sbom_json="$1"
label="${2:-$sbom_json}"

if [[ ! -f "$sbom_json" ]]; then
  echo "SBOM file not found: $sbom_json" >&2
  exit 1
fi

python3 - "$sbom_json" "$label" <<'PY'
import json
import sys

sbom_path, label = sys.argv[1], sys.argv[2]

with open(sbom_path, encoding="utf-8") as handle:
    bom = json.load(handle)

components = bom.get("components")
if not isinstance(components, list):
    print(f"SBOM for {label} does not contain a components array", file=sys.stderr)
    sys.exit(1)


def property_values(component, property_name):
    values = []
    for prop in component.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        if prop.get("name") != property_name:
            continue
        value = prop.get("value")
        if value is not None:
            values.append(str(value))
    return values


os_components = [component for component in components if component.get("type") == "operating-system"]
os_package_purl_prefixes = ("pkg:apk/", "pkg:deb/", "pkg:rpm/", "pkg:alpm/")

go_binary_components = []
golang_components = []
os_package_components = []
for component in components:
    purl = str(component.get("purl") or "")
    pkg_types = set(property_values(component, "aquasecurity:trivy:PkgType"))
    pkg_types.update(property_values(component, "PkgType"))
    if purl.startswith("pkg:golang/"):
        golang_components.append(component)
    if purl.startswith(os_package_purl_prefixes):
        os_package_components.append(component)
    if "gobinary" in pkg_types:
        go_binary_components.append(component)

if not os_components:
    print(f"SBOM for {label} did not contain any operating-system components", file=sys.stderr)
    sys.exit(1)

if not os_package_components:
    os_type_sample = ", ".join(
        str(component.get("name") or "<unnamed>") for component in os_components[:5]
    ) or "<none>"
    print(
        f"SBOM for {label} did not contain any OS package components. "
        f"Found {len(os_components)} operating-system components. Samples: {os_type_sample}",
        file=sys.stderr,
    )
    sys.exit(1)

if not go_binary_components:
    golang_sample = ", ".join(
        str(component.get("name") or "<unnamed>") for component in golang_components[:5]
    ) or "<none>"
    print(
        f"SBOM for {label} did not contain any Go binary components. "
        f"Found {len(golang_components)} golang PURLs. Samples: {golang_sample}",
        file=sys.stderr,
    )
    sys.exit(1)

os_sample = ", ".join(str(component.get("name") or "<unnamed>") for component in os_components[:5])
os_package_sample = ", ".join(
    str(component.get("name") or "<unnamed>") for component in os_package_components[:5]
)
go_sample = ", ".join(str(component.get("name") or "<unnamed>") for component in go_binary_components[:5])
print(
    f"Validated SBOM for {label}: "
    f"os_distribution_components={len(os_components)} "
    f"os_package_components={len(os_package_components)} "
    f"go_binary_components={len(go_binary_components)}"
)
print(f"OS distribution samples: {os_sample}")
print(f"OS package samples: {os_package_sample}")
print(f"Go binary samples: {go_sample}")
PY
