package main

import (
	"crypto/x509"
	"encoding/base64"
	"sort"
	"strings"
)

// Host trust store enumeration (PLAN section 4.2). Host materials go into
// materials (not hostFindings) with hostStores naming the store, so cdxgen's
// certificate path handles them like any other material.

// darwinHostKeychains are the two system keychains read with
// `security find-certificate -a -p` (pem output). Reading is read-only.
var darwinHostKeychains = []struct {
	label string
	path  string
}{
	{label: "macos:System", path: "/Library/Keychains/System.keychain"},
	{label: "macos:SystemRoots", path: "/System/Library/Keychains/SystemRootCertificates.keychain"},
}

// inspectDarwinHostTrustMaterials enumerates the system keychains through the
// commandRunner seam so tests can substitute captured output.
func inspectDarwinHostTrustMaterials() []trustMaterial {
	accumulator := newMaterialAccumulator()
	for _, keychain := range darwinHostKeychains {
		stdout, _, err := commandRunner("security", "find-certificate", "-a", "-p", keychain.path)
		if err != nil || strings.TrimSpace(stdout) == "" {
			continue
		}
		collectHostCertificates(accumulator, parseHostCertificatesPEM(stdout), keychain.label, keychain.path, "host-store")
	}
	return accumulator.resolve()
}

// collectHostCertificates turns parsed host certificates into accumulated
// materials tagged with the store label.
func collectHostCertificates(accumulator *materialAccumulator, certs []*x509.Certificate, storeLabel, storePath, sourceType string) {
	for _, cert := range certs {
		material := buildCertificateFields(cert)
		if material.Name == "" {
			material.Name = storeLabel
		}
		material.HostStores = []string{storeLabel}
		accumulator.add(material, certLocation{
			path:       storePath,
			sourceType: sourceType,
		})
	}
}

// parseHostCertificatesPEM parses concatenated PEM certificates such as the
// output of `security find-certificate -a -p`.
func parseHostCertificatesPEM(pemText string) []*x509.Certificate {
	sniffed, err := sniffTrustMaterial([]byte(pemText))
	if err != nil {
		return nil
	}
	certs := make([]*x509.Certificate, 0, len(sniffed.certificates))
	for _, parsed := range sniffed.certificates {
		certs = append(certs, parsed.cert)
	}
	return certs
}

// windowsCertStorePowerShellScript enumerates the four LocalMachine trust
// stores in one PowerShell invocation and emits {store, rawData(base64)}
// objects. Invariants follow the existing scripts: single-quoted strings, no
// double quotes, -Compress output, and a per-store try/catch.
func windowsCertStorePowerShellScript() string {
	return `$results = @()
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
$results | ConvertTo-Json -Depth 6 -Compress`
}

// windowsHostStoreLabels maps the PowerShell store names to hostStores labels.
var windowsHostStoreLabels = map[string]string{
	"Root":       `windows:LocalMachine\Root`,
	"CA":         `windows:LocalMachine\CA`,
	"AuthRoot":   `windows:LocalMachine\AuthRoot`,
	"Disallowed": `windows:LocalMachine\Disallowed`,
}

// inspectWindowsHostTrustMaterials enumerates the LocalMachine certificate
// stores through the windowsPowerShellJSONRunner seam. A certificate in
// Disallowed is OS-level distrust and gets sourceType ca-blocklist.
func inspectWindowsHostTrustMaterials() []trustMaterial {
	results, err := windowsPowerShellJSONRunner(windowsCertStorePowerShellScript(), nil)
	if err != nil {
		return nil
	}
	accumulator := newMaterialAccumulator()
	for _, item := range results {
		store, _ := item["store"].(string)
		rawData, _ := item["rawData"].(string)
		if _, hasError := item["error"]; hasError {
			continue
		}
		label, ok := windowsHostStoreLabels[store]
		if !ok || rawData == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(rawData)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		sourceType := "host-store"
		if store == "Disallowed" {
			sourceType = "ca-blocklist"
		}
		collectHostCertificates(accumulator, []*x509.Certificate{cert}, label, "Cert:\\LocalMachine\\"+store, sourceType)
	}
	return accumulator.resolve()
}

// sortHostStoreLabels is used by tests to compare hostStores deterministically.
func sortHostStoreLabels(values []string) []string {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return sorted
}

// inspectLinuxHostTrustMaterials runs the rootfs scan for the host case. It
// takes the root as a parameter so tests can fake it; runHost passes "/".
func inspectLinuxHostTrustMaterials(root string) ([]trustMaterial, []string, error) {
	return scanRootfsTrustMaterials(root, scanOptions{})
}
