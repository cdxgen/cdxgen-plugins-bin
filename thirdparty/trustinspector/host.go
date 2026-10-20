package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
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
// commandRunner seam so tests can substitute captured output. A keychain
// whose read fails is reported as a warning, never silently dropped.
func inspectDarwinHostTrustMaterials() ([]trustMaterial, []string) {
	accumulator := newMaterialAccumulator()
	var warnings []string
	for _, keychain := range darwinHostKeychains {
		stdout, _, err := commandRunner("security", "find-certificate", "-a", "-p", keychain.path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("host keychain %s: %v", keychain.path, err))
			continue
		}
		if strings.TrimSpace(stdout) == "" {
			continue
		}
		collectHostCertificates(accumulator, parseHostCertificatesPEM(stdout), keychain.label, keychain.path, "host-store")
	}
	return accumulator.resolve(), warnings
}

// collectHostCertificates turns parsed host certificates into accumulated
// materials. The store label rides on the location so a certificate found in
// several stores carries every hostStores label after the merge.
func collectHostCertificates(accumulator *materialAccumulator, certs []*x509.Certificate, storeLabel, storePath, sourceType string) {
	for _, cert := range certs {
		material := buildCertificateFields(cert)
		if material.Name == "" {
			material.Name = storeLabel
		}
		accumulator.add(material, certLocation{
			path:       storePath,
			sourceType: sourceType,
			hostStore:  storeLabel,
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
// Disallowed is OS-level distrust and gets sourceType ca-blocklist. Per-store
// PowerShell failures and certificates Go cannot parse are reported as
// envelope warnings instead of being silently dropped.
func inspectWindowsHostTrustMaterials() ([]trustMaterial, []string) {
	results, err := windowsPowerShellJSONRunner(windowsCertStorePowerShellScript(), nil)
	if err != nil {
		return nil, []string{fmt.Sprintf("windows host stores: %v", err)}
	}
	accumulator := newMaterialAccumulator()
	storeErrors := map[string]string{}
	unparseable := 0
	for _, item := range results {
		store, _ := item["store"].(string)
		if message, hasError := item["error"].(string); hasError {
			storeErrors[store] = message
			continue
		}
		rawData, _ := item["rawData"].(string)
		label, ok := windowsHostStoreLabels[store]
		if !ok || rawData == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(rawData)
		if err != nil {
			unparseable++
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			unparseable++
			continue
		}
		sourceType := "host-store"
		if store == "Disallowed" {
			sourceType = "ca-blocklist"
		}
		collectHostCertificates(accumulator, []*x509.Certificate{cert}, label, "Cert:\\LocalMachine\\"+store, sourceType)
	}
	stores := make([]string, 0, len(storeErrors))
	for store := range storeErrors {
		stores = append(stores, store)
	}
	sort.Strings(stores)
	var warnings []string
	for _, store := range stores {
		warnings = append(warnings, fmt.Sprintf("windows host store %s: %s", store, storeErrors[store]))
	}
	if unparseable > 0 {
		warnings = append(warnings, fmt.Sprintf("windows host stores: %d certificate(s) could not be parsed", unparseable))
	}
	return accumulator.resolve(), warnings
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
