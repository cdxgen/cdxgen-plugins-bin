package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// jsonUnmarshal wraps json.Unmarshal for the fixture loader.
func jsonUnmarshal(data []byte, target any) error {
	return json.Unmarshal(data, target)
}

// TestDarwinHostTrustMaterials parses the captured keychain output through
// the commandRunner seam (testdata/capture-macos.sh captured the real
// `security find-certificate -a -p` output on this Mac).
func TestDarwinHostTrustMaterials(t *testing.T) {
	systemPEM, err := os.ReadFile(filepath.Join("testdata", "macos-system-keychain.pem"))
	if err != nil {
		t.Fatalf("read captured keychain fixture: %v", err)
	}
	systemRootsPEM, err := os.ReadFile(filepath.Join("testdata", "macos-systemroots-keychain.pem"))
	if err != nil {
		t.Fatalf("read captured keychain fixture: %v", err)
	}
	oldRunner := commandRunner
	commandRunner = func(name string, args ...string) (string, string, error) {
		if name != "security" {
			t.Fatalf("unexpected command %q", name)
		}
		if args[len(args)-1] == "/Library/Keychains/System.keychain" {
			return string(systemPEM), "", nil
		}
		return string(systemRootsPEM), "", nil
	}
	defer func() { commandRunner = oldRunner }()

	materials, warnings := inspectDarwinHostTrustMaterials()
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(materials) == 0 {
		t.Fatal("expected host materials from the captured keychains")
	}
	var systemSeen, rootsSeen bool
	for _, material := range materials {
		if material.Kind != "certificate" {
			t.Fatalf("unexpected host material kind %q", material.Kind)
		}
		if material.SourceType != "host-store" {
			t.Fatalf("expected host-store sourceType, got %q", material.SourceType)
		}
		if len(material.HostStores) != 1 {
			t.Fatalf("expected exactly one hostStore, got %#v", material.HostStores)
		}
		switch material.HostStores[0] {
		case "macos:System":
			systemSeen = true
			if material.Path != "/Library/Keychains/System.keychain" {
				t.Fatalf("unexpected path %q", material.Path)
			}
		case "macos:SystemRoots":
			rootsSeen = true
		default:
			t.Fatalf("unexpected hostStore %q", material.HostStores[0])
		}
	}
	if !systemSeen || !rootsSeen {
		t.Fatalf("expected both keychains, got system=%v roots=%v", systemSeen, rootsSeen)
	}
	// Certificates shipped in both keychains merge into one material with
	// both stores.
	for _, material := range materials {
		if len(material.Paths) > 1 && len(material.HostStores) == 1 {
			t.Fatalf("shared certificate should carry both stores: %#v", material.HostStores)
		}
	}
}

// TestWindowsHostTrustMaterials parses captured VM output through the
// windowsPowerShellJSONRunner seam. The fixture
// (testdata/windows-certstores.json) was captured on the cbom01 VM; see
// testdata/capture-windows-vm.sh.
func TestWindowsHostTrustMaterials(t *testing.T) {
	fixtureData, err := os.ReadFile(filepath.Join("testdata", "windows-certstores.json"))
	if err != nil {
		t.Skipf("windows fixture not captured yet: %v", err)
	}
	var captured []map[string]any
	if err := jsonUnmarshal(fixtureData, &captured); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	// The VM's Disallowed store is empty, so the fixture carries no
	// Disallowed certificate. A synthetic entry (built from a test-generated
	// certificate, base64 of its DER) exercises the ca-blocklist mapping;
	// this is generated at test time and is not VM data.
	syntheticCert := buildTestPKI(t).leaf
	captured = append(captured, map[string]any{
		"store":   "Disallowed",
		"rawData": base64Encode(syntheticCert.Raw),
	})

	oldRunner := windowsPowerShellJSONRunner
	windowsPowerShellJSONRunner = func(script string, payload map[string]any) ([]map[string]any, error) {
		if !strings.Contains(script, "Cert:\\LocalMachine\\") {
			t.Fatal("expected the cert store enumeration script")
		}
		return captured, nil
	}
	defer func() { windowsPowerShellJSONRunner = oldRunner }()

	materials, warnings := inspectWindowsHostTrustMaterials()
	if len(materials) == 0 {
		t.Fatal("expected materials from the captured VM output")
	}
	// The captured VM output carries one certificate Go cannot parse (an RSA
	// modulus bug in a legacy CA certificate); it must surface as a warning,
	// not silently disappear.
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "; "), "could not be parsed") {
		t.Fatalf("expected an unparseable-certificate warning, got %v", warnings)
	}
	var disallowedSeen, storeErrorWarned, sharedSeen bool
	for _, material := range materials {
		if len(material.HostStores) == 0 || len(material.HostStores) > 2 {
			t.Fatalf("expected one or two hostStores per material, got %#v", material.HostStores)
		}
		if len(material.HostStores) == 2 {
			// Every AuthRoot certificate on this VM is also in Root; the
			// merged material must carry both store labels.
			sharedSeen = true
			joined := strings.Join(material.HostStores, ",")
			if !strings.Contains(joined, `windows:LocalMachine\AuthRoot`) || !strings.Contains(joined, `windows:LocalMachine\Root`) {
				t.Fatalf("shared certificate should carry Root and AuthRoot, got %#v", material.HostStores)
			}
		}
		label := material.HostStores[0]
		switch {
		case strings.HasPrefix(label, `windows:LocalMachine\Disallowed`):
			disallowedSeen = true
			if material.SourceType != "ca-blocklist" {
				t.Fatalf("Disallowed certificate must be ca-blocklist, got %q", material.SourceType)
			}
		case strings.HasPrefix(label, `windows:LocalMachine\`):
			hasStoreType := false
			for _, sourceType := range material.SourceTypes {
				if sourceType == "host-store" || sourceType == "ca-blocklist" {
					hasStoreType = true
				}
			}
			if !hasStoreType {
				t.Fatalf("expected a host-store/ca-blocklist sourceType, got %#v", material.SourceTypes)
			}
		default:
			t.Fatalf("unexpected hostStore %q", label)
		}
	}
	if !disallowedSeen {
		t.Fatal("expected a Disallowed store certificate in the fixture")
	}
	if !sharedSeen {
		t.Fatal("expected certificates shared between Root and AuthRoot in the fixture")
	}
	// A per-store PowerShell failure is surfaced as a warning.
	captured = append(captured, map[string]any{"store": "AuthRoot", "error": "access denied"})
	windowsPowerShellJSONRunner = func(script string, payload map[string]any) ([]map[string]any, error) {
		return captured, nil
	}
	materials, warnings = inspectWindowsHostTrustMaterials()
	storeErrorWarned = false
	for _, warning := range warnings {
		if strings.Contains(warning, "windows host store AuthRoot: access denied") {
			storeErrorWarned = true
		}
	}
	if !storeErrorWarned {
		t.Fatalf("expected the store error warning, got %v", warnings)
	}
}

// TestWindowsCertStoreScriptInvariants pins the PowerShell contract.
func TestWindowsCertStoreScriptInvariants(t *testing.T) {
	script := windowsCertStorePowerShellScript()
	if !strings.Contains(script, "'Root', 'CA', 'AuthRoot', 'Disallowed'") {
		t.Fatal("expected all four stores enumerated")
	}
	if !strings.Contains(script, "ConvertTo-Json -Depth 6 -Compress") {
		t.Fatal("expected -Compress JSON output")
	}
	if strings.Contains(script, "\"") {
		t.Fatal("script must not contain double quotes")
	}
	if !strings.Contains(script, "try {") || !strings.Contains(script, "} catch {") {
		t.Fatal("expected per-store try/catch")
	}
}

// TestLinuxHostScanUsesRootfsScanner fakes the root directory the Linux host
// scan reads (runHost calls it with "/"; the test drives it directly).
func TestLinuxHostScanUsesRootfsScanner(t *testing.T) {
	root := t.TempDir()
	writeFileRel(t, root, "etc/ssl/certs/demo-bundle.pem", fixture(t, "demo-bundle.pem"))
	materials, warnings, err := inspectLinuxHostTrustMaterials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(materials) != 3 {
		t.Fatalf("expected 3 certificates from the fake root, got %d", len(materials))
	}
}

// TestHostStoreSorting keeps hostStores comparisons deterministic.
func TestHostStoreSorting(t *testing.T) {
	got := sortHostStoreLabels([]string{"b", "a"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected sort result %#v", got)
	}
}

// base64Encode is the standard encoding used for PowerShell rawData.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
