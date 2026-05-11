package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp/packet"
)

func TestParseCodeSignOutput(t *testing.T) {
	properties := parseCodeSignOutput(`Identifier=com.example.demo
Format=app bundle with Mach-O thin (arm64)
CodeDirectory v=20500 size=123 flags=0x10000(runtime)
Authority=Developer ID Application: Example Corp (ABCDE12345)
Authority=Developer ID Certification Authority
TeamIdentifier=ABCDE12345
Runtime Version=14.0.0`)
	if !hasProperty(properties, "cdx:darwin:codesign:identifier", "com.example.demo") {
		t.Fatalf("missing identifier property: %#v", properties)
	}
	if !hasProperty(properties, "cdx:darwin:codesign:teamIdentifier", "ABCDE12345") {
		t.Fatalf("missing team identifier: %#v", properties)
	}
	if !hasProperty(properties, "cdx:darwin:codesign:authorityCount", "2") {
		t.Fatalf("missing authority count: %#v", properties)
	}
}

func TestParseSpctlOutput(t *testing.T) {
	properties := parseSpctlOutput(`/Applications/Demo.app: accepted
source=Notarized Developer ID
origin=Developer ID Application: Example Corp (ABCDE12345)`)
	if !hasProperty(properties, "cdx:darwin:notarization:assessment", "accepted") {
		t.Fatalf("missing notarization assessment: %#v", properties)
	}
	if !hasProperty(properties, "cdx:darwin:notarization:source", "Notarized Developer ID") {
		t.Fatalf("missing notarization source: %#v", properties)
	}
}

func TestReadOpenPGPEntities(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	pub := packet.NewRSAPublicKey(time.Unix(1700000000, 0), &privateKey.PublicKey)
	uid := packet.NewUserId("Example Maintainer", "", "maintainer@example.com")
	if uid == nil {
		t.Fatal("expected user id")
	}
	var buffer bytes.Buffer
	if err := pub.Serialize(&buffer); err != nil {
		t.Fatalf("serialize public key: %v", err)
	}
	if err := uid.Serialize(&buffer); err != nil {
		t.Fatalf("serialize user id: %v", err)
	}
	entities, err := readOpenPGPEntities(buffer.Bytes())
	if err != nil {
		t.Fatalf("read entities: %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("expected one entity, got %d", len(entities))
	}
	if entities[0].Algorithm != "RSA" {
		t.Fatalf("unexpected algorithm: %#v", entities[0])
	}
	if entities[0].KeyStrength != 2048 {
		t.Fatalf("unexpected key strength: %#v", entities[0])
	}
	if len(entities[0].UserIDs) != 1 || entities[0].UserIDs[0] != "Example Maintainer <maintainer@example.com>" {
		t.Fatalf("unexpected user ids: %#v", entities[0].UserIDs)
	}
}

func TestParseCertificateMaterials(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "demo-root", Organization: []string{"Example Org"}},
		Issuer:                pkix.Name{CommonName: "demo-root", Organization: []string{"Example Org"}},
		NotBefore:             time.Unix(1700000000, 0),
		NotAfter:              time.Unix(1800000000, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	materials := parseCertificateMaterials(pemData, "/etc/ssl/certs/demo-root.crt", "sha1", "sha256", "ca-store", "ca-store", "crt")
	if len(materials) != 1 {
		t.Fatalf("expected one certificate material, got %d", len(materials))
	}
	if materials[0].Kind != "certificate" {
		t.Fatalf("unexpected material kind: %#v", materials[0])
	}
	if materials[0].Subject == "" || materials[0].Issuer == "" {
		t.Fatalf("expected subject and issuer: %#v", materials[0])
	}
	if !hasProperty(materials[0].Properties, "cdx:crypto:isCA", "true") {
		t.Fatalf("expected isCA property: %#v", materials[0].Properties)
	}
}

func TestMapToPropertiesSkipsExcludedKeys(t *testing.T) {
	properties := mapToProperties(map[string]any{
		"path":                                "C:/demo.exe",
		"cdx:windows:authenticode:status":     "Valid",
		"cdx:windows:authenticode:isOSBinary": true,
	}, "path")
	if len(properties) != 2 {
		t.Fatalf("unexpected property count: %#v", properties)
	}
	if !hasProperty(properties, "cdx:windows:authenticode:status", "Valid") {
		t.Fatalf("missing authenticode status property: %#v", properties)
	}
}

func TestInspectWindowsPathsRetainsInspectionErrors(t *testing.T) {
	oldRunner := windowsPowerShellJSONRunner
	windowsPowerShellJSONRunner = func(script string, payload map[string]any) ([]map[string]any, error) {
		return []map[string]any{{
			"path":                            `C:\demo.exe`,
			"cdx:windows:authenticode:status": "error",
			"cdx:windows:authenticode:error":  "Access is denied.",
		}}, nil
	}
	defer func() {
		windowsPowerShellJSONRunner = oldRunner
	}()

	inspections := inspectWindowsPaths([]string{`C:\demo.exe`})
	if len(inspections) != 1 {
		t.Fatalf("expected one inspection, got %#v", inspections)
	}
	if !hasProperty(inspections[0].Properties, "cdx:windows:authenticode:status", "error") {
		t.Fatalf("missing error status property: %#v", inspections[0].Properties)
	}
	if !hasProperty(inspections[0].Properties, "cdx:windows:authenticode:error", "Access is denied.") {
		t.Fatalf("missing error property: %#v", inspections[0].Properties)
	}
}

func TestPathsInspectionPowerShellScriptUsesLiteralPathAndReportsErrors(t *testing.T) {
	script := pathsInspectionPowerShellScript()
	if !strings.Contains(script, "Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop") {
		t.Fatalf("expected script to use LiteralPath, got %s", script)
	}
	if !strings.Contains(script, "'cdx:windows:authenticode:status' = 'error'") {
		t.Fatalf("expected script to emit explicit error status, got %s", script)
	}
	if !strings.Contains(script, "'cdx:windows:authenticode:error'") {
		t.Fatalf("expected script to emit explicit error details, got %s", script)
	}
}

func TestNormalizeInspectablePathReturnsCleanAbsolutePath(t *testing.T) {
	value, err := normalizeInspectablePath(filepath.Join(".", "fixtures", "..", "demo.bin"))
	if err != nil {
		t.Fatalf("normalize path: %v", err)
	}
	if !filepath.IsAbs(value) {
		t.Fatalf("expected absolute path, got %s", value)
	}
	if strings.Contains(value, "..") {
		t.Fatalf("expected cleaned path, got %s", value)
	}
}

func TestInspectDarwinPathsUsesNormalizedAbsolutePath(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
	}()

	filename := "-demo-tool"
	absPath := filepath.Join(tempDir, filename)
	normalizedPath, err := normalizeInspectablePath(filename)
	if err != nil {
		t.Fatalf("normalize path: %v", err)
	}
	if err := os.WriteFile(absPath, []byte("demo"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	oldRunner := commandRunner
	var seenPaths []string
	commandRunner = func(name string, args ...string) (string, string, error) {
		seenPaths = append(seenPaths, args[len(args)-1])
		switch name {
		case "codesign":
			return "", "Identifier=com.example.demo\nTeamIdentifier=ABCDE12345", nil
		case "spctl":
			return "", normalizedPath + ": accepted\nsource=Notarized Developer ID", nil
		default:
			return "", "", nil
		}
	}
	defer func() {
		commandRunner = oldRunner
	}()

	inspections := inspectDarwinPaths([]string{filename})
	if len(inspections) != 1 {
		t.Fatalf("expected one inspection, got %#v", inspections)
	}
	if inspections[0].Path != normalizedPath {
		t.Fatalf("expected absolute inspected path %s, got %s", normalizedPath, inspections[0].Path)
	}
	if len(seenPaths) != 2 {
		t.Fatalf("expected codesign and spctl invocations, got %#v", seenPaths)
	}
	for _, seenPath := range seenPaths {
		if seenPath != normalizedPath {
			t.Fatalf("expected absolute command path %s, got %s", normalizedPath, seenPath)
		}
		if strings.HasPrefix(seenPath, "-") {
			t.Fatalf("expected normalized path not to start with '-', got %s", seenPath)
		}
	}
}

func hasProperty(properties []property, name, value string) bool {
	for _, property := range properties {
		if property.Name == name && property.Value == value {
			return true
		}
	}
	return false
}
