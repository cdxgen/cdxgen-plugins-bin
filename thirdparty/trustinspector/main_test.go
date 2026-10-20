package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// buildTestPKI generates the four-certificate PKI the report-2 tests assert
// on: root A, root B, one intermediate key certified by both roots (the
// cross-signed twins), and a leaf issued by the intermediate. The generation
// code IS the fixture script, so nothing is committed.
type testPKI struct {
	rootA         *x509.Certificate
	rootB         *x509.Certificate
	intermediateA *x509.Certificate
	intermediateB *x509.Certificate
	leaf          *x509.Certificate
}

func buildTestPKI(t *testing.T) testPKI {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := func(cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"Inspector Test"}},
			Issuer:                pkix.Name{CommonName: cn, Organization: []string{"Inspector Test"}},
			NotBefore:             time.Unix(1700000000, 0),
			NotAfter:              time.Unix(1900000000, 0),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			SubjectKeyId:          []byte{1, 2, 3, 4},
		}
	}
	rootADer, err := x509.CreateCertificate(rand.Reader, rootTemplate("root-a"), rootTemplate("root-a"), &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root A: %v", err)
	}
	rootBDer, err := x509.CreateCertificate(rand.Reader, rootTemplate("root-b"), rootTemplate("root-b"), &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root B: %v", err)
	}
	rootA, err := x509.ParseCertificate(rootADer)
	if err != nil {
		t.Fatalf("parse root A: %v", err)
	}
	rootB, err := x509.ParseCertificate(rootBDer)
	if err != nil {
		t.Fatalf("parse root B: %v", err)
	}

	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	intTemplate := func(issuer *x509.Certificate) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: "issuing-ca"},
			Issuer:                issuer.Subject,
			NotBefore:             time.Unix(1700000000, 0),
			NotAfter:              time.Unix(1900000000, 0),
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			SubjectKeyId:          []byte{5, 6, 7, 8},
			AuthorityKeyId:        issuer.SubjectKeyId,
			DNSNames:              []string{"one.test", "two.test"},
		}
	}
	intADer, err := x509.CreateCertificate(rand.Reader, intTemplate(rootA), rootA, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate A: %v", err)
	}
	intBDer, err := x509.CreateCertificate(rand.Reader, intTemplate(rootB), rootB, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate B: %v", err)
	}
	intermediateA, err := x509.ParseCertificate(intADer)
	if err != nil {
		t.Fatalf("parse intermediate A: %v", err)
	}
	intermediateB, err := x509.ParseCertificate(intBDer)
	if err != nil {
		t.Fatalf("parse intermediate B: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		Issuer:       intermediateA.Subject,
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1900000000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.test"},
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateA, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDer)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return testPKI{rootA: rootA, rootB: rootB, intermediateA: intermediateA, intermediateB: intermediateB, leaf: leaf}
}

func pemEncodeCerts(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var buffer bytes.Buffer
	for _, cert := range certs {
		if err := pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			t.Fatalf("pem encode: %v", err)
		}
	}
	return buffer.Bytes()
}

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

// TestParseFileMaterialsCertificate checks the report-1 fields that a
// report-1 consumer depends on are still produced by the report-2 code path.
func TestParseFileMaterialsCertificate(t *testing.T) {
	pki := buildTestPKI(t)
	data := pemEncodeCerts(t, pki.rootA)
	entries := parseFileMaterials(data, "/etc/ssl/certs/demo-root.crt", "ca-store")
	if len(entries) != 1 {
		t.Fatalf("expected one material, got %d", len(entries))
	}
	accumulator := newMaterialAccumulator()
	accumulator.add(entries[0].material, entries[0].location)
	materials := accumulator.resolve()
	material := &materials[0]
	if material.Kind != "certificate" {
		t.Fatalf("unexpected material kind: %#v", material)
	}
	if material.Subject == "" || material.Issuer == "" {
		t.Fatalf("expected subject and issuer: %#v", material)
	}
	if material.Serial != pki.rootA.SerialNumber.String() {
		t.Fatalf("expected decimal serial %q, got %q", pki.rootA.SerialNumber.String(), material.Serial)
	}
	if !hasProperty(material.Properties, "cdx:crypto:isCA", "true") {
		t.Fatalf("expected isCA property: %#v", material.Properties)
	}
	if !hasProperty(material.Properties, "cdx:crypto:sourceType", "ca-store") {
		t.Fatalf("expected sourceType property: %#v", material.Properties)
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

// decodeReportJSON is a small helper for the JSON shape tests.
func decodeReportJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return report
}

// Flags after file arguments are a usage error, not file names, and extra
// dirs must name a directory inside the root.
func TestCLIArgumentChecks(t *testing.T) {
	var usage *usageError
	if err := runCerts([]string{"a.pem", "--root", "r"}); !errors.As(err, &usage) {
		t.Fatalf("certs with a trailing flag: %v", err)
	}
	if err := runRootfs([]string{"dir", "--embedded"}); !errors.As(err, &usage) {
		t.Fatalf("rootfs with a trailing flag: %v", err)
	}
	for dir, ok := range map[string]bool{"": false, ".": false, "..": false, "a/../..": false, "/etc": false, "a/..b": true, "opt/app": true} {
		if err := validateExtraDir(dir); (err == nil) != ok {
			t.Errorf("validateExtraDir(%q) = %v", dir, err)
		}
	}
}
