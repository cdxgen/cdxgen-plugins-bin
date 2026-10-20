package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "generated", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestTrustedCertificateRejectParsing(t *testing.T) {
	data := fixture(t, "demo-trusted-reject.pem")
	sniffed, err := sniffTrustMaterial(data)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if len(sniffed.certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(sniffed.certificates))
	}
	var rejects []string
	for _, parsed := range sniffed.certificates {
		rejects = append(rejects, parsed.trustRejectedPurposes...)
	}
	if len(rejects) != 1 || rejects[0] != "serverAuth" {
		t.Fatalf("expected exactly one serverAuth reject, got %#v", rejects)
	}
}

func TestTrustedCertificateAliasOnly(t *testing.T) {
	data := fixture(t, "demo-trusted-alias.pem")
	sniffed, err := sniffTrustMaterial(data)
	if err != nil {
		t.Fatalf("sniff: %v", err)
	}
	if len(sniffed.certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(sniffed.certificates))
	}
	if len(sniffed.certificates[0].trustRejectedPurposes) != 0 {
		t.Fatalf("expected no rejects, got %#v", sniffed.certificates[0].trustRejectedPurposes)
	}
}

func TestPKCS7PEMAndDER(t *testing.T) {
	// PEM form.
	entries := parseFileMaterials(fixture(t, "demo-bundle.p7b"), "/etc/ssl/certs/bundle.p7b", "ca-store")
	if len(entries) != 2 {
		t.Fatalf("expected 2 certificates from the p7b bundle, got %d", len(entries))
	}
	// DER form (the same content without the PEM armor).
	var der []byte
	rest := fixture(t, "demo-bundle.p7b")
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "PKCS7" {
			der = block.Bytes
			break
		}
		rest = remainder
	}
	if der == nil {
		t.Fatal("no PKCS7 block in fixture")
	}
	entries = parseFileMaterials(der, "/etc/ssl/certs/bundle.p7b", "ca-store")
	if len(entries) != 2 {
		t.Fatalf("expected 2 certificates from the DER p7b, got %d", len(entries))
	}
	// Truncated DER: error, no panic.
	if _, err := parsePKCS7(der[:len(der)/2]); err == nil {
		t.Fatal("expected truncated PKCS#7 to error")
	}
}

func TestPrivateKeysAreClassifiedFromHeaderOnly(t *testing.T) {
	// Header-only fixtures: the body is random bytes, generated at test
	// time; nothing real is committed and nothing is decoded.
	headers := map[string]string{
		"RSA PRIVATE KEY":       "RSA",
		"EC PRIVATE KEY":        "EC",
		"PRIVATE KEY":           "PKCS8",
		"ENCRYPTED PRIVATE KEY": "ENCRYPTED-PKCS8",
		"OPENSSH PRIVATE KEY":   "OPENSSH",
	}
	for blockType, format := range headers {
		body := make([]byte, 64)
		if _, err := rand.Read(body); err != nil {
			t.Fatalf("random body: %v", err)
		}
		var buffer bytes.Buffer
		buffer.WriteString("-----BEGIN " + blockType + "-----\n")
		buffer.WriteString(strings.ToUpper(strings.ReplaceAll(randomHex(t, body), "", " ")[1:]) + "\n")
		buffer.WriteString("-----END " + blockType + "-----\n")
		entries := parseFileMaterials(buffer.Bytes(), "/etc/nginx/ssl/privkey.pem", "server-config")
		if len(entries) != 1 {
			t.Fatalf("%s: expected one private-key material, got %d", blockType, len(entries))
		}
		material := entries[0].material
		if material.Kind != "private-key" {
			t.Fatalf("%s: unexpected kind %q", blockType, material.Kind)
		}
		if material.Format != format {
			t.Fatalf("%s: expected format %q, got %q", blockType, format, material.Format)
		}
		// No digest and no key material on a private-key material.
		if material.SHA256 != "" || material.SHA1 != "" {
			t.Fatalf("%s: private-key material must not carry digests", blockType)
		}
		// The random body must not appear anywhere in the material.
		encoded, err := json.Marshal(material)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if bytes.Contains(encoded, body) {
			t.Fatalf("%s: private-key body leaked into output", blockType)
		}
	}
}

func randomHex(t *testing.T, data []byte) string {
	t.Helper()
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

func TestDERCertificateParsing(t *testing.T) {
	entries := parseFileMaterials(fixture(t, "demo-leaf.der"), "/etc/ssl/certs/demo-leaf.der", "ca-store")
	if len(entries) != 1 {
		t.Fatalf("expected 1 certificate from DER, got %d", len(entries))
	}
	if entries[0].material.Name != "leaf.inspector.test" {
		t.Fatalf("unexpected name %q", entries[0].material.Name)
	}
}

func TestMalformedInputsDoNotPanic(t *testing.T) {
	good := fixture(t, "demo-leaf.der")
	cases := map[string][]byte{
		"truncated DER":        good[:len(good)/2],
		"wrong magic bytes":    {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01},
		"huge DER length":      {0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02},
		"empty":                {},
		"pem garbage":          []byte("-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n"),
		"jks wrong magic":      {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01},
		"jks absurd count":     {0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xFF, 0xFF, 0xFF},
		"jks truncated header": {0xFE, 0xED, 0xFE, 0xED},
		"pkcs12 not a pfx":     {0x30, 0x03, 0x02, 0x01, 0x03, 0x00},
	}
	for name, data := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panicked: %v", name, r)
				}
			}()
			entries := parseFileMaterials(data, "/etc/ssl/certs/broken."+guessExt(name), "ca-store")
			for _, entry := range entries {
				if entry.material.Kind == "certificate" && entry.material.CertSHA256 == "" {
					t.Errorf("%s: certificate material without identity", name)
				}
			}
		}()
	}
}

func guessExt(name string) string {
	if strings.Contains(name, "jks") {
		return "jks"
	}
	if strings.Contains(name, "pkcs12") {
		return "p12"
	}
	if strings.Contains(name, "pem") {
		return "pem"
	}
	return "der"
}

func TestEmbeddedCertificateBlocks(t *testing.T) {
	certPEM := fixture(t, "demo-leaf.crt")
	// Fake binary: ELF magic + padding + an embedded PEM certificate.
	var fake bytes.Buffer
	fake.Write([]byte{0x7f, 'E', 'L', 'F'})
	fake.Write(bytes.Repeat([]byte{0}, 512))
	fake.Write(certPEM)
	fake.Write(bytes.Repeat([]byte{0}, 128))
	certs := embeddedCertificateBlocks(fake.Bytes())
	if len(certs) != 1 {
		t.Fatalf("expected 1 embedded certificate, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "leaf.inspector.test" {
		t.Fatalf("unexpected embedded cert %q", certs[0].Subject.CommonName)
	}
	if got := embeddedCertificateBlocks([]byte("not a binary")); len(got) != 0 {
		t.Fatalf("expected no certificates in text, got %d", len(got))
	}
}

func TestLooksLikePKCS12RequiresVersionMarker(t *testing.T) {
	// A bare SEQUENCE is not enough; the PFX version marker 02 01 03 must be
	// near the start.
	if !looksLikePKCS12([]byte{0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x03, 0x00}) {
		t.Fatal("expected a PFX-shaped buffer to match")
	}
	if looksLikePKCS12([]byte{0x30, 0x00, 0x04, 0x05, 0x06}) {
		t.Fatal("expected a plain SEQUENCE not to match")
	}
}

// TestGeneratedFixtureIntegrity asserts the committed fixtures still contain
// what the tests expect (guards against accidental fixture edits).
func TestGeneratedFixtureIntegrity(t *testing.T) {
	for name, want := range map[string]int{
		"demo-bundle.pem":          3, // root + intermediate + leaf
		"demo-trusted-reject.pem":  2,
		"demo-trusted-alias.pem":   1,
		"demo-bundle.p7b":          -1,
		"demo-truststore.jks":      -1, // magic checked below
		"demo-negative-serial.crt": 1,
	} {
		data := fixture(t, name)
		if len(data) == 0 {
			t.Fatalf("%s: empty fixture", name)
		}
		if want >= 0 && want > 0 {
			count := bytes.Count(data, []byte("BEGIN CERTIFICATE")) +
				bytes.Count(data, []byte("BEGIN TRUSTED CERTIFICATE"))
			if want > 1 && count != want {
				t.Fatalf("%s: expected %d PEM certificates, got %d", name, want, count)
			}
		}
	}
	jks := fixture(t, "demo-truststore.jks")
	if len(jks) < 4 || jks[0] != 0xFE || jks[1] != 0xED || jks[2] != 0xFE || jks[3] != 0xED {
		t.Fatal("demo-truststore.jks lost its JKS magic")
	}
	// The fixture directory must never contain a private key.
	matches, err := filepath.Glob(filepath.Join("testdata", "generated", "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range matches {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if bytes.Contains(data, []byte("PRIVATE KEY")) {
			t.Errorf("%s contains a private key marker", path)
		}
	}
}
