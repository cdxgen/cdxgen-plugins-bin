package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

// The PKCS#12 check parses the PFX structure (version 3, data-typed
// authSafe); a DER certificate whose serial happens to encode as 02 01 03
// near the start is not mistaken for one.
func TestPKCS12StructureDetection(t *testing.T) {
	if _, ok := pkcs12Iterations(fixture(t, "demo-truststore.p12")); !ok {
		t.Fatal("expected the keytool PKCS#12 fixture to be recognized")
	}
	if _, ok := pkcs12Iterations([]byte{0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x03, 0x00}); ok {
		t.Fatal("expected a truncated PFX-shaped buffer not to match")
	}
	for _, name := range []string{"demo-leaf.der", "demo-root.crt"} {
		if _, ok := pkcs12Iterations(fixture(t, name)); ok {
			t.Fatalf("%s recognized as PKCS#12", name)
		}
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

// Review regressions for the format sniffer. Inputs are built from the
// generated fixtures, with the hostile part made by hand in the test (none of
// them come from a real issuer).

// "-----BEGIN PGP" text in a certificate bundle must not hide its
// certificates (OpenSSL trusts the root regardless of the comment).
func TestPGPTextDoesNotHideCertificates(t *testing.T) {
	data := append([]byte("# -----BEGIN PGP note\n"), fixture(t, "demo-root.crt")...)
	entries := parseFileMaterials(data, "/etc/ssl/certs/bundle.pem", "ca-store")
	if len(entries) != 1 || entries[0].material.Kind != "certificate" {
		t.Fatalf("expected the root certificate, got %d entries", len(entries))
	}
}

// A DER certificate carrying PEM text in an extension is read as the DER
// certificate, not as the PEM text inside it.
func TestDERCertificateWithPEMTextIsReadAsDER(t *testing.T) {
	pki := buildTestPKI(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decoy := pemEncodeCerts(t, pki.leaf)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(9),
		Subject:         pkix.Name{CommonName: "carrier"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: decoy}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sniffed, err := sniffTrustMaterial(der)
	if err != nil || len(sniffed.certificates) != 1 || sniffed.certificates[0].cert.Subject.CommonName != "carrier" {
		t.Fatalf("expected only the carrier certificate, got %+v (%v)", sniffed, err)
	}
}

// OpenSSL's legacy "X509 CERTIFICATE" label and a DER certificate followed
// by a newline are both read, as OpenSSL reads them.
func TestLegacyLabelAndTrailingBytes(t *testing.T) {
	block, _ := pem.Decode(fixture(t, "demo-root.crt"))
	legacy := pem.EncodeToMemory(&pem.Block{Type: "X509 CERTIFICATE", Bytes: block.Bytes})
	if sniffed, err := sniffTrustMaterial(legacy); err != nil || len(sniffed.certificates) != 1 {
		t.Fatalf("legacy label: %+v (%v)", sniffed, err)
	}
	der := append(fixture(t, "demo-leaf.der"), '\n')
	if sniffed, err := sniffTrustMaterial(der); err != nil || len(sniffed.certificates) != 1 {
		t.Fatalf("DER with a trailing newline: %+v (%v)", sniffed, err)
	}
}

// A Go string constant leaves no newline after the END marker, and a broken
// BEGIN marker earlier in the binary must not stop the scan.
func TestEmbeddedPEMWithoutNewlineAndAfterBrokenBlock(t *testing.T) {
	pemText := bytes.TrimSpace(fixture(t, "demo-root.crt"))
	data := []byte("\x7fELF\x02\x01-----BEGIN CERTIFICATE-----\x00garbage\x00")
	data = append(data, pemText...)
	data = append(data, 0x01, 0x00, 0x02)
	certs := embeddedCertificateBlocks(data)
	if len(certs) != 1 || certs[0].Subject.CommonName != "Inspector Root A" {
		t.Fatalf("expected the root after the broken block, got %d", len(certs))
	}
}

// The aux trust list is read as well as the reject list, and a field this
// reader does not need (an alias that is not valid UTF-8, an OID arc wider
// than 64 bits) does not hide either list.
func TestTrustedCertificateAuxTrustAndLenientParsing(t *testing.T) {
	block, _ := pem.Decode(fixture(t, "demo-root.crt"))
	oid := func(id asn1.ObjectIdentifier) []byte {
		der, err := asn1.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	tlv := func(tag byte, content ...[]byte) []byte {
		body := bytes.Join(content, nil)
		return append([]byte{tag, byte(len(body))}, body...)
	}
	// 2.25.72057594037927937: first subidentifier 2*40+25 = 105, then
	// 2^56+1 in base 128.
	bigArc := []byte{0x06, 0x0a, 0x69, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	aux := tlv(0x30,
		tlv(0x30, oid(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}), bigArc), // trust
		tlv(0xa0, oid(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})),         // reject
		[]byte{0x0c, 0x02, 0xc3, 0x28},                                           // alias, invalid UTF-8
	)
	parsed, err := parseTrustedCertificate(append(append([]byte{}, block.Bytes...), aux...))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(parsed.trustAcceptedPurposes, []string{"2.25.72057594037927937", "emailProtection"}) ||
		!slices.Equal(parsed.trustRejectedPurposes, []string{"serverAuth"}) {
		t.Fatalf("trust %v reject %v", parsed.trustAcceptedPurposes, parsed.trustRejectedPurposes)
	}
}

// Private keys: DSA keys and legacy encrypted keys are classified from the
// header, and two keys in one file are two materials.
func TestPrivateKeyHeadersAndCount(t *testing.T) {
	keys := []byte("-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n" +
		"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n")
	entries := parseFileMaterials(keys, "/etc/nginx/ssl/keys.pem", "server-config")
	accumulator := newMaterialAccumulator()
	for _, entry := range entries {
		accumulator.add(entry.material, entry.location)
	}
	var formats []string
	for _, m := range accumulator.resolve() {
		formats = append(formats, m.Format)
	}
	slices.Sort(formats)
	if !slices.Equal(formats, []string{"DSA", "ENCRYPTED-RSA"}) {
		t.Fatalf("private key formats = %v", formats)
	}
}
