package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

// TestCertificateIdentityTwins is the core Part A assertion: the cross-signed
// twins share the SPKI hash and differ in the certificate hash, and the leaf
// issued by that key lists both twins as issuers.
func TestCertificateIdentityTwins(t *testing.T) {
	pki := buildTestPKI(t)
	bundle := pemEncodeCerts(t, pki.rootA, pki.intermediateA, pki.intermediateB, pki.leaf)
	entries := parseFileMaterials(bundle, "/etc/ssl/certs/twins.pem", "ca-store")
	if len(entries) != 4 {
		t.Fatalf("expected 4 materials from the bundle, got %d", len(entries))
	}
	accumulator := newMaterialAccumulator()
	for _, entry := range entries {
		accumulator.add(entry.material, entry.location)
	}
	materials := accumulator.resolve()
	if warnings := linkIssuers(materials, accumulator.certs); len(warnings) > 0 {
		t.Fatalf("unexpected issuer warnings: %v", warnings)
	}
	if len(materials) != 4 {
		t.Fatalf("expected 4 deduplicated materials, got %d", len(materials))
	}

	byName := map[string]*trustMaterial{}
	for i := range materials {
		byName[materials[i].Name] = &materials[i]
	}
	// The two twins share a subject CN but differ in certSha256, so both are
	// present as separate materials.
	twinCount := 0
	var twinHashes []string
	for i := range materials {
		if materials[i].Name == "issuing-ca" {
			twinCount++
			twinHashes = append(twinHashes, materials[i].CertSHA256)
		}
	}
	if twinCount != 2 {
		t.Fatalf("expected both cross-signed twins as separate materials, got %d", twinCount)
	}
	if twinHashes[0] == twinHashes[1] {
		t.Fatalf("twins must differ in certSha256: %s", twinHashes[0])
	}

	// Both twins share the SPKI hash, which is the join key.
	var spkiHashes []string
	for i := range materials {
		if materials[i].Name == "issuing-ca" {
			spkiHashes = append(spkiHashes, materials[i].SPKISHA256)
		}
	}
	if spkiHashes[0] == "" || spkiHashes[0] != spkiHashes[1] {
		t.Fatalf("twins must share spkiSha256, got %v", spkiHashes)
	}
	if materials[0].SPKISHA256 != strings.ToLower(materials[0].SPKISHA256) {
		t.Fatalf("spkiSha256 must be lowercase hex: %s", materials[0].SPKISHA256)
	}
	if materials[0].SPKISHA256Base64 == "" {
		t.Fatal("expected spkiSha256Base64")
	}

	// The leaf's issuers contain both twins' certSha256.
	leaf := byName["leaf.test"]
	if leaf == nil {
		t.Fatalf("missing leaf material: %#v", byName)
	}
	if len(leaf.Issuers) != 2 {
		t.Fatalf("expected leaf issuers to contain both twins, got %#v", leaf.Issuers)
	}
	for _, issuer := range leaf.Issuers {
		if issuer != twinHashes[0] && issuer != twinHashes[1] {
			t.Fatalf("unexpected issuer %s in %#v", issuer, leaf.Issuers)
		}
	}

	// Roles and self-signed flags.
	if got := byName["root-a"].Role; got != "root" {
		t.Fatalf("expected root role for root-a, got %s", got)
	}
	if !*byName["root-a"].SelfSigned {
		t.Fatal("expected root-a selfSigned")
	}
	for i := range materials {
		if materials[i].Name == "issuing-ca" {
			if got := materials[i].Role; got != "intermediate" {
				t.Fatalf("expected intermediate role, got %s", got)
			}
			if materials[i].SelfSigned == nil || *materials[i].SelfSigned {
				t.Fatal("expected issuing-ca not self-signed")
			}
		}
		if materials[i].Name == "leaf.test" {
			if got := materials[i].Role; got != "leaf" {
				t.Fatalf("expected leaf role, got %s", got)
			}
		}
	}
}

// TestCertificateFields checks version, pathLen, SKI/AKI, EKU names, key
// usage names, signature algorithm and OID on the generated PKI.
func TestCertificateFields(t *testing.T) {
	pki := buildTestPKI(t)
	entries := parseFileMaterials(pemEncodeCerts(t, pki.intermediateA), "/etc/ssl/certs/int.crt", "ca-store")
	if len(entries) != 1 {
		t.Fatalf("expected one material, got %d", len(entries))
	}
	material := entries[0].material
	if material.CertVersion != 3 {
		t.Fatalf("expected version 3, got %d", material.CertVersion)
	}
	if material.PathLen == nil || *material.PathLen != 0 {
		t.Fatalf("expected pathLen 0, got %#v", material.PathLen)
	}
	if material.SubjectKeyId == "" {
		t.Fatal("expected subjectKeyId")
	}
	if material.SubjectKeyId != strings.ToLower(material.SubjectKeyId) {
		t.Fatalf("subjectKeyId must be lowercase hex: %s", material.SubjectKeyId)
	}
	if material.AuthorityKeyId == "" {
		t.Fatal("expected authorityKeyId")
	}
	// EKU names come from RFC 5280 section 4.2.1.12.
	if len(material.ExtKeyUsage) != 2 || material.ExtKeyUsage[0] != "clientAuth" || material.ExtKeyUsage[1] != "serverAuth" {
		t.Fatalf("expected [clientAuth serverAuth], got %#v", material.ExtKeyUsage)
	}
	// Key usage names in RFC 5280 section 4.2.1.3 order.
	if len(material.KeyUsage) != 2 || material.KeyUsage[0] != "keyCertSign" || material.KeyUsage[1] != "cRLSign" {
		t.Fatalf("expected [keyCertSign cRLSign] in RFC bit order, got %#v", material.KeyUsage)
	}
	if material.SignatureAlgorithm != "SHA256-RSA" {
		t.Fatalf("expected SHA256-RSA, got %q", material.SignatureAlgorithm)
	}
	if material.SignatureAlgorithmOid != "1.2.840.113549.1.1.11" {
		t.Fatalf("expected sha256WithRSAEncryption OID, got %q", material.SignatureAlgorithmOid)
	}
	if material.CertSHA256 == "" || material.SPKISHA256 == "" {
		t.Fatal("expected certSha256 and spkiSha256")
	}
	// dnsNames sorted.
	if len(material.DNSNames) != 2 || material.DNSNames[0] != "one.test" || material.DNSNames[1] != "two.test" {
		t.Fatalf("expected sorted dnsNames, got %#v", material.DNSNames)
	}
	// Report-1 fields keep their meaning.
	if material.Fingerprint != strings.ToUpper(material.CertSHA256) {
		t.Fatalf("fingerprint must stay the uppercase cert SHA-256: %s vs %s", material.Fingerprint, material.CertSHA256)
	}
	if material.Format != "X.509" {
		t.Fatalf("unexpected format %q", material.Format)
	}
}

// TestOneBundleBothTwinsYieldsTwoMaterials is the G2 repro at the
// trustinspector level: one bundle holding both cross-signed twins yields two
// materials, not one.
func TestOneBundleBothTwinsYieldsTwoMaterials(t *testing.T) {
	pki := buildTestPKI(t)
	bundle := pemEncodeCerts(t, pki.intermediateA, pki.intermediateB)
	materials, _, err := scanBytesAsRoot(t, bundle)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	count := 0
	for _, material := range materials {
		if material.Kind == "certificate" && material.Name == "issuing-ca" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 twin materials from one bundle, got %d", count)
	}
}

// scanBytesAsRoot writes the bytes at etc/ssl/certs/bundle.pem inside a fresh
// temp root and scans it.
func scanBytesAsRoot(t *testing.T, data []byte, extra ...func(root string)) ([]trustMaterial, []string, error) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "etc", "ssl", "certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "demo-bundle.pem"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, fn := range extra {
		fn(root)
	}
	return scanRootfsTrustMaterials(root, scanOptions{})
}

// TestNegativeSerialCertificateIsDropped pins the finding that Go's
// x509.ParseCertificate rejects negative serial numbers outright, so a
// negative-serial certificate never reaches the report-2 fields. The
// committed fixture demo-negative-serial.crt (openssl -set_serial -42) is the
// real certificate; the %x formatting of a negative big.Int would be "-2a",
// but that path is unreachable through the parser.
func TestNegativeSerialCertificateIsDropped(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "generated", "demo-negative-serial.crt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("expected PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err == nil {
		t.Fatal("expected x509.ParseCertificate to reject the negative serial")
	}
	// The formatting that serialHex would use, documented for the report.
	if got := big.NewInt(-42).String(); got != "-42" {
		t.Fatalf("decimal formatting changed: %s", got)
	}
	entries := parseFileMaterials(data, "/etc/ssl/certs/neg.crt", "ca-store")
	if len(entries) != 0 {
		t.Fatalf("expected the negative-serial certificate to be dropped, got %d entries", len(entries))
	}
}

// TestReport1FieldsUnchangedOnOldFixture replays the committed report-1
// baseline (captured with the pre-T01 tool) and asserts every report-1 field
// of every certificate material is byte-identical in the report-2 output.
func TestReport1FieldsUnchangedOnOldFixture(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "generated", "report-1-rootfs.json"))
	if err != nil {
		t.Fatalf("read report-1 fixture: %v", err)
	}
	var oldReport struct {
		Schema    string          `json:"schema"`
		Materials []trustMaterial `json:"materials"`
	}
	if err := json.Unmarshal(fixture, &oldReport); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if oldReport.Schema != "trustinspector/report-1" {
		t.Fatalf("unexpected fixture schema %q", oldReport.Schema)
	}

	bundle, err := os.ReadFile(filepath.Join("testdata", "generated", "demo-bundle.pem"))
	if err != nil {
		t.Fatalf("read bundle fixture: %v", err)
	}
	materials, _, err := scanBytesAsRoot(t, bundle)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	newByName := map[string]*trustMaterial{}
	for i := range materials {
		newByName[materials[i].Fingerprint] = &materials[i]
	}
	if len(oldReport.Materials) != 3 {
		t.Fatalf("expected 3 report-1 materials, got %d", len(oldReport.Materials))
	}
	for _, old := range oldReport.Materials {
		fresh, ok := newByName[old.Fingerprint]
		if !ok {
			t.Fatalf("fingerprint %s missing from report-2 output", old.Fingerprint)
		}
		checks := map[string]func() bool{
			"kind":          func() bool { return old.Kind == fresh.Kind },
			"path":          func() bool { return old.Path == fresh.Path },
			"name":          func() bool { return old.Name == fresh.Name },
			"trustDomain":   func() bool { return old.TrustDomain == fresh.TrustDomain },
			"sourceType":    func() bool { return old.SourceType == fresh.SourceType },
			"fileExtension": func() bool { return old.FileExtension == fresh.FileExtension },
			"sha1":          func() bool { return old.SHA1 == fresh.SHA1 },
			"sha256":        func() bool { return old.SHA256 == fresh.SHA256 },
			"algorithm":     func() bool { return old.Algorithm == fresh.Algorithm },
			"keyStrength":   func() bool { return old.KeyStrength == fresh.KeyStrength },
			"createdAt":     func() bool { return old.CreatedAt == fresh.CreatedAt },
			"expiresAt":     func() bool { return old.ExpiresAt == fresh.ExpiresAt },
			"fingerprint":   func() bool { return old.Fingerprint == fresh.Fingerprint },
			"subject":       func() bool { return old.Subject == fresh.Subject },
			"issuer":        func() bool { return old.Issuer == fresh.Issuer },
			"serial":        func() bool { return old.Serial == fresh.Serial },
			"format":        func() bool { return old.Format == fresh.Format },
			"properties": func() bool {
				if len(old.Properties) != len(fresh.Properties) {
					return false
				}
				for i := range old.Properties {
					if old.Properties[i] != fresh.Properties[i] {
						return false
					}
				}
				return true
			},
		}
		for field, check := range checks {
			if !check() {
				t.Errorf("report-1 field %s changed for %s:\n  old=%#v\n  new=%#v", field, old.Name, old, fresh)
			}
		}
	}
}

// TestScanDeterminism runs the scan twice over the same root and asserts the
// JSON output is byte-identical.
func TestScanDeterminism(t *testing.T) {
	generated := filepath.Join("testdata", "generated")
	bundle, err := os.ReadFile(filepath.Join(generated, "demo-bundle.pem"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	p7b, err := os.ReadFile(filepath.Join(generated, "demo-bundle.p7b"))
	if err != nil {
		t.Fatalf("read p7b: %v", err)
	}
	root := t.TempDir()
	write := func(rel string, data []byte) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/ssl/certs/bundle.pem", bundle)
	write("etc/pki/ca-trust/source/blocklist/bundle.p7b", p7b)
	write("usr/share/ca-certificates/mozilla/bundle.crt", bundle)
	write("etc/ca-certificates.conf", []byte("!mozilla/bundle.crt\n"))

	first := scanForDeterminism(t, root, scanOptions{})
	second := scanForDeterminism(t, root, scanOptions{})
	if !bytes.Equal(first, second) {
		t.Fatalf("scan output is not deterministic:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func scanForDeterminism(t *testing.T, root string, options scanOptions) []byte {
	t.Helper()
	materials, _, err := scanRootfsTrustMaterials(root, options)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	encoded, err := json.Marshal(materials)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

// TestIssuerLinkLimitWarning covers the bound on the O(n^2) issuer pass.
func TestIssuerLinkLimitWarning(t *testing.T) {
	pki := buildTestPKI(t)
	materials := []trustMaterial{}
	certs := map[string]*x509.Certificate{}
	for _, cert := range []*x509.Certificate{pki.rootA, pki.intermediateA, pki.leaf} {
		material := buildCertificateFields(cert)
		setCertificateName(material, cert, "/x.pem")
		materials = append(materials, *material)
		certs[material.CertSHA256] = cert
	}
	oldLimit := issuerLinkLimit
	issuerLinkLimit = 2
	defer func() { issuerLinkLimit = oldLimit }()
	warnings := linkIssuers(materials, certs)
	if len(warnings) == 0 {
		t.Fatal("expected an issuer-linking warning")
	}
	// The leaf keeps working without issuers.
	for i := range materials {
		if len(materials[i].Issuers) != 0 {
			t.Fatalf("expected no issuers when linking is skipped: %#v", materials[i].Issuers)
		}
	}
}

// pqMaterials runs the certs-mode pipeline (parse, dedup, issuer linking)
// over the testdata/pqc fixtures generated by testdata/pqc/gen.sh and
// returns the certificates by name.
func pqMaterials(t *testing.T) map[string]trustMaterial {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "pqc", "*.pem"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no pqc fixtures: %v", err)
	}
	accumulator := newMaterialAccumulator()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range parseFileMaterials(data, "/"+filepath.Base(path), "generic") {
			accumulator.add(entry.material, entry.location)
		}
	}
	materials := accumulator.resolve()
	if warnings := linkIssuers(materials, accumulator.certs); len(warnings) > 0 {
		t.Fatalf("issuer warnings: %v", warnings)
	}
	byName := map[string]trustMaterial{}
	for _, material := range materials {
		byName[strings.TrimSuffix(strings.TrimPrefix(material.Path, "/"), ".pem")] = material
	}
	return byName
}

// PLAN section 2.5: post-quantum keys and signatures are named from their
// OIDs, roots whose signature Go cannot check are still roots (self-issued),
// SHA-1 signatures verify, and issuer links Go cannot verify are reported
// separately from verified ones.
func TestPostQuantumAndLegacyCertificates(t *testing.T) {
	got := pqMaterials(t)
	sha := func(name string) string { return got[name].CertSHA256 }
	for name, want := range map[string]struct {
		key, keyOID, sig, role string
		bits                   int
		selfSigned, unverified bool
		issuers, unverifiedIss []string
	}{
		"mldsa65-root":  {"ML-DSA-65", "2.16.840.1.101.3.4.3.18", "ML-DSA-65", "root", 0, true, false, nil, nil},
		"mldsa44-int":   {"ML-DSA-44", "2.16.840.1.101.3.4.3.17", "ML-DSA-65", "intermediate", 0, false, false, []string{sha("mldsa65-root")}, nil},
		"ecdsa-leaf":    {"ECDSA-P256", "1.2.840.10045.2.1", "ML-DSA-44", "leaf", 256, false, false, []string{sha("mldsa44-int")}, nil},
		"mlkem768-leaf": {"ML-KEM-768", "2.16.840.1.101.3.4.4.2", "ML-DSA-44", "leaf", 0, false, false, []string{sha("mldsa44-int")}, nil},
		"slhdsa-root":   {"SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s", "root", 0, true, true, nil, nil},
		"slhdsa-int":    {"ECDSA-P256", "1.2.840.10045.2.1", "SLH-DSA-SHA2-128s", "intermediate", 256, false, false, nil, []string{sha("slhdsa-root")}},
		"sha1-root":     {"RSA-2048", "1.2.840.113549.1.1.1", "SHA1-RSA", "root", 2048, true, false, nil, nil},
		"sha1-int":      {"RSA-2048", "1.2.840.113549.1.1.1", "SHA1-RSA", "intermediate", 2048, false, false, []string{sha("sha1-root")}, nil},
	} {
		m, ok := got[name]
		if !ok {
			t.Fatalf("%s: not found", name)
		}
		if m.KeyName != want.key || m.KeyAlgorithmOid != want.keyOID || m.KeyBits != want.bits || m.SignatureAlgorithm != want.sig ||
			m.Role != want.role || *m.SelfSigned != want.selfSigned || m.SelfSignedUnverified != want.unverified ||
			!slices.Equal(m.Issuers, want.issuers) || !slices.Equal(m.IssuersUnverified, want.unverifiedIss) {
			t.Errorf("%s = key %s/%s/%d sig %s role %s selfSigned %v/%v issuers %v unverified %v",
				name, m.KeyName, m.KeyAlgorithmOid, m.KeyBits, m.SignatureAlgorithm, m.Role, *m.SelfSigned, m.SelfSignedUnverified, m.Issuers, m.IssuersUnverified)
		}
	}
}

// An algorithm with no known name is named by its dotted OID, and a
// self-issued certificate whose signature algorithm is unknown counts as
// self-signed, unverified. The certificate is a generated ECDSA one whose
// key and signature OIDs are rewritten to unassigned arcs of the same length
// (not issued by any real CA).
func TestUnknownAlgorithmsNamedByOID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "unknown-alg"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	// ecdsa-with-SHA256 1.2.840.10045.4.3.2 -> .4.3.99 (both copies),
	// id-ecPublicKey 1.2.840.10045.2.1 -> .2.99.
	der = bytes.ReplaceAll(der, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x63})
	der = bytes.ReplaceAll(der, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x63})
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	m := buildCertificateFields(cert)
	if m.KeyName != "1.2.840.10045.2.99" || m.KeyAlgorithmOid != "1.2.840.10045.2.99" || m.SignatureAlgorithm != "1.2.840.10045.4.3.99" ||
		!*m.SelfSigned || !m.SelfSignedUnverified || m.Role != "leaf" {
		t.Errorf("unknown algorithms = key %s sig %s selfSigned %v/%v role %s", m.KeyName, m.SignatureAlgorithm, *m.SelfSigned, m.SelfSignedUnverified, m.Role)
	}
}
