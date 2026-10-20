package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func TestJavaTrustStoreJKS(t *testing.T) {
	certs, err := readJavaTrustStore(fixture(t, "demo-truststore.jks"))
	if err != nil {
		t.Fatalf("read JKS: %v", err)
	}
	// keytool -list reports 2 trustedCertEntry entries (inspector-int,
	// inspector-root); the reader must agree.
	if len(certs) != 2 {
		t.Fatalf("expected 2 trusted certificates, got %d", len(certs))
	}
	names := map[string]bool{}
	for _, cert := range certs {
		names[cert.Subject.CommonName] = true
	}
	if !names["Inspector Root A"] || !names["Inspector Issuing CA"] {
		t.Fatalf("unexpected certificate subjects: %v", names)
	}
}

func TestPKCS12TrustStoreKeytool(t *testing.T) {
	certs, err := readPKCS12TrustStore(fixture(t, "demo-truststore.p12"))
	if err != nil {
		t.Fatalf("read PKCS#12: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "Inspector Issuing CA" {
		t.Fatalf("expected the issuing CA, got %d certs", len(certs))
	}
}

// TestPKCS12TrustStoreEmptyPassword pins the empty-password retry for stores
// not written with the JDK default "changeit": "changeit" fails with
// ErrIncorrectPassword and the retry must decode the store. The store is
// encoded at test time with go-pkcs12's own encoder, the reference
// implementation of the format.
func TestPKCS12TrustStoreEmptyPassword(t *testing.T) {
	pki := buildTestPKI(t)
	data, err := pkcs12.EncodeTrustStore(rand.Reader, []*x509.Certificate{pki.intermediateA}, "")
	if err != nil {
		t.Fatalf("encode empty-password trust store: %v", err)
	}
	if _, err := pkcs12.DecodeTrustStore(data, "changeit"); err == nil {
		t.Fatal("expected changeit to fail on an empty-password store")
	}
	certs, err := readPKCS12TrustStore(data)
	if err != nil {
		t.Fatalf("read with the empty-password retry: %v", err)
	}
	if len(certs) != 1 || !certs[0].Equal(pki.intermediateA) {
		t.Fatalf("expected the intermediate, got %d certs", len(certs))
	}
}

// TestPKCS12TrustStoreMACLess pins the retry for MAC-less stores, the shape
// JDK cacerts ships in since Java 9: RFC 7292 makes macData OPTIONAL, and
// go-pkcs12 rejects a non-empty password on such files with "no MAC in data"
// (not ErrIncorrectPassword), so the retry must trigger on any error.
func TestPKCS12TrustStoreMACLess(t *testing.T) {
	pki := buildTestPKI(t)
	data, err := pkcs12.EncodeTrustStore(rand.Reader, []*x509.Certificate{pki.intermediateA}, "")
	if err != nil {
		t.Fatalf("encode trust store: %v", err)
	}
	stripped, err := stripPKCS12MacData(data)
	if err != nil {
		t.Fatalf("strip macData: %v", err)
	}
	if bytes.Equal(stripped, data) {
		t.Fatal("expected the stripped DER to differ from the encoded store")
	}
	if _, err := pkcs12.DecodeTrustStore(stripped, "changeit"); err == nil {
		t.Fatal("expected changeit to fail on a MAC-less store")
	}
	certs, err := readPKCS12TrustStore(stripped)
	if err != nil {
		t.Fatalf("read MAC-less store with the empty password: %v", err)
	}
	if len(certs) != 1 || !certs[0].Equal(pki.intermediateA) {
		t.Fatalf("expected the intermediate, got %d certs", len(certs))
	}
}

// stripPKCS12MacData re-encodes a PFX DER with only its first two elements
// (version and authSafe), dropping the optional macData (RFC 7292 appendix).
func stripPKCS12MacData(data []byte) ([]byte, error) {
	var pfx []asn1.RawValue
	if _, err := asn1.Unmarshal(data, &pfx); err != nil {
		return nil, err
	}
	if len(pfx) < 2 {
		return nil, asn1.SyntaxError{Msg: "pfx too short"}
	}
	return asn1.Marshal(pfx[:2])
}

func TestJavaTrustStoreWrongMagicAndTruncation(t *testing.T) {
	if _, ok := javaKeystoreMagic([]byte{0xDE, 0xAD, 0xBE, 0xEF}); ok {
		t.Fatal("wrong magic must not be detected as a Java keystore")
	}
	if format, ok := javaKeystoreMagic([]byte{0xFE, 0xED, 0xFE, 0xED}); !ok || format != "JKS" {
		t.Fatalf("expected JKS magic, got %q ok=%v", format, ok)
	}
	if format, ok := javaKeystoreMagic([]byte{0xCE, 0xCE, 0xCE, 0xCE}); !ok || format != "JCEKS" {
		t.Fatalf("expected JCEKS magic, got %q ok=%v", format, ok)
	}
	// Truncated after the version.
	if _, err := readJavaTrustStore([]byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02}); err == nil {
		t.Fatal("expected truncated keystore to error")
	}
	// Absurd entry count must be rejected, not looped on.
	absurd := []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xFF, 0xFF, 0xFF}
	if _, err := readJavaTrustStore(absurd); err == nil {
		t.Fatal("expected absurd entry count to error")
	}
	// An entry claiming a huge private-key blob must error out, not allocate.
	huge := []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF}
	if _, err := readJavaTrustStore(huge); err == nil {
		t.Fatal("expected implausible length to error")
	}
}

func TestSniffKeystoreByContent(t *testing.T) {
	// The JKS is detected by magic, whatever the file is named.
	sniffed, err := sniffTrustMaterial(fixture(t, "demo-truststore.jks"))
	if err != nil {
		t.Fatalf("sniff JKS: %v", err)
	}
	if len(sniffed.keystores) != 1 || sniffed.keystores[0].format != "JKS" || !sniffed.keystores[0].readable {
		t.Fatalf("expected one readable JKS keystore, got %#v", sniffed.keystores)
	}
	if len(sniffed.keystores[0].certs) != 2 {
		t.Fatalf("expected 2 certs from the JKS, got %d", len(sniffed.keystores[0].certs))
	}
	sniffed, err = sniffTrustMaterial(fixture(t, "demo-truststore.p12"))
	if err != nil {
		t.Fatalf("sniff PKCS#12: %v", err)
	}
	if len(sniffed.keystores) != 1 || sniffed.keystores[0].format != "PKCS12" || !sniffed.keystores[0].readable {
		t.Fatalf("expected one readable PKCS#12 keystore, got %#v", sniffed.keystores)
	}
}
