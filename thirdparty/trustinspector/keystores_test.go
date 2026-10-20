package main

import (
	"testing"
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
