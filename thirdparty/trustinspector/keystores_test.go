package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func TestJavaTrustStoreJKS(t *testing.T) {
	certs, complete := readJavaTrustStore(fixture(t, "demo-truststore.jks"))
	if !complete {
		t.Fatal("read JKS: incomplete")
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
	certs, err := readPKCS12(fixture(t, "demo-truststore.p12"))
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
	certs, err := readPKCS12(data)
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
	certs, err := readPKCS12(stripped)
	if err != nil {
		t.Fatalf("read MAC-less store with the empty password: %v", err)
	}
	if len(certs) != 1 || !certs[0].Equal(pki.intermediateA) {
		t.Fatalf("expected the intermediate, got %d certs", len(certs))
	}
}

// readPKCS12 decodes a PKCS#12 trust store the way the sniffer does.
func readPKCS12(data []byte) ([]*x509.Certificate, error) {
	cost, ok := pkcs12Iterations(data)
	if !ok {
		return nil, errNotTrustMaterial
	}
	return readPKCS12TrustStore(data, cost)
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
	if _, complete := readJavaTrustStore([]byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02}); complete {
		t.Fatal("expected truncated keystore to error")
	}
	// Absurd entry count must be rejected, not looped on.
	absurd := []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xFF, 0xFF, 0xFF}
	if _, complete := readJavaTrustStore(absurd); complete {
		t.Fatal("expected absurd entry count to error")
	}
	// An entry claiming a huge private-key blob must error out, not allocate.
	huge := []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF}
	if _, complete := readJavaTrustStore(huge); complete {
		t.Fatal("expected implausible length to error")
	}
}

func TestSniffKeystoreByContent(t *testing.T) {
	// The JKS is detected by magic, whatever the file is named.
	sniffed, err := sniffTrustMaterial(fixture(t, "demo-truststore.jks"))
	if err != nil {
		t.Fatalf("sniff JKS: %v", err)
	}
	if len(sniffed.keystores) != 1 || sniffed.keystores[0].format != "JKS" || !sniffed.keystores[0].complete {
		t.Fatalf("expected one readable JKS keystore, got %#v", sniffed.keystores)
	}
	if len(sniffed.keystores[0].certs) != 2 {
		t.Fatalf("expected 2 certs from the JKS, got %d", len(sniffed.keystores[0].certs))
	}
	sniffed, err = sniffTrustMaterial(fixture(t, "demo-truststore.p12"))
	if err != nil {
		t.Fatalf("sniff PKCS#12: %v", err)
	}
	if len(sniffed.keystores) != 1 || sniffed.keystores[0].format != "PKCS12" || !sniffed.keystores[0].complete {
		t.Fatalf("expected one readable PKCS#12 keystore, got %#v", sniffed.keystores)
	}
}

// jksEntry and jksStore build JKS/JCEKS bytes in the OpenJDK layout
// (JavaKeyStore.engineStore): magic, version 2, count, then per entry a tag,
// an alias, an 8-byte date and, for a trusted certificate, the type string
// and the DER. No integrity digest is appended (the reader does not read it).
func jksEntry(tag uint32, alias string, body []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, tag)
	out = binary.BigEndian.AppendUint16(out, uint16(len(alias)))
	out = append(out, alias...)
	out = append(out, make([]byte, 8)...)
	return append(out, body...)
}

func jksCertBody(der []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, 5)
	out = append(out, "X.509"...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(der)))
	return append(out, der...)
}

func jksStore(magic uint32, entries ...[]byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, magic)
	out = binary.BigEndian.AppendUint32(out, 2)
	out = binary.BigEndian.AppendUint32(out, uint32(len(entries)))
	for _, entry := range entries {
		out = append(out, entry...)
	}
	return out
}

// A PEM block hidden in an alias does not shadow the store's real entries.
func TestJKSAliasPEMDecoy(t *testing.T) {
	pki := buildTestPKI(t)
	alias := "decoy\n" + string(pemEncodeCerts(t, pki.leaf)) + "x"
	store := jksStore(jksMagic,
		jksEntry(jksTagTrustedCertificate, alias, jksCertBody(pki.intermediateA.Raw)),
		jksEntry(jksTagTrustedCertificate, "rogue", jksCertBody(pki.rootA.Raw)))
	sniffed, err := sniffTrustMaterial(store)
	if err != nil || len(sniffed.certificates) != 0 || len(sniffed.keystores) != 1 {
		t.Fatalf("sniff = %+v (%v)", sniffed, err)
	}
	if ks := sniffed.keystores[0]; !ks.complete || len(ks.certs) != 2 {
		t.Fatalf("keystore = %d certs, complete %v", len(ks.certs), ks.complete)
	}
}

// A trusted entry Go cannot parse is skipped without losing the others, and
// a JCEKS secret-key entry (a serialized SealedObject that cannot be framed)
// stops the walk but keeps what was read; both mark the store partial.
func TestJavaTrustStorePartialReads(t *testing.T) {
	pki := buildTestPKI(t)
	bad := jksStore(jksMagic,
		jksEntry(jksTagTrustedCertificate, "garbage", jksCertBody([]byte("not a certificate"))),
		jksEntry(jksTagTrustedCertificate, "root", jksCertBody(pki.rootA.Raw)))
	if certs, complete := readJavaTrustStore(bad); complete || len(certs) != 1 {
		t.Fatalf("unparseable entry: %d certs, complete %v", len(certs), complete)
	}
	sealed := jksStore(jceksMagic,
		jksEntry(jksTagTrustedCertificate, "root", jksCertBody(pki.rootA.Raw)),
		jksEntry(jksTagSecretKey, "secret", []byte{0xac, 0xed, 0x00, 0x05, 0x73, 0x72}))
	accumulator := newMaterialAccumulator()
	for _, entry := range parseFileMaterials(sealed, "/usr/lib/jvm/x/lib/security/store.jceks", "java-truststore") {
		accumulator.add(entry.material, entry.location)
	}
	var certs int
	readable := ""
	for _, material := range accumulator.resolve() {
		switch material.Kind {
		case "certificate":
			certs++
		case "keystore":
			for _, p := range material.Properties {
				if p.Name == "cdx:crypto:keystoreReadable" {
					readable = p.Value
				}
			}
		}
	}
	if certs != 1 || readable != "partial" {
		t.Fatalf("JCEKS with a secret key: %d certs, keystoreReadable %q", certs, readable)
	}
}

// A PKCS#12 file declaring an absurd key-derivation iteration count is not
// decoded, so a 1 KiB file cannot stall the scan. The store is a real
// go-pkcs12 encoding whose MAC iteration count is rewritten by the test.
func TestPKCS12IterationCountIsBounded(t *testing.T) {
	pki := buildTestPKI(t)
	data, err := pkcs12.EncodeTrustStore(rand.Reader, []*x509.Certificate{pki.rootA}, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	var pfx []asn1.RawValue
	if _, err := asn1.Unmarshal(data, &pfx); err != nil || len(pfx) != 3 {
		t.Fatalf("pfx: %v", err)
	}
	var macData struct {
		Mac        asn1.RawValue
		MacSalt    []byte
		Iterations int `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(pfx[2].FullBytes, &macData); err != nil {
		t.Fatal(err)
	}
	macData.Iterations = 1 << 30
	if pfx[2].FullBytes, err = asn1.Marshal(macData); err != nil {
		t.Fatal(err)
	}
	bomb, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	sniffed, err := sniffTrustMaterial(bomb)
	if err != nil || len(sniffed.keystores) != 1 || sniffed.keystores[0].complete || len(sniffed.keystores[0].certs) != 0 {
		t.Fatalf("sniff = %+v (%v)", sniffed, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("bounded check took %v", elapsed)
	}
}
