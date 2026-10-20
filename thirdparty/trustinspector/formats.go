package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Byte-level format detection and parsing for certificates and related
// trust material. Formats are detected by content, never by extension.

// pemScanLimit bounds how many PEM blocks are read from one file. It stops
// hostile or corrupt files from producing unbounded work.
const pemScanLimit = 2000

// sniffedMaterial is the parsed content of one file, before locations and
// deduplication are applied.
type sniffedMaterial struct {
	certificates []parsedCertificate
	privateKeys  []privateKeyMaterial
	keystores    []keystoreMaterial
}

type parsedCertificate struct {
	cert *x509.Certificate
	// trustAcceptedPurposes and trustRejectedPurposes come from the OpenSSL
	// X509_CERT_AUX trust and reject lists of a "TRUSTED CERTIFICATE" PEM
	// block; empty for ordinary certificates.
	trustAcceptedPurposes []string
	trustRejectedPurposes []string
}

type privateKeyMaterial struct {
	format string // RSA, EC, DSA, PKCS8, ENCRYPTED-PKCS8, ENCRYPTED-RSA, ..., OPENSSH
}

type keystoreMaterial struct {
	format string // JKS, JCEKS, PKCS12
	// complete is false when some or all of the store could not be read;
	// certs holds what was read.
	complete bool
	certs    []*x509.Certificate
}

// errNotTrustMaterial marks input that is not parseable as any known format;
// callers treat it as "nothing found", never as a fatal error.
var errNotTrustMaterial = errors.New("not recognized trust material")

// sniffTrustMaterial classifies file content by inspecting its bytes. Binary
// containers come first (the JKS/JCEKS magic, the PKCS#12 PFX structure, DER
// certificates and PKCS#7): their payload can carry PEM text (an alias, a
// certificate extension) that must not shadow the real entries. PEM blocks
// (CERTIFICATE, TRUSTED CERTIFICATE, PKCS7, private keys) are read only from
// content that is none of those. OpenPGP armor is left to the OpenPGP reader.
func sniffTrustMaterial(data []byte) (*sniffedMaterial, error) {
	result := &sniffedMaterial{}
	if format, ok := javaKeystoreMagic(data); ok {
		certs, complete := readJavaTrustStore(data)
		result.keystores = append(result.keystores, keystoreMaterial{format: format, complete: complete, certs: certs})
		return result, nil
	}
	if cost, ok := pkcs12Iterations(data); ok {
		certs, err := readPKCS12TrustStore(data, cost)
		result.keystores = append(result.keystores, keystoreMaterial{format: "PKCS12", complete: err == nil, certs: certs})
		return result, nil
	}
	if certs := parseDERCertificates(data); len(certs) > 0 {
		for _, cert := range certs {
			result.certificates = append(result.certificates, parsedCertificate{cert: cert})
		}
		return result, nil
	}
	if certs, err := parsePKCS7(data); err == nil && len(certs) > 0 {
		for _, cert := range certs {
			result.certificates = append(result.certificates, parsedCertificate{cert: cert})
		}
		return result, nil
	}
	parsePEMBlocks(data, result)
	if len(result.certificates) == 0 && len(result.privateKeys) == 0 {
		return nil, errNotTrustMaterial
	}
	return result, nil
}

// parseDERCertificates reads one or more concatenated DER certificates. A
// single certificate followed by other bytes (a trailing newline, say) is
// accepted too, as OpenSSL's DER reader does.
func parseDERCertificates(data []byte) []*x509.Certificate {
	if len(data) == 0 || data[0] != 0x30 {
		return nil
	}
	if certs, err := x509.ParseCertificates(data); err == nil {
		return certs
	}
	var element asn1.RawValue
	if _, err := asn1.Unmarshal(data, &element); err != nil {
		return nil
	}
	if cert, err := x509.ParseCertificate(element.FullBytes); err == nil {
		return []*x509.Certificate{cert}
	}
	return nil
}

// pemBlock is one "-----BEGIN <type>-----" ... "-----END <type>-----" block:
// its type and its text from the BEGIN marker through the END marker.
type pemBlock struct {
	typ  string
	text []byte
}

// eachPEMBlock finds PEM blocks anywhere in data (embedded in a binary, or
// with no newline after the END marker, both of which Go's crypto/x509
// accepts in AppendCertsFromPEM's input once isolated) and calls fn for each,
// at most pemScanLimit. A BEGIN marker with no matching END is skipped and
// the scan goes on after it, so a broken block cannot hide the ones after it.
// Nothing is decoded here.
func eachPEMBlock(data []byte, fn func(pemBlock)) {
	begin := []byte("-----BEGIN ")
	dashes := []byte("-----")
	offset := 0
	for count := 0; count < pemScanLimit && offset < len(data); count++ {
		index := bytes.Index(data[offset:], begin)
		if index < 0 {
			return
		}
		start := offset + index
		typeStart := start + len(begin)
		offset = typeStart
		typeLen := bytes.Index(data[typeStart:], dashes)
		if typeLen <= 0 || typeLen > 64 || bytes.ContainsAny(data[typeStart:typeStart+typeLen], "\r\n") {
			continue
		}
		typ := string(data[typeStart : typeStart+typeLen])
		bodyStart := typeStart + typeLen
		endMarker := []byte("-----END " + typ + "-----")
		endIndex := bytes.Index(data[bodyStart:], endMarker)
		if endIndex < 0 {
			continue
		}
		// Another BEGIN before this block's END means this one is broken;
		// the scan resumes at that BEGIN rather than swallowing its block.
		if next := bytes.Index(data[bodyStart:bodyStart+endIndex], begin); next >= 0 {
			continue
		}
		end := bodyStart + endIndex + len(endMarker)
		fn(pemBlock{typ: typ, text: data[start:end]})
		offset = end
	}
}

// decode base64-decodes a block that was isolated by eachPEMBlock.
func (b pemBlock) decode() []byte {
	text := make([]byte, 0, len(b.text)+1)
	text = append(append(text, b.text...), '\n')
	if block, _ := pem.Decode(text); block != nil {
		return block.Bytes
	}
	return nil
}

// parsePEMBlocks dispatches PEM blocks on their type. Unrecognized blocks are
// skipped, matching report-1 behavior. Private keys are classified from the
// BEGIN line and the RFC 1421 Proc-Type header only; their body is never
// decoded (PLAN section 1, principle 7).
func parsePEMBlocks(data []byte, result *sniffedMaterial) {
	eachPEMBlock(data, func(block pemBlock) {
		switch block.typ {
		// "X509 CERTIFICATE" is OpenSSL's legacy label (PEM_STRING_X509_OLD),
		// which it still reads as a certificate.
		case "CERTIFICATE", "X509 CERTIFICATE":
			if cert, err := x509.ParseCertificate(block.decode()); err == nil {
				result.certificates = append(result.certificates, parsedCertificate{cert: cert})
			}
		case "TRUSTED CERTIFICATE":
			if parsed, err := parseTrustedCertificate(block.decode()); err == nil {
				result.certificates = append(result.certificates, parsed)
			}
		case "PKCS7", "CMS":
			if certs, err := parsePKCS7(block.decode()); err == nil {
				for _, cert := range certs {
					result.certificates = append(result.certificates, parsedCertificate{cert: cert})
				}
			}
		default:
			if format, ok := privateKeyPEMFormat(block); ok {
				result.privateKeys = append(result.privateKeys, privateKeyMaterial{format: format})
			}
		}
	})
}

// privateKeyPEMFormat classifies a private key from its BEGIN line, and marks
// legacy OpenSSL keys whose Proc-Type header says ENCRYPTED. The header
// cannot occur in the base64 body, whose alphabet has no ':' or ','.
func privateKeyPEMFormat(block pemBlock) (string, bool) {
	var format string
	switch block.typ {
	case "RSA PRIVATE KEY":
		format = "RSA"
	case "EC PRIVATE KEY":
		format = "EC"
	case "DSA PRIVATE KEY":
		format = "DSA"
	case "PRIVATE KEY":
		return "PKCS8", true
	case "ENCRYPTED PRIVATE KEY":
		return "ENCRYPTED-PKCS8", true
	case "OPENSSH PRIVATE KEY":
		return "OPENSSH", true
	default:
		return "", false
	}
	if bytes.Contains(block.text, []byte("Proc-Type: 4,ENCRYPTED")) {
		format = "ENCRYPTED-" + format
	}
	return format, true
}

// parseTrustedCertificate splits an OpenSSL "TRUSTED CERTIFICATE" DER into the
// certificate and the appended X509_CERT_AUX, and returns the certificate with
// its trust and reject lists.
//
// The on-disk layout is the certificate DER followed by the aux DER: OpenSSL's
// i2d_X509_AUX/d2i_X509_AUX append or consume the aux structure after the
// plain certificate ("This data is appended to the X509 encoding when the
// *_X509_AUX routines are used"). The aux ASN.1 (OpenSSL 3.5,
// crypto/x509/x_x509a.c,
// https://github.com/openssl/openssl/blob/openssl-3.5/crypto/x509/x_x509a.c):
//
//	X509_CERT_AUX ::= SEQUENCE {
//	    trust  SEQUENCE OF OID        OPTIONAL,  -- trusted purposes
//	    reject [0] IMPLICIT SEQUENCE OF OID OPTIONAL,
//	    alias  UTF8String             OPTIONAL,
//	    keyid  OCTET STRING           OPTIONAL,
//	    other  [1] IMPLICIT SEQUENCE OF AlgorithmIdentifier OPTIONAL }
//
// A non-empty trust list matters as much as the reject list: OpenSSL then
// rejects every purpose not on it (obj_trust in crypto/x509/x509_trust.c).
func parseTrustedCertificate(der []byte) (parsedCertificate, error) {
	parsed := parsedCertificate{}
	var certValue asn1.RawValue
	rest, err := asn1.Unmarshal(der, &certValue)
	if err != nil {
		return parsed, err
	}
	cert, err := x509.ParseCertificate(certValue.FullBytes)
	if err != nil {
		return parsed, err
	}
	parsed.cert = cert
	parsed.trustAcceptedPurposes, parsed.trustRejectedPurposes = parseCertificateAux(rest)
	return parsed, nil
}

// parseCertificateAux reads the trust and reject OID lists out of an
// X509_CERT_AUX. It walks the elements one by one instead of unmarshalling
// the whole structure, so a field this reader does not need (an alias that
// is not valid UTF-8, an OID arc wider than 64 bits) cannot hide the lists,
// which OpenSSL still honors in that case. Recognized id-kp OIDs use the same
// short names as extKeyUsage (RFC 5280 section 4.2.1.12); others stay dotted.
func parseCertificateAux(aux []byte) (accepted, rejected []string) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(aux, &outer); err != nil || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return nil, nil
	}
	remaining := outer.Bytes
	for len(remaining) > 0 {
		var element asn1.RawValue
		var err error
		if remaining, err = asn1.Unmarshal(remaining, &element); err != nil {
			break
		}
		switch {
		case element.Class == asn1.ClassUniversal && element.Tag == asn1.TagSequence && element.IsCompound:
			accepted = append(accepted, purposeNames(element.Bytes)...)
		case element.Class == asn1.ClassContextSpecific && element.Tag == 0 && element.IsCompound:
			rejected = append(rejected, purposeNames(element.Bytes)...)
		}
	}
	return uniqueSortedStrings(accepted), uniqueSortedStrings(rejected)
}

// purposeNames reads a sequence of OBJECT IDENTIFIER elements into purpose
// names.
func purposeNames(content []byte) []string {
	var names []string
	for count := 0; len(content) > 0 && count < pemScanLimit; count++ {
		var element asn1.RawValue
		var err error
		if content, err = asn1.Unmarshal(content, &element); err != nil {
			break
		}
		if element.Class != asn1.ClassUniversal || element.Tag != asn1.TagOID {
			continue
		}
		if oid, ok := dottedOID(element.Bytes); ok {
			names = append(names, extKeyUsageOIDName(oid))
		}
	}
	return names
}

// dottedOID renders the content octets of an OBJECT IDENTIFIER (X.690
// section 8.19) in dotted form, with arcs of any size.
func dottedOID(content []byte) (string, bool) {
	if len(content) == 0 || content[len(content)-1]&0x80 != 0 {
		return "", false
	}
	var arcs []*big.Int
	arc := new(big.Int)
	for _, b := range content {
		arc.Lsh(arc, 7)
		arc.Or(arc, big.NewInt(int64(b&0x7f)))
		if b&0x80 == 0 {
			arcs = append(arcs, arc)
			arc = new(big.Int)
		}
	}
	// The first subidentifier packs the first two arcs (X.690 8.19.4).
	first := arcs[0]
	parts := make([]string, 0, len(arcs)+1)
	switch {
	case first.Cmp(big.NewInt(40)) < 0:
		parts = append(parts, "0", first.String())
	case first.Cmp(big.NewInt(80)) < 0:
		parts = append(parts, "1", new(big.Int).Sub(first, big.NewInt(40)).String())
	default:
		parts = append(parts, "2", new(big.Int).Sub(first, big.NewInt(80)).String())
	}
	for _, a := range arcs[1:] {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, "."), true
}

// extKeyUsageOIDName maps id-kp OIDs (RFC 5280 section 4.2.1.12) to their
// short names; anything else stays dotted.
func extKeyUsageOIDName(oid string) string {
	names := map[string]string{
		"2.5.29.37.0":            "any",
		"1.3.6.1.5.5.7.3.1":      "serverAuth",
		"1.3.6.1.5.5.7.3.2":      "clientAuth",
		"1.3.6.1.5.5.7.3.3":      "codeSigning",
		"1.3.6.1.5.5.7.3.4":      "emailProtection",
		"1.3.6.1.5.5.7.3.8":      "timeStamping",
		"1.3.6.1.5.5.7.3.9":      "ocspSigning",
		"1.3.6.1.4.1.311.10.3.1": "microsoftCommercialCodeSigning",
		"1.3.6.1.4.1.311.10.3.2": "microsoftKernelCodeSigning",
		"1.3.6.1.5.5.8.2.2":      "ipsecEndSystem",
		"1.3.6.1.5.5.8.2.3":      "ipsecTunnel",
		"1.3.6.1.5.5.8.2.4":      "ipsecUser",
	}
	if name, ok := names[oid]; ok {
		return name
	}
	return oid
}

// parsePKCS7 extracts the certificate set from a PKCS#7 SignedData content
// (RFC 5652 section 5.1). Only the optional [0] certificates field is read;
// signatures are not verified. Both PEM-decoded DER and raw DER arrive here.
func parsePKCS7(der []byte) ([]*x509.Certificate, error) {
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
	}
	if _, err := asn1.Unmarshal(der, &contentInfo); err != nil {
		return nil, err
	}
	// id-signedData (RFC 5652 section 5.1)
	if !contentInfo.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return nil, fmt.Errorf("pkcs7: content type %s is not signedData", contentInfo.ContentType)
	}
	if len(contentInfo.Content.FullBytes) == 0 {
		return nil, errors.New("pkcs7: signedData content missing")
	}
	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue `asn1:"implicit,tag:0,optional"`
		CRLs             asn1.RawValue `asn1:"implicit,tag:1,optional"`
		SignerInfos      asn1.RawValue
	}
	// For an explicitly tagged RawValue, Bytes holds the payload inside the
	// [0] header: the DER SignedData SEQUENCE (RFC 5652 section 5.1).
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, err
	}
	if len(signedData.Certificates.FullBytes) == 0 {
		return nil, nil
	}
	// Certificates is [0] IMPLICIT SET OF Certificate, so after the implicit
	// header the content is the concatenated certificate TLVs; encoding/asn1
	// cannot unmarshal that context-tagged container as a slice, so the
	// elements are walked directly from the content bytes.
	var certs []*x509.Certificate
	remaining := signedData.Certificates.Bytes
	for count := 0; len(remaining) > 0 && count < pemScanLimit; count++ {
		var element asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &element)
		if err != nil {
			break
		}
		if cert, err := x509.ParseCertificate(element.FullBytes); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// embeddedCertificateBlocks extracts PEM CERTIFICATE blocks from binary
// content (go:embed pools, packaged resources). A Go string constant puts the
// END marker straight against other bytes, which is why eachPEMBlock isolates
// each block before decoding it. DER-embedded certificates are out of scope
// (PLAN section 4.1).
func embeddedCertificateBlocks(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	eachPEMBlock(data, func(block pemBlock) {
		if block.typ != "CERTIFICATE" {
			return
		}
		if cert, err := x509.ParseCertificate(block.decode()); err == nil {
			certs = append(certs, cert)
		}
	})
	return certs
}
