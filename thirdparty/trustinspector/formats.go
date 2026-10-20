package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
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
	openPGP      bool // handled by the existing OpenPGP path
}

type parsedCertificate struct {
	cert *x509.Certificate
	// trustRejectedPurposes comes from the OpenSSL X509_CERT_AUX reject list
	// of a "TRUSTED CERTIFICATE" PEM block; empty for ordinary certificates.
	trustRejectedPurposes []string
}

type privateKeyMaterial struct {
	format string // RSA, EC, PKCS8, ENCRYPTED-PKCS8, OPENSSH
}

type keystoreMaterial struct {
	format   string // JKS, JCEKS, PKCS12
	readable bool
	certs    []*x509.Certificate
}

// contentError marks input that is not parseable as any known format; callers
// treat it as "nothing found", never as a fatal error.
var errNotTrustMaterial = errors.New("not recognized trust material")

// sniffTrustMaterial classifies file content by inspecting its bytes:
// PEM blocks (CERTIFICATE, TRUSTED CERTIFICATE, PKCS7, private keys), raw DER
// certificates, PKCS#7, JKS/JCEKS keystores and PKCS#12 trust stores.
func sniffTrustMaterial(data []byte) (*sniffedMaterial, error) {
	result := &sniffedMaterial{}
	if looksLikeOpenPGP(data) {
		result.openPGP = true
		return result, nil
	}
	if hasPEMHeader(data) {
		parsePEMBlocks(data, result)
		if len(result.certificates) > 0 || len(result.privateKeys) > 0 || len(result.keystores) > 0 {
			return result, nil
		}
	}
	// Raw DER or binary forms.
	if len(result.certificates) == 0 {
		if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
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
	}
	if format, ok := javaKeystoreMagic(data); ok {
		keystore := keystoreMaterial{format: format}
		certs, err := readJavaTrustStore(data)
		if err != nil {
			result.keystores = append(result.keystores, keystoreMaterial{format: format, readable: false})
			return result, nil
		}
		keystore.readable = true
		keystore.certs = certs
		result.keystores = append(result.keystores, keystore)
		return result, nil
	}
	if looksLikePKCS12(data) {
		keystore := keystoreMaterial{format: "PKCS12"}
		certs, err := readPKCS12TrustStore(data)
		if err != nil {
			result.keystores = append(result.keystores, keystoreMaterial{format: "PKCS12", readable: false})
			return result, nil
		}
		keystore.readable = true
		keystore.certs = certs
		result.keystores = append(result.keystores, keystore)
		return result, nil
	}
	return nil, errNotTrustMaterial
}

func looksLikeOpenPGP(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN PGP"))
}

func hasPEMHeader(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN "))
}

// parsePEMBlocks walks PEM blocks in order and dispatches on the block type.
// Unrecognized blocks are skipped, matching report-1 behavior.
func parsePEMBlocks(data []byte, result *sniffedMaterial) {
	remaining := data
	for count := 0; count < pemScanLimit; count++ {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return
		}
		remaining = rest
		switch block.Type {
		case "CERTIFICATE":
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				result.certificates = append(result.certificates, parsedCertificate{cert: cert})
			}
		case "TRUSTED CERTIFICATE":
			if parsed, err := parseTrustedCertificate(block.Bytes); err == nil {
				result.certificates = append(result.certificates, parsed)
			}
		case "PKCS7":
			if certs, err := parsePKCS7(block.Bytes); err == nil {
				for _, cert := range certs {
					result.certificates = append(result.certificates, parsedCertificate{cert: cert})
				}
			}
		default:
			if format, ok := privateKeyPEMFormat(block.Type); ok {
				result.privateKeys = append(result.privateKeys, privateKeyMaterial{format: format})
			}
		}
	}
}

// privateKeyPEMFormat classifies a private key from its PEM header line only.
// The body is never decoded (PLAN section 1, principle 7).
func privateKeyPEMFormat(blockType string) (string, bool) {
	switch blockType {
	case "RSA PRIVATE KEY":
		return "RSA", true
	case "EC PRIVATE KEY":
		return "EC", true
	case "PRIVATE KEY":
		return "PKCS8", true
	case "ENCRYPTED PRIVATE KEY":
		return "ENCRYPTED-PKCS8", true
	case "OPENSSH PRIVATE KEY":
		return "OPENSSH", true
	default:
		return "", false
	}
}

// parseTrustedCertificate splits an OpenSSL "TRUSTED CERTIFICATE" DER into the
// certificate and the appended X509_CERT_AUX, and returns the certificate with
// its reject list.
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
	if len(rest) > 0 {
		if purposes := parseCertificateAuxReject(rest); len(purposes) > 0 {
			parsed.trustRejectedPurposes = purposes
		}
	}
	return parsed, nil
}

// parseCertificateAuxReject reads the reject OIDs out of an X509_CERT_AUX.
// Unknown OIDs are reported dotted; recognized id-kp OIDs use the same short
// names as extKeyUsage (RFC 5280 section 4.2.1.12).
func parseCertificateAuxReject(aux []byte) []string {
	var auxStructure struct {
		Trust  []asn1.ObjectIdentifier `asn1:"optional"`
		Reject []asn1.ObjectIdentifier `asn1:"tag:0,optional"`
		Alias  string                  `asn1:"optional"`
		KeyID  []byte                  `asn1:"optional"`
		Other  []asn1.RawValue         `asn1:"tag:1,optional"`
	}
	if _, err := asn1.Unmarshal(aux, &auxStructure); err != nil {
		return nil
	}
	if len(auxStructure.Reject) == 0 {
		return nil
	}
	purposes := make([]string, 0, len(auxStructure.Reject))
	for _, oid := range auxStructure.Reject {
		purposes = append(purposes, extKeyUsageOIDName(oid))
	}
	return uniqueSortedStrings(purposes)
}

// extKeyUsageOIDName maps id-kp OIDs (RFC 5280 section 4.2.1.12) to their
// short names; anything else stays dotted.
func extKeyUsageOIDName(oid asn1.ObjectIdentifier) string {
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
	if name, ok := names[oid.String()]; ok {
		return name
	}
	return oid.String()
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

// looksLikePKCS12 is a cheap pre-check before handing bytes to the PKCS#12
// decoder: the outer element must be a SEQUENCE carrying the PFX version
// INTEGER 3 (RFC 7292 section 4: PFX ::= SEQUENCE { version INTEGER, ... }) —
// the DER bytes 02 01 03 appear near the start of every PFX.
func looksLikePKCS12(data []byte) bool {
	if len(data) < 8 || data[0] != 0x30 {
		return false
	}
	index := bytes.Index(data, []byte{0x02, 0x01, 0x03})
	return index >= 0 && index < 16
}

// embeddedCertificateBlocks extracts PEM CERTIFICATE blocks from binary
// content (go:embed pools, packaged resources). DER-embedded certificates are
// out of scope (PLAN section 4.1).
func embeddedCertificateBlocks(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	begin := []byte("-----BEGIN CERTIFICATE-----")
	offset := 0
	for count := 0; count < pemScanLimit; count++ {
		index := bytes.Index(data[offset:], begin)
		if index < 0 {
			return certs
		}
		block, rest := pem.Decode(data[offset+index:])
		if block == nil {
			return certs
		}
		offset += index + (len(data) - (offset + index) - len(rest))
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}
