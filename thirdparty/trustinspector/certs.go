package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Certificate identity for trustinspector/report-2. Every field is additive;
// the report-1 keys (fingerprint, serial, sha1/sha256, ...) keep their
// meaning, so a report-1 consumer keeps parsing unchanged.

// dnsNamesLimit caps the reported dnsNames list; dnsNamesTruncated marks a
// capped list.
const dnsNamesLimit = 20

// issuerLinkLimit bounds the O(n^2) issuer verification pass. Past it, issuer
// linking is skipped and an envelope warning is emitted. It is a variable so
// tests can tighten it; production keeps 5000.
var issuerLinkLimit = 5000

// pqAlgorithm is a post-quantum algorithm as certificates identify it:
// ML-DSA (FIPS 204, RFC 9881), SLH-DSA (FIPS 205, RFC 9909) and ML-KEM
// (FIPS 203, RFC 9935). Keys and signatures are named from these OIDs, not
// from crypto/x509, which (as of Go 1.27) knows ML-DSA but neither SLH-DSA
// nor ML-KEM. PLAN section 2.5 is the contract; cdxgen and safer-exec use the
// same names.
type pqAlgorithm struct{ oid, name string }

var pqAlgorithms = []pqAlgorithm{
	{"2.16.840.1.101.3.4.3.17", "ML-DSA-44"},
	{"2.16.840.1.101.3.4.3.18", "ML-DSA-65"},
	{"2.16.840.1.101.3.4.3.19", "ML-DSA-87"},
	{"2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"},
	{"2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f"},
	{"2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192s"},
	{"2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192f"},
	{"2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s"},
	{"2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f"},
	{"2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s"},
	{"2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128f"},
	{"2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192s"},
	{"2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192f"},
	{"2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256s"},
	{"2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f"},
	{"2.16.840.1.101.3.4.4.1", "ML-KEM-512"},
	{"2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
	{"2.16.840.1.101.3.4.4.3", "ML-KEM-1024"},
}

func pqAlgorithmName(oid string) (string, bool) {
	for _, a := range pqAlgorithms {
		if a.oid == oid {
			return a.name, true
		}
	}
	return "", false
}

// nameConstraintsOID is the RFC 5280 section 4.2.1.10 extension. Go does not
// expose a "hasNameConstraints" bit, so presence of the extension is checked
// in the parsed extension list.
var nameConstraintsOID = asn1.ObjectIdentifier{2, 5, 29, 30}

// certLocation records where one certificate (or other material) was found.
// Report-1 kept only the first location; report-2 keeps every location.
type certLocation struct {
	path          string
	sourceType    string
	trustDomain   string
	fileExtension string
	sha1Value     string
	sha256Value   string
	// hostStore labels the host trust store this location came from (host
	// mode only), so a certificate found in several stores carries them all.
	hostStore string
}

// materialAccumulator deduplicates materials by identity
// (certSha256 || fingerprint || sha256 || path) and accumulates every
// location per identity, so no occurrence is lost.
type materialAccumulator struct {
	order     []string
	materials map[string]*trustMaterial
	locations map[string][]certLocation
	// certs keeps the parsed certificate per certSha256 for issuer linking.
	certs map[string]*x509.Certificate
}

func newMaterialAccumulator() *materialAccumulator {
	return &materialAccumulator{
		materials: map[string]*trustMaterial{},
		locations: map[string][]certLocation{},
		certs:     map[string]*x509.Certificate{},
	}
}

func materialDedupKey(material *trustMaterial) string {
	return material.Kind + "\x00" + firstNonEmpty(material.CertSHA256, material.Fingerprint, material.SHA256, material.dedupID, material.Path)
}

func (a *materialAccumulator) add(material *trustMaterial, location certLocation) {
	key := materialDedupKey(material)
	if _, ok := a.materials[key]; !ok {
		copied := *material
		a.materials[key] = &copied
		a.order = append(a.order, key)
	}
	if material.Kind == "certificate" && material.CertSHA256 != "" {
		if _, ok := a.certs[material.CertSHA256]; !ok {
			a.certs[material.CertSHA256] = material.certificate
		}
	}
	a.locations[key] = append(a.locations[key], location)
}

// resolve merges the accumulated locations into one material per identity.
// path becomes the lexicographically smallest path (an embedded-binary
// location only when there is no other), and sourceType,
// sha1/sha256, trustDomain and fileExtension follow that path, which keeps
// the report-1 meaning of those fields ("sha1/sha256 are the file digests of
// path").
func (a *materialAccumulator) resolve() []trustMaterial {
	results := make([]trustMaterial, 0, len(a.order))
	for _, key := range a.order {
		material := a.materials[key]
		locations := a.locations[key]
		// The primary location is the smallest path, preferring files that
		// are trust material themselves over binaries embedding the
		// certificate, so sourceType and the report-1 fields describe the
		// trust store a certificate is in.
		sort.Slice(locations, func(i, j int) bool {
			if ei, ej := locations[i].sourceType == "embedded-binary", locations[j].sourceType == "embedded-binary"; ei != ej {
				return ej
			}
			return locations[i].path < locations[j].path
		})
		var paths []string
		var sourceTypes []string
		var hostStores []string
		seenPath := map[string]bool{}
		seenSource := map[string]bool{}
		seenStore := map[string]bool{}
		for _, location := range locations {
			if !seenPath[location.path] {
				seenPath[location.path] = true
				paths = append(paths, location.path)
			}
			if location.sourceType != "" && !seenSource[location.sourceType] {
				seenSource[location.sourceType] = true
				sourceTypes = append(sourceTypes, location.sourceType)
			}
			if location.hostStore != "" && !seenStore[location.hostStore] {
				seenStore[location.hostStore] = true
				hostStores = append(hostStores, location.hostStore)
			}
		}
		sort.Strings(paths)
		sort.Strings(sourceTypes)
		sort.Strings(hostStores)
		first := locations[0]
		material.Path = first.path
		material.Paths = paths
		material.SourceType = first.sourceType
		material.SourceTypes = sourceTypes
		material.HostStores = hostStores
		material.SHA1 = first.sha1Value
		material.SHA256 = first.sha256Value
		material.TrustDomain = first.trustDomain
		material.FileExtension = first.fileExtension
		material.Properties = buildMaterialProperties(material, first)
		results = append(results, *material)
	}
	sort.Slice(results, func(i, j int) bool { return materialLess(results[i], results[j]) })
	return results
}

// buildMaterialProperties rebuilds the per-material property list from the
// material and its primary (smallest-path) location. The report-1 properties
// keep their names and values; nothing new is added here so the report-1
// consumer output is unchanged.
func buildMaterialProperties(material *trustMaterial, location certLocation) []property {
	var values []property
	switch material.Kind {
	case "certificate":
		values = []property{
			{Name: "cdx:crypto:sourceType", Value: location.sourceType},
			{Name: "cdx:crypto:trustDomain", Value: location.trustDomain},
			{Name: "cdx:crypto:fileExtension", Value: firstNonEmpty(location.fileExtension, "crt")},
			{Name: "cdx:crypto:isCA", Value: fmt.Sprintf("%t", material.IsCA != nil && *material.IsCA)},
		}
	case "public-key":
		values = []property{
			{Name: "cdx:crypto:sourceType", Value: location.sourceType},
			{Name: "cdx:crypto:trustDomain", Value: location.trustDomain},
			{Name: "cdx:crypto:fileExtension", Value: firstNonEmpty(location.fileExtension, "gpg")},
		}
	default:
		values = []property{
			{Name: "cdx:crypto:sourceType", Value: location.sourceType},
		}
		// A keystore's readability is a fact about the file, not the
		// location; keep it.
		for _, p := range material.Properties {
			if p.Name == "cdx:crypto:keystoreReadable" {
				values = append(values, p)
			}
		}
	}
	return uniqueProperties(values)
}

func materialIdentity(material trustMaterial) string {
	return firstNonEmpty(material.CertSHA256, material.Fingerprint, material.SHA256, material.dedupID)
}

// materialLess is the total order over materials:
// (kind, certSha256 || fingerprint || sha256, path). No map iteration order
// or unstable sort reaches the output.
func materialLess(a, b trustMaterial) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	ai, bi := materialIdentity(a), materialIdentity(b)
	if ai != bi {
		return ai < bi
	}
	return a.Path < b.Path
}

// buildCertificateFields fills the report-2 identity fields for one parsed
// certificate. Location fields (path, digests, sourceType) are added later by
// the accumulator.
func buildCertificateFields(cert *x509.Certificate) *trustMaterial {
	certSHA := sha256SumHex(cert.Raw)
	spkiSHA := sha256SumHex(cert.RawSubjectPublicKeyInfo)
	selfSigned, unverified := certificateSelfSigned(cert)
	keyName, keyBits, keyOID := publicKeyID(cert)
	isCA := cert.IsCA
	material := &trustMaterial{
		certificate:            cert,
		Kind:                   "certificate",
		Name:                   cert.Subject.CommonName,
		Algorithm:              publicKeyType(cert.PublicKeyAlgorithm),
		KeyStrength:            certificateKeyStrength(cert),
		CreatedAt:              cert.NotBefore.UTC().Format(time.RFC3339),
		ExpiresAt:              cert.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint:            strings.ToUpper(certSHA),
		Subject:                cert.Subject.String(),
		Issuer:                 cert.Issuer.String(),
		Serial:                 cert.SerialNumber.String(),
		SerialHex:              fmt.Sprintf("%x", cert.SerialNumber),
		Format:                 "X.509",
		CertSHA256:             certSHA,
		SPKISHA256:             spkiSHA,
		SPKISHA256Base64:       base64.StdEncoding.EncodeToString(sha256SumBytes(cert.RawSubjectPublicKeyInfo)),
		CertVersion:            cert.Version,
		IsCA:                   &isCA,
		SelfSigned:             &selfSigned,
		SelfSignedUnverified:   unverified,
		Role:                   certificateRole(cert, selfSigned),
		KeyName:                keyName,
		KeyBits:                keyBits,
		KeyAlgorithmOid:        keyOID,
		SubjectKeyId:           hex.EncodeToString(cert.SubjectKeyId),
		AuthorityKeyId:         hex.EncodeToString(cert.AuthorityKeyId),
		KeyUsage:               keyUsageNames(cert.KeyUsage),
		ExtKeyUsage:            extKeyUsageNames(cert),
		SignatureAlgorithm:     signatureAlgorithmName(cert),
		SignatureAlgorithmOid:  signatureAlgorithmOID(cert),
		DNSNames:               truncateStrings(cert.DNSNames, dnsNamesLimit),
		DNSNamesTruncated:      len(cert.DNSNames) > dnsNamesLimit,
		OCSPServers:            sortedCopy(cert.OCSPServer),
		IssuingCertificateURLs: sortedCopy(cert.IssuingCertificateURL),
		CRLDistributionPoints:  sortedCopy(cert.CRLDistributionPoints),
		PolicyOIDs:             policyOIDStrings(cert),
		HasNameConstraints:     certificateHasNameConstraints(cert),
	}
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		pathLen := cert.MaxPathLen
		material.PathLen = &pathLen
	}
	return material
}

// setCertificateName applies the name fallback chain from PLAN section 2.1:
// subject CN, else the first subject RDN value, else the file basename.
func setCertificateName(material *trustMaterial, cert *x509.Certificate, relPath string) {
	if cn := cert.Subject.CommonName; cn != "" {
		material.Name = cn
		return
	}
	for _, rdn := range cert.Subject.Names {
		if value, ok := rdn.Value.(string); ok && strings.TrimSpace(value) != "" {
			material.Name = value
			return
		}
	}
	material.Name = baseName(relPath)
}

// certificateSelfSigned follows PLAN sections 2.3 and 2.5: subject equals
// issuer AND the self-signature verifies. CheckSignature is used, not
// CheckSignatureFrom, which also refuses SHA-1 signatures (most older roots
// in CA stores) and signers that are not CAs. When the signature cannot be
// checked (an algorithm Go does not implement, or MD5), a self-issued
// certificate (equal names, and an authority key identifier that is absent
// or equals the subject key identifier) counts as self-signed, unverified.
func certificateSelfSigned(cert *x509.Certificate) (selfSigned, unverified bool) {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false, false
	}
	switch err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); {
	case err == nil:
		return true, false
	case signatureUncheckable(err) && keyIDsChain(cert, cert):
		return true, true
	}
	return false, false
}

// signatureUncheckable reports whether a signature check failed only because
// Go cannot check it, not because the signature is wrong.
func signatureUncheckable(err error) bool {
	var insecure x509.InsecureAlgorithmError
	return errors.Is(err, x509.ErrUnsupportedAlgorithm) || errors.As(err, &insecure)
}

// keyIDsChain reports whether child's authority key identifier, when it has
// one, names parent's subject key identifier.
func keyIDsChain(child, parent *x509.Certificate) bool {
	return len(child.AuthorityKeyId) == 0 || bytes.Equal(child.AuthorityKeyId, parent.SubjectKeyId)
}

// publicKeyID names a certificate's public key ("RSA-2048", "ECDSA-P256",
// "Ed25519", "ML-DSA-65"), with its size in bits (0 for post-quantum and
// unknown keys) and the dotted OID of its SubjectPublicKeyInfo algorithm. A
// key no name is known for is named by that OID (PLAN section 2.5).
func publicKeyID(cert *x509.Certificate) (name string, bits int, oid string) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err == nil {
		oid = spki.Algorithm.Algorithm.String()
	}
	if pq, ok := pqAlgorithmName(oid); ok {
		return pq, 0, oid
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", key.N.BitLen()), key.N.BitLen(), oid
	case *ecdsa.PublicKey:
		bits := key.Curve.Params().BitSize
		return fmt.Sprintf("ECDSA-P%d", bits), bits, oid
	case ed25519.PublicKey:
		return "Ed25519", 256, oid
	}
	if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm || oid == "" {
		return cert.PublicKeyAlgorithm.String(), 0, oid
	}
	return oid, 0, oid
}

// certificateRole: root (self-signed, and CA or v1), intermediate (CA, not
// self-signed), leaf (everything else).
func certificateRole(cert *x509.Certificate, selfSigned bool) string {
	switch {
	case selfSigned && (cert.IsCA || cert.Version == 1):
		return "root"
	case cert.IsCA:
		return "intermediate"
	default:
		return "leaf"
	}
}

// keyUsageNames maps the RFC 5280 section 4.2.1.3 KeyUsage bits to their
// short names, in bit order.
func keyUsageNames(ku x509.KeyUsage) []string {
	if ku == 0 {
		return nil
	}
	type bit struct {
		flag x509.KeyUsage
		name string
	}
	bits := []bit{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var names []string
	for _, b := range bits {
		if ku&b.flag != 0 {
			names = append(names, b.name)
		}
	}
	return names
}

// extKeyUsageNames uses the RFC 5280 section 4.2.1.12 short names for the
// recognized purposes and dotted OIDs for x509.UnknownExtKeyUsage entries.
func extKeyUsageNames(cert *x509.Certificate) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "any",
		x509.ExtKeyUsageServerAuth:                     "serverAuth",
		x509.ExtKeyUsageClientAuth:                     "clientAuth",
		x509.ExtKeyUsageCodeSigning:                    "codeSigning",
		x509.ExtKeyUsageEmailProtection:                "emailProtection",
		x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
		x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
		x509.ExtKeyUsageTimeStamping:                   "timeStamping",
		x509.ExtKeyUsageOCSPSigning:                    "ocspSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "msSGC",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "nsSGC",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoftCommercialCodeSigning",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoftKernelCodeSigning",
	}
	var values []string
	for _, eku := range cert.ExtKeyUsage {
		if name, ok := names[eku]; ok {
			values = append(values, name)
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		values = append(values, oid.String())
	}
	return sortedCopy(values)
}

// signatureAlgorithmName is the post-quantum name for its OID (PLAN section
// 2.5), else Go's SignatureAlgorithm.String() ("SHA256-RSA"), else the dotted
// OID.
func signatureAlgorithmName(cert *x509.Certificate) string {
	oid := signatureAlgorithmOID(cert)
	if pq, ok := pqAlgorithmName(oid); ok {
		return pq
	}
	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm || oid == "" {
		return cert.SignatureAlgorithm.String()
	}
	return oid
}

// signatureAlgorithmOID is the dotted OID from the certificate's raw DER
// AlgorithmIdentifier. Go exposes the raw bytes but no OID field, so the OID
// is decoded here.
func signatureAlgorithmOID(cert *x509.Certificate) string {
	if len(cert.RawSignatureAlgorithm) == 0 {
		return ""
	}
	var algorithmIdentifier struct {
		Algorithm asn1.ObjectIdentifier
	}
	if _, err := asn1.Unmarshal(cert.RawSignatureAlgorithm, &algorithmIdentifier); err != nil {
		return ""
	}
	return algorithmIdentifier.Algorithm.String()
}

func policyOIDStrings(cert *x509.Certificate) []string {
	if len(cert.PolicyIdentifiers) == 0 {
		return nil
	}
	values := make([]string, 0, len(cert.PolicyIdentifiers))
	for _, oid := range cert.PolicyIdentifiers {
		values = append(values, oid.String())
	}
	return sortedCopy(values)
}

func certificateHasNameConstraints(cert *x509.Certificate) bool {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(nameConstraintsOID) {
			return true
		}
	}
	return false
}

// linkIssuers adds, for each pair (child, parent) of certificates found in
// this run whose names chain (child issuer == parent subject), the parent's
// certSha256 to child.issuers when the child's signature verifies under the
// parent's key; a certificate never lists itself. CheckSignature is used,
// which allows SHA-1 and skips CA constraint checks: the edge means "signed
// by this key". A pair whose signature cannot be checked (PLAN section 2.5)
// goes to issuersUnverified instead, when the key identifiers agree. Only
// same-name pairs are verified; past issuerLinkLimit certificates the pass is
// skipped with a warning.
func linkIssuers(materials []trustMaterial, certs map[string]*x509.Certificate) []string {
	var indexes []int
	for index := range materials {
		if materials[index].CertSHA256 != "" && certs[materials[index].CertSHA256] != nil {
			indexes = append(indexes, index)
		}
	}
	if len(indexes) > issuerLinkLimit {
		return []string{fmt.Sprintf("issuer linking skipped: more than %d certificates found", issuerLinkLimit)}
	}
	bySubject := map[string][]int{}
	for _, index := range indexes {
		subject := string(certs[materials[index].CertSHA256].RawSubject)
		bySubject[subject] = append(bySubject[subject], index)
	}
	for _, childIndex := range indexes {
		child := certs[materials[childIndex].CertSHA256]
		var verified, unverified []string
		for _, parentIndex := range bySubject[string(child.RawIssuer)] {
			if parentIndex == childIndex {
				continue
			}
			parent := certs[materials[parentIndex].CertSHA256]
			switch err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); {
			case err == nil:
				verified = append(verified, materials[parentIndex].CertSHA256)
			case signatureUncheckable(err) && keyIDsChain(child, parent):
				unverified = append(unverified, materials[parentIndex].CertSHA256)
			}
		}
		materials[childIndex].Issuers = sortedCopy(verified)
		materials[childIndex].IssuersUnverified = sortedCopy(unverified)
	}
	return nil
}

func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	copied := make([]string, len(values))
	copy(copied, values)
	sort.Strings(copied)
	return copied
}

// truncateStrings caps a list and reports whether it was capped.
func truncateStrings(values []string, limit int) []string {
	if len(values) == 0 {
		return nil
	}
	if len(values) <= limit {
		return sortedCopy(values)
	}
	capped := make([]string, limit)
	copy(capped, values)
	sort.Strings(capped)
	return capped
}

// baseName is the file-name fallback for material names.
func baseName(path string) string {
	return filepath.Base(path)
}
