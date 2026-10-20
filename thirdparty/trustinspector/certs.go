package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
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
	return material.Kind + "\x00" + firstNonEmpty(material.CertSHA256, material.Fingerprint, material.SHA256, material.Path)
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
// path becomes the lexicographically smallest path, and sourceType,
// sha1/sha256, trustDomain and fileExtension follow that path, which keeps
// the report-1 meaning of those fields ("sha1/sha256 are the file digests of
// path").
func (a *materialAccumulator) resolve() []trustMaterial {
	results := make([]trustMaterial, 0, len(a.order))
	for _, key := range a.order {
		material := a.materials[key]
		locations := a.locations[key]
		sort.Slice(locations, func(i, j int) bool { return locations[i].path < locations[j].path })
		var paths []string
		var sourceTypes []string
		seenPath := map[string]bool{}
		seenSource := map[string]bool{}
		for _, location := range locations {
			if !seenPath[location.path] {
				seenPath[location.path] = true
				paths = append(paths, location.path)
			}
			if location.sourceType != "" && !seenSource[location.sourceType] {
				seenSource[location.sourceType] = true
				sourceTypes = append(sourceTypes, location.sourceType)
			}
		}
		sort.Strings(paths)
		sort.Strings(sourceTypes)
		first := locations[0]
		material.Path = first.path
		material.Paths = paths
		material.SourceType = first.sourceType
		material.SourceTypes = sourceTypes
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
	}
	return uniqueProperties(values)
}

func materialIdentity(material trustMaterial) string {
	return firstNonEmpty(material.CertSHA256, material.Fingerprint, material.SHA256)
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
	selfSigned := certificateSelfSigned(cert)
	material := &trustMaterial{
		certificate:            cert,
		Kind:                   "certificate",
		Name:                   firstNonEmpty(cert.Subject.CommonName, ""),
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
		Role:                   certificateRole(cert, selfSigned),
		SubjectKeyId:           strings.ToLower(hex.EncodeToString(cert.SubjectKeyId)),
		AuthorityKeyId:         strings.ToLower(hex.EncodeToString(cert.AuthorityKeyId)),
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
	if selfSigned {
		value := true
		material.SelfSigned = &value
	} else {
		value := false
		material.SelfSigned = &value
	}
	if cert.IsCA {
		value := true
		material.IsCA = &value
	} else {
		value := false
		material.IsCA = &value
	}
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		pathLen := cert.MaxPathLen
		material.PathLen = &pathLen
	}
	if material.Name == "" {
		// The caller falls back to the first subject RDN value and then the
		// file basename when the subject has no CN; that needs the path, so
		// it is done by the caller (setCertificateName).
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

// certificateSelfSigned follows PLAN section 2.3: subject equals issuer AND
// the self-signature verifies.
func certificateSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil
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

// signatureAlgorithmName is Go's SignatureAlgorithm.String() (for example
// "SHA256-RSA"); omitted for unknown algorithms.
func signatureAlgorithmName(cert *x509.Certificate) string {
	if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return ""
	}
	return cert.SignatureAlgorithm.String()
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
// this run, the parent's certSha256 to child.issuers when the child's
// signature verifies against the parent's key. Self-signed certificates
// never list themselves. The pass is O(n^2) but CheckSignatureFrom compares
// subject names before verifying, so only same-name pairs pay for the
// signature check; past issuerLinkLimit certificates the pass is skipped.
func linkIssuers(materials []trustMaterial, certs map[string]*x509.Certificate) []string {
	if len(materials) > issuerLinkLimit {
		return []string{fmt.Sprintf("issuer linking skipped: more than %d certificates found", issuerLinkLimit)}
	}
	byCertSHA := map[string]int{}
	for index := range materials {
		if materials[index].CertSHA256 != "" {
			byCertSHA[materials[index].CertSHA256] = index
		}
	}
	issuerSets := map[string]map[string]bool{}
	for childKey, childIndex := range byCertSHA {
		child := materials[childIndex]
		childCert := certs[childKey]
		if childCert == nil {
			continue
		}
		for parentKey, parentIndex := range byCertSHA {
			if childIndex == parentIndex {
				continue
			}
			parentCert := certs[parentKey]
			if parentCert == nil {
				continue
			}
			if childCert.CheckSignatureFrom(parentCert) == nil {
				set, ok := issuerSets[child.CertSHA256]
				if !ok {
					set = map[string]bool{}
					issuerSets[child.CertSHA256] = set
				}
				set[materials[parentIndex].CertSHA256] = true
			}
		}
	}
	var warnings []string
	for index := range materials {
		if set := issuerSets[materials[index].CertSHA256]; len(set) > 0 {
			issuers := make([]string, 0, len(set))
			for issuer := range set {
				issuers = append(issuers, issuer)
			}
			sort.Strings(issuers)
			materials[index].Issuers = issuers
		}
	}
	return warnings
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
