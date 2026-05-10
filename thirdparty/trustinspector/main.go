package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type trustMaterial struct {
	Kind          string     `json:"kind"`
	Path          string     `json:"path"`
	Name          string     `json:"name,omitempty"`
	TrustDomain   string     `json:"trustDomain,omitempty"`
	SourceType    string     `json:"sourceType,omitempty"`
	FileExtension string     `json:"fileExtension,omitempty"`
	SHA1          string     `json:"sha1,omitempty"`
	SHA256        string     `json:"sha256,omitempty"`
	KeyID         string     `json:"keyId,omitempty"`
	Algorithm     string     `json:"algorithm,omitempty"`
	KeyStrength   int        `json:"keyStrength,omitempty"`
	CreatedAt     string     `json:"createdAt,omitempty"`
	ExpiresAt     string     `json:"expiresAt,omitempty"`
	Fingerprint   string     `json:"fingerprint,omitempty"`
	UserIDs       []string   `json:"userIds,omitempty"`
	Subject       string     `json:"subject,omitempty"`
	Issuer        string     `json:"issuer,omitempty"`
	Serial        string     `json:"serial,omitempty"`
	Format        string     `json:"format,omitempty"`
	Properties    []property `json:"properties,omitempty"`
}

type pathInspection struct {
	Path       string     `json:"path"`
	Properties []property `json:"properties,omitempty"`
}

type hostFinding struct {
	Kind        string     `json:"kind"`
	Name        string     `json:"name,omitempty"`
	Path        string     `json:"path,omitempty"`
	Version     string     `json:"version,omitempty"`
	Description string     `json:"description,omitempty"`
	SHA256      string     `json:"sha256,omitempty"`
	Properties  []property `json:"properties,omitempty"`
}

type output struct {
	Materials   []trustMaterial `json:"materials,omitempty"`
	Inspections []pathInspection `json:"inspections,omitempty"`
	HostFindings []hostFinding   `json:"hostFindings,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "rootfs":
		err = runRootfs(os.Args[2:])
	case "paths":
		err = runPaths(os.Args[2:])
	case "host":
		err = runHost(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: trustinspector-cdxgen <command> [options]

Commands:
  rootfs <dir>   inspect trust material in an unpacked root filesystem
  paths [paths]  inspect selected binaries/apps on the current platform
  host           inspect host trust posture on the current platform`)
}

func runRootfs(args []string) error {
	flags := flag.NewFlagSet("rootfs", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("rootfs requires exactly one target directory")
	}
	materials, err := scanRootfsTrustMaterials(flags.Arg(0))
	if err != nil {
		return err
	}
	return writeJSON(output{Materials: materials})
}

func runPaths(args []string) error {
	flags := flag.NewFlagSet("paths", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stdin := flags.Bool("stdin", false, "read newline-delimited paths from stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	paths := uniqueSortedStrings(flags.Args())
	if *stdin {
		stdinPaths, err := readLines(os.Stdin)
		if err != nil {
			return err
		}
		paths = uniqueSortedStrings(append(paths, stdinPaths...))
	}
	if len(paths) == 0 {
		return writeJSON(output{})
	}

	var inspections []pathInspection
	switch runtime.GOOS {
	case "darwin":
		inspections = inspectDarwinPaths(paths)
	case "windows":
		inspections = inspectWindowsPaths(paths)
	default:
		inspections = nil
	}
	return writeJSON(output{Inspections: inspections})
}

func runHost(args []string) error {
	flags := flag.NewFlagSet("host", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return err
	}
	var findings []hostFinding
	switch runtime.GOOS {
	case "darwin":
		findings = inspectDarwinHost()
	case "windows":
		findings = inspectWindowsHost()
	default:
		findings = nil
	}
	return writeJSON(output{HostFindings: findings})
}

func writeJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(value)
}

func readLines(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func scanRootfsTrustMaterials(root string) ([]trustMaterial, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}

	candidateDirs := []struct {
		rel        string
		sourceType string
	}{
		{rel: filepath.Join("etc", "apt", "trusted.gpg.d"), sourceType: "repository-keyring"},
		{rel: filepath.Join("usr", "share", "keyrings"), sourceType: "repository-keyring"},
		{rel: filepath.Join("etc", "pki", "rpm-gpg"), sourceType: "repository-keyring"},
		{rel: filepath.Join("usr", "share", "distribution-gpg-keys"), sourceType: "repository-keyring"},
		{rel: filepath.Join("etc", "apk", "keys"), sourceType: "repository-keyring"},
		{rel: filepath.Join("etc", "ssl", "certs"), sourceType: "ca-store"},
		{rel: filepath.Join("usr", "local", "share", "ca-certificates"), sourceType: "ca-store"},
		{rel: filepath.Join("usr", "share", "ca-certificates"), sourceType: "ca-store"},
		{rel: filepath.Join("etc", "pki", "ca-trust", "source", "anchors"), sourceType: "ca-store"},
	}

	seen := map[string]trustMaterial{}
	for _, candidate := range candidateDirs {
		baseDir := filepath.Join(root, candidate.rel)
		if _, err := os.Stat(baseDir); err != nil {
			continue
		}
		_ = filepath.WalkDir(baseDir, func(current string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if !looksLikeTrustMaterialPath(current) {
				return nil
			}
			materials := inspectTrustMaterialFile(current, root, candidate.sourceType)
			for _, material := range materials {
				key := material.Kind + "\x00" + firstNonEmpty(material.Fingerprint, material.SHA256, material.Path)
				if existing, ok := seen[key]; ok {
					merged := mergeTrustMaterial(existing, material)
					seen[key] = merged
					continue
				}
				seen[key] = material
			}
			return nil
		})
	}
	results := make([]trustMaterial, 0, len(seen))
	for _, material := range seen {
		results = append(results, material)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Path == results[j].Path {
			return results[i].Kind < results[j].Kind
		}
		return results[i].Path < results[j].Path
	})
	return results, nil
}

func mergeTrustMaterial(existing, incoming trustMaterial) trustMaterial {
	if existing.Path == "" {
		existing.Path = incoming.Path
	}
	if existing.Name == "" {
		existing.Name = incoming.Name
	}
	if existing.TrustDomain == "" {
		existing.TrustDomain = incoming.TrustDomain
	}
	if existing.SourceType == "" {
		existing.SourceType = incoming.SourceType
	}
	if existing.FileExtension == "" {
		existing.FileExtension = incoming.FileExtension
	}
	if existing.SHA1 == "" {
		existing.SHA1 = incoming.SHA1
	}
	if existing.SHA256 == "" {
		existing.SHA256 = incoming.SHA256
	}
	if existing.KeyID == "" {
		existing.KeyID = incoming.KeyID
	}
	if existing.Algorithm == "" {
		existing.Algorithm = incoming.Algorithm
	}
	if existing.KeyStrength == 0 {
		existing.KeyStrength = incoming.KeyStrength
	}
	if existing.CreatedAt == "" {
		existing.CreatedAt = incoming.CreatedAt
	}
	if existing.ExpiresAt == "" {
		existing.ExpiresAt = incoming.ExpiresAt
	}
	if existing.Fingerprint == "" {
		existing.Fingerprint = incoming.Fingerprint
	}
	if existing.Subject == "" {
		existing.Subject = incoming.Subject
	}
	if existing.Issuer == "" {
		existing.Issuer = incoming.Issuer
	}
	if existing.Serial == "" {
		existing.Serial = incoming.Serial
	}
	if existing.Format == "" {
		existing.Format = incoming.Format
	}
	existing.UserIDs = uniqueSortedStrings(append(existing.UserIDs, incoming.UserIDs...))
	existing.Properties = uniqueProperties(append(existing.Properties, incoming.Properties...))
	return existing
}

func looksLikeTrustMaterialPath(path string) bool {
	lowerPath := strings.ToLower(path)
	base := strings.ToLower(filepath.Base(path))
	if strings.Contains(lowerPath, string(filepath.Separator)+"private"+string(filepath.Separator)) {
		return false
	}
	if base == "trusted.gpg" || strings.HasPrefix(base, "rpm-gpg-key") {
		return true
	}
	for _, suffix := range []string{".asc", ".gpg", ".pgp", ".pub", ".pem", ".crt", ".cer", ".der"} {
		if strings.HasSuffix(lowerPath, suffix) {
			return true
		}
	}
	return strings.Contains(lowerPath, string(filepath.Separator)+"certs"+string(filepath.Separator))
}

func inspectTrustMaterialFile(absolutePath, root, sourceType string) []trustMaterial {
	data, err := os.ReadFile(absolutePath)
	if err != nil || len(data) == 0 {
		return nil
	}
	relPath := "/" + filepath.ToSlash(strings.TrimPrefix(absolutePath, root))
	relPath = strings.ReplaceAll(relPath, "//", "/")
	sha1Value, sha256Value := digestBytes(data)
	trustDomain := deriveTrustDomain(relPath)
	fileExtension := strings.TrimPrefix(strings.ToLower(filepath.Ext(relPath)), ".")

	var materials []trustMaterial
	materials = append(materials, parseOpenPGPMaterials(data, relPath, sha1Value, sha256Value, trustDomain, sourceType, fileExtension)...)
	materials = append(materials, parseCertificateMaterials(data, relPath, sha1Value, sha256Value, trustDomain, sourceType, fileExtension)...)
	if len(materials) > 0 {
		return materials
	}
	return nil
}

func digestBytes(data []byte) (string, string) {
	sha1Sum := sha1.Sum(data)
	sha256Sum := sha256.Sum256(data)
	return hex.EncodeToString(sha1Sum[:]), hex.EncodeToString(sha256Sum[:])
}

func deriveTrustDomain(path string) string {
	lowerPath := strings.ToLower(filepath.ToSlash(path))
	switch {
	case strings.Contains(lowerPath, "/apt/") || strings.Contains(lowerPath, "/keyrings/"):
		return "apt"
	case strings.Contains(lowerPath, "/rpm-gpg/") || strings.Contains(lowerPath, "/distribution-gpg-keys/"):
		return "rpm"
	case strings.Contains(lowerPath, "/apk/keys/"):
		return "apk"
	case strings.Contains(lowerPath, "/ssl/certs/") || strings.Contains(lowerPath, "/ca-certificates/") || strings.Contains(lowerPath, "/ca-trust/"):
		return "ca-store"
	default:
		return "generic"
	}
}

func parseOpenPGPMaterials(data []byte, relPath, sha1Value, sha256Value, trustDomain, sourceType, fileExtension string) []trustMaterial {
	entities, err := readOpenPGPEntities(data)
	if err != nil || len(entities) == 0 {
		return nil
	}
	var materials []trustMaterial
	for _, entity := range entities {
		materials = append(materials, trustMaterial{
			Kind:          "public-key",
			Path:          relPath,
			Name:          filepath.Base(relPath),
			TrustDomain:   trustDomain,
			SourceType:    sourceType,
			FileExtension: firstNonEmpty(fileExtension, "gpg"),
			SHA1:          sha1Value,
			SHA256:        sha256Value,
			KeyID:         entity.KeyID,
			Algorithm:     entity.Algorithm,
			KeyStrength:   entity.KeyStrength,
			CreatedAt:     entity.CreatedAt,
			ExpiresAt:     entity.ExpiresAt,
			Fingerprint:   entity.Fingerprint,
			UserIDs:       entity.UserIDs,
			Properties: uniqueProperties([]property{
				{Name: "cdx:crypto:sourceType", Value: sourceType},
				{Name: "cdx:crypto:trustDomain", Value: trustDomain},
				{Name: "cdx:crypto:fileExtension", Value: firstNonEmpty(fileExtension, "gpg")},
			}),
		})
	}
	return materials
}

type openPGPEntity struct {
	Fingerprint string
	KeyID       string
	Algorithm   string
	KeyStrength int
	CreatedAt   string
	ExpiresAt   string
	UserIDs     []string
}

func readOpenPGPEntities(data []byte) ([]openPGPEntity, error) {
	decoded := data
	if bytes.Contains(data, []byte("-----BEGIN PGP")) {
		block, err := armor.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		decoded, err = io.ReadAll(block.Body)
		if err != nil {
			return nil, err
		}
	}

	reader := packet.NewReader(bytes.NewReader(decoded))
	var entities []openPGPEntity
	var current *openPGPEntity
	for {
		pkt, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value := pkt.(type) {
		case *packet.PublicKey:
			bitLength, _ := value.BitLength()
			entity := openPGPEntity{
				Fingerprint: strings.ToUpper(hex.EncodeToString(value.Fingerprint[:])),
				KeyID:       fmt.Sprintf("%016X", value.KeyId),
				Algorithm:   publicKeyAlgorithm(value.PubKeyAlgo),
				KeyStrength: int(bitLength),
				CreatedAt:   value.CreationTime.UTC().Format(time.RFC3339),
			}
			entities = append(entities, entity)
			current = &entities[len(entities)-1]
		case *packet.UserId:
			if current != nil {
				current.UserIDs = append(current.UserIDs, strings.TrimSpace(value.Id))
			}
		case *packet.Signature:
			if current != nil && value.KeyLifetimeSecs != nil && *value.KeyLifetimeSecs > 0 {
				expires := currentCreatedAt(current.CreatedAt).Add(time.Duration(*value.KeyLifetimeSecs) * time.Second)
				current.ExpiresAt = expires.UTC().Format(time.RFC3339)
			}
		}
	}
	if len(entities) == 0 {
		return nil, errors.New("no OpenPGP entities found")
	}
	for index := range entities {
		entities[index].UserIDs = uniqueSortedStrings(entities[index].UserIDs)
	}
	return entities, nil
}

func currentCreatedAt(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func publicKeyAlgorithm(algo packet.PublicKeyAlgorithm) string {
	switch algo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		return "RSA"
	case packet.PubKeyAlgoDSA:
		return "DSA"
	case packet.PubKeyAlgoECDH:
		return "ECDH"
	case packet.PubKeyAlgoECDSA:
		return "ECDSA"
	default:
		return fmt.Sprintf("ALGO-%d", int(algo))
	}
}

func parseCertificateMaterials(data []byte, relPath, sha1Value, sha256Value, trustDomain, sourceType, fileExtension string) []trustMaterial {
	certs := readCertificates(data)
	if len(certs) == 0 {
		return nil
	}
	var materials []trustMaterial
	for _, cert := range certs {
		certFingerprintBytes := sha256.Sum256(cert.Raw)
		materials = append(materials, trustMaterial{
			Kind:          "certificate",
			Path:          relPath,
			Name:          firstNonEmpty(cert.Subject.CommonName, filepath.Base(relPath)),
			TrustDomain:   trustDomain,
			SourceType:    sourceType,
			FileExtension: firstNonEmpty(fileExtension, "crt"),
			SHA1:          sha1Value,
			SHA256:        sha256Value,
			Algorithm:     publicKeyType(cert.PublicKeyAlgorithm),
			KeyStrength:   certificateKeyStrength(cert),
			CreatedAt:     cert.NotBefore.UTC().Format(time.RFC3339),
			ExpiresAt:     cert.NotAfter.UTC().Format(time.RFC3339),
			Fingerprint:   strings.ToUpper(hex.EncodeToString(certFingerprintBytes[:])),
			Subject:       cert.Subject.String(),
			Issuer:        cert.Issuer.String(),
			Serial:        cert.SerialNumber.String(),
			Format:        "X.509",
			Properties: uniqueProperties([]property{
				{Name: "cdx:crypto:sourceType", Value: sourceType},
				{Name: "cdx:crypto:trustDomain", Value: trustDomain},
				{Name: "cdx:crypto:fileExtension", Value: firstNonEmpty(fileExtension, "crt")},
				{Name: "cdx:crypto:isCA", Value: fmt.Sprintf("%t", cert.IsCA)},
			}),
		})
	}
	return materials
}

func readCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certs = append(certs, parsed)
		}
	}
	if len(certs) > 0 {
		return certs
	}
	parsed, err := x509.ParseCertificates(data)
	if err == nil {
		return parsed
	}
	return nil
}

func publicKeyType(algo x509.PublicKeyAlgorithm) string {
	switch algo {
	case x509.RSA:
		return "RSA"
	case x509.DSA:
		return "DSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return algo.String()
	}
}

func certificateKeyStrength(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		return pub.Size() * 8
	case interface{ BitSize() int }:
		return pub.BitSize()
	default:
		return 0
	}
}

func inspectDarwinPaths(paths []string) []pathInspection {
	var inspections []pathInspection
	for _, candidate := range uniqueSortedStrings(paths) {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		properties := uniqueProperties(append(runCodeSignInspection(candidate), runSpctlInspection(candidate)...))
		if len(properties) == 0 {
			continue
		}
		inspections = append(inspections, pathInspection{Path: candidate, Properties: properties})
	}
	return inspections
}

func runCodeSignInspection(path string) []property {
	stdout, stderr, err := runCommand("codesign", "-dv", "--verbose=4", path)
	if err != nil && stderr == "" {
		return nil
	}
	return parseCodeSignOutput(firstNonEmpty(stderr, stdout))
}

func parseCodeSignOutput(output string) []property {
	var properties []property
	var authorities []string
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Identifier="):
			properties = append(properties, property{Name: "cdx:darwin:codesign:identifier", Value: strings.TrimPrefix(line, "Identifier=")})
		case strings.HasPrefix(line, "Format="):
			properties = append(properties, property{Name: "cdx:darwin:codesign:format", Value: strings.TrimPrefix(line, "Format=")})
		case strings.HasPrefix(line, "TeamIdentifier="):
			value := strings.TrimPrefix(line, "TeamIdentifier=")
			properties = append(properties,
				property{Name: "cdx:darwin:codesign:teamIdentifier", Value: value},
				property{Name: "cdx:darwin:codesign:signed", Value: fmt.Sprintf("%t", value != "not set")},
			)
		case strings.HasPrefix(line, "Runtime Version="):
			properties = append(properties, property{Name: "cdx:darwin:codesign:runtimeVersion", Value: strings.TrimPrefix(line, "Runtime Version=")})
		case strings.HasPrefix(line, "Authority="):
			authorities = append(authorities, strings.TrimPrefix(line, "Authority="))
		}
	}
	if len(authorities) > 0 {
		properties = append(properties,
			property{Name: "cdx:darwin:codesign:authorityCount", Value: fmt.Sprintf("%d", len(authorities))},
		)
		for _, authority := range uniqueSortedStrings(authorities) {
			properties = append(properties, property{Name: "cdx:darwin:codesign:authority", Value: authority})
		}
	}
	return uniqueProperties(properties)
}

func runSpctlInspection(path string) []property {
	stdout, stderr, _ := runCommand("spctl", "--assess", "--type", "execute", "--verbose=4", path)
	combined := strings.TrimSpace(strings.Join([]string{stdout, stderr}, "\n"))
	if combined == "" {
		return nil
	}
	return parseSpctlOutput(combined)
}

func parseSpctlOutput(output string) []property {
	var properties []property
	assessment := "unknown"
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasSuffix(line, ": accepted"):
			assessment = "accepted"
		case strings.HasSuffix(line, ": rejected"):
			assessment = "rejected"
		case strings.HasPrefix(line, "source="):
			properties = append(properties, property{Name: "cdx:darwin:notarization:source", Value: strings.TrimPrefix(line, "source=")})
		case strings.HasPrefix(line, "origin="):
			properties = append(properties, property{Name: "cdx:darwin:notarization:origin", Value: strings.TrimPrefix(line, "origin=")})
		}
	}
	properties = append(properties, property{Name: "cdx:darwin:notarization:assessment", Value: assessment})
	return uniqueProperties(properties)
}

func inspectDarwinHost() []hostFinding {
	stdout, stderr, err := runCommand("spctl", "--status")
	statusOutput := strings.TrimSpace(firstNonEmpty(stdout, stderr))
	if err != nil && statusOutput == "" {
		return nil
	}
	status := "unknown"
	if strings.Contains(strings.ToLower(statusOutput), "enabled") {
		status = "enabled"
	} else if strings.Contains(strings.ToLower(statusOutput), "disabled") {
		status = "disabled"
	}
	return []hostFinding{{
		Kind:        "darwin-gatekeeper-status",
		Name:        "gatekeeper-system-policy",
		Version:     status,
		Description: statusOutput,
		Properties: []property{{Name: "cdx:darwin:gatekeeper:status", Value: status}},
	}}
}

func inspectWindowsPaths(paths []string) []pathInspection {
	results, err := runWindowsPowerShellJSON(pathsInspectionPowerShellScript(), map[string]any{
		"paths": uniqueSortedStrings(paths),
	})
	if err != nil {
		return nil
	}
	var inspections []pathInspection
	for _, item := range results {
		pathValue, _ := item["path"].(string)
		if pathValue == "" {
			continue
		}
		inspections = append(inspections, pathInspection{Path: pathValue, Properties: mapToProperties(item, "path")})
	}
	return inspections
}

func inspectWindowsHost() []hostFinding {
	results, err := runWindowsPowerShellJSON(wdacInspectionPowerShellScript(), nil)
	if err != nil {
		return nil
	}
	var findings []hostFinding
	for _, item := range results {
		kind, _ := item["kind"].(string)
		name, _ := item["name"].(string)
		version, _ := item["version"].(string)
		description, _ := item["description"].(string)
		pathValue, _ := item["path"].(string)
		sha256Value, _ := item["sha256"].(string)
		findings = append(findings, hostFinding{
			Kind:        kind,
			Name:        name,
			Version:     version,
			Description: description,
			Path:        pathValue,
			SHA256:      sha256Value,
			Properties:  mapToProperties(item, "kind", "name", "version", "description", "path", "sha256"),
		})
	}
	return findings
}

func pathsInspectionPowerShellScript() string {
	return `$payload = ConvertFrom-Json -InputObject $env:TRUSTINSPECTOR_PAYLOAD_JSON
$results = @()
foreach ($path in $payload.paths) {
  if (-not (Test-Path -LiteralPath $path)) { continue }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    $entry = [ordered]@{
      path = $path
      'cdx:windows:authenticode:status' = [string]$sig.Status
      'cdx:windows:authenticode:isOSBinary' = [string]$sig.IsOSBinary
    }
    if ($sig.StatusMessage) { $entry['cdx:windows:authenticode:statusMessage'] = [string]$sig.StatusMessage }
    if ($sig.SignerCertificate) {
      $entry['cdx:windows:authenticode:signerSubject'] = [string]$sig.SignerCertificate.Subject
      $entry['cdx:windows:authenticode:signerIssuer'] = [string]$sig.SignerCertificate.Issuer
      $entry['cdx:windows:authenticode:signerThumbprint'] = [string]$sig.SignerCertificate.Thumbprint
      $entry['cdx:windows:authenticode:signerNotAfter'] = [string]$sig.SignerCertificate.NotAfter.ToUniversalTime().ToString('o')
    }
    if ($sig.TimeStamperCertificate) {
      $entry['cdx:windows:authenticode:timestampSubject'] = [string]$sig.TimeStamperCertificate.Subject
      $entry['cdx:windows:authenticode:timestampIssuer'] = [string]$sig.TimeStamperCertificate.Issuer
      $entry['cdx:windows:authenticode:timestampThumbprint'] = [string]$sig.TimeStamperCertificate.Thumbprint
    }
    $results += [pscustomobject]$entry
  } catch {
    continue
  }
}
$results | ConvertTo-Json -Depth 6 -Compress`
}

func wdacInspectionPowerShellScript() string {
	return `$results = @()
$policyRoot = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
$policyFiles = @()
if (Test-Path -LiteralPath $policyRoot) {
  $policyFiles = Get-ChildItem -LiteralPath $policyRoot -File -ErrorAction SilentlyContinue
}
$results += [pscustomobject]@{
  kind = 'windows-wdac-status'
  name = 'wdac-active-policies'
  version = [string]$policyFiles.Count
  description = $policyRoot
  'cdx:windows:wdac:activePolicyCount' = [string]$policyFiles.Count
}
foreach ($file in $policyFiles) {
  $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
  $results += [pscustomobject]@{
    kind = 'windows-wdac-policy'
    name = $file.BaseName
    path = $file.FullName
    version = [string]$file.Length
    description = $file.Name
    sha256 = $sha256
    'cdx:windows:wdac:policyPath' = $file.FullName
    'cdx:windows:wdac:policySize' = [string]$file.Length
    'cdx:windows:wdac:lastModified' = [string]$file.LastWriteTimeUtc.ToString('o')
  }
}
$results | ConvertTo-Json -Depth 6 -Compress`
}

func runWindowsPowerShellJSON(script string, payload map[string]any) ([]map[string]any, error) {
	payloadJSON := "{}"
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadJSON = string(encoded)
	}
	stdout, stderr, err := runCommandWithEnv(map[string]string{"TRUSTINSPECTOR_PAYLOAD_JSON": payloadJSON}, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil && strings.TrimSpace(stdout) == "" {
		return nil, fmt.Errorf("powershell failed: %w: %s", err, strings.TrimSpace(stderr))
	}
	decoded := strings.TrimSpace(stdout)
	if decoded == "" || decoded == "null" {
		return nil, nil
	}
	var list []map[string]any
	if err := json.Unmarshal([]byte(decoded), &list); err == nil {
		return list, nil
	}
	var item map[string]any
	if err := json.Unmarshal([]byte(decoded), &item); err == nil {
		return []map[string]any{item}, nil
	}
	return nil, fmt.Errorf("unable to parse powershell JSON output: %s", decoded)
}

func runCommand(name string, args ...string) (string, string, error) {
	return runCommandWithEnv(nil, name, args...)
}

func runCommandWithEnv(extraEnv map[string]string, name string, args ...string) (string, string, error) {
	cmd := exec.Command(name, args...)
	if len(extraEnv) > 0 {
		env := os.Environ()
		for key, value := range extraEnv {
			env = append(env, key+"="+value)
		}
		cmd.Env = env
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), err
}

func mapToProperties(item map[string]any, excludeKeys ...string) []property {
	excluded := make(map[string]struct{}, len(excludeKeys))
	for _, key := range excludeKeys {
		excluded[key] = struct{}{}
	}
	var properties []property
	for key, value := range item {
		if _, ok := excluded[key]; ok {
			continue
		}
		stringValue := strings.TrimSpace(fmt.Sprintf("%v", value))
		if stringValue == "" || stringValue == "<nil>" || stringValue == "[]" {
			continue
		}
		properties = append(properties, property{Name: key, Value: stringValue})
	}
	return uniqueProperties(properties)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	uniqueValues := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		uniqueValues = append(uniqueValues, trimmed)
	}
	sort.Strings(uniqueValues)
	if len(uniqueValues) == 0 {
		return nil
	}
	return uniqueValues
}

func uniqueProperties(values []property) []property {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	uniqueValues := make([]property, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value.Name) == "" || strings.TrimSpace(value.Value) == "" {
			continue
		}
		key := value.Name + "\x00" + value.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		uniqueValues = append(uniqueValues, value)
	}
	sort.Slice(uniqueValues, func(i, j int) bool {
		if uniqueValues[i].Name == uniqueValues[j].Name {
			return uniqueValues[i].Value < uniqueValues[j].Value
		}
		return uniqueValues[i].Name < uniqueValues[j].Name
	})
	if len(uniqueValues) == 0 {
		return nil
	}
	return uniqueValues
}
