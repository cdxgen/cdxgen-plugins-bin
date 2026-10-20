package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	// The maintained ProtonMail fork of x/crypto/openpgp: x/crypto's copy is
	// frozen and its OpenPGP implementation carries an unfixed advisory
	// (GO-2026-5932) with no fixed version to move to.
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// trustMaterial is one finding. report-2 keeps every report-1 key with the
// same meaning and adds certificate identity, extension and location fields
// (all omitempty, so nothing moves for a report-1 consumer).
type trustMaterial struct {
	Kind          string     `json:"kind"`
	Path          string     `json:"path"`
	Paths         []string   `json:"paths,omitempty"`
	Name          string     `json:"name,omitempty"`
	TrustDomain   string     `json:"trustDomain,omitempty"`
	SourceType    string     `json:"sourceType,omitempty"`
	SourceTypes   []string   `json:"sourceTypes,omitempty"`
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
	SerialHex     string     `json:"serialHex,omitempty"`
	Format        string     `json:"format,omitempty"`
	Properties    []property `json:"properties,omitempty"`

	// report-2 certificate identity. certificate is the parsed certificate
	// kept for issuer linking; it is never serialized.
	CertSHA256       string   `json:"certSha256,omitempty"`
	SPKISHA256       string   `json:"spkiSha256,omitempty"`
	SPKISHA256Base64 string   `json:"spkiSha256Base64,omitempty"`
	CertVersion      int      `json:"version,omitempty"`
	IsCA             *bool    `json:"isCA,omitempty"`
	SelfSigned       *bool    `json:"selfSigned,omitempty"`
	Role             string   `json:"role,omitempty"`
	PathLen          *int     `json:"pathLen,omitempty"`
	SubjectKeyId     string   `json:"subjectKeyId,omitempty"`
	AuthorityKeyId   string   `json:"authorityKeyId,omitempty"`
	Issuers          []string `json:"issuers,omitempty"`
	HostStores       []string `json:"hostStores,omitempty"`

	// report-2 certificate extensions and URLs.
	KeyUsage               []string `json:"keyUsage,omitempty"`
	ExtKeyUsage            []string `json:"extKeyUsage,omitempty"`
	SignatureAlgorithm     string   `json:"signatureAlgorithm,omitempty"`
	SignatureAlgorithmOid  string   `json:"signatureAlgorithmOid,omitempty"`
	DNSNames               []string `json:"dnsNames,omitempty"`
	DNSNamesTruncated      bool     `json:"dnsNamesTruncated,omitempty"`
	OCSPServers            []string `json:"ocspServers,omitempty"`
	IssuingCertificateURLs []string `json:"issuingCertificateUrls,omitempty"`
	CRLDistributionPoints  []string `json:"crlDistributionPoints,omitempty"`
	PolicyOIDs             []string `json:"policyOids,omitempty"`
	HasNameConstraints     bool     `json:"hasNameConstraints,omitempty"`
	TrustRejectedPurposes  []string `json:"trustRejectedPurposes,omitempty"`

	certificate *x509.Certificate `json:"-"`
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

// reportOptions records the scan options that produced the report.
type reportOptions struct {
	Embedded  bool     `json:"embedded"`
	ExtraDirs []string `json:"extraDirs,omitempty"`
}

type output struct {
	// Envelope: schema, tool and toolVersion identify the report shape and
	// the binary that produced it. The payload keys below stay at the top
	// level so existing consumers keep parsing unchanged.
	Schema       string           `json:"schema"`
	Tool         string           `json:"tool"`
	ToolVersion  string           `json:"toolVersion"`
	Options      *reportOptions   `json:"options,omitempty"`
	Materials    []trustMaterial  `json:"materials,omitempty"`
	Inspections  []pathInspection `json:"inspections,omitempty"`
	HostFindings []hostFinding    `json:"hostFindings,omitempty"`
	Warnings     []string         `json:"warnings,omitempty"`
}

// trustInspectorSchemaVersion is bumped whenever the output shape changes.
const trustInspectorSchemaVersion = "trustinspector/report-2"

// version is injected at build time (-X main.version=...); "dev" marks a
// binary built without the injection.
var version = "dev"

// Exit codes follow the suite convention kosi documents: 0 success,
// 2 usage error, 3 runtime error. 1 is reserved for expectations failures,
// which trustinspector has no gate of.
const (
	exitOK      = 0
	exitUsage   = 2
	exitRuntime = 3
)

var windowsPowerShellJSONRunner = runWindowsPowerShellJSON
var commandRunner = runCommand

// usageError marks a mistake in how the tool was invoked: an unparseable
// flag or a missing argument.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// repeatableFlag collects repeated string flags (--extra-dir).
type repeatableFlag []string

func (r *repeatableFlag) String() string { return strings.Join(*r, ",") }
func (r *repeatableFlag) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Printf("trustinspector-cdxgen %s\n", version)
			os.Exit(exitOK)
		case "help", "--help", "-h":
			printUsage()
			os.Exit(exitOK)
		}
	}
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(exitUsage)
	}

	var err error
	switch os.Args[1] {
	case "rootfs":
		err = runRootfs(os.Args[2:])
	case "paths":
		err = runPaths(os.Args[2:])
	case "host":
		err = runHost(os.Args[2:])
	case "certs":
		err = runCerts(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "trustinspector-cdxgen: unknown command %q\n", os.Args[1])
		printUsage()
		os.Exit(exitUsage)
	}
	if errors.Is(err, flag.ErrHelp) {
		printUsage()
		os.Exit(exitOK)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		var ue *usageError
		if errors.As(err, &ue) {
			os.Exit(exitUsage)
		}
		os.Exit(exitRuntime)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: trustinspector-cdxgen <command> [options]

Commands:
  rootfs <dir>            inspect trust material in an unpacked root filesystem
  certs [options] <file>  parse exactly the given certificate files
  paths [paths]           inspect selected binaries/apps on the current platform
  host                    inspect host trust posture on the current platform
  version                 print the tool version

rootfs options:
  --embedded              scan ELF/Mach-O/PE binaries for embedded PEM certificates
  --extra-dir <rel>       also scan this directory relative to the root (repeatable)

certs options:
  --stdin                 read newline-delimited paths from stdin
  --embedded              scan the given files for embedded PEM certificates
  --root <dir>            report paths relative to this directory (leading /)

Exit codes: 0 success; 2 usage error; 3 runtime error.`)
}

func runRootfs(args []string) error {
	flags := flag.NewFlagSet("rootfs", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	embedded := flags.Bool("embedded", false, "scan binaries for embedded PEM certificates")
	var extraDirs repeatableFlag
	flags.Var(&extraDirs, "extra-dir", "additional directory to scan, relative to the root (repeatable)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &usageError{err: err}
	}
	if flags.NArg() != 1 {
		return &usageError{err: errors.New("rootfs requires exactly one target directory")}
	}
	for _, dir := range extraDirs {
		if err := validateExtraDir(dir); err != nil {
			return &usageError{err: err}
		}
	}
	materials, warnings, err := scanRootfsTrustMaterials(flags.Arg(0), scanOptions{Embedded: *embedded, ExtraDirs: extraDirs})
	if err != nil {
		return err
	}
	return writeJSON(output{
		Options:   &reportOptions{Embedded: *embedded, ExtraDirs: uniqueSortedStrings(extraDirs)},
		Materials: materials,
		Warnings:  warnings,
	})
}

// validateExtraDir rejects --extra-dir values that escape the scanned root.
func validateExtraDir(dir string) error {
	slash := filepath.ToSlash(dir)
	if filepath.IsAbs(dir) || slash == ".." || strings.HasPrefix(slash, "../") || strings.Contains(slash, "/../") || strings.Contains(slash, "/..") {
		return fmt.Errorf("extra dir %q must be a relative path inside the root", dir)
	}
	return nil
}

// runCerts parses exactly the given files (PLAN section 3): same parsers as
// rootfs, sourceType generic, and with --root the reported paths are
// relative to that directory.
func runCerts(args []string) error {
	flags := flag.NewFlagSet("certs", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stdin := flags.Bool("stdin", false, "read newline-delimited paths from stdin")
	embedded := flags.Bool("embedded", false, "scan the given files for embedded PEM certificates")
	root := flags.String("root", "", "report paths relative to this directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &usageError{err: err}
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
		return writeJSON(output{Options: &reportOptions{Embedded: *embedded}})
	}
	if *root != "" {
		if info, err := os.Stat(*root); err != nil || !info.IsDir() {
			return fmt.Errorf("--root %s is not a directory", *root)
		}
	}
	accumulator := newMaterialAccumulator()
	warnings := &warningList{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		if *embedded {
			if isExecutableBinaryMagic(data) && int64(len(data)) <= maxEmbeddedFileBytes {
				for _, cert := range embeddedCertificateBlocks(data) {
					material := buildCertificateFields(cert)
					setCertificateName(material, cert, path)
					accumulator.add(material, certLocation{path: displayPathCerts(path, *root), sourceType: "generic"})
				}
				continue
			}
			if !isExecutableBinaryMagic(data) {
				// fall through to the regular parsers
			}
		}
		for _, entry := range parseFileMaterials(data, displayPathCerts(path, *root), "generic") {
			accumulator.add(entry.material, entry.location)
		}
	}
	materials := accumulator.resolve()
	if issuerWarnings := linkIssuers(materials, accumulator.certs); len(issuerWarnings) > 0 {
		warnings.add(issuerWarnings...)
	}
	return writeJSON(output{
		Options:   &reportOptions{Embedded: *embedded},
		Materials: materials,
		Warnings:  warnings.list(),
	})
}

// displayPathCerts resolves the reported path for certs mode: relative to
// --root with a leading slash when given, otherwise the path as passed.
func displayPathCerts(path, root string) string {
	if root == "" {
		return path
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(absPath)
	}
	return "/" + filepath.ToSlash(rel)
}

func runPaths(args []string) error {
	flags := flag.NewFlagSet("paths", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stdin := flags.Bool("stdin", false, "read newline-delimited paths from stdin")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &usageError{err: err}
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
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &usageError{err: err}
	}
	var findings []hostFinding
	var materials []trustMaterial
	var warnings []string
	switch runtime.GOOS {
	case "darwin":
		findings = inspectDarwinHost()
		materials, warnings = inspectDarwinHostTrustMaterials()
	case "windows":
		findings = inspectWindowsHost()
		materials, warnings = inspectWindowsHostTrustMaterials()
	default:
		// Linux: the host scan is a rootfs scan of /, without --embedded
		// (PLAN section 4.2).
		scanMaterials, scanWarnings, err := inspectLinuxHostTrustMaterials("/")
		if err == nil {
			materials = scanMaterials
			warnings = scanWarnings
		}
	}
	return writeJSON(output{Materials: materials, HostFindings: findings, Warnings: warnings})
}

// writeJSON stamps the schema, tool and version envelope onto the report
// without moving the payload keys, so existing consumers keep working.
func writeJSON(out output) error {
	out.Schema = trustInspectorSchemaVersion
	out.Tool = "trustinspector-cdxgen"
	out.ToolVersion = version
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
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

func digestBytes(data []byte) (string, string) {
	sha1Sum := sha1.Sum(data)
	sha256Sum := sha256.Sum256(data)
	return hex.EncodeToString(sha1Sum[:]), hex.EncodeToString(sha256Sum[:])
}

func sha256SumBytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha256SumHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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
		normalizedCandidate, err := normalizeInspectablePath(candidate)
		if err != nil {
			continue
		}
		if _, err := os.Stat(normalizedCandidate); err != nil {
			continue
		}
		properties := uniqueProperties(append(runCodeSignInspection(normalizedCandidate), runSpctlInspection(normalizedCandidate)...))
		if len(properties) == 0 {
			continue
		}
		inspections = append(inspections, pathInspection{Path: normalizedCandidate, Properties: properties})
	}
	return inspections
}

func normalizeInspectablePath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absPath), nil
}

func runCodeSignInspection(path string) []property {
	stdout, stderr, err := commandRunner("codesign", "-dv", "--verbose=4", path)
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
	stdout, stderr, _ := commandRunner("spctl", "--assess", "--type", "execute", "--verbose=4", path)
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
		Properties:  []property{{Name: "cdx:darwin:gatekeeper:status", Value: status}},
	}}
}

func inspectWindowsPaths(paths []string) []pathInspection {
	results, err := windowsPowerShellJSONRunner(pathsInspectionPowerShellScript(), map[string]any{
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
	results, err := windowsPowerShellJSONRunner(wdacInspectionPowerShellScript(), nil)
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
	$sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
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
	$results += [pscustomobject]@{
	  path = $path
	  'cdx:windows:authenticode:status' = 'error'
	  'cdx:windows:authenticode:error' = [string]$_.Exception.Message
	}
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
