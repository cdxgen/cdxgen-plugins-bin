package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// rootfs coverage: which directories are scanned, with which sourceType, and
// the parsing bounds (PLAN section 4.1).

// Bounds (PLAN section 4.1). They are variables so tests can tighten them;
// production values: 16 MiB per file, 128 MiB per binary, 20,000 files per
// tree, depth 12, 100 warnings.
var (
	// maxMaterialFileBytes skips files over 16 MiB before reading them.
	maxMaterialFileBytes = int64(16) << 20
	// maxEmbeddedFileBytes bounds the --embedded binary scan at 128 MiB.
	maxEmbeddedFileBytes = int64(128) << 20
	// maxFilesPerTree stops a walk after 20,000 entries.
	maxFilesPerTree = 20000
	// maxScanDepth is the maximum path depth (relative to the scanned
	// directory) a file may have.
	maxScanDepth = 12
	// maxWarnings caps the envelope warnings list.
	maxWarnings = 100
)

// scanOptions carries the rootfs/certs mode flags.
type scanOptions struct {
	Embedded  bool
	ExtraDirs []string
}

// candidateDir is one scanned location (relative to the root) and the
// sourceType its findings carry.
type candidateDir struct {
	rel        string
	isFile     bool // the candidate is a single file, not a directory
	sourceType string
}

// candidateDirs is the coverage table. sourceTypes follow PLAN section 4.1;
// repository-keyring entries keep their report-1 sourceType.
func candidateDirs() []candidateDir {
	dirs := []candidateDir{
		{rel: filepath.Join("etc", "apt", "trusted.gpg.d"), sourceType: "repository-keyring"},
		{rel: filepath.Join("usr", "share", "keyrings"), sourceType: "repository-keyring"},
		{rel: filepath.Join("etc", "pki", "rpm-gpg"), sourceType: "repository-keyring"},
		{rel: filepath.Join("usr", "share", "distribution-gpg-keys"), sourceType: "repository-keyring"},
		{rel: filepath.Join("etc", "apk", "keys"), sourceType: "repository-keyring"},
		// ca-store: report-1's list plus the RHEL/Fedora and var/lib
		// locations (update-ca-trust(8), update-ca-certificates(8)).
		{rel: filepath.Join("etc", "ssl", "certs"), sourceType: "ca-store"},
		{rel: filepath.Join("etc", "ssl", "cert.pem"), isFile: true, sourceType: "ca-store"},
		{rel: filepath.Join("usr", "local", "share", "ca-certificates"), sourceType: "ca-store"},
		{rel: filepath.Join("usr", "share", "ca-certificates"), sourceType: "ca-store"},
		{rel: filepath.Join("etc", "pki", "tls", "certs"), sourceType: "ca-store"},
		{rel: filepath.Join("etc", "pki", "ca-trust", "source", "anchors"), sourceType: "ca-store"},
		{rel: filepath.Join("etc", "pki", "ca-trust", "extracted"), sourceType: "ca-store"},
		{rel: filepath.Join("var", "lib", "ca-certificates"), sourceType: "ca-store"},
		{rel: filepath.Join("usr", "share", "pki", "ca-trust-source", "anchors"), sourceType: "ca-store"},
		// ca-blocklist: p11-kit block and blacklist anchors. Debian ships
		// "blacklist"; Fedora ships "blocklist".
		{rel: filepath.Join("etc", "pki", "ca-trust", "source", "blocklist"), sourceType: "ca-blocklist"},
		{rel: filepath.Join("etc", "pki", "ca-trust", "source", "blacklist"), sourceType: "ca-blocklist"},
		{rel: filepath.Join("usr", "share", "pki", "ca-trust-source", "blocklist"), sourceType: "ca-blocklist"},
		{rel: filepath.Join("usr", "share", "pki", "ca-trust-source", "blacklist"), sourceType: "ca-blocklist"},
	}
	// server-config: server chain files and keys live here.
	for _, rel := range []string{
		filepath.Join("etc", "nginx"),
		filepath.Join("etc", "apache2"),
		filepath.Join("etc", "httpd"),
		filepath.Join("etc", "haproxy"),
		filepath.Join("etc", "letsencrypt", "live"),
		filepath.Join("etc", "letsencrypt", "archive"),
		filepath.Join("etc", "kubernetes", "pki"),
		filepath.Join("var", "lib", "kubelet", "pki"),
		filepath.Join("etc", "docker", "certs.d"),
		filepath.Join("etc", "containerd", "certs.d"),
		filepath.Join("etc", "envoy"),
		filepath.Join("etc", "traefik"),
	} {
		dirs = append(dirs, candidateDir{rel: rel, sourceType: "server-config"})
	}
	// java-truststore roots: any regular file with a keystore name under
	// these trees is content-sniffed (magic), never trusted by name.
	for _, rel := range []string{
		filepath.Join("usr", "lib", "jvm"),
		filepath.Join("opt"),
		filepath.Join("etc", "ssl", "certs", "java"),
		filepath.Join("etc", "pki", "java"),
		filepath.Join("usr", "share", "elasticsearch"),
	} {
		dirs = append(dirs, candidateDir{rel: rel, sourceType: "java-truststore"})
	}
	// language-bundle roots: any cacert.pem under these trees (certifi,
	// botocore, pip's vendored certifi, ruby gems).
	for _, rel := range []string{
		filepath.Join("usr", "lib"),
		filepath.Join("usr", "local", "lib"),
		filepath.Join("opt"),
	} {
		dirs = append(dirs, candidateDir{rel: rel, sourceType: "language-bundle"})
	}
	return dirs
}

// scanRootfsTrustMaterials walks the coverage table under root and returns
// the deduplicated materials plus any warnings produced by bound hits.
func scanRootfsTrustMaterials(root string, options scanOptions) ([]trustMaterial, []string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", root)
	}

	accumulator := newMaterialAccumulator()
	warnings := &warningList{}
	deselected := deselectedCACertificates(root)

	for _, candidate := range candidateDirs() {
		baseDir := filepath.Join(root, candidate.rel)
		if _, err := os.Stat(baseDir); err != nil {
			continue
		}
		if candidate.isFile {
			collectFileMaterial(accumulator, baseDir, root, candidate.sourceType, warnings)
			continue
		}
		walkMaterialDir(accumulator, baseDir, root, candidate.sourceType, warnings)
	}

	// --extra-dir <rel>: generic directories requested on the command line.
	for _, rel := range options.ExtraDirs {
		baseDir := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(baseDir); err != nil {
			continue
		}
		walkMaterialDir(accumulator, baseDir, root, "generic", warnings)
	}

	// --embedded: opt-in scan of the whole root for PEM blocks inside ELF,
	// Mach-O and PE binaries.
	if options.Embedded {
		walkEmbeddedBinaries(accumulator, root, warnings)
	}

	materials := accumulator.resolve()
	applyCADeselected(materials, deselected)
	if issuerWarnings := linkIssuers(materials, accumulator.certs); len(issuerWarnings) > 0 {
		warnings.add(issuerWarnings...)
	}
	return materials, warnings.list(), nil
}

type warningList struct {
	items     []string
	seen      map[string]bool
	truncated bool
}

func (w *warningList) add(warnings ...string) {
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	for _, warning := range warnings {
		if w.seen[warning] {
			continue
		}
		w.seen[warning] = true
		if len(w.items) >= maxWarnings {
			w.truncated = true
			return
		}
		w.items = append(w.items, warning)
	}
}

func (w *warningList) list() []string {
	sort.Strings(w.items)
	if w.truncated {
		w.items = append(w.items, fmt.Sprintf("further warnings suppressed (limit %d)", maxWarnings))
	}
	return w.items
}

// walkMaterialDir walks one candidate directory with the bounds from PLAN
// section 4.1: symlinks skipped, 16 MiB per file, 20,000 files per tree,
// depth 12. Each bound hit adds an envelope warning.
func walkMaterialDir(accumulator *materialAccumulator, baseDir, root, sourceType string, warnings *warningList) {
	fileCount := 0
	depthWarned := false
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
		fileCount++
		if fileCount > maxFilesPerTree {
			warnings.add(fmt.Sprintf("file count limit (%d) reached in %s", maxFilesPerTree, displayPath(baseDir, root)))
			return fs.SkipAll
		}
		relBase, err := filepath.Rel(baseDir, current)
		if err != nil {
			return nil
		}
		if depth := strings.Count(relBase, string(filepath.Separator)) + 1; depth > maxScanDepth {
			if !depthWarned {
				depthWarned = true
				warnings.add(fmt.Sprintf("depth limit (%d) exceeded in %s", maxScanDepth, displayPath(baseDir, root)))
			}
			return nil
		}
		if info, err := d.Info(); err == nil && info.Size() > maxMaterialFileBytes {
			warnings.add(fmt.Sprintf("file over %d MiB skipped: %s", maxMaterialFileBytes>>20, displayPath(current, root)))
			return nil
		}
		collectFileMaterial(accumulator, current, root, sourceType, warnings)
		return nil
	})
}

// collectFileMaterial parses one file and feeds everything it contains into
// the accumulator. Parse failures are not errors: a file that is not trust
// material is simply skipped.
func collectFileMaterial(accumulator *materialAccumulator, absolutePath, root, sourceType string, warnings *warningList) {
	relPath := relativeRootPath(absolutePath, root)
	if !looksLikeTrustMaterialPath(relPath, sourceType) {
		return
	}
	data, err := os.ReadFile(absolutePath)
	if err != nil || len(data) == 0 {
		return
	}
	for _, entry := range parseFileMaterials(data, relPath, sourceType) {
		accumulator.add(entry.material, entry.location)
	}
}

// parsedEntry pairs a built material with the location it was found at.
type parsedEntry struct {
	material *trustMaterial
	location certLocation
}

// parseFileMaterials runs the format sniffers over one file's bytes and
// returns one material per finding, each with its location record.
func parseFileMaterials(data []byte, relPath, sourceType string) []parsedEntry {
	sha1Value, sha256Value := digestBytes(data)
	trustDomain := deriveTrustDomain(relPath)
	fileExtension := strings.TrimPrefix(strings.ToLower(filepath.Ext(relPath)), ".")
	location := certLocation{
		path:          relPath,
		sourceType:    sourceType,
		trustDomain:   trustDomain,
		fileExtension: fileExtension,
		sha1Value:     sha1Value,
		sha256Value:   sha256Value,
	}

	// OpenPGP keyrings keep their report-1 handling.
	if openPGPMaterials := parseOpenPGPMaterials(data, relPath, sha1Value, sha256Value, trustDomain, sourceType, fileExtension); len(openPGPMaterials) > 0 {
		var entries []parsedEntry
		for i := range openPGPMaterials {
			entries = append(entries, parsedEntry{material: &openPGPMaterials[i], location: location})
		}
		return entries
	}

	sniffed, err := sniffTrustMaterial(data)
	if err != nil {
		return nil
	}
	var entries []parsedEntry
	for _, parsed := range sniffed.certificates {
		material := buildCertificateFields(parsed.cert)
		setCertificateName(material, parsed.cert, relPath)
		material.TrustRejectedPurposes = parsed.trustRejectedPurposes
		entries = append(entries, parsedEntry{material: material, location: location})
	}
	for _, privateKey := range sniffed.privateKeys {
		// Private keys carry the header-line format only; nothing is
		// decoded and no digest is emitted (PLAN section 3).
		entries = append(entries, parsedEntry{
			material: &trustMaterial{
				Kind:       "private-key",
				Path:       relPath,
				SourceType: sourceType,
				Format:     privateKey.format,
				Properties: []property{{Name: "cdx:crypto:sourceType", Value: sourceType}},
			},
			location: certLocation{path: relPath, sourceType: sourceType},
		})
	}
	for _, keystore := range sniffed.keystores {
		if keystore.readable {
			// A readable trust store yields its certificates; the container
			// itself is not a material (kind "keystore" is reserved for
			// stores that could not be read).
			for _, cert := range keystore.certs {
				material := buildCertificateFields(cert)
				setCertificateName(material, cert, relPath)
				entries = append(entries, parsedEntry{material: material, location: location})
			}
			continue
		}
		entries = append(entries, parsedEntry{
			material: &trustMaterial{
				Kind:       "keystore",
				Path:       relPath,
				Name:       filepath.Base(relPath),
				SourceType: sourceType,
				Format:     keystore.format,
				Properties: []property{
					{Name: "cdx:crypto:sourceType", Value: sourceType},
					{Name: "cdx:crypto:keystoreReadable", Value: "false"},
				},
			},
			location: certLocation{path: relPath, sourceType: sourceType},
		})
	}
	return entries
}

// looksLikeTrustMaterialPath decides whether a file inside a candidate
// directory is inspected. It works on the root-relative path.
//
// The "private" exclusion (G7) tests the path relative to the scanned root,
// not the absolute host path: a scan rooted at a macOS temp directory (which
// lives under /private/...) must still find everything. The exclusion matches
// the segment "private" only directly under etc/ssl/ or etc/pki/tls/, the
// real key directories (update-ca-certificates(8)).
//
// Dedicated walks apply their own name filter: the language-bundle walk only
// follows cacert.pem, and the java-truststore walk only follows keystore
// names; the content sniff then decides what the file really is.
func looksLikeTrustMaterialPath(relPath, sourceType string) bool {
	lowerPath := strings.ToLower(filepath.ToSlash(relPath))
	if strings.HasPrefix(lowerPath, "etc/ssl/private/") || strings.HasPrefix(lowerPath, "etc/pki/tls/private/") {
		return false
	}
	base := strings.ToLower(filepath.Base(relPath))
	switch sourceType {
	case "language-bundle":
		return base == "cacert.pem"
	case "java-truststore":
		return isJavaKeystoreName(base)
	}
	if base == "trusted.gpg" || strings.HasPrefix(base, "rpm-gpg-key") {
		return true
	}
	// Keystore-looking names are inspected wherever they appear; the content
	// sniff (magic) decides what they actually are.
	if isJavaKeystoreName(base) {
		return true
	}
	for _, suffix := range []string{".asc", ".gpg", ".pgp", ".pub", ".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".p12", ".pfx", ".jks", ".jceks", ".truststore", ".key"} {
		if strings.HasSuffix(lowerPath, suffix) {
			return true
		}
	}
	return strings.Contains(lowerPath, "/certs/")
}

// isJavaKeystoreName matches the keystore file names Java tooling looks for
// (keytool -cacerts, jssecacerts, and the common extensions).
func isJavaKeystoreName(base string) bool {
	switch base {
	case "cacerts", "jssecacerts":
		return true
	}
	for _, suffix := range []string{".jks", ".jceks", ".truststore", ".p12", ".pfx"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

// relativeRootPath renders the reported path: root-relative with a leading
// slash (the report-1 convention).
func relativeRootPath(absolutePath, root string) string {
	relPath := "/" + filepath.ToSlash(strings.TrimPrefix(absolutePath, root))
	relPath = strings.ReplaceAll(relPath, "//", "/")
	return relPath
}

func displayPath(absolutePath, root string) string {
	return relativeRootPath(absolutePath, root)
}

// deselectedCACertificates reads etc/ca-certificates.conf and returns the
// root-relative paths of entries disabled with a leading "!". Debian's
// update-ca-certificates(8): "the listed certificates will be removed" /
// lines prefixed with ! are deactivated; the files may still exist under
// usr/share/ca-certificates.
// https://manpages.debian.org/bookworm/ca-certificates/update-ca-certificates.8.en.html
func deselectedCACertificates(root string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(root, "etc", "ca-certificates.conf"))
	if err != nil {
		return nil
	}
	deselected := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "!") {
			entry := strings.TrimSpace(strings.TrimPrefix(line, "!"))
			if entry != "" {
				deselected[strings.TrimPrefix(filepath.ToSlash(filepath.Join("usr", "share", "ca-certificates", entry)), "/")] = true
			}
		}
	}
	if len(deselected) == 0 {
		return nil
	}
	return deselected
}

// applyCADeselected marks locations that point at a certificate disabled in
// etc/ca-certificates.conf with sourceType ca-deselected.
func applyCADeselected(materials []trustMaterial, deselected map[string]bool) {
	if len(deselected) == 0 {
		return
	}
	for index := range materials {
		material := &materials[index]
		isDeselected := false
		for _, path := range material.Paths {
			if deselected[strings.Trim(path, "/")] {
				isDeselected = true
				break
			}
		}
		if !isDeselected {
			continue
		}
		if deselected[strings.Trim(material.Path, "/")] {
			material.SourceType = "ca-deselected"
		}
		has := false
		for _, sourceType := range material.SourceTypes {
			if sourceType == "ca-deselected" {
				has = true
			}
		}
		if !has {
			material.SourceTypes = append(material.SourceTypes, "ca-deselected")
			sort.Strings(material.SourceTypes)
		}
	}
}

// embeddedExcludedDirs are virtual filesystems that are never scanned.
var embeddedExcludedDirs = map[string]bool{
	"proc": true,
	"sys":  true,
	"dev":  true,
	"run":  true,
}

// walkEmbeddedBinaries scans the whole root for ELF/Mach-O/PE binaries (magic
// check) holding PEM CERTIFICATE blocks, at most 128 MiB each (PLAN section
// 4.1, --embedded). It is opt-in because it touches every regular file.
func walkEmbeddedBinaries(accumulator *materialAccumulator, root string, warnings *warningList) {
	fileCount := 0
	depthWarned := false
	_ = filepath.WalkDir(root, func(current string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if current != root && embeddedExcludedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		fileCount++
		if fileCount > maxFilesPerTree {
			warnings.add(fmt.Sprintf("file count limit (%d) reached during embedded scan", maxFilesPerTree))
			return fs.SkipAll
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return nil
		}
		if depth := strings.Count(rel, string(filepath.Separator)) + 1; depth > maxScanDepth {
			if !depthWarned {
				depthWarned = true
				warnings.add(fmt.Sprintf("depth limit (%d) exceeded during embedded scan", maxScanDepth))
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > maxEmbeddedFileBytes {
			return nil
		}
		if isPEMBasedPath(rel) {
			// PEM-suffixed files are parsed by the regular walks.
			return nil
		}
		data, err := os.ReadFile(current)
		if err != nil || !isExecutableBinaryMagic(data) {
			return nil
		}
		relPath := relativeRootPath(current, root)
		for _, cert := range embeddedCertificateBlocks(data) {
			material := buildCertificateFields(cert)
			setCertificateName(material, cert, relPath)
			accumulator.add(material, certLocation{
				path:       relPath,
				sourceType: "embedded-binary",
			})
		}
		return nil
	})
}

// isPEMBasedPath reports whether a path looks like a PEM/cert file so the
// embedded walk can skip it.
func isPEMBasedPath(relPath string) bool {
	lower := strings.ToLower(filepath.ToSlash(relPath))
	for _, suffix := range []string{".pem", ".crt", ".cer", ".der", ".gpg", ".pgp", ".asc", ".pub", ".p7b", ".p7c"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// isExecutableBinaryMagic checks ELF, Mach-O and PE magic numbers:
// ELF "\x7fELF", Mach-O 0xfeedface/0xfeedfacf and byte-swapped variants, PE
// "MZ".
func isExecutableBinaryMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return true
	}
	if data[0] == 'M' && data[1] == 'Z' {
		return true
	}
	macho := binaryBigEndianUint32(data[:4])
	switch macho {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE:
		return true
	}
	return false
}

func binaryBigEndianUint32(data []byte) uint32 {
	return uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
}
