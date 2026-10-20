package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// rootfs coverage: which directories are scanned, with which sourceType, and
// the parsing bounds (PLAN section 4.1).

// Bounds (PLAN section 4.1). They are variables so tests can tighten them;
// production values: 16 MiB per file, 128 MiB per binary, 20,000 files read
// per tree, 500,000 directory entries visited per tree, depth 12, 100
// warnings.
var (
	// maxMaterialFileBytes skips files over 16 MiB; reads are capped at it
	// too, so a file cannot grow past it after the size check.
	maxMaterialFileBytes = int64(16) << 20
	// maxEmbeddedFileBytes bounds the --embedded binary scan at 128 MiB.
	maxEmbeddedFileBytes = int64(128) << 20
	// maxFilesPerTree stops a walk after reading 20,000 files.
	maxFilesPerTree = 20000
	// maxEntriesPerTree stops a walk after visiting 500,000 entries of any
	// type (directories, symlinks, files), so trees of empty directories or
	// links cannot make a walk unbounded.
	maxEntriesPerTree = 500000
	// maxScanDepth is the maximum path depth (relative to the scanned
	// directory) a file may have; deeper directories are not descended.
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

// rootScan confines every file access of a scan to the scanned root.
// os.Root resolves each name inside the root and refuses any symlink, in any
// path component, that leads outside it, so an image cannot point the scan
// at host files; symlinks as the final component and non-regular files
// (FIFOs, devices, sockets) are skipped outright. Every name is
// slash-separated and relative to the root; reported paths are that name with
// a leading "/".
type rootScan struct {
	root        *os.Root
	fsys        fs.FS
	accumulator *materialAccumulator
	warnings    *warningList
	// collected records the files already parsed, so a file inside two
	// candidate directories (etc/ssl/certs/java/cacerts) is read once, by the
	// more specific candidate, which is walked first.
	collected map[string]bool
}

// scanRootfsTrustMaterials walks the coverage table under root and returns
// the deduplicated materials plus any warnings produced by bound hits.
func scanRootfsTrustMaterials(root string, options scanOptions) ([]trustMaterial, []string, error) {
	confined, err := os.OpenRoot(root)
	if err != nil {
		return nil, nil, err
	}
	defer confined.Close()
	scan := &rootScan{
		root:        confined,
		fsys:        confined.FS(),
		accumulator: newMaterialAccumulator(),
		warnings:    &warningList{},
		collected:   map[string]bool{},
	}
	deselected := scan.deselectedCACertificates()

	candidates := candidateDirs()
	for i := range candidates {
		candidates[i].rel = filepath.ToSlash(candidates[i].rel)
	}
	// Most specific first: a file under two candidates takes the sourceType
	// of the deeper one.
	sort.SliceStable(candidates, func(i, j int) bool {
		return strings.Count(candidates[i].rel, "/") > strings.Count(candidates[j].rel, "/")
	})
	for _, candidate := range candidates {
		if candidate.isFile {
			scan.collectFile(candidate.rel, candidate.sourceType)
			continue
		}
		scan.walkMaterialDir(candidate.rel, candidate.sourceType)
	}

	// --extra-dir <rel>: generic directories requested on the command line.
	for _, rel := range options.ExtraDirs {
		scan.walkMaterialDir(path.Clean(filepath.ToSlash(rel)), "generic")
	}

	// --embedded: opt-in scan of the whole root for PEM blocks inside ELF,
	// Mach-O and PE binaries.
	if options.Embedded {
		scan.walkEmbeddedBinaries()
	}

	materials := scan.accumulator.resolve()
	applyCADeselected(materials, deselected)
	if issuerWarnings := linkIssuers(materials, scan.accumulator.certs); len(issuerWarnings) > 0 {
		scan.warnings.add(issuerWarnings...)
	}
	return materials, scan.warnings.list(), nil
}

// errNotRegularFile and errFileTooLarge are the reasons readRegularFile skips
// a file.
var (
	errNotRegularFile = errors.New("not a regular file")
	errFileTooLarge   = errors.New("file too large")
)

// readRegularFile reads a regular file of at most limit bytes. The final
// path component must not be a symlink, the file must be regular when opened
// (not a FIFO or device, which could block or never end), and the read itself
// is capped, so a file growing after the size check is still bounded.
func readRegularFile(open func() (fs.File, error), lstat func() (fs.FileInfo, error), limit int64) ([]byte, error) {
	info, err := lstat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegularFile
	}
	if info.Size() > limit {
		return nil, errFileTooLarge
	}
	file, err := open()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info, err = file.Stat(); err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegularFile
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errFileTooLarge
	}
	return data, nil
}

// readFile reads name (relative to the root) under the confinement and
// bounds of readRegularFile.
func (s *rootScan) readFile(name string, limit int64) ([]byte, error) {
	return readRegularFile(
		func() (fs.File, error) { return s.root.Open(name) },
		func() (fs.FileInfo, error) { return s.root.Lstat(name) },
		limit,
	)
}

// readHostFile reads a file named on the command line (certs mode): not
// confined to a root, but held to the same regular-file and size rules.
func readHostFile(name string, limit int64) ([]byte, error) {
	return readRegularFile(
		func() (fs.File, error) { return os.Open(name) },
		func() (fs.FileInfo, error) { return os.Lstat(name) },
		limit,
	)
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
// section 4.1: symlinks and non-regular files skipped, 16 MiB per file,
// 20,000 files read and 500,000 entries visited per tree, depth 12 (deeper
// directories are not descended). Each bound hit adds an envelope warning.
func (s *rootScan) walkMaterialDir(base, sourceType string) {
	if info, err := s.root.Stat(base); err != nil || !info.IsDir() {
		return
	}
	fileCount, entryCount := 0, 0
	_ = fs.WalkDir(s.fsys, base, func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		entryCount++
		if entryCount > maxEntriesPerTree {
			s.warnings.add(fmt.Sprintf("entry limit (%d) reached in /%s", maxEntriesPerTree, base))
			return fs.SkipAll
		}
		if d.IsDir() {
			if name != base && strings.Count(strings.TrimPrefix(name, base+"/"), "/")+1 >= maxScanDepth {
				s.warnings.add(fmt.Sprintf("depth limit (%d) exceeded in /%s", maxScanDepth, base))
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || s.collected[name] || !looksLikeTrustMaterialPath("/"+name, sourceType) {
			return nil
		}
		fileCount++
		if fileCount > maxFilesPerTree {
			s.warnings.add(fmt.Sprintf("file count limit (%d) reached in /%s", maxFilesPerTree, base))
			return fs.SkipAll
		}
		s.collectFile(name, sourceType)
		return nil
	})
}

// collectFile parses one file and feeds everything it contains into the
// accumulator. Parse failures are not errors: a file that is not trust
// material is simply skipped.
func (s *rootScan) collectFile(name, sourceType string) {
	relPath := "/" + name
	if s.collected[name] || !looksLikeTrustMaterialPath(relPath, sourceType) {
		return
	}
	data, err := s.readFile(name, maxMaterialFileBytes)
	if errors.Is(err, errFileTooLarge) {
		s.warnings.add(fmt.Sprintf("file over %d MiB skipped: %s", maxMaterialFileBytes>>20, relPath))
	}
	if err != nil || len(data) == 0 {
		return
	}
	s.collected[name] = true
	for _, entry := range parseFileMaterials(data, relPath, sourceType) {
		s.accumulator.add(entry.material, entry.location)
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

	// OpenPGP keyrings keep their report-1 handling. A file holding OpenPGP
	// keys can hold certificates too, so both readers always run.
	var entries []parsedEntry
	openPGPMaterials := parseOpenPGPMaterials(data, relPath, sha1Value, sha256Value, trustDomain, sourceType, fileExtension)
	for i := range openPGPMaterials {
		entries = append(entries, parsedEntry{material: &openPGPMaterials[i], location: location})
	}

	sniffed, err := sniffTrustMaterial(data)
	if err != nil {
		return entries
	}
	for _, parsed := range sniffed.certificates {
		material := buildCertificateFields(parsed.cert)
		setCertificateName(material, parsed.cert, relPath)
		material.TrustAcceptedPurposes = parsed.trustAcceptedPurposes
		material.TrustRejectedPurposes = parsed.trustRejectedPurposes
		entries = append(entries, parsedEntry{material: material, location: location})
	}
	for index, privateKey := range sniffed.privateKeys {
		// Private keys carry the header-line format only; nothing is
		// decoded and no digest is emitted (PLAN section 3). Each key in a
		// file is its own material.
		entries = append(entries, parsedEntry{
			material: &trustMaterial{
				Kind:       "private-key",
				Path:       relPath,
				SourceType: sourceType,
				Format:     privateKey.format,
				Properties: []property{{Name: "cdx:crypto:sourceType", Value: sourceType}},
				dedupID:    fmt.Sprintf("%s#%d", relPath, index),
			},
			location: certLocation{path: relPath, sourceType: sourceType},
		})
	}
	for _, keystore := range sniffed.keystores {
		// A trust store yields the certificates it could read; the container
		// itself is a material only when it was not read in full, with
		// keystoreReadable "false" (nothing read) or "partial".
		for _, cert := range keystore.certs {
			material := buildCertificateFields(cert)
			setCertificateName(material, cert, relPath)
			entries = append(entries, parsedEntry{material: material, location: location})
		}
		if keystore.complete {
			continue
		}
		readable := "false"
		if len(keystore.certs) > 0 {
			readable = "partial"
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
					{Name: "cdx:crypto:keystoreReadable", Value: readable},
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
	lowerPath := strings.TrimPrefix(strings.ToLower(filepath.ToSlash(relPath)), "/")
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

// deselectedCACertificates reads etc/ca-certificates.conf and returns the
// root-relative paths of entries disabled with a leading "!". Debian's
// update-ca-certificates(8): "the listed certificates will be removed" /
// lines prefixed with ! are deactivated; the files may still exist under
// usr/share/ca-certificates. Entries are relative to that directory; one that
// resolves outside it is ignored.
// https://manpages.debian.org/bookworm/ca-certificates/update-ca-certificates.8.en.html
func (s *rootScan) deselectedCACertificates() map[string]bool {
	data, err := s.readFile("etc/ca-certificates.conf", maxMaterialFileBytes)
	if err != nil {
		return nil
	}
	const base = "usr/share/ca-certificates/"
	deselected := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		entry, ok := strings.CutPrefix(strings.TrimSpace(line), "!")
		if !ok {
			continue
		}
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		if name := path.Join(base, entry); strings.HasPrefix(name, base) {
			deselected[name] = true
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
			for i := range material.Properties {
				if material.Properties[i].Name == "cdx:crypto:sourceType" {
					material.Properties[i].Value = "ca-deselected"
				}
			}
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

// embeddedExcludedDirs are the root's virtual filesystems, never scanned.
var embeddedExcludedDirs = map[string]bool{
	"proc": true,
	"sys":  true,
	"dev":  true,
	"run":  true,
}

// walkEmbeddedBinaries scans the whole root for ELF/Mach-O/PE binaries (magic
// check) holding PEM CERTIFICATE blocks, at most 128 MiB each (PLAN section
// 4.1, --embedded). It is opt-in because it touches every regular file; only
// a file whose first bytes carry an executable magic is read in full. The
// location carries the binary's digests, like any other file.
func (s *rootScan) walkEmbeddedBinaries() {
	fileCount, entryCount := 0, 0
	_ = fs.WalkDir(s.fsys, ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		entryCount++
		if entryCount > maxEntriesPerTree {
			s.warnings.add(fmt.Sprintf("entry limit (%d) reached during embedded scan", maxEntriesPerTree))
			return fs.SkipAll
		}
		if d.IsDir() {
			if name == "." {
				return nil
			}
			if !strings.Contains(name, "/") && embeddedExcludedDirs[name] {
				return fs.SkipDir
			}
			if strings.Count(name, "/")+1 >= maxScanDepth {
				s.warnings.add(fmt.Sprintf("depth limit (%d) exceeded during embedded scan", maxScanDepth))
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || isPEMBasedPath(name) || !s.hasExecutableMagic(name) {
			// PEM-suffixed files are parsed by the regular walks.
			return nil
		}
		fileCount++
		if fileCount > maxFilesPerTree {
			s.warnings.add(fmt.Sprintf("file count limit (%d) reached during embedded scan", maxFilesPerTree))
			return fs.SkipAll
		}
		data, err := s.readFile(name, maxEmbeddedFileBytes)
		if err != nil {
			return nil
		}
		relPath := "/" + name
		sha1Value, sha256Value := digestBytes(data)
		for _, cert := range embeddedCertificateBlocks(data) {
			material := buildCertificateFields(cert)
			setCertificateName(material, cert, relPath)
			s.accumulator.add(material, certLocation{
				path:          relPath,
				sourceType:    "embedded-binary",
				trustDomain:   deriveTrustDomain(relPath),
				fileExtension: strings.TrimPrefix(strings.ToLower(path.Ext(relPath)), "."),
				sha1Value:     sha1Value,
				sha256Value:   sha256Value,
			})
		}
		return nil
	})
}

// hasExecutableMagic reads only the first bytes of a regular file to check
// for an ELF, Mach-O or PE magic.
func (s *rootScan) hasExecutableMagic(name string) bool {
	file, err := s.root.Open(name)
	if err != nil {
		return false
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() || info.Size() < 4 || info.Size() > maxEmbeddedFileBytes {
		return false
	}
	magic := make([]byte, 4)
	if _, err := io.ReadFull(file, magic); err != nil {
		return false
	}
	return isExecutableBinaryMagic(magic)
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
