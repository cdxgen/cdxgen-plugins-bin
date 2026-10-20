package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeFileRel writes data under root/rel, creating directories.
func writeFileRel(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestG7ScanUnderPrivateTempPath is the regression test for G7: a scan rooted
// at a directory whose ABSOLUTE path contains /private/ (any macOS t.TempDir)
// must still find certificates. The exclusion now tests the path relative to
// the root.
func TestG7ScanUnderPrivateTempPath(t *testing.T) {
	root := t.TempDir() // on macOS this lives under /var/folders/... -> /private/var/folders
	if !strings.Contains(root, "/private/") {
		t.Skipf("temp dir %s does not contain /private/", root)
	}
	writeFileRel(t, root, "etc/ssl/certs/demo-bundle.pem", fixture(t, "demo-bundle.pem"))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	certs := 0
	for _, material := range materials {
		if material.Kind == "certificate" {
			certs++
		}
	}
	if certs != 3 {
		t.Fatalf("expected 3 certificates under a /private/ root, got %d", certs)
	}
}

// TestG7RealPrivateDirsStayExcluded keeps the original intent of the
// exclusion: etc/ssl/private and etc/pki/tls/private are never scanned.
func TestG7RealPrivateDirsStayExcluded(t *testing.T) {
	root := t.TempDir()
	writeFileRel(t, root, "etc/ssl/certs/demo-bundle.pem", fixture(t, "demo-bundle.pem"))
	writeFileRel(t, root, "etc/ssl/private/server.key.pem", fixture(t, "demo-leaf.crt"))
	writeFileRel(t, root, "etc/pki/tls/private/server.crt", fixture(t, "demo-leaf.crt"))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, material := range materials {
		for _, path := range material.Paths {
			if strings.HasPrefix(path, "/etc/ssl/private/") || strings.HasPrefix(path, "/etc/pki/tls/private/") {
				t.Fatalf("private directory was scanned: %s", path)
			}
		}
	}
	if len(materials) != 3 {
		t.Fatalf("expected only the 3 bundle certificates, got %d", len(materials))
	}
}

// TestServerConfigPrivateKeysAreReported checks the server-config walks pick
// up chain files and private keys (header only) while ca-store walks still
// skip private keys under the real key directories.
func TestServerConfigPrivateKeysAreReported(t *testing.T) {
	root := t.TempDir()
	writeFileRel(t, root, "etc/nginx/ssl/fullchain.pem", fixture(t, "demo-bundle.pem"))
	writeFileRel(t, root, "etc/nginx/ssl/privkey.pem", privateKeyHeaderPEM(t, "RSA PRIVATE KEY"))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	kinds := map[string]int{}
	for _, material := range materials {
		kinds[material.Kind]++
		if material.Kind == "private-key" {
			if material.Format != "RSA" {
				t.Fatalf("expected RSA format from the header, got %q", material.Format)
			}
			if material.SourceType != "server-config" {
				t.Fatalf("expected server-config sourceType, got %q", material.SourceType)
			}
		}
	}
	if kinds["certificate"] != 3 || kinds["private-key"] != 1 {
		t.Fatalf("expected 3 certificates and 1 private key, got %#v", kinds)
	}
}

// TestDirectoryClasses checks each coverage-table class lands its sourceType.
func TestDirectoryClasses(t *testing.T) {
	root := t.TempDir()
	bundle := fixture(t, "demo-bundle.pem")
	writeFileRel(t, root, "etc/pki/tls/certs/store.pem", bundle)
	writeFileRel(t, root, "etc/pki/ca-trust/source/blocklist/bad.pem", fixture(t, "demo-cross-signed.crt"))
	writeFileRel(t, root, "usr/share/pki/ca-trust-source/blacklist/bad2.pem", fixture(t, "demo-cross-signed.crt"))
	writeFileRel(t, root, "usr/lib/jvm/java-21/lib/security/cacerts", fixture(t, "demo-truststore.jks"))
	writeFileRel(t, root, "usr/lib/python3/dist-packages/certifi/cacert.pem", fixture(t, "demo-bundle.pem"))
	writeFileRel(t, root, "etc/letsencrypt/live/example/fullchain.pem", fixture(t, "demo-bundle.pem"))
	writeFileRel(t, root, "etc/ssl/cert.pem", fixture(t, "demo-root.crt"))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	sourceTypes := map[string]bool{}
	for _, material := range materials {
		for _, sourceType := range material.SourceTypes {
			sourceTypes[sourceType] = true
		}
	}
	for _, want := range []string{"ca-store", "ca-blocklist", "java-truststore", "language-bundle", "server-config"} {
		if !sourceTypes[want] {
			t.Fatalf("expected sourceType %s in %#v", want, sourceTypes)
		}
	}
	// The certifi bundle and the system store hold the same certificates:
	// each cert must carry both locations (G3).
	for _, material := range materials {
		if material.Kind == "certificate" && material.CertSHA256 != "" && len(material.Paths) > 1 {
			hasBundle := false
			hasCertifi := false
			for _, path := range material.Paths {
				if strings.HasPrefix(path, "/usr/lib/python3/") {
					hasCertifi = true
				}
				if strings.HasPrefix(path, "/etc/pki/tls/") {
					hasBundle = true
				}
			}
			if hasBundle && !hasCertifi {
				t.Fatalf("expected every location to be kept, got %#v", material.Paths)
			}
		}
	}
}

// TestCADeselected marks certificates disabled via etc/ca-certificates.conf.
func TestCADeselected(t *testing.T) {
	root := t.TempDir()
	writeFileRel(t, root, "usr/share/ca-certificates/mozilla/demo.crt", fixture(t, "demo-root.crt"))
	writeFileRel(t, root, "usr/share/ca-certificates/mozilla/keep.crt", fixture(t, "demo-leaf.crt"))
	writeFileRel(t, root, "etc/ca-certificates.conf", []byte("mozilla/keep.crt\n!mozilla/demo.crt\n# comment\n"))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	byName := map[string]trustMaterial{}
	for _, material := range materials {
		byName[material.Name] = material
	}
	deselected, ok := byName["Inspector Root A"]
	if !ok {
		t.Fatalf("missing deselected certificate in %#v", byName)
	}
	if deselected.SourceType != "ca-deselected" {
		t.Fatalf("expected ca-deselected sourceType, got %q", deselected.SourceType)
	}
	kept, ok := byName["leaf.inspector.test"]
	if !ok || kept.SourceType == "ca-deselected" {
		t.Fatalf("expected the active certificate to keep its sourceType, got %#v", kept)
	}
}

// TestExtraDirs covers --extra-dir: relative dirs are scanned as generic;
// absolute paths and .. are rejected.
func TestExtraDirs(t *testing.T) {
	root := t.TempDir()
	writeFileRel(t, root, "srv/app/pool.pem", fixture(t, "demo-bundle.pem"))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{ExtraDirs: []string{"srv/app"}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := false
	for _, material := range materials {
		if material.SourceType == "generic" && material.Kind == "certificate" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected generic certificates from the extra dir, got %#v", materials)
	}
	for _, bad := range []string{"../etc", "/etc/ssl", "a/../.."} {
		if err := validateExtraDir(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

// TestScanBounds verifies each bound hit adds a warning and stops the walk.
func TestScanBounds(t *testing.T) {
	setBounds := func(t *testing.T, files int64, depth int) {
		t.Helper()
		oldFiles, oldDepth := maxFilesPerTree, maxScanDepth
		maxFilesPerTree = int(files)
		maxScanDepth = depth
		t.Cleanup(func() {
			maxFilesPerTree = oldFiles
			maxScanDepth = oldDepth
		})
	}

	t.Run("file size", func(t *testing.T) {
		root := t.TempDir()
		writeFileRel(t, root, "etc/ssl/certs/small.pem", fixture(t, "demo-bundle.pem"))
		// A sparse 2 MiB file: over the lowered limit, never read.
		path := filepath.Join(root, "etc", "ssl", "certs", "huge.pem")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(2 << 20); err != nil {
			t.Fatal(err)
		}
		file.Close()
		maxMaterialFileBytes = 1 << 20
		defer func() { maxMaterialFileBytes = int64(16) << 20 }()
		materials, warnings, err := scanRootfsTrustMaterials(root, scanOptions{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(warnings) == 0 {
			t.Fatal("expected a file-size warning")
		}
		for _, material := range materials {
			for _, path := range material.Paths {
				if strings.HasSuffix(path, "huge.pem") {
					t.Fatal("oversized file was parsed")
				}
			}
		}
	})

	t.Run("file count", func(t *testing.T) {
		setBounds(t, 5, 12)
		root := t.TempDir()
		for i := 0; i < 8; i++ {
			writeFileRel(t, root, "etc/ssl/certs/c"+string(rune('a'+i))+".pem", fixture(t, "demo-leaf.crt"))
		}
		_, warnings, err := scanRootfsTrustMaterials(root, scanOptions{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		joined := strings.Join(warnings, "\n")
		if !strings.Contains(joined, "file count limit") {
			t.Fatalf("expected a file count warning, got %v", warnings)
		}
	})

	t.Run("depth", func(t *testing.T) {
		setBounds(t, 20000, 2)
		root := t.TempDir()
		writeFileRel(t, root, "etc/ssl/certs/a/b/deep.pem", fixture(t, "demo-leaf.crt"))
		writeFileRel(t, root, "etc/ssl/certs/top.pem", fixture(t, "demo-leaf.crt"))
		materials, warnings, err := scanRootfsTrustMaterials(root, scanOptions{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "\n"), "depth limit") {
			t.Fatalf("expected a depth warning, got %v", warnings)
		}
		for _, material := range materials {
			for _, path := range material.Paths {
				if strings.HasSuffix(path, "deep.pem") {
					t.Fatal("over-deep file was parsed")
				}
			}
		}
	})
}

// TestEmbeddedScanFindsGoBinary builds a real Go binary with an embedded PEM
// at test time (go build into a temp dir; nothing committed) and asserts the
// --embedded scan finds the certificate with sourceType embedded-binary.
func TestEmbeddedScanFindsGoBinary(t *testing.T) {
	binary := buildEmbeddedGoBinary(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "local", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "local", "bin", "goapp"), binary, 0o755); err != nil {
		t.Fatal(err)
	}
	materials, warnings, err := scanRootfsTrustMaterials(root, scanOptions{Embedded: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	found := false
	for _, material := range materials {
		if material.SourceType == "embedded-binary" && material.Kind == "certificate" {
			found = true
			if material.Name != "Inspector Issuing CA" {
				t.Fatalf("unexpected embedded certificate %q", material.Name)
			}
		}
	}
	if !found {
		t.Fatalf("embedded certificate not found in %d materials", len(materials))
	}
	// Without --embedded the binary is not scanned.
	materials, _, err = scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(materials) != 0 {
		t.Fatalf("expected no materials without --embedded, got %d", len(materials))
	}
}

// buildEmbeddedGoBinary writes a tiny main.go with a //go:embed certificate
// into a temp module and runs go build on it.
func buildEmbeddedGoBinary(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	main := `package main

import (
	_ "embed"
	"crypto/x509"
)

//go:embed pinned.pem
var pinned []byte

func main() {
	pool := x509.NewCertPool()
	println(pool.AppendCertsFromPEM(pinned))
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/embedapp\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pinned.pem"), fixture(t, "demo-intermediate.crt"), 0o644); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "embedapp")
	output, err := goBuild(binaryPath, dir)
	if err != nil {
		t.Fatalf("go build: %v: %s", err, output)
	}
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// privateKeyHeaderPEM builds a private-key PEM with a header line and a
// random body: classified from the header only, never decoded.
func privateKeyHeaderPEM(t *testing.T, blockType string) []byte {
	t.Helper()
	body := make([]byte, 48)
	if _, err := randomRead(body); err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	buffer.WriteString("-----BEGIN " + blockType + "-----\n")
	buffer.WriteString(randomHex(t, body) + "\n")
	buffer.WriteString("-----END " + blockType + "-----\n")
	return buffer.Bytes()
}

// randomRead wraps crypto/rand.Read for the header-only key fixtures.
func randomRead(data []byte) (int, error) {
	return rand.Read(data)
}

// goBuild runs go build for the embedded-binary test fixture.
func goBuild(output, dir string) (string, error) {
	command := exec.Command("go", "build", "-o", output, ".")
	command.Dir = dir
	var stderr bytes.Buffer
	command.Stderr = &stderr
	err := command.Run()
	return stderr.String(), err
}

// Review regressions for the rootfs scanner.

// The G7 key-directory exclusion holds even when an extra dir covers it.
func TestG7PrivateDirExcludedUnderExtraDir(t *testing.T) {
	root := t.TempDir()
	writeFileRel(t, root, "etc/ssl/private/server.pem", fixture(t, "demo-leaf.crt"))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{ExtraDirs: []string{"etc/ssl"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(materials) != 0 {
		t.Fatalf("etc/ssl/private was scanned: %+v", materials)
	}
}

// Reported paths are root-relative however the root argument is spelled.
func TestUncleanRootArgument(t *testing.T) {
	root := t.TempDir()
	writeFileRel(t, root, "etc/ssl/certs/a.pem", fixture(t, "demo-root.crt"))
	for _, spelled := range []string{root + "/", root + "/./", filepath.Dir(root) + "//" + filepath.Base(root)} {
		materials, _, err := scanRootfsTrustMaterials(spelled, scanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(materials) != 1 || materials[0].Path != "/etc/ssl/certs/a.pem" {
			t.Fatalf("root %q: %+v", spelled, materials)
		}
	}
}

// A certificate in a CA store and in a binary keeps the CA store as its
// primary location, with that file's digests, and the binary location has
// the binary's digests.
func TestEmbeddedLocationDoesNotBecomePrimary(t *testing.T) {
	root := t.TempDir()
	pemText := fixture(t, "demo-root.crt")
	writeFileRel(t, root, "etc/ssl/certs/root.pem", pemText)
	writeFileRel(t, root, "app/server", append([]byte("\x7fELF\x02\x01\x01\x00"), pemText...))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{Embedded: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(materials) != 1 {
		t.Fatalf("materials = %+v", materials)
	}
	m := materials[0]
	_, wantSHA := digestBytes(pemText)
	if m.Path != "/etc/ssl/certs/root.pem" || m.SourceType != "ca-store" || m.SHA256 != wantSHA ||
		!slices.Equal(m.Paths, []string{"/app/server", "/etc/ssl/certs/root.pem"}) ||
		!slices.Equal(m.SourceTypes, []string{"ca-store", "embedded-binary"}) {
		t.Fatalf("material = path %s sourceType %s sha256 %s paths %v sourceTypes %v", m.Path, m.SourceType, m.SHA256, m.Paths, m.SourceTypes)
	}
}

// ca-deselected updates the sourceType property with the field, and a "!"
// entry that climbs out of usr/share/ca-certificates is ignored.
func TestCADeselectedPropertyAndEscape(t *testing.T) {
	root := t.TempDir()
	writeFileRel(t, root, "usr/share/ca-certificates/mozilla/demo.crt", fixture(t, "demo-root.crt"))
	writeFileRel(t, root, "etc/ssl/certs/leaf.pem", fixture(t, "demo-leaf.crt"))
	writeFileRel(t, root, "etc/ca-certificates.conf", []byte("!mozilla/demo.crt\r\n!../../../etc/ssl/certs/leaf.pem\n"))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range materials {
		deselected := m.SourceType == "ca-deselected"
		if deselected != (m.Path == "/usr/share/ca-certificates/mozilla/demo.crt") {
			t.Errorf("%s: sourceType %s", m.Path, m.SourceType)
		}
		if !hasProperty(m.Properties, "cdx:crypto:sourceType", m.SourceType) {
			t.Errorf("%s: property disagrees with sourceType %s: %+v", m.Path, m.SourceType, m.Properties)
		}
	}
}

// Directories past the depth limit are not descended, and the entry limit
// stops walks of empty directories.
func TestWalkBoundsCountDirectories(t *testing.T) {
	oldDepth, oldEntries := maxScanDepth, maxEntriesPerTree
	maxScanDepth, maxEntriesPerTree = 3, 50
	defer func() { maxScanDepth, maxEntriesPerTree = oldDepth, oldEntries }()
	root := t.TempDir()
	writeFileRel(t, root, "etc/ssl/certs/a/b/c/d/deep.pem", fixture(t, "demo-root.crt"))
	for i := range 60 {
		if err := os.MkdirAll(filepath.Join(root, "usr", "local", "share", "ca-certificates", fmt.Sprintf("d%02d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	materials, warnings, err := scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(materials) != 0 {
		t.Fatalf("depth limit: %+v", materials)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "depth limit (3) exceeded in /etc/ssl/certs") || !strings.Contains(joined, "entry limit (50) reached in /usr/local/share/ca-certificates") {
		t.Fatalf("warnings = %v", warnings)
	}
}

// Debian's etc/ssl/certs/java/cacerts belongs to the java-truststore
// candidate, not the enclosing ca-store one.
func TestNestedCandidateKeepsSpecificSourceType(t *testing.T) {
	root := t.TempDir()
	writeFileRel(t, root, "etc/ssl/certs/java/cacerts", fixture(t, "demo-truststore.jks"))
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(materials) != 2 {
		t.Fatalf("materials = %+v", materials)
	}
	for _, m := range materials {
		if !slices.Equal(m.SourceTypes, []string{"java-truststore"}) {
			t.Fatalf("%s sourceTypes %v", m.Name, m.SourceTypes)
		}
	}
}

// Only the root's own run/ is skipped by the embedded scan.
func TestEmbeddedSkipsOnlyTopLevelVirtualDirs(t *testing.T) {
	root := t.TempDir()
	binary := append([]byte("\x7fELF\x02\x01\x01\x00"), fixture(t, "demo-root.crt")...)
	writeFileRel(t, root, "opt/app/run/server", binary)
	writeFileRel(t, root, "run/ignored", binary)
	materials, _, err := scanRootfsTrustMaterials(root, scanOptions{Embedded: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(materials) != 1 || !slices.Equal(materials[0].Paths, []string{"/opt/app/run/server"}) {
		t.Fatalf("materials = %+v", materials)
	}
}

// Oversized single-file candidates are skipped with a warning.
func TestOversizedSingleFileCandidate(t *testing.T) {
	old := maxMaterialFileBytes
	maxMaterialFileBytes = 64
	defer func() { maxMaterialFileBytes = old }()
	root := t.TempDir()
	writeFileRel(t, root, "etc/ssl/cert.pem", fixture(t, "demo-root.crt"))
	materials, warnings, err := scanRootfsTrustMaterials(root, scanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(materials) != 0 || !slices.Contains(warnings, "file over 0 MiB skipped: /etc/ssl/cert.pem") {
		t.Fatalf("materials %d, warnings %v", len(materials), warnings)
	}
}
