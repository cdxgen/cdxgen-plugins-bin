package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
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
