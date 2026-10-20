//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Symlinks cannot take the scan outside the root, whether the link is the
// final component (etc/ssl/cert.pem) or a parent directory (etc/pki), and a
// FIFO in a trust directory does not block the scan.
func TestScanStaysInsideRoot(t *testing.T) {
	outside := t.TempDir()
	writeFileRel(t, outside, "host-root.pem", fixture(t, "demo-root.crt"))
	writeFileRel(t, outside, "pki/tls/certs/host-root.pem", fixture(t, "demo-root.crt"))

	root := t.TempDir()
	writeFileRel(t, root, "etc/ssl/certs/image.pem", fixture(t, "demo-leaf.crt"))
	if err := os.Symlink(filepath.Join(outside, "host-root.pem"), filepath.Join(root, "etc", "ssl", "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "pki"), filepath.Join(root, "etc", "pki")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "etc", "ssl", "certs", "trap.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan []trustMaterial, 1)
	go func() {
		materials, _, err := scanRootfsTrustMaterials(root, scanOptions{Embedded: true, ExtraDirs: []string{"etc/pki"}})
		if err != nil {
			t.Error(err)
		}
		done <- materials
	}()
	select {
	case materials := <-done:
		if len(materials) != 1 || materials[0].Path != "/etc/ssl/certs/image.pem" {
			t.Fatalf("expected only the image's own certificate, got %d materials: %+v", len(materials), materials)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("scan blocked on the FIFO")
	}
}
