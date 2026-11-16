//go:build unix

package analyzer

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO committed under a .go or .syso name, or named by a #cgo -L flag,
// must not block the textual cgo read: nothing ever writes to it.
func TestCgoEvidenceSkipsFifos(t *testing.T) {
	root := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/fifo\n\ngo 1.26\n")
	write("c.go", "package fifo\n\n// #cgo LDFLAGS: -L${SRCDIR}/libdir\nimport \"C\"\n")
	for _, name := range []string{"pipe.go", "pipe.syso", "libdir"} {
		if err := syscall.Mkfifo(filepath.Join(root, name), 0o644); err != nil {
			t.Skipf("cannot create a FIFO here: %v", err)
		}
	}
	done := make(chan *cgoEvidence, 1)
	go func() {
		a := &Analyzer{options: Options{Dir: root}}
		done <- a.collectCgoEvidence(nil, root)
	}()
	select {
	case collected := <-done:
		if _, ok := collected.files[filepath.Join(root, "c.go")]; !ok {
			t.Error("the regular cgo file next to the FIFOs was not read")
		}
		if valid, ok := collected.syso[filepath.Join(root, "pipe.syso")]; ok && valid {
			t.Error("a FIFO named .syso was classified as a valid object")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the textual cgo read blocked on a FIFO")
	}
}
