package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const original = `package demo

import (
	"fmt"
	"heavy/dependency"
)

func A() { fmt.Println(dependency.Value) }

func B() {}
`

const patchText = `Why this patch exists.

--- a/example.com/demo/demo.go
+++ b/example.com/demo/demo.go
@@ -2,7 +2,6 @@

 import (
 	"fmt"
-	"heavy/dependency"
 )

-func A() { fmt.Println(dependency.Value) }
+func A() { fmt.Println(42) }

`

func mustParse(t *testing.T, text string) []filePatch {
	t.Helper()
	patches, err := parsePatch(text)
	if err != nil {
		t.Fatalf("parsePatch: %v", err)
	}
	return patches
}

func TestApplyReplacesTheMatchedHunk(t *testing.T) {
	patches := mustParse(t, patchText)
	if len(patches) != 1 || patches[0].path != "example.com/demo/demo.go" {
		t.Fatalf("unexpected sections: %+v", patches)
	}
	got, err := patches[0].apply(original)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(strings.Replace(original, "\t\"heavy/dependency\"\n", "", 1),
		"fmt.Println(dependency.Value)", "fmt.Println(42)", 1)
	if got != want {
		t.Fatalf("patched content mismatch:\n%s", got)
	}
}

func TestApplyToleratesStrippedBlankContextLines(t *testing.T) {
	// Editors strip the lone space diff writes for an empty context line.
	stripped := strings.ReplaceAll(patchText, "\n \n", "\n\n")
	if _, err := mustParse(t, stripped)[0].apply(original); err != nil {
		t.Fatal(err)
	}
}

func TestApplyReadsCRLFPatches(t *testing.T) {
	// A Windows checkout with core.autocrlf rewrites the patch files.
	crlf := strings.ReplaceAll(patchText, "\n", "\r\n")
	got, err := mustParse(t, crlf)[0].apply(original)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "\r") || strings.Contains(got, "heavy/dependency") {
		t.Fatalf("CRLF patch applied incorrectly:\n%q", got)
	}
}

func TestApplyFailsWhenUpstreamChanged(t *testing.T) {
	changed := strings.Replace(original, "dependency.Value", "dependency.Other", 1)
	_, err := mustParse(t, patchText)[0].apply(changed)
	if err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("expected a no-match error, got %v", err)
	}
}

func TestApplyFailsOnAmbiguousHunk(t *testing.T) {
	text := `--- a/x.go
+++ b/x.go
@@ -1,1 +1,1 @@
-dup
+one
`
	_, err := mustParse(t, text)[0].apply("dup\ndup\n")
	if err == nil || !strings.Contains(err.Error(), "matches 2 places") {
		t.Fatalf("expected an ambiguity error, got %v", err)
	}
}

func TestDeletionVerifiesTheWholeFile(t *testing.T) {
	text := `--- a/x.go
+++ /dev/null
@@ -1,2 +0,0 @@
-package x
-var V = 1
`
	fp := mustParse(t, text)[0]
	if !fp.deleted {
		t.Fatal("expected a deletion")
	}
	if _, err := fp.apply("package x\nvar V = 1\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := fp.apply("package x\nvar V = 2\n"); err == nil {
		t.Fatal("expected deleting a changed file to fail")
	}
}

func TestParseRejectsNewFilesAndTruncatedHunks(t *testing.T) {
	if _, err := parsePatch("--- /dev/null\n+++ b/x.go\n@@ -0,0 +1 @@\n+x\n"); err == nil {
		t.Fatal("expected new files to be rejected")
	}
	if _, err := parsePatch("--- a/x.go\n+++ b/x.go\n@@ -1,3 +1,3 @@\n a\n"); err == nil {
		t.Fatal("expected a truncated hunk to be rejected")
	}
}

func TestRunWritesOverlayAndRejectsDoublePatching(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "vendor")
	patchDir := filepath.Join(dir, "patches")
	outDir := filepath.Join(dir, "out")
	for path, content := range map[string]string{
		filepath.Join(vendorDir, "modules.txt"):              "",
		filepath.Join(vendorDir, "example.com/demo/demo.go"): original,
		filepath.Join(patchDir, "01-demo.patch"):             patchText,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(vendorDir, patchDir, outDir); err != nil {
		t.Fatal(err)
	}
	overlay, err := os.ReadFile(filepath.Join(outDir, "overlay.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(overlay), "demo.go") {
		t.Fatalf("overlay.json does not map the patched file: %s", overlay)
	}

	if err := os.WriteFile(filepath.Join(patchDir, "02-again.patch"), []byte(patchText), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(vendorDir, patchDir, outDir); err == nil || !strings.Contains(err.Error(), "already patched") {
		t.Fatalf("expected double patching to fail, got %v", err)
	}
}
