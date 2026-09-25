package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDotlessModuleNamedLikeACarrierIsNotACarrier covers the other half of
// classifying the standard library by path shape. The carrier list matches
// paths ("encoding", "path", "io", ...), and a dot-less module can own one of
// those paths outright. Its helpers are not standard library carriers: a
// helper that discards its input must not propagate it the way an unmodelled
// encoding/json call does. The same module's direct flow is the control that
// keeps the negative from passing because nothing materialised at all.
func TestDotlessModuleNamedLikeACarrierIsNotACarrier(t *testing.T) {
	skipIfShort(t, "loads and analyses a module")
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module encoding/dotless\n\ngo 1.21\n",
		"main.go": `package main

import (
	"net/http"
	"os/exec"

	"encoding/dotless/clean"
)

func Cleaned(r *http.Request) { _ = exec.Command("sh", "-c", clean.Clean(r.FormValue("cmd"))) }

func Direct(r *http.Request) { _ = exec.Command("sh", "-c", r.FormValue("cmd")) }

func main() {}
`,
		"clean/clean.go": `package clean

// Clean discards its input.
func Clean(string) string { return "ls" }
`,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	report := analyzeWithEngine(t, dir, "security", "seam")
	for _, pkg := range report.Packages {
		if pkg.Standard || !pkg.Local {
			t.Errorf("package %s: standard=%v local=%v, want a local non-standard package", pkg.PackagePath, pkg.Standard, pkg.Local)
		}
	}
	sinks := map[string]int{}
	for _, slice := range report.DataFlow.Slices {
		if slice.SourceCategory == "http-input" && slice.SinkCategory == "command-execution" {
			sinks[slice.SinkFunction]++
		}
	}
	if sinks["encoding/dotless.Direct"] == 0 {
		t.Errorf("the direct flow in the dot-less module was not reported; flows by sink function: %v", sinks)
	}
	if sinks["encoding/dotless.Cleaned"] != 0 {
		t.Errorf("encoding/dotless/clean.Clean was treated as a standard library carrier; flows by sink function: %v", sinks)
	}
}
