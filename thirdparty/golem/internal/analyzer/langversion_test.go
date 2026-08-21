package analyzer

import (
	"go/version"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func TestLanguageVersionIsTheBuildToolchain(t *testing.T) {
	got := languageVersion()
	want := version.Lang(runtime.Version())
	if got != want {
		t.Fatalf("languageVersion() = %q, want %q (from runtime.Version() %q)", got, want, runtime.Version())
	}
	if got != "" && !version.IsValid(got) {
		t.Fatalf("languageVersion() = %q, which is not a valid Go version", got)
	}
}

func TestLanguageVersionDiagnosticsFlagOnlyTheUnanalysable(t *testing.T) {
	ceiling := languageVersion()
	if ceiling == "" {
		t.Skip("development build: no language-version ceiling to compare against")
	}
	// One version below the ceiling and one far above it. The high bound is
	// deliberately absurd so the test does not need updating every release.
	below := strings.TrimPrefix(ceiling, "go")
	modules := []model.Module{
		{Path: "example.com/ok", GoVersion: below},
		{Path: "example.com/too-new", GoVersion: "99.0"},
	}
	diags := languageVersionDiagnostics(modules)
	if len(diags) != 1 {
		t.Fatalf("want exactly one diagnostic, got %d: %+v", len(diags), diags)
	}
	if diags[0].Kind != "go-version" {
		t.Fatalf("diagnostic kind = %q, want %q", diags[0].Kind, "go-version")
	}
	for _, want := range []string{"example.com/too-new", "go99.0", ceiling, "Rebuild golem"} {
		if !strings.Contains(diags[0].Message, want) {
			t.Errorf("diagnostic does not mention %q: %s", want, diags[0].Message)
		}
	}
}

func TestLanguageVersionDiagnosticsIgnoreMissingDirective(t *testing.T) {
	// A module with no `go` directive, and the vendored-dependency case where
	// go/packages reports no version at all. Neither is a ceiling breach.
	if diags := languageVersionDiagnostics([]model.Module{{Path: "example.com/none"}}); len(diags) != 0 {
		t.Fatalf("want no diagnostics for a module with no go directive, got %+v", diags)
	}
}

// goDirectiveRange is the span of `go` directives golem is expected to analyze
// identically. 1.16 predates generics and workspaces, 1.18 introduces type
// parameters, 1.21 introduces the toolchain line and the version-ordering
// rules, 1.27 is the newest. The fixture below deliberately uses only syntax
// valid in all of them, so a difference in the result is a difference in how
// golem treats the directive rather than in what the code means.
var goDirectiveRange = []string{"1.16", "1.18", "1.21", "1.23", "1.25", "1.27"}

const versionRangeFixture = `package versionrange

import (
	"net/http"
	"os/exec"
)

type Carrier struct{ raw string }

func (c Carrier) Raw() string { return c.raw }

func Handler(r *http.Request) {
	c := Carrier{raw: r.FormValue("cmd")}
	_ = exec.Command("sh", "-c", c.Raw())
}
`

// TestFlowFoundAcrossGoDirectiveRange is the regression guard for "golem
// analyzes any Go version up to the one it was built with".
//
// The same source, the same flow, one `go` directive apart. A directive changes
// the language version go/types applies and, from 1.21 on, whether the toolchain
// switches — all of which have silently emptied golem's output before. Asserting
// one fixture at one version cannot see that; asserting the range can.
func TestFlowFoundAcrossGoDirectiveRange(t *testing.T) {
	if testing.Short() {
		t.Skip("analyzes one module per Go directive")
	}
	ceiling := languageVersion()
	for _, directive := range goDirectiveRange {
		t.Run("go"+directive, func(t *testing.T) {
			if ceiling != "" && version.Compare("go"+directive, ceiling) > 0 {
				t.Skipf("this golem was built with %s and cannot type-check go%s", ceiling, directive)
			}
			dir := t.TempDir()
			mod := "module example.com/golem/versionrange\n\ngo " + directive + "\n"
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(versionRangeFixture), 0o600); err != nil {
				t.Fatal(err)
			}

			report, err := Analyze(Options{
				Dir:           dir,
				IncludeLocal:  true,
				CallGraphMode: "cha",
				DataFlowMode:  "security",
				DataFlowMax:   10,
				ToolVersion:   "test",
			})
			if err != nil {
				t.Fatalf("analyze go%s: %v", directive, err)
			}
			for _, d := range report.Diagnostics {
				if d.Kind == "go-version" || d.Kind == "load" {
					t.Errorf("go%s: unexpected %s diagnostic: %s", directive, d.Kind, d.Message)
				}
			}
			if report.DataFlow == nil {
				t.Fatalf("go%s: no data-flow evidence", directive)
			}
			var found bool
			for _, slice := range report.DataFlow.Slices {
				if slice.SourceCategory == "http-input" && slice.SinkCategory == "command-execution" {
					found = true
				}
			}
			if !found {
				t.Errorf("go%s: http-input->command-execution flow not reported; got %d slice(s)",
					directive, len(report.DataFlow.Slices))
			}
			if report.CallGraph == nil || len(report.CallGraph.Edges) == 0 {
				t.Errorf("go%s: call graph has no edges", directive)
			}
			if report.Runtime.LanguageVersion != ceiling {
				t.Errorf("go%s: report says languageVersion %q, want %q",
					directive, report.Runtime.LanguageVersion, ceiling)
			}
		})
	}
}
