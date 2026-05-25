package analyzer

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestAnalyzeSimpleProject(t *testing.T) {
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "simple"), IncludeLocal: true, CallGraphMode: "none", ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.PackageCount == 0 {
		t.Fatalf("expected packages, got %#v", report.Stats)
	}
	if report.Stats.ImportCount == 0 {
		t.Fatalf("expected imports, got %#v", report.Stats)
	}
	var foundImport bool
	for _, imp := range report.Imports {
		if imp.Path == "example.com/golem/simple/lib" && imp.Local {
			foundImport = true
		}
	}
	if !foundImport {
		t.Fatalf("expected local lib import in %#v", report.Imports)
	}
	var foundUsage bool
	for _, usage := range report.Usages {
		if usage.PackagePath == "example.com/golem/simple/lib" && usage.Call {
			foundUsage = true
		}
	}
	if !foundUsage {
		t.Fatalf("expected type-resolved local lib call usage in %#v", report.Usages)
	}
}

func TestAnalyzeSimpleProjectStaticCallGraph(t *testing.T) {
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "simple"), IncludeLocal: true, CallGraphMode: "static", ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.CallGraph == nil {
		t.Fatal("expected call graph")
	}
	if report.CallGraph.Stats.NodeCount == 0 || report.CallGraph.Stats.EdgeCount == 0 {
		t.Fatalf("expected graph nodes and edges, got %#v", report.CallGraph.Stats)
	}
}

func TestAnalyzeAdvancedAliasesAndFunctionValues(t *testing.T) {
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "advanced"), IncludeLocal: true, CallGraphMode: "none", ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var namedAliasImport bool
	for _, imp := range report.Imports {
		if imp.Path == "example.com/golem/dep/lib" && imp.Name == "alias" && imp.AliasKind == "named" {
			namedAliasImport = true
			if imp.Module == nil || imp.Module.PURL != "pkg:golang/example.com/golem/dep@v0.0.0" {
				t.Fatalf("expected slash-preserving Go module purl, got %#v", imp.Module)
			}
		}
	}
	if !namedAliasImport {
		t.Fatalf("expected named import alias evidence in %#v", report.Imports)
	}
	var typeAliasCount int
	for _, decl := range report.Declarations {
		if decl.Alias && decl.AliasedPackagePath == "example.com/golem/dep/lib" && decl.AliasedModule != nil {
			typeAliasCount++
		}
	}
	if typeAliasCount < 2 {
		t.Fatalf("expected external type alias provenance, got %#v", report.Declarations)
	}
	var functionValueCalls int
	var methodValueCalls int
	var externalInterfaceMethod bool
	for _, usage := range report.Usages {
		switch usage.Kind {
		case "functionValueCall":
			functionValueCalls++
		case "methodValueCall":
			methodValueCalls++
		}
		if usage.Name == "Greet" && usage.PackagePath == "example.com/golem/dep/lib" && usage.Enclosing != nil && usage.Enclosing.Name == "useInterface" {
			externalInterfaceMethod = true
		}
	}
	if functionValueCalls < 3 {
		t.Fatalf("expected function value call evidence, got %#v", report.Usages)
	}
	if methodValueCalls < 2 {
		t.Fatalf("expected method value/expression call evidence, got %#v", report.Usages)
	}
	if !externalInterfaceMethod {
		t.Fatalf("expected external interface method dispatch evidence, got %#v", report.Usages)
	}
}

func TestAnalyzeSecurityAndComplianceEvidence(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("security fixture build tags target darwin/linux")
	}
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "security"), IncludeLocal: true, CallGraphMode: "none", ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.BuildDirectiveCount < 4 {
		t.Fatalf("expected build/generate/embed directives, got %#v", report.BuildDirectives)
	}
	var generateSeen bool
	var embedSeen bool
	for _, directive := range report.BuildDirectives {
		if directive.Kind == "go-generate" && directive.Command == "go" {
			generateSeen = true
		}
		if directive.Kind == "go-embed" && directive.Target == "config" && len(directive.Patterns) == 1 {
			embedSeen = true
		}
	}
	if !generateSeen || !embedSeen {
		t.Fatalf("expected go:generate and go:embed evidence, got %#v", report.BuildDirectives)
	}
	var nativeSeen bool
	for _, artifact := range report.NativeArtifacts {
		if artifact.Kind == "assembly" && filepath.Base(artifact.Path) == "native.s" {
			nativeSeen = true
		}
	}
	if !nativeSeen {
		t.Fatalf("expected native assembly artifact evidence, got %#v", report.NativeArtifacts)
	}
	categories := map[string]bool{}
	for _, signal := range report.SecuritySignals {
		categories[signal.Category] = true
	}
	for _, category := range []string{"process-execution", "weak-crypto", "weak-randomness", "unsafe", "http-client", "tls-insecure"} {
		if !categories[category] {
			t.Fatalf("expected security signal category %s in %#v", category, report.SecuritySignals)
		}
	}
}
