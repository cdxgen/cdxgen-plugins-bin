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

func TestAnalyzeAdvancedScopesAndSupplyChainEvidence(t *testing.T) {
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "advanced"), IncludeLocal: true, Tests: true, CallGraphMode: "none", ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	scopes := map[string]int{}
	for _, usage := range report.Usages {
		if usage.PackagePath == "example.com/golem/dep/lib" {
			scopes[usage.UsageScope]++
		}
	}
	for _, scope := range []string{"runtime", "test", "benchmark", "fuzz", "example"} {
		if scopes[scope] == 0 {
			t.Fatalf("expected %s usage scope for dep lib, got %#v", scope, scopes)
		}
	}
	var generatedSeen bool
	for _, file := range report.Files {
		if filepath.Base(file.Path) == "generated.go" && file.Generated && file.GeneratedBy == "protoc-gen-go" {
			generatedSeen = true
		}
	}
	if !generatedSeen {
		t.Fatalf("expected generated file attribution, got %#v", report.Files)
	}
	if report.SupplyChain == nil {
		t.Fatal("expected supply-chain evidence")
	}
	if len(report.SupplyChain.Replaces) != 1 || !report.SupplyChain.Replaces[0].LocalReplacement {
		t.Fatalf("expected local replace evidence, got %#v", report.SupplyChain.Replaces)
	}
	if len(report.SupplyChain.Excludes) != 1 || report.SupplyChain.Excludes[0].ModulePath != "example.com/unused/module" {
		t.Fatalf("expected exclude evidence, got %#v", report.SupplyChain.Excludes)
	}
	var licenseSeen bool
	for _, module := range report.SupplyChain.Modules {
		if module.Path == "example.com/golem/dep" && len(module.LicenseFiles) > 0 && module.LicenseFiles[0] == "LICENSE" {
			licenseSeen = true
		}
	}
	if !licenseSeen {
		t.Fatalf("expected dependency license evidence, got %#v", report.SupplyChain.Modules)
	}
	if report.Stats.TestUsageCount == 0 || report.Stats.BenchmarkUsageCount == 0 || report.Stats.FuzzUsageCount == 0 || report.Stats.ExampleUsageCount == 0 || report.Stats.GeneratedFileCount == 0 {
		t.Fatalf("expected expanded usage/generated stats, got %#v", report.Stats)
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
	if report.Crypto == nil {
		t.Fatal("expected dedicated crypto evidence")
	}
	if report.Stats.CryptoLibraryCount == 0 || report.Stats.CryptoAssetCount == 0 || report.Stats.CryptoOperationCount == 0 || report.Stats.CryptoProtocolCount == 0 || report.Stats.CryptoFindingCount == 0 {
		t.Fatalf("expected crypto stats, got %#v", report.Stats)
	}
	var md5Seen bool
	var tlsSeen bool
	var weakFindingSeen bool
	for _, asset := range report.Crypto.Assets {
		if asset.Name == "md5" && asset.AssetType == "algorithm" && asset.OID != "" {
			md5Seen = true
		}
	}
	for _, protocol := range report.Crypto.Protocols {
		if protocol.Type == "tls" {
			tlsSeen = true
		}
	}
	for _, finding := range report.Crypto.Findings {
		if finding.RuleID == "GOLEM-CRYPTO-WEAK-MD5" || finding.RuleID == "GOLEM-CRYPTO-TLS-INSECURE-SKIP-VERIFY" {
			weakFindingSeen = true
		}
	}
	if !md5Seen || !tlsSeen || !weakFindingSeen {
		t.Fatalf("expected md5/tls crypto evidence, got %#v", report.Crypto)
	}
}
