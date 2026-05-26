package analyzer

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
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

func TestAnalyzeSimpleProjectAdvancedCallGraphModes(t *testing.T) {
	for _, mode := range []string{"cha", "vta"} {
		t.Run(mode, func(t *testing.T) {
			report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "simple"), IncludeLocal: true, CallGraphMode: mode, ToolVersion: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if report.CallGraph == nil {
				t.Fatal("expected call graph")
			}
			if report.CallGraph.Stats.NodeCount == 0 || report.CallGraph.Stats.EdgeCount == 0 {
				t.Fatalf("expected graph nodes and edges for %s, got %#v diagnostics=%#v", mode, report.CallGraph.Stats, report.CallGraph.Diagnostics)
			}
		})
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

func TestReplacementPathClassification(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		version  string
		local    bool
		pathKind string
	}{
		{name: "relative dot slash", path: "./dep", local: true, pathKind: "relative"},
		{name: "relative dot dot", path: "../dep", local: true, pathKind: "relative"},
		{name: "posix absolute", path: "/opt/dep", local: true, pathKind: "absolute"},
		{name: "windows drive backslash absolute", path: `C:\dep`, local: true, pathKind: "absolute"},
		{name: "windows drive slash absolute", path: `D:/src/dep`, local: true, pathKind: "absolute"},
		{name: "windows unc absolute", path: `\\server\share\dep`, local: true, pathKind: "absolute"},
		{name: "module path", path: "example.com/dep", local: false, pathKind: "module"},
		{name: "versioned replacement", path: "example.com/dep", version: "v1.2.3", local: false, pathKind: "module"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalReplacement(tt.path, tt.version); got != tt.local {
				t.Fatalf("isLocalReplacement(%q, %q)=%v want %v", tt.path, tt.version, got, tt.local)
			}
			if got := replacementPathKind(tt.path, tt.version); got != tt.pathKind {
				t.Fatalf("replacementPathKind(%q, %q)=%q want %q", tt.path, tt.version, got, tt.pathKind)
			}
		})
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

func TestAnalyzeSemanticDataFlowSlices(t *testing.T) {
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "dataflow"), IncludeLocal: true, CallGraphMode: "none", DataFlowMode: "all", DataFlowCallGraphMode: "cha", DataFlowMax: 100, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.DataFlow == nil {
		t.Fatal("expected data-flow evidence")
	}
	if report.Stats.DataFlowSourceCount == 0 || report.Stats.DataFlowSinkCount == 0 || report.Stats.DataFlowSliceCount == 0 {
		t.Fatalf("expected data-flow stats, got %#v", report.Stats)
	}
	if report.Stats.APIEndpointCount < 3 || report.Stats.ExternalURLCount == 0 || report.Stats.ServiceCount < 2 {
		t.Fatalf("expected endpoint/url/service stats, got endpoints=%#v urls=%#v services=%#v stats=%#v", report.APIEndpoints, report.ExternalURLs, report.Services, report.Stats)
	}
	if report.DataFlow.Stats.SliceCount < 6 {
		t.Fatalf("expected interprocedural, field, channel, closure, crypto, and native slices, got %#v", report.DataFlow.Slices)
	}
	expectedCategories := map[string]bool{
		"http-input->command-execution": false,
		"http-input->filesystem":        false,
		"http-input->logging":           false,
		"http-input->panic":             false,
		"environment->crypto":           false,
		"http-input->native-interop":    false,
	}
	for _, slice := range report.DataFlow.Slices {
		key := slice.SourceCategory + "->" + slice.SinkCategory
		if _, ok := expectedCategories[key]; ok {
			expectedCategories[key] = true
		}
		if len(slice.NodeIDs) == 0 || len(slice.EdgeIDs) == 0 {
			t.Fatalf("expected populated slice path, got %#v", slice)
		}
		if slice.FlowKey == "" || slice.PathLength != len(slice.EdgeIDs) || len(slice.EdgeKinds) == 0 || slice.SourceFunction == "" || slice.SinkFunction == "" || slice.SinkSymbol == "" {
			t.Fatalf("expected enriched slice quality metadata, got %#v", slice)
		}
		if slice.RuleID == "" || slice.RuleName == "" || slice.Severity == "" || slice.RiskScore == 0 || slice.SourceScope == "" || slice.SinkScope == "" || slice.SourceCriticality == "" || slice.SinkCriticality == "" {
			t.Fatalf("expected rule/severity/scope metadata, got %#v", slice)
		}
		if slice.Description == "" {
			t.Fatalf("expected slice description, got %#v", slice)
		}
	}
	if report.DataFlow.Stats.UniqueFlowCount == 0 || report.DataFlow.Stats.MaxPathLength == 0 || report.DataFlow.Stats.AveragePathLength == 0 {
		t.Fatalf("expected enriched slice quality stats, got %#v", report.DataFlow.Stats)
	}
	for key, found := range expectedCategories {
		if !found {
			t.Fatalf("expected data-flow category %s in %#v", key, report.DataFlow.Slices)
		}
	}
	functions := map[string]bool{}
	var categorySanitizerSeen bool
	var redirectSanitizerSeen bool
	for _, node := range report.DataFlow.Nodes {
		if node.Sink {
			functions[node.Function] = true
			if node.Function == "example.com/golem/dataflow.SanitizedPathFlow" && node.Category == "filesystem" {
				t.Fatalf("sanitized path flow should not produce filesystem sink node: %#v", node)
			}
			if node.Function == "example.com/golem/dataflow.SanitizedRedirectFlow" && node.Category == "redirect" {
				t.Fatalf("sanitized redirect flow should not produce redirect sink node: %#v", node)
			}
		}
		if node.Kind == "sanitizer" && node.Function == "example.com/golem/dataflow.SanitizedPathFlow" && strings.Contains(node.Properties["sanitizesCategories"], "filesystem") {
			categorySanitizerSeen = true
		}
		if node.Kind == "sanitizer" && node.Function == "example.com/golem/dataflow.SanitizedRedirectFlow" && strings.Contains(node.Properties["sanitizesCategories"], "redirect") {
			redirectSanitizerSeen = true
		}
	}
	if !categorySanitizerSeen {
		t.Fatalf("expected category-aware filesystem sanitizer evidence in %#v", report.DataFlow.Nodes)
	}
	if !redirectSanitizerSeen {
		t.Fatalf("expected category-aware redirect sanitizer evidence in %#v", report.DataFlow.Nodes)
	}
	for _, name := range []string{"example.com/golem/dataflow.Interprocedural", "example.com/golem/dataflow.InterfaceFlow", "example.com/golem/dataflow.FieldFlow", "example.com/golem/dataflow.ChannelFlow", "example.com/golem/dataflow.SelectFlow", "example.com/golem/dataflow.ClosureFlow", "example.com/golem/dataflow.CryptoFlow", "example.com/golem/dataflow.NativeFlow", "example.com/golem/dataflow.ReflectionFlow", "example.com/golem/dataflow.UnsafeFlow", "example.com/golem/dataflow.LoggingFlow", "example.com/golem/dataflow.PanicFlow"} {
		if !functions[name] {
			t.Fatalf("expected sink slice in %s, got sink functions %#v", name, functions)
		}
	}
	paths := map[string]bool{}
	listeners := map[string]bool{}
	var wrappedHandlerSeen bool
	for _, endpoint := range report.APIEndpoints {
		paths[endpoint.Path] = true
		if endpoint.Kind == "http-listener" {
			listeners[endpoint.Host] = true
		}
		if endpoint.Path == "/wrapped" && endpoint.Handler == "Handler" {
			wrappedHandlerSeen = true
		}
	}
	for _, path := range []string{"/search", "/api/exec", "/wrapped"} {
		if !paths[path] {
			t.Fatalf("expected endpoint path %s in %#v", path, report.APIEndpoints)
		}
	}
	if !listeners[":8080"] {
		t.Fatalf("expected :8080 listener endpoint in %#v", report.APIEndpoints)
	}
	if !wrappedHandlerSeen {
		t.Fatalf("expected middleware-wrapped endpoint to resolve Handler in %#v", report.APIEndpoints)
	}
	var sanitizedURL bool
	for _, external := range report.ExternalURLs {
		if external.URL == "https://api.example.com/v1/search" && external.Host == "api.example.com" {
			sanitizedURL = true
		}
		if strings.Contains(external.URL, "token=") || strings.Contains(external.URL, "fragment") {
			t.Fatalf("external URL was not sanitized: %#v", external)
		}
	}
	if !sanitizedURL {
		t.Fatalf("expected sanitized external URL evidence in %#v", report.ExternalURLs)
	}
}

func TestDataFlowConfigurableBudgetsAndPatternMetadata(t *testing.T) {
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "dataflow"), IncludeLocal: true, CallGraphMode: "none", DataFlowMode: "security", DataFlowCallGraphMode: "none", DataFlowMax: 10, DataFlowLargeRepoFunctions: 7, DataFlowMaxFunctionInstructions: 33, DataFlowMaxTraceNodes: 11, DataFlowMaxTraceEdges: 12, DataFlowSkipGenerated: true, DataFlowSkipTests: true, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Options.DataFlowLargeRepoFunctions != 7 || report.Options.DataFlowMaxFunctionInstructions != 33 || report.Options.DataFlowMaxTraceNodes != 11 || report.Options.DataFlowMaxTraceEdges != 12 || !report.Options.DataFlowSkipGenerated || !report.Options.DataFlowSkipTests {
		t.Fatalf("expected configured data-flow options in report, got %#v", report.Options)
	}
	set := builtinDataFlowPatterns([]string{"all"})
	var redirectArgs, httpErrorArgs, viperSource, cloudSink bool
	for _, sink := range set.Sinks {
		if sink.Pattern == "http.Redirect" && len(sink.RelevantArguments) == 1 && sink.RelevantArguments[0] == 2 && sink.RuleID == "GOLEM-DATAFLOW-OPEN-REDIRECT" {
			redirectArgs = true
		}
		if sink.Pattern == "http.Error" && len(sink.RelevantArguments) == 1 && sink.RelevantArguments[0] == 1 && sink.RuleID == "GOLEM-DATAFLOW-REFLECTED-OUTPUT" {
			httpErrorArgs = true
		}
		if sink.Category == "external-service" && strings.Contains(sink.Pattern, "aws-sdk-go") {
			cloudSink = true
		}
	}
	for _, source := range set.Sources {
		if strings.Contains(source.Pattern, "viper.GetString") && source.Category == "configuration" {
			viperSource = true
		}
	}
	if !redirectArgs || !httpErrorArgs || !viperSource || !cloudSink {
		t.Fatalf("expected enriched pattern metadata/packs redirect=%v httpError=%v viper=%v cloud=%v", redirectArgs, httpErrorArgs, viperSource, cloudSink)
	}
	narrow := builtinDataFlowPatterns([]string{"process"})
	for _, source := range narrow.Sources {
		if strings.Contains(source.Pattern, "viper") || strings.Contains(source.Pattern, "gin") {
			t.Fatalf("explicit process pack should not include config/framework sources: %#v", narrow.Sources)
		}
	}
	for _, sink := range narrow.Sinks {
		if sink.Category != "command-execution" && sink.Category != "dynamic-loading" {
			t.Fatalf("explicit process pack should only include process sinks, got %#v", narrow.Sinks)
		}
	}
}

func TestDataFlowTestLikeFunctionPredicate(t *testing.T) {
	if !dataFlowTestLikeFunction(filepath.Join("pkg", "handler_test.go"), nil) {
		t.Fatal("expected _test.go file to be treated as test-like")
	}
	if dataFlowTestLikeFunction(filepath.Join("pkg", "handler.go"), nil) {
		t.Fatal("expected runtime .go file not to be treated as test-like")
	}
}

func TestAnalyzeDataFlowSliceLimitDiagnostics(t *testing.T) {
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "dataflow"), IncludeLocal: true, CallGraphMode: "none", DataFlowMode: "all", DataFlowCallGraphMode: "none", DataFlowMax: 1, DataFlowWorkers: 1, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.DataFlow == nil {
		t.Fatal("expected data-flow evidence")
	}
	if got := len(report.DataFlow.Slices); got != 1 {
		t.Fatalf("expected exactly one slice after DataFlowMax limit, got %d", got)
	}
	if !report.DataFlow.Stats.Truncated || len(report.DataFlow.Stats.TruncationReasons) == 0 {
		t.Fatalf("expected truncation stats, got %#v diagnostics=%#v", report.DataFlow.Stats, report.DataFlow.Diagnostics)
	}
	if report.Stats.DiagnosticCount < len(report.DataFlow.Diagnostics) {
		t.Fatalf("expected report diagnostic count to include data-flow diagnostics, got stats=%#v diagnostics=%#v", report.Stats, report.DataFlow.Diagnostics)
	}
	for _, diag := range report.DataFlow.Diagnostics {
		if diag.Kind == "dataflow-budget" && strings.Contains(diag.Message, "slice limit") {
			return
		}
	}
	t.Fatalf("expected slice limit diagnostic, got %#v", report.DataFlow.Diagnostics)
}

func TestParseByteSize(t *testing.T) {
	tests := map[string]int64{
		"":       0,
		"0":      0,
		"1024":   1024,
		"1KiB":   1024,
		"1.5MiB": 1572864,
		"2GB":    2000000000,
		"3g":     3 << 30,
	}
	for input, want := range tests {
		got, err := ParseByteSize(input)
		if err != nil {
			t.Fatalf("ParseByteSize(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseByteSize(%q)=%d want %d", input, got, want)
		}
	}
	for _, input := range []string{"abc", "MiB", "-1MiB", "NaN", "Inf", "+Inf", "9223372036854775808", "9223372036854775808B", "9000000000000000000GiB"} {
		if _, err := ParseByteSize(input); err == nil {
			t.Fatalf("ParseByteSize(%q) expected error", input)
		}
	}
}

func TestApplyRuntimeLimitsMemoryLimitBehavior(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(0)
	previousMemoryLimit := debug.SetMemoryLimit(256 << 20)
	defer runtime.GOMAXPROCS(previousProcs)
	defer debug.SetMemoryLimit(previousMemoryLimit)

	state := applyRuntimeLimits(Options{MaxProcs: previousProcs})
	if state.memoryLimitChanged {
		t.Fatalf("memory limit should not be marked changed without an override: %#v", state)
	}
	if got := debug.SetMemoryLimit(-1); got != 256<<20 {
		t.Fatalf("memory limit changed without override: got %d", got)
	}
	restoreRuntimeLimits(state)
	if got := debug.SetMemoryLimit(-1); got != 256<<20 {
		t.Fatalf("memory limit changed after restore without override: got %d", got)
	}

	state = applyRuntimeLimits(Options{MaxProcs: previousProcs, MemoryLimit: 128 << 20})
	if !state.memoryLimitChanged {
		t.Fatalf("memory limit should be marked changed with an override: %#v", state)
	}
	if got := debug.SetMemoryLimit(-1); got != 128<<20 {
		t.Fatalf("memory limit override was not applied: got %d", got)
	}
	restoreRuntimeLimits(state)
	if got := debug.SetMemoryLimit(-1); got != 256<<20 {
		t.Fatalf("memory limit override was not restored: got %d", got)
	}
}

func TestAnalyzeProgressAndResourceOptions(t *testing.T) {
	var logs bytes.Buffer
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "dataflow"), IncludeLocal: true, CallGraphMode: "none", DataFlowMode: "security", DataFlowCallGraphMode: "none", DataFlowMax: 10, DataFlowWorkers: 2, MaxProcs: 1, MemoryLimit: 256 << 20, Progress: true, ProgressInterval: time.Nanosecond, ProgressWriter: &logs, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Options.MaxProcs != 1 || report.Options.MemoryLimitBytes != 256<<20 || report.Options.DataFlowWorkers != 2 {
		t.Fatalf("expected resource options in report, got %#v", report.Options)
	}
	text := logs.String()
	for _, expected := range []string{"analysis starting", "loading packages", "building SSA", "data-flow starting", "analysis complete"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected progress log %q in %s", expected, text)
		}
	}
}

func TestAnalyzeInvalidDataFlowRegexDiagnostic(t *testing.T) {
	patternFile := filepath.Join(t.TempDir(), "patterns.json")
	if err := os.WriteFile(patternFile, []byte(`{"sources":[{"kind":"function","match":"regex","pattern":"[","category":"broken"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := Analyze(Options{Dir: filepath.Join("..", "..", "testdata", "dataflow"), IncludeLocal: true, CallGraphMode: "none", DataFlowMode: "security", DataFlowCallGraphMode: "none", DataFlowConfig: patternFile, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if report.DataFlow == nil {
		t.Fatal("expected data-flow evidence")
	}
	for _, diag := range report.DataFlow.Diagnostics {
		if strings.Contains(diag.Message, "invalid regex pattern") {
			return
		}
	}
	t.Fatalf("expected invalid regex diagnostic, got %#v", report.DataFlow.Diagnostics)
}
