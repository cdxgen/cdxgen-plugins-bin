package analyzer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func analyzeAcrossChildModules(options Options, absDir string, progress *progressLogger) (*model.Report, bool, error) {
	if options.NoRecurse || directoryHasGoModuleRoot(absDir) {
		return nil, false, nil
	}
	moduleDirs, err := discoverChildGoModuleDirs(absDir)
	if err != nil {
		return nil, true, err
	}
	if len(moduleDirs) == 0 {
		return nil, false, nil
	}
	progress.Logf("root has no go.mod/go.work; recursing into %d child modules", len(moduleDirs))
	var merged *model.Report
	var failures []string
	for _, moduleDir := range moduleDirs {
		child := options
		child.Dir = moduleDir
		child.NoRecurse = true
		report, err := Analyze(child)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", moduleDir, err))
			continue
		}
		if merged == nil {
			merged = report
			continue
		}
		mergeReports(merged, report)
	}
	if merged == nil {
		if len(failures) > 0 {
			return nil, true, fmt.Errorf("failed to analyze discovered modules: %s", strings.Join(failures, "; "))
		}
		return nil, true, fmt.Errorf("no analyzable child modules found under %s", absDir)
	}
	for _, failure := range failures {
		merged.Diagnostics = append(merged.Diagnostics, model.Diagnostic{Kind: "recurse", Message: failure})
	}
	merged.Runtime.WorkingDir = absDir
	merged.Runtime.Patterns = append([]string{}, options.Patterns...)
	merged.Runtime.BuildTags = append([]string{}, options.BuildTags...)
	merged.Runtime.Tests = options.Tests
	merged.Options.Directory = absDir
	merged.Options.NoRecurse = options.NoRecurse
	merged.Options.IncludeAllFlows = options.IncludeAllFlows
	merged.Options.Patterns = append([]string{}, options.Patterns...)
	merged.Options.BuildTags = append([]string{}, options.BuildTags...)
	merged.Options.Tests = options.Tests
	merged.Options.IncludeStdlib = options.IncludeStdlib
	merged.Options.IncludeLocal = options.IncludeLocal
	merged.Options.CallGraphMode = options.CallGraphMode
	merged.Options.DataFlowMode = options.DataFlowMode
	merged.Options.DataFlowCallGraphMode = options.DataFlowCallGraphMode
	filterExternalOnlyModuleCacheFlows(merged, options.IncludeAllFlows)
	a := &Analyzer{}
	a.populateStats(merged)
	sortReport(merged)
	return merged, true, nil
}

func directoryHasGoModuleRoot(dir string) bool {
	if dir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
		return true
	}
	return false
}

func discoverChildGoModuleDirs(root string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			if strings.HasPrefix(d.Name(), ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			dirs = append(dirs, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(dirs) == 0 {
		return nil, nil
	}
	sort.Strings(dirs)
	out := dirs[:0]
	for _, dir := range dirs {
		if len(out) == 0 || out[len(out)-1] != dir {
			out = append(out, dir)
		}
	}
	return out, nil
}
func mergeReports(dst *model.Report, src *model.Report) {
	if dst == nil || src == nil {
		return
	}
	dst.RootModules = append(dst.RootModules, src.RootModules...)
	dst.Modules = append(dst.Modules, src.Modules...)
	dst.Packages = append(dst.Packages, src.Packages...)
	dst.Files = append(dst.Files, src.Files...)
	dst.Imports = append(dst.Imports, src.Imports...)
	dst.Declarations = append(dst.Declarations, src.Declarations...)
	dst.Usages = append(dst.Usages, src.Usages...)
	dst.BuildDirectives = append(dst.BuildDirectives, src.BuildDirectives...)
	dst.NativeArtifacts = append(dst.NativeArtifacts, src.NativeArtifacts...)
	dst.APIEndpoints = dedupeEndpoints(append(dst.APIEndpoints, src.APIEndpoints...))
	dst.ExternalURLs = dedupeExternalURLs(append(dst.ExternalURLs, src.ExternalURLs...))
	dst.Services = append(dst.Services, src.Services...)
	dst.SecuritySignals = dedupeSignals(append(dst.SecuritySignals, src.SecuritySignals...))
	dst.Crypto = mergeCryptoEvidence(dst.Crypto, src.Crypto)
	dst.SupplyChain = mergeSupplyChainEvidence(dst.SupplyChain, src.SupplyChain)
	dst.Diagnostics = append(dst.Diagnostics, src.Diagnostics...)
	if src.CallGraph != nil {
		if dst.CallGraph == nil {
			dst.CallGraph = src.CallGraph
		} else {
			dst.CallGraph.Nodes = appendUniqueCallGraphNodes(dst.CallGraph.Nodes, src.CallGraph.Nodes)
			dst.CallGraph.Edges = appendUniqueCallGraphEdges(dst.CallGraph.Edges, src.CallGraph.Edges)
			dst.CallGraph.Diagnostics = append(dst.CallGraph.Diagnostics, src.CallGraph.Diagnostics...)
			dst.CallGraph.Stats.NodeCount = len(dst.CallGraph.Nodes)
			dst.CallGraph.Stats.EdgeCount = len(dst.CallGraph.Edges)
		}
	}
	if src.DataFlow != nil {
		if dst.DataFlow == nil {
			dst.DataFlow = src.DataFlow
		} else {
			mergeDataFlowAggregateStats(&dst.DataFlow.Stats, src.DataFlow.Stats)
			dst.DataFlow.Nodes = appendUniqueDataFlowNodes(dst.DataFlow.Nodes, src.DataFlow.Nodes)
			dst.DataFlow.Edges = appendUniqueDataFlowEdges(dst.DataFlow.Edges, src.DataFlow.Edges)
			dst.DataFlow.Slices = appendUniqueDataFlowSlices(dst.DataFlow.Slices, src.DataFlow.Slices)
			dst.DataFlow.Summaries = appendUniqueDataFlowSummaries(dst.DataFlow.Summaries, src.DataFlow.Summaries)
			if dst.DataFlow.Patterns == nil {
				dst.DataFlow.Patterns = src.DataFlow.Patterns
			}
			dst.DataFlow.Diagnostics = append(dst.DataFlow.Diagnostics, src.DataFlow.Diagnostics...)
			recomputeDataFlowStats(dst.DataFlow)
			dst.DataFlow.Stats.SummaryCount = len(dst.DataFlow.Summaries)
			dst.DataFlow.Stats.TruncationReasons = dataFlowTruncationReasons(dst.DataFlow.Diagnostics)
			dst.DataFlow.Stats.Truncated = len(dst.DataFlow.Stats.TruncationReasons) > 0
		}
	}
}

func mergeDataFlowAggregateStats(dst *model.DataFlowStats, src model.DataFlowStats) {
	if dst == nil {
		return
	}
	dst.CandidateFunctionCount += src.CandidateFunctionCount
	dst.FunctionCount += src.FunctionCount
	dst.SkippedFunctionCount += src.SkippedFunctionCount
	dst.InstructionCount += src.InstructionCount
	dst.ElapsedMillis += src.ElapsedMillis
	if src.WorkerCount > dst.WorkerCount {
		dst.WorkerCount = src.WorkerCount
	}
}

func mergeSupplyChainEvidence(dst *model.SupplyChainEvidence, src *model.SupplyChainEvidence) *model.SupplyChainEvidence {
	if src == nil {
		return dst
	}
	if dst == nil {
		copied := *src
		copied.Replaces = append([]model.GoModDirective{}, src.Replaces...)
		copied.Excludes = append([]model.GoModDirective{}, src.Excludes...)
		copied.Modules = append([]model.ModuleCompliance{}, src.Modules...)
		if src.Properties != nil {
			copied.Properties = map[string]string{}
			for key, value := range src.Properties {
				copied.Properties[key] = value
			}
		}
		return &copied
	}
	dst.GoDirectiveVersion = firstNonEmpty(dst.GoDirectiveVersion, src.GoDirectiveVersion)
	dst.ToolchainDirective = firstNonEmpty(dst.ToolchainDirective, src.ToolchainDirective)
	dst.GoWorkPresent = dst.GoWorkPresent || src.GoWorkPresent
	dst.VendorDirectoryPresent = dst.VendorDirectoryPresent || src.VendorDirectoryPresent
	dst.Replaces = appendUniqueGoModDirectives(dst.Replaces, src.Replaces)
	dst.Excludes = appendUniqueGoModDirectives(dst.Excludes, src.Excludes)
	dst.Modules = appendUniqueModuleCompliance(dst.Modules, src.Modules)
	dst.WorkspaceModuleCount = countWorkspaceModules(dst.Modules)
	dst.VendorModuleCount = countVendoredModules(dst.Modules)
	if dst.Properties == nil {
		dst.Properties = map[string]string{}
	}
	for key, value := range src.Properties {
		if _, ok := dst.Properties[key]; !ok {
			dst.Properties[key] = value
		}
	}
	return dst
}

func appendUniqueGoModDirectives(dst, src []model.GoModDirective) []model.GoModDirective {
	seen := map[string]bool{}
	for _, directive := range dst {
		seen[goModDirectiveKey(directive)] = true
	}
	for _, directive := range src {
		key := goModDirectiveKey(directive)
		if seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, directive)
	}
	return dst
}

func goModDirectiveKey(d model.GoModDirective) string {
	return strings.Join([]string{d.Kind, d.ModulePath, d.Version, d.TargetModulePath, d.TargetVersion, d.Source}, "\x00")
}

func appendUniqueModuleCompliance(dst, src []model.ModuleCompliance) []model.ModuleCompliance {
	seen := map[string]bool{}
	for _, module := range dst {
		seen[moduleComplianceKey(module)] = true
	}
	for _, module := range src {
		key := moduleComplianceKey(module)
		if seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, module)
	}
	return dst
}

func moduleComplianceKey(module model.ModuleCompliance) string {
	return strings.Join([]string{module.Path, module.Version, module.PURL}, "\x00")
}

func countWorkspaceModules(modules []model.ModuleCompliance) int {
	count := 0
	for _, module := range modules {
		if module.Main {
			count++
		}
	}
	return count
}

func countVendoredModules(modules []model.ModuleCompliance) int {
	count := 0
	for _, module := range modules {
		if module.Vendored {
			count++
		}
	}
	return count
}

func appendUniqueCallGraphNodes(dst, src []model.CallGraphNode) []model.CallGraphNode {
	seen := map[string]bool{}
	for _, node := range dst {
		seen[node.ID] = true
	}
	for _, node := range src {
		if !seen[node.ID] {
			seen[node.ID] = true
			dst = append(dst, node)
		}
	}
	return dst
}

func appendUniqueCallGraphEdges(dst, src []model.CallGraphEdge) []model.CallGraphEdge {
	seen := map[string]bool{}
	for _, edge := range dst {
		seen[edge.ID] = true
	}
	for _, edge := range src {
		if !seen[edge.ID] {
			seen[edge.ID] = true
			dst = append(dst, edge)
		}
	}
	return dst
}

func appendUniqueDataFlowNodes(dst, src []model.DataFlowNode) []model.DataFlowNode {
	seen := map[string]bool{}
	for _, node := range dst {
		seen[node.ID] = true
	}
	for _, node := range src {
		if !seen[node.ID] {
			seen[node.ID] = true
			dst = append(dst, node)
		}
	}
	return dst
}

func appendUniqueDataFlowEdges(dst, src []model.DataFlowEdge) []model.DataFlowEdge {
	seen := map[string]bool{}
	for _, edge := range dst {
		seen[edge.ID] = true
	}
	for _, edge := range src {
		if !seen[edge.ID] {
			seen[edge.ID] = true
			dst = append(dst, edge)
		}
	}
	return dst
}

func appendUniqueDataFlowSlices(dst, src []model.DataFlowSlice) []model.DataFlowSlice {
	seen := map[string]bool{}
	for _, slice := range dst {
		seen[slice.ID] = true
	}
	for _, slice := range src {
		if !seen[slice.ID] {
			seen[slice.ID] = true
			dst = append(dst, slice)
		}
	}
	return dst
}

func appendUniqueDataFlowSummaries(dst, src []model.DataFlowMethodSummary) []model.DataFlowMethodSummary {
	seen := map[string]bool{}
	for _, summary := range dst {
		seen[summary.FunctionID] = true
	}
	for _, summary := range src {
		if !seen[summary.FunctionID] {
			seen[summary.FunctionID] = true
			dst = append(dst, summary)
		}
	}
	return dst
}
