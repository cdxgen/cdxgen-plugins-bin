package analyzer

import (
	"go/build"
	"go/token"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func Analyze(options Options) (*model.Report, error) {
	normalizePerformanceOptions(&options)
	previousProcs, previousMemoryLimit := applyRuntimeLimits(options)
	defer runtime.GOMAXPROCS(previousProcs)
	defer debug.SetMemoryLimit(previousMemoryLimit)
	progress := newProgressLogger(options)
	if options.Dir == "" {
		options.Dir = "."
	}
	absDir, err := filepath.Abs(options.Dir)
	if err != nil {
		return nil, err
	}
	options.Dir = absDir
	if len(options.Patterns) == 0 {
		options.Patterns = []string{"./..."}
	}
	if options.CallGraphMode == "" {
		options.CallGraphMode = "none"
	}
	options.CallGraphMode = strings.ToLower(strings.TrimSpace(options.CallGraphMode))
	if options.DataFlowMode == "" {
		options.DataFlowMode = "none"
	}
	options.DataFlowMode = strings.ToLower(strings.TrimSpace(options.DataFlowMode))
	if options.DataFlowCallGraphMode == "" {
		options.DataFlowCallGraphMode = "static"
	}
	options.DataFlowCallGraphMode = strings.ToLower(strings.TrimSpace(options.DataFlowCallGraphMode))
	if options.DataFlowMax <= 0 {
		options.DataFlowMax = 1000
	}
	progress.Logf("analysis starting dir=%s patterns=%s maxProcs=%d workers=%d memoryLimit=%s", options.Dir, strings.Join(options.Patterns, ","), runtime.GOMAXPROCS(0), dataFlowWorkerCount(options, 0), formatBytes(options.MemoryLimit))

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedSyntax |
			packages.NeedTypesInfo |
			packages.NeedTypesSizes |
			packages.NeedModule,
		Dir:   absDir,
		Fset:  fset,
		Tests: options.Tests,
	}
	if len(options.BuildTags) > 0 {
		cfg.BuildFlags = []string{"-tags=" + strings.Join(options.BuildTags, ",")}
	}

	progress.Memoryf("loading packages")
	pkgs, loadErr := packages.Load(cfg, options.Patterns...)
	progress.Memoryf("loaded %d package roots", len(pkgs))
	a := &Analyzer{
		fset:          fset,
		options:       options,
		packageByPath: map[string]*packages.Package{},
		moduleByPath:  map[string]*model.Module{},
		rootModules:   map[string]*model.Module{},
	}
	a.indexPackages(pkgs)

	report := &model.Report{
		SchemaVersion: SchemaVersion,
		Tool: model.ToolInfo{
			Name:        "golem",
			Version:     options.ToolVersion,
			Description: "Go Library Evidence Mapper: semantic Go source evidence and call graph analyzer",
		},
		Runtime: model.RuntimeInfo{
			GOOS:       runtime.GOOS,
			GOARCH:     runtime.GOARCH,
			GoVersion:  runtime.Version(),
			Goroot:     build.Default.GOROOT,
			WorkingDir: absDir,
			Patterns:   append([]string{}, options.Patterns...),
			BuildTags:  append([]string{}, options.BuildTags...),
			Tests:      options.Tests,
		},
		Options: model.AnalysisOptions{
			Directory:                       absDir,
			Patterns:                        append([]string{}, options.Patterns...),
			BuildTags:                       append([]string{}, options.BuildTags...),
			Tests:                           options.Tests,
			IncludeStdlib:                   options.IncludeStdlib,
			IncludeLocal:                    options.IncludeLocal,
			CallGraphMode:                   options.CallGraphMode,
			DataFlowMode:                    options.DataFlowMode,
			DataFlowCallGraphMode:           options.DataFlowCallGraphMode,
			DataFlowPacks:                   append([]string{}, options.DataFlowPacks...),
			DataFlowWorkers:                 dataFlowWorkerCount(options, 0),
			DataFlowLargeRepoFunctions:      dataFlowLargeRepoFunctions(options),
			DataFlowMaxFunctionInstructions: dataFlowMaxFunctionInstructions(options),
			DataFlowMaxTraceNodes:           dataFlowMaxTraceNodes(options),
			DataFlowMaxTraceEdges:           dataFlowMaxTraceEdges(options),
			DataFlowSkipGenerated:           options.DataFlowSkipGenerated,
			DataFlowSkipTests:               options.DataFlowSkipTests,
			MaxProcs:                        runtime.GOMAXPROCS(0),
			MemoryLimitBytes:                options.MemoryLimit,
			IncludeSSA:                      options.IncludeSSA,
			IncludeSources:                  options.IncludeSources,
		},
	}
	if loadErr != nil {
		report.Diagnostics = append(report.Diagnostics, model.Diagnostic{Kind: "load", Message: loadErr.Error()})
	}
	for _, pkg := range pkgs {
		pe := a.packageEvidence(pkg)
		ef := a.endpointFactsForPackage(pkg)
		report.Packages = append(report.Packages, pe)
		report.Imports = append(report.Imports, pe.Imports...)
		report.Declarations = append(report.Declarations, pe.Declarations...)
		report.Usages = append(report.Usages, pe.Usages...)
		report.BuildDirectives = append(report.BuildDirectives, pe.BuildDirectives...)
		report.NativeArtifacts = append(report.NativeArtifacts, pe.NativeArtifacts...)
		report.APIEndpoints = append(report.APIEndpoints, ef.endpoints...)
		report.ExternalURLs = append(report.ExternalURLs, ef.urls...)
		report.SecuritySignals = append(report.SecuritySignals, pe.SecuritySignals...)
		report.Crypto = mergeCryptoEvidence(report.Crypto, pe.Crypto)
		report.Diagnostics = append(report.Diagnostics, pe.Diagnostics...)
		report.Files = append(report.Files, a.fileEvidence(pkg, pe)...)
	}
	report.APIEndpoints = dedupeEndpoints(report.APIEndpoints)
	report.ExternalURLs = dedupeExternalURLs(report.ExternalURLs)
	report.Services = servicesFromEndpointFacts(report.APIEndpoints, report.ExternalURLs)
	report.RootModules = sortedModules(a.rootModules)
	report.Modules = sortedModules(a.moduleByPath)
	report.SupplyChain = a.supplyChainEvidence(report.Modules)
	var ssaCtx *ssaContext
	if options.CallGraphMode != "none" || options.DataFlowMode != "none" {
		ssaCtx = a.buildSSA(pkgs, progress)
	}
	if options.CallGraphMode != "none" {
		progress.Memoryf("building call graph mode=%s", options.CallGraphMode)
		report.CallGraph = a.buildCallGraph(ssaCtx)
		progress.Memoryf("built call graph")
	}
	if options.DataFlowMode != "none" {
		report.DataFlow = a.buildDataFlow(pkgs, ssaCtx, progress)
	}
	a.populateStats(report)
	sortReport(report)
	progress.Memoryf("analysis complete")
	return report, nil
}

func (a *Analyzer) indexPackages(pkgs []*packages.Package) {
	seen := map[string]bool{}
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if pkg == nil || seen[pkg.ID] {
			return
		}
		seen[pkg.ID] = true
		if pkg.PkgPath != "" {
			a.packageByPath[pkg.PkgPath] = pkg
		}
		if pkg.Module != nil {
			mod := convertModule(pkg.Module)
			a.moduleByPath[moduleKey(mod)] = mod
			if pkg.Module.Main {
				a.rootModules[moduleKey(mod)] = mod
			}
		}
	})
}

func (a *Analyzer) populateStats(report *model.Report) {
	report.Stats.PackageCount = len(report.Packages)
	report.Stats.ModuleCount = len(report.Modules)
	report.Stats.FileCount = len(report.Files)
	for _, file := range report.Files {
		if file.Generated {
			report.Stats.GeneratedFileCount++
		}
	}
	report.Stats.ImportCount = len(report.Imports)
	report.Stats.DeclarationCount = len(report.Declarations)
	report.Stats.UsageCount = len(report.Usages)
	for _, usage := range report.Usages {
		switch usage.UsageScope {
		case "test":
			report.Stats.TestUsageCount++
		case "benchmark":
			report.Stats.BenchmarkUsageCount++
		case "fuzz":
			report.Stats.FuzzUsageCount++
		case "example":
			report.Stats.ExampleUsageCount++
		default:
			report.Stats.RuntimeUsageCount++
		}
	}
	report.Stats.BuildDirectiveCount = len(report.BuildDirectives)
	report.Stats.NativeArtifactCount = len(report.NativeArtifacts)
	report.Stats.APIEndpointCount = len(report.APIEndpoints)
	report.Stats.ExternalURLCount = len(report.ExternalURLs)
	report.Stats.ServiceCount = len(report.Services)
	report.Stats.SecuritySignalCount = len(report.SecuritySignals)
	if report.Crypto != nil {
		report.Stats.CryptoLibraryCount = len(report.Crypto.Libraries)
		report.Stats.CryptoAssetCount = len(report.Crypto.Assets)
		report.Stats.CryptoOperationCount = len(report.Crypto.Operations)
		report.Stats.CryptoMaterialCount = len(report.Crypto.Materials)
		report.Stats.CryptoProtocolCount = len(report.Crypto.Protocols)
		report.Stats.CryptoFindingCount = len(report.Crypto.Findings)
	}
	if report.DataFlow != nil {
		report.Stats.DataFlowSourceCount = report.DataFlow.Stats.SourceCount
		report.Stats.DataFlowSinkCount = report.DataFlow.Stats.SinkCount
		report.Stats.DataFlowSliceCount = report.DataFlow.Stats.SliceCount
	}
	if report.SupplyChain != nil {
		report.Stats.GoModReplaceCount = len(report.SupplyChain.Replaces)
		report.Stats.GoModExcludeCount = len(report.SupplyChain.Excludes)
		report.Stats.VendorModuleCount = report.SupplyChain.VendorModuleCount
		report.Stats.WorkspaceModuleCount = report.SupplyChain.WorkspaceModuleCount
		for _, module := range report.SupplyChain.Modules {
			if module.PrivateModuleCandidate {
				report.Stats.PrivateModuleHintCount++
			}
			if len(module.LicenseFiles) > 0 {
				report.Stats.LicenseFileModuleCount++
			}
		}
	}
	report.Stats.DiagnosticCount = len(report.Diagnostics)
	if report.CallGraph != nil {
		report.Stats.DiagnosticCount += len(report.CallGraph.Diagnostics)
	}
	if report.DataFlow != nil {
		report.Stats.DiagnosticCount += len(report.DataFlow.Diagnostics)
	}
}

func sortReport(report *model.Report) {
	sort.Slice(report.Packages, func(i, j int) bool { return report.Packages[i].ID < report.Packages[j].ID })
	sort.Slice(report.Files, func(i, j int) bool { return report.Files[i].Path < report.Files[j].Path })
	sort.Slice(report.Imports, func(i, j int) bool {
		left := report.Imports[i].Path + report.Imports[i].Range.Start.Filename
		right := report.Imports[j].Path + report.Imports[j].Range.Start.Filename
		return left < right
	})
	sort.Slice(report.Declarations, func(i, j int) bool { return report.Declarations[i].ID < report.Declarations[j].ID })
	sort.Slice(report.Usages, func(i, j int) bool { return report.Usages[i].ID < report.Usages[j].ID })
	sort.Slice(report.BuildDirectives, func(i, j int) bool {
		return report.BuildDirectives[i].Range.Start.Filename+report.BuildDirectives[i].Kind < report.BuildDirectives[j].Range.Start.Filename+report.BuildDirectives[j].Kind
	})
	sort.Slice(report.NativeArtifacts, func(i, j int) bool { return report.NativeArtifacts[i].Path < report.NativeArtifacts[j].Path })
	sort.Slice(report.APIEndpoints, func(i, j int) bool { return report.APIEndpoints[i].ID < report.APIEndpoints[j].ID })
	sort.Slice(report.ExternalURLs, func(i, j int) bool { return report.ExternalURLs[i].ID < report.ExternalURLs[j].ID })
	sort.Slice(report.Services, func(i, j int) bool { return report.Services[i].ID < report.Services[j].ID })
	sort.Slice(report.SecuritySignals, func(i, j int) bool { return report.SecuritySignals[i].ID < report.SecuritySignals[j].ID })
	sortCryptoEvidence(report.Crypto)
	sortDataFlowEvidence(report.DataFlow)
}
