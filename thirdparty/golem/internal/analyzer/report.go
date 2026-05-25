package analyzer

import (
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func Analyze(options Options) (*model.Report, error) {
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

	pkgs, loadErr := packages.Load(cfg, options.Patterns...)
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
			Goroot:     runtime.GOROOT(),
			WorkingDir: absDir,
			Patterns:   append([]string{}, options.Patterns...),
			BuildTags:  append([]string{}, options.BuildTags...),
			Tests:      options.Tests,
		},
		Options: model.AnalysisOptions{
			Directory:      absDir,
			Patterns:       append([]string{}, options.Patterns...),
			BuildTags:      append([]string{}, options.BuildTags...),
			Tests:          options.Tests,
			IncludeStdlib:  options.IncludeStdlib,
			IncludeLocal:   options.IncludeLocal,
			CallGraphMode:  options.CallGraphMode,
			IncludeSSA:     options.IncludeSSA,
			IncludeSources: options.IncludeSources,
		},
	}
	if loadErr != nil {
		report.Diagnostics = append(report.Diagnostics, model.Diagnostic{Kind: "load", Message: loadErr.Error()})
	}
	for _, pkg := range pkgs {
		pe := a.packageEvidence(pkg)
		report.Packages = append(report.Packages, pe)
		report.Imports = append(report.Imports, pe.Imports...)
		report.Declarations = append(report.Declarations, pe.Declarations...)
		report.Usages = append(report.Usages, pe.Usages...)
		report.BuildDirectives = append(report.BuildDirectives, pe.BuildDirectives...)
		report.NativeArtifacts = append(report.NativeArtifacts, pe.NativeArtifacts...)
		report.SecuritySignals = append(report.SecuritySignals, pe.SecuritySignals...)
		report.Diagnostics = append(report.Diagnostics, pe.Diagnostics...)
		report.Files = append(report.Files, a.fileEvidence(pkg, pe)...)
	}
	report.RootModules = sortedModules(a.rootModules)
	report.Modules = sortedModules(a.moduleByPath)
	if options.CallGraphMode != "none" {
		report.CallGraph = a.buildCallGraph(pkgs)
	}
	a.populateStats(report)
	sortReport(report)
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
	report.Stats.ImportCount = len(report.Imports)
	report.Stats.DeclarationCount = len(report.Declarations)
	report.Stats.UsageCount = len(report.Usages)
	report.Stats.BuildDirectiveCount = len(report.BuildDirectives)
	report.Stats.NativeArtifactCount = len(report.NativeArtifacts)
	report.Stats.SecuritySignalCount = len(report.SecuritySignals)
	report.Stats.DiagnosticCount = len(report.Diagnostics)
	if report.CallGraph != nil {
		report.Stats.DiagnosticCount += len(report.CallGraph.Diagnostics)
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
	sort.Slice(report.SecuritySignals, func(i, j int) bool { return report.SecuritySignals[i].ID < report.SecuritySignals[j].ID })
}
