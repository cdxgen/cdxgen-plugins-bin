package analyzer

import (
	"sort"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type ssaContext struct {
	program   *ssa.Program
	packages  []*ssa.Package
	functions []*ssa.Function
}

func (a *Analyzer) buildSSA(pkgs []*packages.Package, progress *progressLogger) *ssaContext {
	mode := ssa.BuilderMode(ssa.InstantiateGenerics | ssa.GlobalDebug)
	progress.Memoryf("building SSA")
	prog, ssaPkgs := ssautil.AllPackages(pkgs, mode)
	prog.Build()
	progress.Memoryf("indexing SSA functions")
	funcSet := ssautil.AllFunctions(prog)
	funcs := make([]*ssa.Function, 0, len(funcSet))
	for fn := range funcSet {
		if fn == nil || fn.Blocks == nil {
			continue
		}
		funcs = append(funcs, fn)
	}
	sort.Slice(funcs, func(i, j int) bool { return funcs[i].String() < funcs[j].String() })
	progress.Memoryf("built SSA packages=%d functions=%d", len(ssaPkgs), len(funcs))
	return &ssaContext{program: prog, packages: ssaPkgs, functions: funcs}
}

func (ctx *ssaContext) filteredFunctions(include func(*ssa.Function) bool) []*ssa.Function {
	if ctx == nil {
		return nil
	}
	funcs := make([]*ssa.Function, 0, len(ctx.functions))
	for _, fn := range ctx.functions {
		if include == nil || include(fn) {
			funcs = append(funcs, fn)
		}
	}
	return funcs
}
