package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
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
	prog, ssaPkgs := buildAllPackages(pkgs, mode)
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

// buildAllPackages constructs an SSA program for the initial packages and all
// their transitive dependencies, mirroring ssautil.AllPackages but with one
// crucial difference: packages whose own type-checking succeeded are built even
// when a dependency is ill-typed.
//
// ssautil.AllPackages (and its underlying doPackages) skips every package with
// IllTyped==true, and IllTyped is transitive — "the package OR any of its
// dependencies has type errors." A cgo dependency that cannot be fully
// type-checked (the C pseudo-package is unavailable) marks every importer as
// IllTyped, so their function bodies never reach SSA and the call graph drops
// them entirely. This is how a zip-slip flow through github.com/gen2brain/go-unarr
// vanished: the path-traversal package compiled cleanly but inherited
// IllTyped from the cgo dependency.
//
// The fix registers every package that has a non-nil types.Package so imports
// resolve without "unsatisfied import" panics, and builds bodies for any package
// that carries its own complete type information (no own errors, TypesInfo and
// Syntax present) regardless of dependency health. Ill-typedness is only
// contagious in go/packages' bookkeeping, not in the type information itself:
// go-unarr's exported signatures reference no C types, so its importers
// type-check cleanly and their bodies are safe to build.
//
// Packages that are themselves broken — own type errors, or missing TypesInfo —
// are registered with nil syntax so only their signatures are visible. Nothing
// is ever built from incomplete type information.
func buildAllPackages(initial []*packages.Package, mode ssa.BuilderMode) (*ssa.Program, []*ssa.Package) {
	var fset *token.FileSet
	if len(initial) > 0 {
		fset = initial[0].Fset
	}
	prog := ssa.NewProgram(fset, mode)

	ssamap := make(map[*packages.Package]*ssa.Package)
	// packages.Visit with a nil pre-order function visits in post-order, so
	// every import of p is already in ssamap by the time p is considered.
	packages.Visit(initial, nil, func(p *packages.Package) {
		if p.Types == nil {
			return
		}
		var files []*ast.File
		var info *types.Info
		if ownTypeInfoComplete(p) && importsRegistered(p, ssamap) {
			files = p.Syntax
			info = p.TypesInfo
		}
		ssamap[p] = prog.CreatePackage(p.Types, files, info, true)
	})

	var ssapkgs []*ssa.Package
	for _, p := range initial {
		ssapkgs = append(ssapkgs, ssamap[p])
	}
	return prog, ssapkgs
}

// ownTypeInfoComplete reports whether p type-checked successfully on its own
// terms, ignoring p.IllTyped, which is true whenever any transitive dependency
// has an error. p.Errors is not transitive, so it is the right question to ask.
func ownTypeInfoComplete(p *packages.Package) bool {
	return len(p.Errors) == 0 && p.TypesInfo != nil && len(p.Syntax) > 0
}

// importsRegistered reports whether every package p imports was created in the
// SSA program. The builder panics with "unsatisfied import" if it constructs a
// body that references a package it has never seen, and a panic here aborts the
// whole analysis, so a package with an unregistered import is built without a
// body instead.
func importsRegistered(p *packages.Package, ssamap map[*packages.Package]*ssa.Package) bool {
	for _, imp := range p.Imports {
		if _, ok := ssamap[imp]; !ok {
			return false
		}
	}
	return true
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
