package analyzer

import (
	"go/ast"
	"go/types"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// A package whose only defect is an ill-typed dependency must still have its
// bodies built. ssautil.AllPackages skips it, because packages.IllTyped is
// transitive, and that is how a whole handler package went missing from the
// call graph when it imported a cgo dependency the loader could not fully
// type-check. Regression guard for the go-unarr / zip-slip case.
func TestOwnTypeInfoCompleteIgnoresInheritedIllTypedness(t *testing.T) {
	syntax := []*ast.File{{}}

	cases := []struct {
		name string
		pkg  *packages.Package
		want bool
	}{
		{
			name: "clean package",
			pkg:  &packages.Package{TypesInfo: &types.Info{}, Syntax: syntax},
			want: true,
		},
		{
			name: "ill-typed only through a dependency",
			pkg:  &packages.Package{TypesInfo: &types.Info{}, Syntax: syntax, IllTyped: true},
			want: true,
		},
		{
			name: "own type errors",
			pkg: &packages.Package{
				TypesInfo: &types.Info{},
				Syntax:    syntax,
				IllTyped:  true,
				Errors:    []packages.Error{{Msg: "could not import C (no metadata for C)"}},
			},
			want: false,
		},
		{
			name: "no type info",
			pkg:  &packages.Package{Syntax: syntax},
			want: false,
		},
		{
			// Building a body without source files panics the SSA builder in
			// buildPackageInit, so such a package is registered signatures-only.
			name: "no syntax",
			pkg:  &packages.Package{TypesInfo: &types.Info{}},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownTypeInfoComplete(tc.pkg); got != tc.want {
				t.Fatalf("ownTypeInfoComplete = %v, want %v", got, tc.want)
			}
		})
	}
}

// The SSA builder panics with "unsatisfied import" if it builds a body that
// references a package never created in the program, and that panic aborts the
// entire analysis. Such a package is built signatures-only instead.
func TestImportsRegisteredRequiresEveryImport(t *testing.T) {
	dep := &packages.Package{PkgPath: "example.com/dep"}
	other := &packages.Package{PkgPath: "example.com/other"}
	pkg := &packages.Package{
		PkgPath: "example.com/pkg",
		Imports: map[string]*packages.Package{
			"example.com/dep":   dep,
			"example.com/other": other,
		},
	}

	ssamap := map[*packages.Package]*ssa.Package{dep: nil}
	if importsRegistered(pkg, ssamap) {
		t.Fatal("importsRegistered = true with an unregistered import")
	}

	ssamap[other] = nil
	if !importsRegistered(pkg, ssamap) {
		t.Fatal("importsRegistered = false with every import registered")
	}
}
