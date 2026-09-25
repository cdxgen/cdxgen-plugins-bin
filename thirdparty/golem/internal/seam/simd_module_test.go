package seam

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// buildFunc type-checks a one-function package at pkgPath and returns its SSA
// function named name.
func buildFunc(t *testing.T, pkgPath, src, name string) *ssa.Function {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, types.NewPackage(pkgPath, file.Name.Name), []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	fn := pkg.Func(name)
	if fn == nil {
		t.Fatalf("no function %s in %s", name, pkgPath)
	}
	return fn
}

// A module may legally be named simd/…; its functions are user code with
// bodies to walk, not the standard library's intrinsics. The path shape alone
// must not decide it.
func TestSimdIntrinsicRequiresNoModule(t *testing.T) {
	std := buildFunc(t, "simd", "package simd\n\nfunc LoadUint8s(s []uint8) []uint8 { return s }\n", "LoadUint8s")
	user := buildFunc(t, "simd/local/scrub", "package scrub\n\nfunc Clean(s string) string { return \"ls\" }\n", "Clean")
	e := &Engine{moduleByPath: map[string]*model.Module{
		"simd/local/scrub": {Path: "simd/local", Main: true},
	}}
	if !e.isSimdIntrinsic(std) {
		t.Error("the standard library's simd package, which has no module, was not treated as the intrinsic")
	}
	if e.isSimdIntrinsic(user) {
		t.Error("a function of module simd/local was treated as a standard-library simd intrinsic")
	}
}
