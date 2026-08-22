package models_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/models"
)

// TestMethodDoesNotMatchPackageFunctionOfTheSameName pins the separation
// between math/rand's func Int63 and its (*Rand).Int63.
//
// The two are distinct entries, and a call on the method used to match both:
// the unqualified "math/rand.Int63" key reached the package-level entry from
// a method call, and the same draw was reported twice. Zero-argument draws
// cannot be told apart by arity — max 0 means "unlimited" — so the receiver
// is the only thing that separates them.
func TestMethodDoesNotMatchPackageFunctionOfTheSameName(t *testing.T) {
	pkgCall, methodCall := loadRandCalls(t)

	db := models.NewDB()
	if err := db.LoadBuiltins(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		fn   *ssa.Function
		want string
	}{
		{"package function", pkgCall, "go.math-rand-int63.source"},
		{"method", methodCall, "go.math-rand-rand-int63.source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := db.MatchFunction(tc.fn)
			if len(got) != 1 {
				ids := make([]string, 0, len(got))
				for _, e := range got {
					ids = append(ids, e.ID)
				}
				t.Fatalf("%s matched %d entries %v, want exactly one (%s)", tc.fn, len(got), ids, tc.want)
			}
			if got[0].ID != tc.want {
				t.Errorf("%s matched %s, want %s", tc.fn, got[0].ID, tc.want)
			}
		})
	}
}

// loadRandCalls builds SSA for a program that draws from math/rand both ways
// and returns the callee of each call.
func loadRandCalls(t *testing.T) (pkgFn, method *ssa.Function) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/randcalls\n\ngo 1.22.0\n")
	write("main.go", `package main

import "math/rand"

func main() {
	_ = rand.Int63()
	_ = rand.New(rand.NewSource(1)).Int63()
}
`)

	pkgs, err := packages.Load(&packages.Config{Mode: packages.LoadAllSyntax, Dir: dir}, "./...")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("the temporary module did not type-check")
	}
	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	for _, pkg := range pkgs {
		fn := prog.Package(pkg.Types).Func("main")
		if fn == nil {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				call, ok := instr.(*ssa.Call)
				if !ok {
					continue
				}
				callee := call.Common().StaticCallee()
				if callee == nil || callee.Name() != "Int63" {
					continue
				}
				if callee.Signature.Recv() != nil {
					method = callee
				} else {
					pkgFn = callee
				}
			}
		}
	}
	if pkgFn == nil || method == nil {
		t.Fatalf("did not find both Int63 calls (package=%v method=%v)", pkgFn, method)
	}
	return pkgFn, method
}
