package rta

import (
	"go/version"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// toolchainLang is the language version of the toolchain compiling this
// test, mirroring the analyzer's languageVersion: go/types applies the
// rules of the release it was built from.
func toolchainLang() string {
	return version.Lang(runtime.Version())
}

// loadFixture loads and SSA-builds a testdata module exactly the way the
// analyzer does: full syntax+types, all packages, InstantiateGenerics.
func loadFixture(t *testing.T, dir string) (*ssa.Program, []*ssa.Package) {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedTypesSizes |
			packages.NeedModule,
		Dir: dir,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("loading %s: %v", dir, err)
	}
	for _, p := range pkgs {
		for _, e := range p.Errors {
			t.Errorf("package %s: %v", p.PkgPath, e)
		}
	}
	prog, ssapkgs := ssautil.AllPackages(pkgs, ssa.BuilderMode(ssa.InstantiateGenerics|ssa.GlobalDebug))
	prog.Build()
	return prog, ssapkgs
}

func mainAndInit(t *testing.T, ssapkgs []*ssa.Package) []*ssa.Function {
	t.Helper()
	var roots []*ssa.Function
	for _, p := range ssapkgs {
		if p == nil {
			continue
		}
		if fn := p.Func("init"); fn != nil {
			roots = append(roots, fn)
		}
		if fn := p.Func("main"); fn != nil {
			roots = append(roots, fn)
		}
	}
	if len(roots) == 0 {
		t.Fatal("no main/init roots in fixture")
	}
	return roots
}

// TestAnalyzeGenericMethodRuntimeType is the regression test for
// golang/go#80973. Before the vendored fix, rta.Analyze on this fixture
// died with a nil-pointer dereference in visitFunc: boxing a type with an
// exported generic method into an interface made addRuntimeType enumerate
// that method, MethodValue answered nil for it (a Go 1.27 generic method
// has no SSA form), and the nil went straight onto the worklist.
//
// The upstream x/tools rta.Analyze still crashes on this input; keeping
// the call unwrapped makes any accidental revert of the vendored copy
// fail loudly here.
func TestAnalyzeGenericMethodRuntimeType(t *testing.T) {
	if toolchainLang() != "" && version.Compare(toolchainLang(), "go1.27") < 0 {
		t.Skipf("generic methods require go1.27; this test binary was built with %s", toolchainLang())
	}
	_, ssapkgs := loadFixture(t, "../../testdata/rta-generic-method")
	result := Analyze(mainAndInit(t, ssapkgs), true)
	if result == nil {
		t.Fatal("Analyze returned nil for a non-empty root set")
	}
	if result.CallGraph == nil {
		t.Fatal("Analyze returned no call graph")
	}
	// main must be reachable, and no reachable entry may be a nil
	// function: the worklist nil is the crash, not a graph detail.
	var mainSeen bool
	for fn := range result.Reachable {
		if fn == nil {
			t.Fatal("nil *ssa.Function in Reachable: the guarded call site leaked")
		}
		if fn.Pkg != nil && fn.Name() == "main" {
			mainSeen = true
		}
	}
	if !mainSeen {
		t.Error("main is not reachable")
	}
	// The invoke edge through Describer must still resolve to the real
	// method, and a direct call to the generic method must still resolve
	// to its instantiation: InstantiateGenerics gives Convert[int] an
	// SSA body at each call site, so skipping the *uninstantiated*
	// method-set form must not thin the graph. (Plain name matching
	// would trip over (reflect.Value).Convert from the stdlib.)
	var describeSeen, convertInstantiationSeen bool
	for fn := range result.Reachable {
		if fn == nil {
			continue
		}
		switch s := fn.String(); {
		case strings.Contains(s, "Processor).Describe"):
			describeSeen = true
		case strings.Contains(s, "Processor).Convert["):
			convertInstantiationSeen = true
		}
	}
	if !describeSeen {
		t.Error("Processor.Describe is not reachable; the invoke edge over the interface was lost")
	}
	if !convertInstantiationSeen {
		t.Error("the Convert[int] instantiation is not reachable; the direct call to the generic method was lost")
	}
	// No graph node may carry a nil function.
	for node := range result.CallGraph.Nodes {
		if node == nil {
			t.Fatal("nil key in call graph nodes")
		}
	}
}

// TestAnalyzeStillFindsOrdinaryEdges guards the guard: skipping generic
// methods must not thin the graph on ordinary Go. The classic fixture has
// main, init, a handler registered via a func value, and a goroutine.
func TestAnalyzeStillFindsOrdinaryEdges(t *testing.T) {
	_, ssapkgs := loadFixture(t, "../../testdata/rta")
	result := Analyze(mainAndInit(t, ssapkgs), true)
	if result == nil || result.CallGraph == nil {
		t.Fatal("Analyze returned no result for the classic fixture")
	}
	var reachable []string
	for fn := range result.Reachable {
		reachable = append(reachable, fn.String())
	}
	for _, want := range []string{"main", "init", "worker"} {
		if !slices.ContainsFunc(reachable, func(s string) bool { return strings.Contains(s, want) }) {
			t.Errorf("%s is not reachable; got %v", want, reachable)
		}
	}
}
