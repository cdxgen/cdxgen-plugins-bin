package seam

import (
	"go/types"
	"os"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// loadSimdPackages loads the portable simd package and simd/archsimd from the
// GOROOT of the toolchain golem is built with, under GOEXPERIMENT=simd. The
// environment is passed through packages.Config.Env rather than t.Setenv
// because corpus tests run cases in parallel in this process.
//
// A toolchain without the simd experiment skips gracefully.
func loadSimdPackages(t *testing.T) []*types.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedImports | packages.NeedDeps,
		Env:  append(os.Environ(), "GOEXPERIMENT=simd"),
	}
	pkgs, err := packages.Load(cfg, "simd", "simd/archsimd")
	if err != nil {
		t.Skipf("simd experiment not loadable with this toolchain: %v", err)
	}
	var out []*types.Package
	for _, p := range pkgs {
		if p.PkgPath != "simd" && p.PkgPath != "simd/archsimd" {
			continue
		}
		if p.Types == nil || p.Types.Scope() == nil || len(p.Errors) > 0 {
			t.Skipf("simd experiment not loadable with this toolchain: %v", p.Errors)
		}
		out = append(out, p.Types)
	}
	if len(out) == 0 {
		t.Skip("simd experiment not present in this toolchain")
	}
	return out
}

// simdSymbols indexes the declared functions and methods of the loaded simd
// packages by bare function name and by receiver-qualified method name
// ("LoadUint8s", "Store", "(Uint8s).Store").
func simdSymbols(pkgs []*types.Package) map[string]*types.Func {
	out := map[string]*types.Func{}
	for _, pkg := range pkgs {
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if fn, ok := obj.(*types.Func); ok {
				out[fn.Name()] = fn
				continue
			}
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			for i := 0; i < named.NumMethods(); i++ {
				m := named.Method(i)
				out[named.Obj().Name()+"."+m.Name()] = m
				out[m.Name()] = m
			}
		}
	}
	return out
}

// TestSimdIntrinsicCoverage holds the intrinsic classification against every
// function and method the simd packages actually declare, derived with
// go/types from the loaded GOROOT packages rather than from a list anyone
// wrote by hand. A shape the classifier does not expect fails here, so a new
// simd API cannot silently start (or stop) propagating taint.
func TestSimdIntrinsicCoverage(t *testing.T) {
	pkgs := loadSimdPackages(t)

	var total, propagate, store, clean int
	var cleanNames []string
	for _, pkg := range pkgs {
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if fn, ok := obj.(*types.Func); ok {
				classifySimdSymbol(t, pkg.Path()+"."+name, fn, &total, &propagate, &store, &clean, &cleanNames)
				continue
			}
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			for i := 0; i < named.NumMethods(); i++ {
				classifySimdSymbol(t, pkg.Path()+"."+named.Obj().Name(), named.Method(i), &total, &propagate, &store, &clean, &cleanNames)
			}
		}
	}

	// Named representatives of every part of the rule, so a refactor that
	// flips a kind cannot pass on counts alone. A symbol this toolchain does
	// not declare (IsZero is amd64-only) is skipped; the walk above still
	// holds every declared symbol to the invariant.
	symbols := simdSymbols(pkgs)
	expectations := map[string]simdIntrinsicKind{
		// Package-level Load* carry the slice's taint into the vector; the
		// Part variants return a (vector, count) tuple, tainted as a whole.
		"LoadUint8s":           simdPropagate,
		"LoadUint8sPart":       simdPropagate,
		"BroadcastUint8s":      simdPropagate,
		"Uint8sFromArch":       simdPropagate,
		"(Uint8s).String":      simdPropagate,
		"(Uint8s).ToArch":      simdPropagate,
		"(Uint8s).Xor":         simdPropagate,
		"(Uint8s).Store":       simdStore,
		"(Uint8s).Len":         simdClean,
		"(X86Features).AVX512": simdClean,
		// Not a CPU feature check: a lane-wise reduction on the receiver, so
		// its result carries the receiver's taint.
		"(Int16x16).IsZero": simdPropagate,
	}
	for symbol, want := range expectations {
		fn, ok := symbols[symbol]
		if !ok {
			continue
		}
		name := symbol
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		if got := simdKindFor(name, simdReceiverTypeName(fn.Type().(*types.Signature))); got != want {
			t.Errorf("%s classified %v, want %v", symbol, got, want)
		}
	}

	t.Logf("simd intrinsic rule covers %d functions/methods: %d propagate, %d store, %d clean",
		total, propagate, store, clean)
}

// classifySimdSymbol classifies one declared function or method and holds it
// to the invariant that the clean set is exactly the derived results: the Len
// methods and the CPU feature checks on the *Features receiver types.
func classifySimdSymbol(t *testing.T, fullName string, fn *types.Func, total, propagate, store, clean *int, cleanNames *[]string) {
	t.Helper()
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		t.Fatalf("%s: not a signature", fullName)
	}
	recvName := simdReceiverTypeName(sig)
	kind := simdKindFor(fn.Name(), recvName)
	*total++
	switch kind {
	case simdPropagate:
		*propagate++
	case simdStore:
		*store++
	case simdClean:
		*clean++
		*cleanNames = append(*cleanNames, fullName+"."+fn.Name())
	}
	isLen := fn.Name() == "Len"
	isFeatureCheck := strings.Contains(recvName, "Features")
	if kind == simdClean && !isLen && !isFeatureCheck {
		t.Errorf("%s classified clean but is neither Len nor a *Features method", fullName)
	}
	if kind != simdClean && (isLen || isFeatureCheck) {
		t.Errorf("%s is Len or a *Features method but classified %v", fullName, kind)
	}
}
