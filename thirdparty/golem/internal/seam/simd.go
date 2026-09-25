package seam

import (
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// simdIntrinsicKind classifies a function or method of Go's simd experiment
// packages for the taint rule in resolveCallTaint.
type simdIntrinsicKind int

const (
	// simdPropagate: the result carries the union of the receiver's and the
	// arguments' taint.
	simdPropagate simdIntrinsicKind = iota
	// simdStore: a Store* method. The receiver's taint is written into the
	// destination argument (see (*intra).applySimdStoreWrites); the result,
	// where one exists (StorePart's element count), is derived and clean.
	simdStore
	// simdClean: the result is derived rather than carried — the Len methods
	// and the CPU feature checks.
	simdClean
)

// isSimdIntrinsicPackage reports whether a package path has the shape of one of
// Go's simd experiment packages: the portable `simd`, the architecture-specific
// `simd/archsimd`, or their internal helpers. The path alone does not prove the
// package is the standard library's — a module may legally be named `simd/…`
// — so callers go through (*Engine).isSimdIntrinsic, which also requires the
// package to be the standard library.
//
// This predicate is deliberately local to SEAM. IsStdlibCarrierPackage is
// shared with the legacy engine, and adding simd there would change legacy's
// behaviour at the same time.
func isSimdIntrinsicPackage(pkgPath string) bool {
	return pkgPath == "simd" || strings.HasPrefix(pkgPath, "simd/")
}

// simdIntrinsicKind classifies one simd callee. The rule is keyed on the
// callee's package path before anything looks at a body, because the same name
// is a bodiless stub on amd64, arm64 and wasm and a real emulated body
// everywhere else: keying on body presence would make the analysis
// architecture-dependent.
//
// The classification is derived from the callee's own type information rather
// than from a hand-maintained list of names; see simdKindFor.
func simdIntrinsicKindOf(fn *ssa.Function) simdIntrinsicKind {
	return simdKindFor(fn.Name(), simdReceiverTypeName(fn.Signature))
}

// simdKindFor classifies a simd function by its name and receiver type name.
//
//   - a method whose name starts with Store moves the receiver into its
//     destination argument;
//   - the Len methods return the vector's lane count, and the methods on the
//     *Features receiver types (X86Features.AVX512 and friends) answer what the
//     CPU supports; neither carries data;
//   - everything else — Load*, Broadcast*, the lane-wise arithmetic, ToArch,
//     the *FromArch generics, String — propagates the values it is given.
//
// internal/seam/simd_test.go holds this classification against the actual
// packages loaded from $GOROOT with go/types, so a new API shape that does not
// fit one of the three kinds fails the test instead of silently propagating or
// silently stopping taint.
func simdKindFor(name, recvTypeName string) simdIntrinsicKind {
	if strings.HasPrefix(name, "Store") {
		return simdStore
	}
	if name == "Len" {
		return simdClean
	}
	if strings.Contains(recvTypeName, "Features") {
		return simdClean
	}
	return simdPropagate
}

// simdReceiverTypeName names a signature's receiver's named type, or "" when
// the signature has none.
func simdReceiverTypeName(sig *types.Signature) string {
	if sig == nil || sig.Recv() == nil {
		return ""
	}
	recv := types.Unalias(sig.Recv().Type())
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = types.Unalias(ptr.Elem())
	}
	if named, ok := recv.(*types.Named); ok {
		return named.Obj().Name()
	}
	return ""
}

// simdFunctionPackagePath returns the package path of a callee, or "" when it
// has none (synthetic wrappers, foreign packages without type information).
func simdFunctionPackagePath(fn *ssa.Function) string {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return ""
	}
	return fn.Pkg.Pkg.Path()
}

// isSimdIntrinsic reports whether fn belongs to the standard library's simd
// packages, classified like every other standard-library question in the
// engine (isStandardPackage). A package with module information is never the
// standard library:
// `module simd/local` is a user module whose bodies must be walked and whose
// sinks must be found, not an intrinsic to be approximated.
func (e *Engine) isSimdIntrinsic(fn *ssa.Function) bool {
	path := simdFunctionPackagePath(fn)
	return isSimdIntrinsicPackage(path) && e.isStandardPackage(path)
}

// simdCallWriteDestination returns the destination argument of a call to a simd
// Store* method, or nil. For a static method call the receiver is Args[0], so
// the destination is Args[1].
func (e *Engine) simdCallWriteDestination(common *ssa.CallCommon) ssa.Value {
	if common == nil || common.IsInvoke() || len(common.Args) < 2 {
		return nil
	}
	callee := common.StaticCallee()
	if callee == nil || !e.isSimdIntrinsic(callee) || simdIntrinsicKindOf(callee) != simdStore {
		return nil
	}
	return common.Args[1]
}

// isIntegerType reports whether t is an integer basic type.
func isIntegerType(t types.Type) bool {
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsInteger != 0
}
