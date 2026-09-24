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

// isSimdIntrinsicPackage reports whether a package path is one of Go's simd
// experiment packages: the portable `simd`, the architecture-specific
// `simd/archsimd`, or their internal helpers. Only standard-library packages
// have a dot-less first path element, so the prefix cannot reach a third-party
// module that merely starts with the same letters.
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
