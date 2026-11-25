package puregocheck

// A module with no cgo anywhere: the GODEBUG line in its Dockerfile cannot
// disable a check no crossing uses, so the cgocheck-disabled category must
// stay silent here. The annotations keep the case honest: no signal of the
// new families may appear.
//
// golem:want-not signal category=cgocheck-disabled
// golem:want-not signal category=cgo-pointer-check-untyped
// golem:want-not signal category=cgo-unpinned-reachable
func Add(a, b int) int {
	return a + b
}
