package cmemory

/*
#include <stdlib.h>
static void take(void *p) { (void)p; }
*/
import "C"

import "unsafe"

// C-owned memory is never a finding: cgoCheckPointer returns as soon as it
// sees the pointer does not name Go memory, so the checks cgo emits for these
// calls are free and cannot panic. The detector excludes arguments rooted in
// C.CString, C.CBytes, C.malloc and C.calloc results for exactly this
// reason.

// freeOwned passes a C.CString result to C.free. cgo does emit the nil-typed
// check here (free takes a void *), and it is still not a finding.
//
// golem:want-not signal category=cgo-pointer-check-untyped line=23
func freeOwned(v string) {
	cs := C.CString(v)
	C.free(unsafe.Pointer(cs))
}

// passToOther hands C-owned memory to another C function. Same verdict as
// freeOwned, through a different callee.
//
// golem:want-not signal category=cgo-pointer-check-untyped line=32
func passToOther(v string) {
	cs := C.CString(v)
	C.take(unsafe.Pointer(cs))
	_ = cs
}

// contrast is the same call shape with a Go pointer instead of a C one, next
// to the two negatives above: the untyped check now scans Go memory.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=43
func contrast(v string) {
	buf := make([]byte, 4)
	p := unsafe.Pointer(&buf[0])
	C.take(p)
	_ = v
}
