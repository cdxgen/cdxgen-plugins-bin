package cmemory

/*
#include <stdlib.h>
static void take(void *p) { (void)p; }
static int load(char **err) { *err = 0; return 0; }
struct ctx { int n; };
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
// golem:want-not signal category=cgo-pointer-check-untyped line=25
func freeOwned(v string) {
	cs := C.CString(v)
	C.free(unsafe.Pointer(cs))
}

// passToOther hands C-owned memory to another C function. Same verdict as
// freeOwned, through a different callee.
//
// golem:want-not signal category=cgo-pointer-check-untyped line=34
func passToOther(v string) {
	cs := C.CString(v)
	C.take(unsafe.Pointer(cs))
	_ = cs
}

// contrast is the same call shape with a Go pointer instead of a C one, next
// to the two negatives above: the untyped check now scans Go memory.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=45
func contrast(v string) {
	buf := make([]byte, 4)
	p := unsafe.Pointer(&buf[0])
	C.take(p)
	_ = v
}

// outParam receives a C string through an out-parameter. No assignment in
// the function says where errMsg points, so the text does not claim Go
// memory, and the compiled pass reads its type, *C.char, as C's.
//
// golem:want-not signal category=cgo-pointer-check-untyped line=57
func outParam() {
	var errMsg *C.char
	if C.load(&errMsg) != 0 {
		C.take(unsafe.Pointer(errMsg))
	}
}

// handle is a Go name for a C struct, the form go-sqlite3 uses for its
// SQLiteContext. A *handle points at C memory although no C call in this
// function produced it.
type handle C.struct_ctx

// golem:want-not signal category=cgo-pointer-check-untyped line=68
func (h *handle) use() {
	C.take(unsafe.Pointer(h))
}

// fromParam passes an unsafe.Pointer the caller supplied. cgo emits the
// untyped check, and whether the runtime scans anything depends on memory
// this function does not show: the compiled pass reports it at low severity
// with the owner unknown. The text sees no unsafe.Pointer conversion and
// stays silent.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=80 cgo=compiled
// golem:want-not signal category=cgo-pointer-check-untyped line=80 cgo=textual
func fromParam(p unsafe.Pointer) {
	C.take(p)
}
