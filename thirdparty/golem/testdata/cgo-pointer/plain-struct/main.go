package plainstruct

/*
#include <stdlib.h>
static void take(void *p) { (void)p; }
*/
import "C"

import "unsafe"

// plain is the same shape of call as the addr-shapes case, but with no
// pointer field anywhere: the untyped check still scans the whole object, so
// the finding stands, and it stays medium severity because the scan cannot
// meet an unpinned Go pointer it could panic on.
type plain struct {
	a int
	b int
}

// viaVariable passes the address through a variable, so cgo checks it with
// nil type information and the runtime scans the sixteen bytes of plain.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=27
func viaVariable() {
	var s plain
	p := unsafe.Pointer(&s.a)
	C.take(p)
}

// viaPointer is the same call with s a *plain. The selector dereferences s,
// so the scanned object is the plain value, not the pointer variable, and
// there is still nothing for the scan to panic on: this program runs clean
// on go1.27.4. Reading the pointer variable's own type would call it a
// pointer slot and claim a panic risk that does not exist.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=40
func viaPointer() {
	s := &plain{}
	p := unsafe.Pointer(&s.a)
	C.take(p)
}
