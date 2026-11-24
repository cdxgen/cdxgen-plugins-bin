package pinstate

/*
#include <stdlib.h>
static void take(void *p) { (void)p; }
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// holder holds a Go pointer, so an untyped check of a holder object meets
// that pointer and panics when it is set and unpinned.
type holder struct {
	data  int
	other *int
}

// unpinned passes the address through a variable with no pin anywhere: the
// untyped check runs and panics when other is set. The finding is the same
// as in the addr-shapes case; what this package adds is the pinned flag on
// the call-site record.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=30
func unpinned() {
	var s holder
	p := unsafe.Pointer(&s.other)
	C.take(p)
}

// pinned pins the field before the same call. The runtime check still runs
// and still scans the object, so the finding stands, but a pinned object
// cannot panic the way an unpinned one does, and the call-site record says
// so. The pin analysis is intraprocedural and path-insensitive: it sees what
// one function body shows.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=47
func pinned() {
	var s holder
	var pin runtime.Pinner
	mark := 7
	s.other = &mark
	pin.Pin(&s.other)
	p := unsafe.Pointer(&s.other)
	C.take(p)
	pin.Unpin()
}
