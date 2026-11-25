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

// pinned pins the pointer the scan meets, s.other, before the same call.
// The runtime check still runs and still scans the object, so the finding
// stands, but every pointer it can meet is pinned and it cannot panic, which
// the call-site record and the finding's pinned property say. The pin
// analysis is intraprocedural and path-insensitive: it sees what one function
// body shows.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=48
func pinned() {
	var s holder
	var pin runtime.Pinner
	mark := 7
	s.other = &mark
	pin.Pin(s.other)
	p := unsafe.Pointer(&s.other)
	C.take(p)
	pin.Unpin()
}

// wrongPin pins &s.other, which pins the object s, not the int s.other points
// to. The scan meets s.other, finds its target unpinned and panics: this is
// the same program as pinned with one character more, and on go1.27.4 it
// panics with "argument of cgo function has Go pointer to unpinned Go
// pointer". It must read as unpinned, with the panic risk. s is a pointer
// here, so the scan covers the holder the selector reaches through it.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=67
func wrongPin() {
	s := &holder{}
	pin := runtime.Pinner{}
	mark := 7
	s.other = &mark
	pin.Pin(&s.other)
	p := unsafe.Pointer(&s.other)
	C.take(p)
	pin.Unpin()
}
