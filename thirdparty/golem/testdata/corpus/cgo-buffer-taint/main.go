package cgobuffertaint

/*
#include <stdlib.h>
static void take(void *p) { (void)p; }
*/
import "C"

import (
	"net/http"
	"unsafe"
)

// A request value copied into a byte slice and handed to C through the
// address of one element. With CGO_ENABLED=1 cgo wraps the call in an
// immediately invoked closure, and the taint must still reach the _Cfunc_
// wrapper inside it: the boundary crossing does not move because the check
// code moved around it.
//
// The argument itself is the recognised &buf[0] shape, so the pointer-check
// analysis emits no untyped finding here: this case pins the taint flow,
// not the shape.
//
// golem:want flow source=http-input sink=native-interop
// golem:want-not signal category=cgo-pointer-check-untyped line=29
func Handler(r *http.Request) {
	buf := make([]byte, 0, 64)
	buf = append(buf, r.FormValue("payload")...)
	C.take(unsafe.Pointer(&buf[0]))
}
