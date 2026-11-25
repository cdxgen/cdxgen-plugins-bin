package addrshapes

/*
#include <stdlib.h>
static void take(void *p) { (void)p; }
*/
import "C"

import "unsafe"

// pair is the struct the three call shapes below pass into C. Its other
// field holds a Go pointer, so an untyped check of a pair object scans that
// field and panics when it is set: this is the shape difference the three
// functions exist to show.
type pair struct {
	data  int
	other *int
}

// inline takes the address inside the call. checkAddr recognises the shape
// and bounds the runtime check to the one field, so nothing here is a
// finding, whatever pair holds.
//
// golem:want-not signal category=cgo-pointer-check-untyped line=27
func inline() {
	var s pair
	C.take(unsafe.Pointer(&s.data))
}

// viaVariable hides the address in a variable first. rewriteCall sees only
// the identifier argument at the call, matches none of its three shapes, and
// checks the value with nil type information, which scans the whole pair
// object.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=39
func viaVariable() {
	var s pair
	p := unsafe.Pointer(&s.data)
	C.take(p)
}

// parenthesized wraps the same address in parentheses, which checkAddr does
// not unwrap: gcc.go's shape matcher sees a ParenExpr, not a UnaryExpr, and
// falls through to the untyped check exactly as it does for viaVariable.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=49
func parenthesized() {
	var s pair
	C.take(unsafe.Pointer((&s.data)))
}

// reusedName is viaVariable twice, in two switch cases that each define their
// own p. Real code reuses short names this way; the read must pick the p each
// call sees, not give up because the name is assigned more than once.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=64
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=67
// golem:want-not signal category=cgo-pointer-check-untyped line=70
func reusedName(mode int) {
	var s pair
	switch mode {
	case 0:
		p := unsafe.Pointer(&s.data)
		C.take(p)
	case 1:
		p := unsafe.Pointer((&s.data))
		C.take(p)
	default:
		p := C.malloc(8)
		C.take(p)
		C.free(p)
	}
}
