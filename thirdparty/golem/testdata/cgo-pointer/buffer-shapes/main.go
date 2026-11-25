package buffershapes

/*
#include <stdlib.h>
static void take(void *p) { (void)p; }
static int total(int *values) { return values[0]; }
*/
import "C"

import "unsafe"

func buffer() []C.int {
	return make([]C.int, 8)
}

// indexed takes the address of one element inside the call. checkIndex
// recognises the shape and bounds the runtime check to the indexed array, so
// the rest of the allocation is not scanned.
//
// golem:want-not signal category=cgo-pointer-check-untyped line=23
func indexed() {
	buf := buffer()
	C.take(unsafe.Pointer(&buf[0]))
}

// indexedReslice addresses one element of a reslice. checkIndex still
// recognises it, because its matcher strips the conversions first and the
// surviving expression is &x[i].
//
// golem:want-not signal category=cgo-pointer-check-untyped line=33
func indexedReslice() {
	buf := buffer()
	C.take(unsafe.Pointer(&buf[1:4][0]))
}

// sliced passes a reslice through unsafe.SliceData. checkSlice recognises the
// surviving slice expression and bounds the check to that slice. This is the
// shape the article's "buf[1:4]" case names: SliceData only reaches the
// checkSlice matcher when its argument is a slice expression.
//
// golem:want-not signal category=cgo-pointer-check-untyped line=44
func sliced() {
	buf := buffer()
	C.take(unsafe.Pointer(unsafe.SliceData(buf[1:4])))
}

// sliceData looks like the safest way to hand a whole buffer over, and
// against go1.27.4 cmd/cgo it is not: checkIndex, checkAddr and checkSlice
// all strip unsafe.SliceData as a passthrough conversion, and the bare
// buffer variable that survives matches none of the three shapes, so cgo
// checks the value with nil type information and the runtime scans the whole
// backing array. The detector mirrors that verdict instead of the intuition
// that SliceData is a bounded shape; the sliced negative above differs only
// in the slice expression inside the same call.
//
// golem:want signal category=cgo-pointer-check-untyped symbol=C.take line=59
func sliceData() {
	buf := buffer()
	C.take(unsafe.Pointer(unsafe.SliceData(buf)))
}

// scalarParam rules the whole call out through the C prototype read from the
// preamble: `int *` points at a scalar, needsPointerCheck answers false, and
// cgo emits no check at all, whatever the argument looks like.
//
// golem:want-not signal category=cgo-pointer-check-untyped line=69
func scalarParam() {
	buf := buffer()
	C.total(&buf[0])
}

// nilArgument is not checked: needsPointerCheck answers false for the
// untyped nil before any shape is considered.
//
// golem:want-not signal category=cgo-pointer-check-untyped line=77
func nilArgument() {
	C.take(nil)
}
