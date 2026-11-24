package linkedlist

/*
#include <stdlib.h>
static void take(void *p) { (void)p; }
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// node is a recursive type: next points back at node. C receiving a pointer
// into a list can walk every node, and cgo's check follows only two pointer
// levels, so the nodes past the second are visible to C and to nobody who
// verifies their pinning.
type node struct {
	val  int
	next *node
}

// leaf terminates a chain; branch points at leaves but nothing points back,
// so the structure is two levels deep and fully covered by the check.
type leaf struct {
	v int
}

type branch struct {
	l *leaf
	r *leaf
}

// walkList hands the second node's field to C. The type behind the argument
// is recursive, so the finding stands whether cgo bounded the check (this
// address shape) or not: the bounds only say which nodes the CHECK covers,
// and C can keep walking.
//
// golem:want signal category=cgo-unpinned-reachable symbol=C.take line=41 cgo=compiled
func walkList(head *node) {
	C.take(unsafe.Pointer(&head.next))
}

// pinnedList pins the next node before the same call. The pin analysis is
// intraprocedural and path-insensitive: it sees what this function body
// shows, which is enough to cover the value passed here.
//
// golem:want-not signal category=cgo-unpinned-reachable line=52
func pinnedList(head *node) {
	var pin runtime.Pinner
	pin.Pin(head.next)
	C.take(unsafe.Pointer(&head.next))
	pin.Unpin()
}

// flatTwoLevels passes a two-level structure that fully pins its leaves: no
// recursion, chain depth two, nothing for C to walk past the check.
//
// golem:want-not signal category=cgo-unpinned-reachable line=68
func flatTwoLevels() {
	var b branch
	mark := 3
	l, r := leaf{v: 1}, leaf{v: mark}
	b.l, b.r = &l, &r
	var pin runtime.Pinner
	pin.Pin(b.l)
	pin.Pin(b.r)
	C.take(unsafe.Pointer(&b))
	pin.Unpin()
}
