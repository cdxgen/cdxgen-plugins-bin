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

// pinnedHead pins only the second node before the same call. That satisfies
// cgo's check for the first hop, and the program runs, but the list is
// recursive and C can walk every node after it, none of which the function
// pinned: one Pin does not cover a recursive structure.
//
// golem:want signal category=cgo-unpinned-reachable symbol=C.take line=53 cgo=compiled
func pinnedHead(head *node) {
	var pin runtime.Pinner
	pin.Pin(head.next)
	C.take(unsafe.Pointer(&head.next))
	pin.Unpin()
}

// pinnedLoop walks the list and pins every node before handing it to C,
// which is how a recursive structure is made safe for C to walk.
//
// golem:want-not signal category=cgo-unpinned-reachable line=66
func pinnedLoop(head *node) {
	var pin runtime.Pinner
	for n := head.next; n != nil; n = n.next {
		pin.Pin(n)
	}
	C.take(unsafe.Pointer(&head.next))
	pin.Unpin()
}

// flatTwoLevels passes a two-level structure that fully pins its leaves: no
// recursion, chain depth two, nothing for C to walk past the check.
//
// golem:want-not signal category=cgo-unpinned-reachable line=82
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

// throughPointer passes a field of a branch reached through a pointer. The
// scanned memory is the branch the selector dereferences, so the chain is
// the same two levels as flatTwoLevels; counting the pointer variable itself
// as a hop would invent a third level.
//
// golem:want-not signal category=cgo-unpinned-reachable line=97
func throughPointer() {
	l := leaf{v: 1}
	bp := &branch{l: &l}
	var pin runtime.Pinner
	pin.Pin(bp.l)
	C.take(unsafe.Pointer(&bp.l))
	pin.Unpin()
}

// c0 to c3 form a finite chain three pointer levels deep from a c0 value.
type c3 struct{ v int }
type c2 struct{ n *c3 }
type c1 struct{ n *c2 }
type c0 struct{ n *c1 }

// deepChain passes a c0. On go1.27.4 the check panics until the c1 and the
// c2 are pinned and then passes with the c3 unpinned: it follows two levels
// from the memory C receives, and C can read the third.
//
// golem:want signal category=cgo-unpinned-reachable symbol=C.take line=113 cgo=compiled
func deepChain(x *c0) {
	C.take(unsafe.Pointer(&x.n))
}

// shallowChain passes a c1, whose chain ends at the second level, the last
// one the check covers. Nothing is left for C to reach unchecked.
//
// golem:want-not signal category=cgo-unpinned-reachable line=121
func shallowChain(y *c1) {
	C.take(unsafe.Pointer(&y.n))
}
