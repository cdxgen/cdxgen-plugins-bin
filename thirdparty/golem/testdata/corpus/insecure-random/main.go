package insecurerandom

import (
	crand "crypto/rand"
	"fmt"
	"log"
	"math/rand"
	randv2 "math/rand/v2"
	"os"
)

// math/rand and math/rand/v2 draw from predictable sources, so a value they
// produce is a weak token by construction. The crypto/rand.Read sanitizer
// removes the "insecure-random" taint kind; nothing else mints it, so a draw
// keeps it all the way to a sink.
//
// golem:want flow source=insecure-random sink=logging
func WeakTokenV1() {
	n := rand.Int63()
	log.Printf("session token=%x", n)
}

// The same draw through math/rand/v2, at a distinct sink category so this
// expectation cannot be satisfied by WeakTokenV1's slice.
//
// golem:want flow source=insecure-random sink=formatted-output
func WeakTokenV2() {
	n := randv2.Int64N(1 << 62)
	fmt.Fprintf(os.Stderr, "reset code=%x", n)
}

// A seeded (*rand.Rand) is the classic insecure form; the receiver methods
// are modelled too. Int63 takes no argument, so nothing but the receiver
// separates it from the package-level rand.Int63 — a call that matched both
// reported this one draw twice.
//
// golem:want flow source=insecure-random sink=logging
func WeakTokenSeeded() {
	r := rand.New(rand.NewSource(42))
	log.Printf("pin=%06d", r.Intn(1000000))
	log.Printf("seq=%d", r.Int63())
}

// math/rand/v2's own generator, at the filesystem sink so this expectation
// stands on its own.
//
// golem:want flow source=insecure-random sink=filesystem
func WeakNameV2() {
	r := randv2.New(randv2.NewPCG(1, 2))
	_, _ = os.ReadFile(fmt.Sprintf("/tmp/scratch-%d", r.IntN(4096)))
}

// crypto/rand is the secure counterpart and must not be flagged: it is a
// sanitizer for this taint kind, never a source of it. The expectation is
// scoped to its symbol so the legitimate math/rand slices above cannot
// satisfy it.
//
// golem:want-not flow source=insecure-random sink=logging sourceFn=crypto/rand.Read
func SecureToken() {
	buf := make([]byte, 8)
	_, _ = crand.Read(buf)
	log.Printf("token=%x", buf)
}
