package copytaint

import (
	"net/http"
	"os/exec"
)

// The copy builtin writes through its first argument instead of returning, so
// the taint only moves if the engine models that write (defect 36).

// CopySlice copies into a make'd slice.
// golem:want flow source=http-input sink=command-execution sinkFn=~CopySlice known-fail=legacy:36
func CopySlice(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	out := make([]byte, len(in))
	copy(out, in)
	_ = exec.Command("sh", "-c", string(out))
}

// CopyArray copies through arr[:], so the write has to reach the array behind
// the re-slice for the flow to appear.
// golem:want flow source=http-input sink=command-execution sinkFn=~CopyArray known-fail=legacy:36
func CopyArray(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	var arr [8]byte
	copy(arr[:], in)
	_ = exec.Command("sh", "-c", string(arr[:]))
}

// CopyConstants copies constants while a tainted value sits unused, so no flow
// may reach the sink. Scoped to this function; the case's positives legitimately
// produce the same category pair.
// golem:want-not flow source=http-input sink=command-execution sinkFn=~CopyConstants
func CopyConstants(r *http.Request) {
	_ = r.FormValue("cmd")
	dst := make([]byte, 3)
	copy(dst, []byte("abc"))
	_ = exec.Command("sh", "-c", string(dst))
}

// fill is the usual shape of copy: a helper that fills its destination
// parameter. The caller only sees the write if the helper's summary records it
// (defect 39).
func fill(dst []byte, src string) { copy(dst, src) }

// CopyViaHelper fills out through fill.
// golem:want flow source=http-input sink=command-execution sinkFn=~CopyViaHelper known-fail=legacy:39
func CopyViaHelper(r *http.Request) {
	out := make([]byte, 64)
	fill(out, r.FormValue("cmd"))
	_ = exec.Command("sh", "-c", string(out))
}

type buffer struct{ buf []byte }

// CopyIntoField copies into a struct field's slice. copy's destination is the
// load of the field, and the write has to reach the field's location for the
// later read of b.buf to see it (defect 40).
// golem:want flow source=http-input sink=command-execution sinkFn=~CopyIntoField known-fail=legacy:40
func CopyIntoField(r *http.Request) {
	b := &buffer{buf: make([]byte, 64)}
	copy(b.buf, r.FormValue("cmd"))
	_ = exec.Command("sh", "-c", string(b.buf))
}
