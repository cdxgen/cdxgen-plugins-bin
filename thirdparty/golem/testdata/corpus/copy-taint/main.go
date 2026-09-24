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
// the re-slice for the flow to appear. SEAM's copy write still lands on the
// re-slice's own register until the re-slice aliasing fix (defect 37's
// mechanism), so it stays a known failure under SEAM as well as legacy.
// golem:want flow source=http-input sink=command-execution sinkFn=~CopyArray known-fail=seam:36 known-fail=legacy:36
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
