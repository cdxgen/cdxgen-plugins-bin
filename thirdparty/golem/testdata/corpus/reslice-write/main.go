package reslicewrite

import (
	"net/http"
	"os/exec"
)

// A re-slice aliases its base's backing store. SEAM keys the re-slice value
// under its own SSA register, so a store through out[1:] lands on a location no
// read of out consults, and the flow drops (defect 37).

// resliceWrite writes through a re-slice of out and returns the base.
func resliceWrite(in []byte) []byte {
	out := make([]byte, len(in)+1)
	o := out[1:]
	o[0] = in[0]
	return out
}

// ResliceWrite: the taint written through o must be visible when out is read.
// golem:want flow source=http-input sink=command-execution sinkFn=~ResliceWrite known-fail=seam:37 known-fail=legacy:37
func ResliceWrite(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	out := resliceWrite(in)
	_ = exec.Command("sh", "-c", string(out))
}

// ResliceOfOther writes through a re-slice of a DIFFERENT allocation, so out
// must stay clean. Scoped to this function; the positive handler legitimately
// produces the same category pair.
// golem:want-not flow source=http-input sink=command-execution sinkFn=~ResliceOfOther
func ResliceOfOther(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	out := make([]byte, len(in)+1)
	other := make([]byte, len(in)+1)
	o := other[1:]
	o[0] = in[0]
	_ = exec.Command("sh", "-c", string(out))
}
