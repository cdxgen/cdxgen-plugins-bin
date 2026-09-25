package appendtaint

import (
	"net/http"
	"os/exec"
)

// The append builtin has no static callee, so SEAM's call resolution returns
// nothing for it and every append-shaped flow drops (defect 35).

// SpreadAppend covers append(x, y...), which passes y through directly.
// golem:want flow source=http-input sink=command-execution sinkFn=~SpreadAppend
func SpreadAppend(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	out := append([]byte{}, in...)
	_ = exec.Command("sh", "-c", string(out))
}

// AppendElement covers append(in, 1), which appends onto a tainted slice.
// golem:want flow source=http-input sink=command-execution sinkFn=~AppendElement
func AppendElement(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	out := append(in, 1)
	_ = exec.Command("sh", "-c", string(out))
}

// LoopAccumulate covers the append-in-a-loop accumulator, where the phi carries
// the slice around the back edge.
// golem:want flow source=http-input sink=command-execution sinkFn=~LoopAccumulate
func LoopAccumulate(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	var out []byte
	for _, b := range in {
		out = append(out, b)
	}
	_ = exec.Command("sh", "-c", string(out))
}

// AppendArgs covers the common `args := append([]string{"-c"}, v)` shape, where
// SSA packs v into a fresh varargs slice and the taint sits on its elements.
// golem:want flow source=http-input sink=command-execution sinkFn=~AppendArgs
func AppendArgs(r *http.Request) {
	v := r.FormValue("cmd")
	args := append([]string{"-c"}, v)
	_ = exec.Command("sh", args...)
}

// ConstantsOnly appends and copies constants while a tainted value sits unused,
// so no flow may reach the sink. The negative is scoped to this function
// because the case's other handlers legitimately produce the same category
// pair.
// golem:want-not flow source=http-input sink=command-execution sinkFn=~ConstantsOnly
func ConstantsOnly(r *http.Request) {
	_ = r.FormValue("cmd")
	args := append([]string{"-c"}, "echo", "hi")
	buf := make([]byte, 8)
	copy(buf, []byte("const"))
	_ = exec.Command("sh", args...)
	_ = exec.Command("sh", "-c", string(buf))
}
