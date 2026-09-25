//go:build goexperiment.simd

package simdvector

import (
	"net/http"
	"os/exec"
	"simd"
	"strconv"
)

// The portable simd package is a bodiless stub on amd64, arm64 and wasm and
// carries real emulated bodies elsewhere, so nothing but the package-path
// intrinsic rule can move taint through it. There is deliberately no fallback
// file: a driver that forgets the golem:env directive below fails loudly with
// a load error instead of passing an empty analysis.

// golem:env GOEXPERIMENT=simd

// ValueChain: the vector carries the taint of the slice it was loaded from,
// through the lane-wise op, and Store writes the receiver's taint into its
// destination argument.
// golem:want flow source=http-input sink=command-execution sinkFn=~ValueChain
func ValueChain(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	out := make([]byte, len(in))
	simd.LoadUint8s(in).Xor(simd.BroadcastUint8s(1)).Store(out)
	_ = exec.Command("sh", "-c", string(out))
}

// Stringify: String propagates, so the vector's taint reaches the sink as text.
// golem:want flow source=http-input sink=command-execution sinkFn=~Stringify
func Stringify(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	_ = exec.Command("sh", "-c", simd.LoadUint8s(in).String())
}

// LenMustNotPropagate: Len returns a derived lane count, so strconv.Itoa(n) is
// clean and nothing may reach the sink.
// golem:want-not flow source=http-input sink=command-execution sinkFn=~LenMustNotPropagate
func LenMustNotPropagate(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	n := simd.LoadUint8s(in).Len()
	_ = exec.Command("sh", "-c", strconv.Itoa(n))
}

// BroadcastConstant stores a constant vector and executes it; the tainted input
// sits unused, so nothing may reach the sink.
// golem:want-not flow source=http-input sink=command-execution sinkFn=~BroadcastConstant
func BroadcastConstant(r *http.Request) {
	_ = r.FormValue("cmd")
	out := make([]byte, 64)
	simd.BroadcastUint8s(1).Store(out)
	_ = exec.Command("sh", "-c", string(out))
}
