//go:build goexperiment.simd

package simdchunkedloop

import (
	"net/http"
	"os/exec"
	"simd"
)

// The realistic chunked shape: LoadUint8sPart returns a (vector, count) tuple
// — tainted as a whole — and StorePart writes the receiver's taint into the
// base slice behind out[i:]. No fallback file: a driver that forgets the env
// directive fails on a load error, not on an empty analysis.

// golem:env GOEXPERIMENT=simd

// golem:want flow source=http-input sink=command-execution sinkFn=~ChunkedXor
func ChunkedXor(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	out := make([]byte, len(in))
	for i := 0; i < len(in); {
		v, n := simd.LoadUint8sPart(in[i:])
		k := simd.BroadcastUint8s(1)
		v.Xor(k).StorePart(out[i:])
		i += n
	}
	_ = exec.Command("sh", "-c", string(out))
}
