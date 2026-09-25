//go:build goexperiment.simd && amd64

package simdarchsimd

import (
	"net/http"
	"os/exec"

	"simd/archsimd"
)

// The architecture-specific layer, loaded only for amd64: the golem:env
// directive pins the target so the case runs on any host, and there is no
// fallback file, so a driver that forgets it fails on a load error rather than
// analysing nothing. archsimd's Load*/Store* are bodiless stubs here exactly as
// in the portable package, so the same package-path rule must carry the taint;
// StoreArray is the store-into-an-array-pointer shape.

// golem:env GOEXPERIMENT=simd GOARCH=amd64

// golem:want flow source=http-input sink=command-execution sinkFn=~ArchLoadStore known-fail=legacy:38
func ArchLoadStore(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	out := make([]byte, len(in))
	archsimd.LoadUint8x64(in).Xor(archsimd.BroadcastUint8x64(1)).Store(out)
	_ = exec.Command("sh", "-c", string(out))
}

// golem:want flow source=http-input sink=command-execution sinkFn=~ArchStoreArray known-fail=legacy:38
func ArchStoreArray(r *http.Request) {
	in := []byte(r.FormValue("cmd"))
	var arr [64]byte
	archsimd.LoadUint8x64(in).StoreArray(&arr)
	_ = exec.Command("sh", "-c", string(arr[:]))
}
