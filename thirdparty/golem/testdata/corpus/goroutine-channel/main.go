package goroutinechannel

import (
	"net/http"
	"os"
)

// Goroutine with channel: taint flows through a channel to a goroutine.
// golem:want flow source=http-input sink=filesystem
func Handler(r *http.Request) {
	ch := make(chan string, 1)
	ch <- r.Header.Get("X-Path")
	v := <-ch
	_ = os.WriteFile(v, []byte("x"), 0o600)
}
