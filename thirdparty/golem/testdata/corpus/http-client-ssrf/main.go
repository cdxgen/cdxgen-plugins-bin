package httpclientssrf

import (
	"net/http"
)

// A request-supplied URL handed to the standard library's client is the
// external-service sink: the server fetches whatever the caller names.
//
// golem:want flow source=http-input sink=external-service
func Fetch(r *http.Request) {
	target := r.FormValue("url")
	resp, err := http.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// The same shape through a client's method, which is spelled with a pointer
// receiver and only matches once the source notation is rewritten to SSA's.
//
// golem:want flow source=http-input sink=external-service
func FetchWithClient(r *http.Request, c *http.Client) {
	resp, err := c.Get(r.FormValue("url"))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// Reading a header is not a call out to anything. It matched the net/http.Head
// sink by substring — "net/http.Head" is a prefix of the symbol
// "(net/http.Header).Get" — and every handler that read a header reported an
// external-service flow.
//
// golem:want-not flow source=http-input sink=external-service sinkFn=(net/http.Header).Get
func ReadHeader(r *http.Request) string {
	return r.Header.Get("X-Trace")
}
