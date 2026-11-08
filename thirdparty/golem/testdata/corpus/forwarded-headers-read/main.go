package forwardedheadersread

import (
	"log"
	"net/http"
	"os/exec"
)

// A literal read of a forwarded header is a proxy-derived source: behind a
// reverse proxy that passes the header through, the client chose the value.
//
// golem:want flow source=proxy-derived sink=logging
func ReadForwardedFor(r *http.Request) {
	ip := r.Header.Get("X-Forwarded-For")
	log.Printf("client %s", ip)
}

// The RFC 7239 spelling is in the family too.
//
// golem:want flow source=proxy-derived sink=logging
func ReadForwarded(r *http.Request) {
	fwd := r.Header.Get("Forwarded")
	log.Printf("forwarded %s", fwd)
}

// The end-to-end shape: a header-chosen client IP reaching a command. Behind
// a pass-through proxy the client picks the argument.
//
// golem:want flow source=proxy-derived sink=command-execution
func ForwardedForToCommand(r *http.Request) {
	ip := r.Header.Get("X-Forwarded-For")
	cmd := exec.Command("dig", ip)
	_ = cmd.Run()
}
