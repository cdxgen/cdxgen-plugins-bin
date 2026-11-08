package requestremoteaddrhost

import (
	"log"
	"net/http"
)

// RemoteAddr is rewritten by forwarded-header middleware (chi RealIP,
// gorilla ProxyHeaders), so its read is proxy-derived rather than the
// request's generic http-input.
//
// golem:want flow source=proxy-derived sink=logging
// golem:want-not flow source=http-input sink=logging
func RemoteAddr(r *http.Request) {
	log.Printf("peer %s", r.RemoteAddr)
}

// Host is rewritten from X-Forwarded-Host by the same middleware.
//
// golem:want flow source=proxy-derived sink=logging
func Host(r *http.Request) {
	log.Printf("host %s", r.Host)
}
