package forwardedheadersnegative

import (
	"log"
	"net/http"
)

// A header outside the family keeps its generic category: the read is
// reported as http-input, never as proxy-derived.
//
// golem:want flow source=http-input sink=logging
// golem:want-not flow source=proxy-derived sink=logging
func ReadTraceHeader(r *http.Request) {
	log.Printf("trace %s", r.Header.Get("X-Trace"))
}

// A non-literal header name is not a forwarded-header read: the analysis
// cannot see which header the caller asks for, so the generic source stands.
//
// golem:want flow source=http-input sink=logging
// golem:want-not flow source=proxy-derived sink=logging
func ReadDynamicHeader(r *http.Request, name string) {
	log.Printf("header %s", r.Header.Get(name))
}

// r.TLS is the socket's connection state, not a value any middleware
// rewrites from a header.
//
// golem:want-not flow source=proxy-derived sink=logging
func TLS(r *http.Request) {
	if r.TLS != nil {
		log.Print("tls")
	}
}

// peerAddr is an application type with the same field name. The field rule
// keys on net/http's own Request, so this read stays untagged.
//
// golem:want-not flow source=proxy-derived sink=logging
type peerAddr struct {
	RemoteAddr string
}

func TwinRemoteAddr(p peerAddr) {
	log.Printf("peer %s", p.RemoteAddr)
}
