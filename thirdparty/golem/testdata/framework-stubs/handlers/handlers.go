// A hermetic stub of github.com/gorilla/handlers covering the ProxyHeaders
// middleware golem recognises. Fixtures depend on it through a filesystem
// `replace`, so the module path stays github.com/gorilla/handlers.
package handlers

import "net/http"

// ProxyHeaders rewrites Request.RemoteAddr, Request.URL.Scheme and
// Request.Host from the X-Forwarded-*, X-Real-IP and Forwarded headers,
// matching the real middleware.
func ProxyHeaders(h http.Handler) http.Handler { return h }
