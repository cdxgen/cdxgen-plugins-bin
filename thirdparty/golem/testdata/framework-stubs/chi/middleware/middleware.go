// A hermetic stub of github.com/go-chi/chi/v5/middleware, the subpackage the
// RealIP middleware lives in. Fixtures reach it through the chi module's
// filesystem `replace`.
package middleware

import "net/http"

// RealIP rewrites Request.RemoteAddr from X-Forwarded-For, X-Real-IP or
// True-Client-IP, matching the real middleware.
func RealIP(next http.Handler) http.Handler { return next }
