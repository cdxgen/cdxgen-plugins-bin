// Sample service that turns on forwarded-header handling in each framework
// golem recognises, together with the negative twins the same rules must not
// tag: an empty trusted list, a literal false, an empty header name, and the
// same names on application types.
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	fiber "github.com/gofiber/fiber/v2"
	"github.com/gorilla/handlers"
	"github.com/labstack/echo/v4"
)

func chiRealIP() {
	r := chi.NewRouter()
	// signal: trusted-proxy-config, framework=chi, headers=x-forwarded
	r.Use(middleware.RealIP)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {})
}

func gorillaProxyHeaders(h http.Handler) http.Handler {
	// signal: trusted-proxy-config, framework=gorilla, headers=all
	return handlers.ProxyHeaders(h)
}

func ginTrusted(r *gin.Engine) {
	// signal: trusted-proxy-config, framework=gin
	_ = r.SetTrustedProxies([]string{"10.0.0.0/8"})
}

func ginTrustedNil(r *gin.Engine) {
	// twin: an explicitly empty list turns the feature off, no signal, also
	// when the call sits in an if statement's init
	if err := r.SetTrustedProxies(nil); err != nil {
		panic(err)
	}
	_ = r.SetTrustedProxies([]string{})
}

func ginForwardedByClientIP(r *gin.Engine) {
	// signal: trusted-proxy-config, framework=gin (Engine.ForwardedByClientIP),
	// assigned the way gin applications set Engine fields
	r.ForwardedByClientIP = true
}

func ginForwardedByClientIPFalse(r *gin.Engine) {
	// twin: a literal false turns the behaviour off, no signal
	r.ForwardedByClientIP = false
}

func ginRemoteIPHeaders(r *gin.Engine) {
	// signal: trusted-proxy-config, framework=gin, headers=x-forwarded
	r.RemoteIPHeaders = []string{"X-Forwarded-For"}
}

func echoIPExtractor() *echo.Echo {
	// signal: trusted-proxy-config, framework=echo, headers=x-forwarded
	return &echo.Echo{IPExtractor: echo.ExtractIPFromXFFHeader()}
}

func echoRealIPExtractor() *echo.Echo {
	// signal: trusted-proxy-config, framework=echo, headers=x-forwarded
	// (X-Real-IP is the single-value spelling of the de-facto family)
	return &echo.Echo{IPExtractor: echo.ExtractIPFromRealIPHeader()}
}

func fiberProxyHeader() *fiber.App {
	// signal: trusted-proxy-config, framework=fiber, headers=x-forwarded
	return fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
}

func fiberTrustedProxyCheck() *fiber.App {
	// twin: the check narrows which peers fiber trusts, it never turns
	// forwarded-header handling on, so no signal
	return fiber.New(fiber.Config{EnableTrustedProxyCheck: true})
}

func fiberEmptyProxyHeader() *fiber.App {
	// twin: an empty header name names nothing, no signal
	return fiber.New(fiber.Config{ProxyHeader: ""})
}

func fiberTrustedProxyCheckFalse() *fiber.App {
	// twin: a literal false turns the check off, no signal
	return fiber.New(fiber.Config{EnableTrustedProxyCheck: false})
}

// localMiddleware is an application package-shaped twin for chi's middleware:
// the same function name on an unrelated receiver must not signal.
func localMiddleware() {
	r := chi.NewRouter()
	r.Use(realIP)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {})
}

func realIP(next http.Handler) http.Handler { return next }

// localConfig mirrors fiber's Config shape on an application type; the same
// field name must not signal.
type localConfig struct {
	ProxyHeader             string
	EnableTrustedProxyCheck bool
}

func localFiberTwin() {
	_ = localConfig{ProxyHeader: "X-Forwarded-For", EnableTrustedProxyCheck: true}
}

func main() {
	ginTrusted(gin.Default())
	chiRealIP()
	_ = gorillaProxyHeaders(http.NotFoundHandler())
	_ = echoIPExtractor()
	_ = fiberProxyHeader()
}
