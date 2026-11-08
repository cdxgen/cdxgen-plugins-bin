package frameworkforwardedaccessors

import (
	"log"

	fiber "github.com/gofiber/fiber/v2"
	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

// ClientIP resolves the address from the forwarded headers gin is configured
// to trust, so its value is client-choosable behind a pass-through proxy.
//
// golem:want flow source=proxy-derived sink=logging
func ginClientIP(c *gin.Context) {
	log.Printf("client %s", c.ClientIP())
}

// GetHeader reads a request header; naming a forwarded one by literal makes
// the read proxy-derived.
//
// golem:want flow source=proxy-derived sink=logging
func ginGetForwarded(c *gin.Context) {
	log.Printf("xff %s", c.GetHeader("X-Forwarded-For"))
}

// RealIP resolves the address from the configured IPExtractor or
// X-Forwarded-For/X-Real-IP, so its value is client-choosable behind a
// pass-through proxy.
//
// golem:want flow source=proxy-derived sink=logging
func echoRealIP(c echo.Context) {
	log.Printf("client %s", c.RealIP())
}

// Scheme resolves the protocol from X-Forwarded-Proto when the connection is
// not TLS.
//
// golem:want flow source=proxy-derived sink=logging
func echoScheme(c echo.Context) {
	log.Printf("scheme %s", c.Scheme())
}

// IP returns the address fiber extracts from Config.ProxyHeader when the
// proxy is trusted, so its value is client-choosable behind a pass-through
// proxy.
//
// golem:want flow source=proxy-derived sink=logging
func fiberIP(c *fiber.Ctx) error {
	log.Printf("client %s", c.IP())
	return nil
}

// IPs returns every address in X-Forwarded-For.
//
// golem:want flow source=proxy-derived sink=logging
func fiberIPs(c *fiber.Ctx) error {
	log.Printf("chain %v", c.IPs())
	return nil
}
