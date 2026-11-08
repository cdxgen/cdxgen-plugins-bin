package frameworkforwardedaccessorsnegative

import (
	"log"

	"github.com/gin-gonic/gin"
	fiber "github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

// fakeContext is an application type with the same accessor name. The rule
// keys on gin's own symbol, so this read stays untagged.
//
// golem:want-not flow source=proxy-derived sink=logging
func twinGinClientIP(c *fakeContext) {
	log.Printf("twin %s", c.ClientIP())
}

type fakeContext struct{}

func (c *fakeContext) ClientIP() string { return "" }

// gin's RemoteIP is the socket address (net.SplitHostPort of
// Request.RemoteAddr); no middleware rewrites it through a header, so it is
// not proxy-derived.
//
// golem:want-not flow source=proxy-derived sink=logging
func ginRemoteIP(c *gin.Context) {
	log.Printf("socket %s", c.RemoteIP())
}

// localContext carries the same accessor names on an application type; the
// rule keys on echo's own interface, so these reads stay untagged.
//
// golem:want-not flow source=proxy-derived sink=logging
func twinEchoRealIP(c localContext) {
	log.Printf("twin %s", c.RealIP())
}

type localContext struct{}

func (c localContext) RealIP() string { return "" }

// localCtx carries the same accessor names on an application type; the rule
// keys on fiber's own symbol, so these reads stay untagged.
//
// golem:want-not flow source=proxy-derived sink=logging
func twinFiberIP(c localCtx) {
	log.Printf("twin %s", c.IP())
}

type localCtx struct{}

func (c localCtx) IP() string    { return "" }
func (c localCtx) IPs() []string { return nil }
