// Authentication evidence per route, in the three states the exposure
// contract distinguishes: a declared requirement, a route with none, and an
// explicit anonymity marker that must NOT read as a requirement.
//
// Every signature exercised here was read from the framework's own reference.
// gin and fiber put the endpoint handler LAST among variadic handlers; echo
// puts it at argument 1 and middleware AFTER it; chi has no route-level
// middleware at all. A single guessed convention names a middleware as the
// handler on one framework or the other.
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

func requireAuth(c *gin.Context)   {}
func noAuth(c *gin.Context)        {}
func requestLogger(c *gin.Context) {}

func listUsers(c *gin.Context)  {}
func createUser(c *gin.Context) {}
func health(c *gin.Context)     {}
func openStatus(c *gin.Context) {}

// gin: middleware on the GROUP, handler last on the route.
func ginRoutes() {
	r := gin.Default()

	// Declared: the group carries the requirement, so both routes inherit it.
	api := r.Group("/api", requireAuth)
	api.GET("/users", listUsers)
	api.POST("/users", createUser)

	// Declared at the ROUTE, with the handler last.
	r.GET("/admin/users", requireAuth, listUsers)

	// Nothing declared: a logging middleware is not authentication, and the
	// result must be no field at all rather than "anonymous".
	open := r.Group("/open", requestLogger)
	open.GET("/health", health)

	// The inverse marker must not read as a requirement.
	r.GET("/public/status", noAuth, openStatus)
}

func echoAuth(next echo.HandlerFunc) echo.HandlerFunc { return next }
func echoLog(next echo.HandlerFunc) echo.HandlerFunc  { return next }
func echoList(c echo.Context) error                   { return nil }
func echoHealth(c echo.Context) error                 { return nil }

// echo: the handler is argument 1 and middleware FOLLOWS it — the opposite
// of gin.
func echoRoutes() {
	e := echo.New()

	// Declared on the group.
	g := e.Group("/api", echoAuth)
	g.GET("/items", echoList)

	// Declared on the route, AFTER the handler.
	e.GET("/secure/items", echoList, echoAuth)

	// Nothing declared.
	e.GET("/health", echoHealth, echoLog)
}

func plainHandler(w http.ResponseWriter, r *http.Request) {}

// net/http: no middleware vocabulary, so nothing is ever declared here.
func netHTTPRoutes() {
	http.HandleFunc("/metrics", plainHandler)
}

func main() {
	ginRoutes()
	echoRoutes()
	netHTTPRoutes()
}
