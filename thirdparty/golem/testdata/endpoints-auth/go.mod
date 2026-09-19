module example.com/golem/endpoints-auth

go 1.25

require (
	github.com/gin-gonic/gin v0.0.0
	github.com/labstack/echo/v4 v4.0.0
)

replace github.com/labstack/echo/v4 => ../framework-stubs/echo

replace github.com/gin-gonic/gin => ../framework-stubs/gin
