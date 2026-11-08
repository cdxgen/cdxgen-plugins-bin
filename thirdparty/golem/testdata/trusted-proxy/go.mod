module example.com/golem/trusted-proxy

go 1.25

require (
	github.com/gin-gonic/gin v1.0.0
	github.com/go-chi/chi/v5 v5.0.0
	github.com/gofiber/fiber/v2 v2.0.0
	github.com/gorilla/handlers v1.0.0
	github.com/labstack/echo/v4 v4.0.0
)

replace github.com/gin-gonic/gin => ../framework-stubs/gin

replace github.com/go-chi/chi/v5 => ../framework-stubs/chi

replace github.com/gofiber/fiber/v2 => ../framework-stubs/fiber

replace github.com/gorilla/handlers => ../framework-stubs/handlers

replace github.com/labstack/echo/v4 => ../framework-stubs/echo
