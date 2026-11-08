module example.com/golem/corpus/framework-forwarded-accessors-negative

go 1.25

require (
	github.com/gin-gonic/gin v1.0.0
	github.com/gofiber/fiber/v2 v2.0.0
	github.com/labstack/echo/v4 v4.0.0
)

replace github.com/gin-gonic/gin => ../../framework-stubs/gin

replace github.com/labstack/echo/v4 => ../../framework-stubs/echo

replace github.com/gofiber/fiber/v2 => ../../framework-stubs/fiber
