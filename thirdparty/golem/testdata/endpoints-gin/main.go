// Sample Gin service used to verify golem's enriched endpoint discovery.
// The router intentionally exercises:
//   - top-level routes on the engine (/health),
//   - nested Group prefixes (/api/v1 -> /users, /orders),
//   - the group-root idiom `users.GET("", listUsers)`,
//   - path-parameter helpers (c.Param),
//   - query-parameter helpers (c.Query and c.DefaultQuery),
//   - request-body binders (c.ShouldBindJSON) with an abort error path,
//   - response emitters (c.JSON) returning a named struct, a struct slice,
//     and the framework's ad-hoc gin.H map,
//   - an error-only handler whose only response is a 4xx status,
//   - a handler registered as a method expression (svc.Ping) that emits no
//     body at all,
//   - a handler in admin.go reached through an import alias with a renamed
//     context parameter.
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Order struct {
	ID    int   `json:"id"`
	Total int64 `json:"total"`
}

type Service struct{}

// Ping is registered as a method expression and emits no body, so the
// enriched endpoint must carry no parameters, body, or response type.
func (s *Service) Ping(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

func health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func listUsers(c *gin.Context) {
	limit := c.Query("limit")
	page := c.DefaultQuery("page", "1")
	_, _ = limit, page
	c.JSON(http.StatusOK, []User{})
}

func createUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, User{ID: 1, Username: req.Username, Email: req.Email})
}

func getUser(c *gin.Context) {
	id := c.Param("id")
	_ = id
	c.JSON(http.StatusOK, User{ID: 1})
}

// deprecatedListOrders is an error-only handler: its only emitter is a 410,
// so the reported responseType is the promoted error shape.
func deprecatedListOrders(c *gin.Context) {
	c.JSON(http.StatusGone, gin.H{"error": "orders endpoint retired"})
}

func getOrder(c *gin.Context) {
	id := c.Param("id")
	_ = id
	c.JSON(http.StatusOK, Order{ID: 1})
}

func main() {
	r := gin.Default()

	r.GET("/health", health)

	api := r.Group("/api/v1")
	{
		svc := &Service{}
		users := api.Group("/users")
		{
			users.GET("", listUsers)
			users.POST("", createUser)
			users.GET("/:id", getUser)
		}

		orders := api.Group("/orders")
		{
			orders.GET("", deprecatedListOrders)
			orders.GET("/:id", getOrder)
		}

		api.GET("/ping", svc.Ping)
		api.DELETE("/admin/users/:id", deleteAdminUser)
	}

	_ = r.Run(":8080")
}
