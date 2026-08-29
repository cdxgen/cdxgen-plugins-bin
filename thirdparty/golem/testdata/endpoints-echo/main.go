// Sample echo service used to verify golem's enriched endpoint discovery.
// Handlers take the interface-valued echo.Context and intentionally
// exercise:
//   - c.Param and c.QueryParam,
//   - c.Bind for the request body with an error echo.Map path,
//   - c.JSON and c.JSONPretty for response types,
//   - an error-only handler whose only response is a 4xx status.
package main

import (
	"net/http"

	"github.com/labstack/echo"
)

type Item struct {
	ID    int    `json:"id"`
	Label string `json:"label"`
}

type CreateItemRequest struct {
	Label string `json:"label"`
}

func health(c echo.Context) error {
	return c.JSON(http.StatusOK, echo.Map{"status": "ok"})
}

func listItems(c echo.Context) error {
	page := c.QueryParam("page")
	_ = page
	return c.JSON(http.StatusOK, []Item{})
}

func createItem(c echo.Context) error {
	var req CreateItemRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}
	return c.JSON(http.StatusCreated, Item{ID: 1, Label: req.Label})
}

func getItem(c echo.Context) error {
	id := c.Param("id")
	_ = id
	return c.JSONPretty(http.StatusOK, Item{ID: 1}, "  ")
}

// gone is an error-only handler: its only emitter is a 410, so the
// reported responseType is the promoted error shape.
func gone(c echo.Context) error {
	return c.JSON(http.StatusGone, echo.Map{"reason": "retired"})
}

func main() {
	e := echo.New()
	e.GET("/health", health)
	e.GET("/items", listItems)
	e.POST("/items", createItem)
	e.GET("/items/:id", getItem)
	e.GET("/gone", gone)
	_ = e.Start(":8080")
}
