package main

import (
	"net/http"

	// Aliased versioned import on purpose: the extractor must normalize the
	// /v4 module-path suffix AND resolve the alias through the type checker
	// — the source spelling "e.Context" matches nothing by text.
	e "github.com/labstack/echo/v4"
)

// archiveItem mirrors the gin fixture's deleteAdminUser: role resolution
// must key on the parameter's resolved type, not its identifier.
func archiveItem(c e.Context) error {
	id := c.Param("id")
	_ = id
	return c.JSON(http.StatusOK, e.Map{"archived": id})
}
