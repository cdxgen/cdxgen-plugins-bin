package main

import (
	"net/http"

	// Aliased on purpose: handler-role resolution must key on the resolved
	// import path of the parameter's type, not on the package identifier.
	g "github.com/gin-gonic/gin"
)

// deleteAdminUser also spells its context parameter `ctx`, the name most
// implementations would use for a stdlib context, to pin down that the
// extractor binds roles by type and not by identifier spelling.
func deleteAdminUser(ctx *g.Context) {
	id := ctx.Param("id")
	_ = id
	ctx.JSON(http.StatusOK, g.H{"deleted": id})
}

type UserRepo struct{}

// Find reads a query parameter. Its name deliberately collides with
// OrderRepo.Find below: the registration string "userRepo.Find" carries no
// receiver type, so the extractor must skip both rather than enrich one of
// them from the other's body.
func (r *UserRepo) Find(c *g.Context) {
	verbose := c.Query("verbose")
	_ = verbose
	c.JSON(http.StatusOK, g.H{"user": 1})
}

type OrderRepo struct{}

// Find reads a path parameter — different from UserRepo.Find on purpose,
// so a wrong-body enrichment is observable in tests.
func (r *OrderRepo) Find(c *g.Context) {
	id := c.Param("id")
	_ = id
	c.JSON(http.StatusOK, g.H{"order": 1})
}
