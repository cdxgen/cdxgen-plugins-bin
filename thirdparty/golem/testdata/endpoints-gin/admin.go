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
