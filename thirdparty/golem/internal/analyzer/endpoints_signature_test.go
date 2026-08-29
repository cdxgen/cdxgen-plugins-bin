package analyzer

import (
	"go/token"
	"go/types"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// analyzeEndpointFixture analyzes one of the testdata/endpoints-* fixture
// modules and indexes its http-route endpoints by "METHOD path". It also
// asserts the per-framework services roll-up the report promises.
func analyzeEndpointFixture(t *testing.T, dir string) map[string]model.APIEndpoint {
	t.Helper()
	report, err := Analyze(Options{Dir: dir, IncludeLocal: true, CallGraphMode: "none", ToolVersion: "test"})
	if err != nil {
		t.Fatalf("analyze %s: %v", dir, err)
	}
	if report.Stats.APIEndpointCount == 0 {
		t.Fatalf("%s: expected endpoints, got none", dir)
	}
	var serverServices int
	for _, svc := range report.Services {
		if svc.Kind == "server" {
			serverServices++
		}
	}
	if serverServices == 0 {
		t.Fatalf("%s: expected at least one server service roll-up, got %v", dir, report.Services)
	}
	byKey := map[string]model.APIEndpoint{}
	for _, ep := range report.APIEndpoints {
		if ep.Kind != "http-route" {
			continue
		}
		key := ep.Method + " " + ep.Path
		if _, dup := byKey[key]; dup {
			t.Fatalf("%s: duplicate endpoint %q", dir, key)
		}
		byKey[key] = ep
	}
	return byKey
}

func requireEndpoint(t *testing.T, byKey map[string]model.APIEndpoint, key string) model.APIEndpoint {
	t.Helper()
	ep, ok := byKey[key]
	if !ok {
		t.Fatalf("expected endpoint %q; got %v", key, endpointKeys(byKey))
	}
	return ep
}

// requireNoScratchProperties guards the extractor's error-response stash:
// it must never leak into the serialized properties map.
func requireNoScratchProperties(t *testing.T, byKey map[string]model.APIEndpoint) {
	t.Helper()
	for _, ep := range byKey {
		if _, ok := ep.Properties["errorResponseType"]; ok {
			t.Fatalf("%s %s: extractor scratch key leaked into properties: %v", ep.Method, ep.Path, ep.Properties)
		}
	}
}

func requireParams(t *testing.T, ep model.APIEndpoint, want []model.EndpointParameter) {
	t.Helper()
	if len(ep.Parameters) != len(want) {
		t.Fatalf("%s %s: expected params %v, got %v", ep.Method, ep.Path, want, ep.Parameters)
	}
	for _, w := range want {
		found := false
		for _, got := range ep.Parameters {
			if got == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s %s: expected params %v, got %v", ep.Method, ep.Path, want, ep.Parameters)
		}
	}
}

func endpointKeys(byKey map[string]model.APIEndpoint) []string {
	out := make([]string, 0, len(byKey))
	for k := range byKey {
		out = append(out, k)
	}
	return out
}

// TestEndpointsEnrichedForGin ties the two improvements in this change
// together against the hermetic Gin fixture:
//
//   - the empty-path fix — group-root registrations like
//     `users.GET("", listUsers)` are composed with their group's prefix and
//     reported instead of being dropped as pathless, and
//   - the handler-signature extractor — endpoints carry path parameters from
//     `c.Param(...)`, query parameters from `c.Query(...)`/`c.DefaultQuery`,
//     the request body from `c.ShouldBindJSON(&x)`, and response types from
//     `c.JSON(...)`, with gin.H collapsing to `object` and error-only
//     handlers keeping their (promoted) error shape.
func TestEndpointsEnrichedForGin(t *testing.T) {
	byKey := analyzeEndpointFixture(t, "../../testdata/endpoints-gin")

	wantRoutes := []string{
		"GET /health",
		"GET /api/v1/users",
		"POST /api/v1/users",
		"GET /api/v1/users/:id",
		"GET /api/v1/orders",
		"GET /api/v1/orders/:id",
		"GET /api/v1/ping",
		"DELETE /api/v1/admin/users/:id",
		"GET /api/v1/repos/users",
		"GET /api/v1/repos/orders",
		"GET /api/v1/inline",
	}
	for _, key := range wantRoutes {
		requireEndpoint(t, byKey, key)
	}
	requireNoScratchProperties(t, byKey)

	// getUser reads c.Param("id").
	getUser := requireEndpoint(t, byKey, "GET /api/v1/users/:id")
	requireParams(t, getUser, []model.EndpointParameter{{Name: "id", Location: "path", TypeName: "string"}})
	if getUser.ResponseType != "User" {
		t.Fatalf("getUser: expected responseType 'User', got %q", getUser.ResponseType)
	}

	// listUsers reads c.Query("limit") and c.DefaultQuery("page", ...) and
	// returns a slice, whose multiplicity must survive.
	listUsers := requireEndpoint(t, byKey, "GET /api/v1/users")
	requireParams(t, listUsers, []model.EndpointParameter{
		{Name: "limit", Location: "query", TypeName: "string"},
		{Name: "page", Location: "query", TypeName: "string"},
	})
	if listUsers.ResponseType != "[]User" {
		t.Fatalf("listUsers: expected responseType '[]User', got %q", listUsers.ResponseType)
	}
	if listUsers.RequestBodyType != "" {
		t.Fatalf("listUsers: expected no requestBodyType, got %q", listUsers.RequestBodyType)
	}

	// createUser binds CreateUserRequest; its AbortWithStatusJSON error path
	// must not displace the successful response shape.
	createUser := requireEndpoint(t, byKey, "POST /api/v1/users")
	if createUser.RequestBodyType != "CreateUserRequest" {
		t.Fatalf("createUser: expected requestBodyType 'CreateUserRequest', got %q", createUser.RequestBodyType)
	}
	if createUser.ResponseType != "User" {
		t.Fatalf("createUser: expected responseType 'User', got %q", createUser.ResponseType)
	}

	// health returns gin.H, which collapses to a free-form object.
	health := requireEndpoint(t, byKey, "GET /health")
	if health.ResponseType != "object" {
		t.Fatalf("health: expected responseType 'object' (from gin.H), got %q", health.ResponseType)
	}

	// deprecatedListOrders only ever emits 410 gin.H: the error shape is
	// promoted so the endpoint still carries a schema.
	deprecated := requireEndpoint(t, byKey, "GET /api/v1/orders")
	if deprecated.ResponseType != "object" {
		t.Fatalf("deprecatedListOrders: expected promoted responseType 'object', got %q", deprecated.ResponseType)
	}

	// getOrder reads the wildcard through c.Param and returns a named struct.
	getOrder := requireEndpoint(t, byKey, "GET /api/v1/orders/:id")
	requireParams(t, getOrder, []model.EndpointParameter{{Name: "id", Location: "path", TypeName: "string"}})
	if getOrder.ResponseType != "Order" {
		t.Fatalf("getOrder: expected responseType 'Order', got %q", getOrder.ResponseType)
	}

	// svc.Ping is registered as a method expression and only writes a bare
	// status: nothing to enrich.
	ping := requireEndpoint(t, byKey, "GET /api/v1/ping")
	if ping.Handler != "svc.Ping" {
		t.Fatalf("ping: expected handler 'svc.Ping', got %q", ping.Handler)
	}
	requireParams(t, ping, nil)
	if ping.RequestBodyType != "" || ping.ResponseType != "" {
		t.Fatalf("ping: expected no body/response types, got %q / %q", ping.RequestBodyType, ping.ResponseType)
	}

	// deleteAdminUser lives in admin.go behind an aliased import (g) and a
	// renamed context parameter (ctx): role resolution must key on the
	// parameter's resolved type.
	admin := requireEndpoint(t, byKey, "DELETE /api/v1/admin/users/:id")
	requireParams(t, admin, []model.EndpointParameter{{Name: "id", Location: "path", TypeName: "string"}})
	if admin.ResponseType != "object" {
		t.Fatalf("deleteAdminUser: expected responseType 'object' (from g.H), got %q", admin.ResponseType)
	}

	// userRepo.Find and orderRepo.Find share a short name across receiver
	// types. The registration strings carry no receiver, so both endpoints
	// must stay unenriched rather than one being enriched from the other's
	// body — UserRepo.Find reads a query param, OrderRepo.Find a path param.
	for _, key := range []string{"GET /api/v1/repos/users", "GET /api/v1/repos/orders"} {
		repo := requireEndpoint(t, byKey, key)
		requireParams(t, repo, nil)
		if repo.RequestBodyType != "" || repo.ResponseType != "" {
			t.Fatalf("%s: ambiguous handler must not be enriched, got body=%q resp=%q", key, repo.RequestBodyType, repo.ResponseType)
		}
	}

	// The inline func-literal handler is enriched straight from the closure
	// at the registration site.
	inline := requireEndpoint(t, byKey, "GET /api/v1/inline")
	requireParams(t, inline, []model.EndpointParameter{{Name: "verbose", Location: "query", TypeName: "string"}})
	if inline.ResponseType != "object" {
		t.Fatalf("inline: expected responseType 'object' (from gin.H), got %q", inline.ResponseType)
	}
}

// TestEndpointsEnrichedForChi covers the chi handler shapes: chi.URLParam,
// r.URL.Query().Get, render.DecodeJSON/JSON/Respond, and the stdlib
// json.NewDecoder/json.NewEncoder pair.
func TestEndpointsEnrichedForChi(t *testing.T) {
	byKey := analyzeEndpointFixture(t, "../../testdata/endpoints-chi")

	wantRoutes := []string{
		"GET /products",
		"POST /products",
		"GET /products/{id}",
		"POST /widgets",
	}
	for _, key := range wantRoutes {
		requireEndpoint(t, byKey, key)
	}
	requireNoScratchProperties(t, byKey)

	list := requireEndpoint(t, byKey, "GET /products")
	requireParams(t, list, []model.EndpointParameter{{Name: "limit", Location: "query", TypeName: "string"}})
	if list.ResponseType != "[]Product" {
		t.Fatalf("listProducts: expected responseType '[]Product', got %q", list.ResponseType)
	}

	create := requireEndpoint(t, byKey, "POST /products")
	if create.RequestBodyType != "CreateProductRequest" {
		t.Fatalf("createProduct: expected requestBodyType 'CreateProductRequest', got %q", create.RequestBodyType)
	}
	if create.ResponseType != "Product" {
		t.Fatalf("createProduct: expected responseType 'Product' (from render.Respond), got %q", create.ResponseType)
	}

	get := requireEndpoint(t, byKey, "GET /products/{id}")
	requireParams(t, get, []model.EndpointParameter{{Name: "id", Location: "path", TypeName: "string"}})
	if get.ResponseType != "Product" {
		t.Fatalf("getProduct: expected responseType 'Product', got %q", get.ResponseType)
	}

	// createWidget uses only the stdlib codec pair against the handler's
	// (w, r) parameters.
	widget := requireEndpoint(t, byKey, "POST /widgets")
	if widget.RequestBodyType != "Widget" {
		t.Fatalf("createWidget: expected requestBodyType 'Widget', got %q", widget.RequestBodyType)
	}
	if widget.ResponseType != "Widget" {
		t.Fatalf("createWidget: expected responseType 'Widget', got %q", widget.ResponseType)
	}
}

// TestEndpointsEnrichedForEcho covers the echo handler shapes: interface-
// valued echo.Context, c.Param/QueryParam, c.Bind, c.JSON/JSONPretty, and
// error-shape promotion for an error-only handler.
func TestEndpointsEnrichedForEcho(t *testing.T) {
	byKey := analyzeEndpointFixture(t, "../../testdata/endpoints-echo")

	wantRoutes := []string{
		"GET /health",
		"GET /items",
		"POST /items",
		"GET /items/:id",
		"GET /items/:id/archive",
		"GET /gone",
	}
	for _, key := range wantRoutes {
		requireEndpoint(t, byKey, key)
	}
	requireNoScratchProperties(t, byKey)

	health := requireEndpoint(t, byKey, "GET /health")
	if health.ResponseType != "object" {
		t.Fatalf("health: expected responseType 'object' (from echo.Map), got %q", health.ResponseType)
	}

	list := requireEndpoint(t, byKey, "GET /items")
	requireParams(t, list, []model.EndpointParameter{{Name: "page", Location: "query", TypeName: "string"}})
	if list.ResponseType != "[]Item" {
		t.Fatalf("listItems: expected responseType '[]Item', got %q", list.ResponseType)
	}

	create := requireEndpoint(t, byKey, "POST /items")
	if create.RequestBodyType != "CreateItemRequest" {
		t.Fatalf("createItem: expected requestBodyType 'CreateItemRequest', got %q", create.RequestBodyType)
	}
	if create.ResponseType != "Item" {
		t.Fatalf("createItem: expected responseType 'Item', got %q", create.ResponseType)
	}

	get := requireEndpoint(t, byKey, "GET /items/:id")
	requireParams(t, get, []model.EndpointParameter{{Name: "id", Location: "path", TypeName: "string"}})
	if get.ResponseType != "Item" {
		t.Fatalf("getItem: expected responseType 'Item' (from c.JSONPretty), got %q", get.ResponseType)
	}

	gone := requireEndpoint(t, byKey, "GET /gone")
	if gone.ResponseType != "object" {
		t.Fatalf("gone: expected promoted responseType 'object', got %q", gone.ResponseType)
	}

	// archiveItem (endpoints-echo/admin.go) reaches the framework through an
	// aliased, versioned import (e "github.com/labstack/echo/v4"): the
	// extractor must normalize the /v4 suffix and resolve roles by type —
	// the source spelling "e.Context" matches no text fallback.
	archive := requireEndpoint(t, byKey, "GET /items/:id/archive")
	requireParams(t, archive, []model.EndpointParameter{{Name: "id", Location: "path", TypeName: "string"}})
	if archive.ResponseType != "object" {
		t.Fatalf("archiveItem: expected responseType 'object' (from aliased e.Map), got %q", archive.ResponseType)
	}
}

// TestEndpointsEnrichedForNetHTTP covers the stdlib-only service: named
// handlers on a ServeMux enriched through r.PathValue, r.URL.Query().Get,
// and the json codec pair — no third-party framework needed.
func TestEndpointsEnrichedForNetHTTP(t *testing.T) {
	byKey := analyzeEndpointFixture(t, "../../testdata/endpoints-nethttp")

	list := requireEndpoint(t, byKey, " /tickets")
	requireParams(t, list, []model.EndpointParameter{{Name: "limit", Location: "query", TypeName: "string"}})
	if list.ResponseType != "[]Ticket" {
		t.Fatalf("listTickets: expected responseType '[]Ticket', got %q", list.ResponseType)
	}

	get := requireEndpoint(t, byKey, " /tickets/{id}")
	requireParams(t, get, []model.EndpointParameter{{Name: "id", Location: "path", TypeName: "string"}})
	if get.ResponseType != "Ticket" {
		t.Fatalf("getTicket: expected responseType 'Ticket', got %q", get.ResponseType)
	}

	create := requireEndpoint(t, byKey, " /tickets/new")
	if create.RequestBodyType != "CreateTicketRequest" {
		t.Fatalf("createTicket: expected requestBodyType 'CreateTicketRequest', got %q", create.RequestBodyType)
	}
	if create.ResponseType != "Ticket" {
		t.Fatalf("createTicket: expected responseType 'Ticket', got %q", create.ResponseType)
	}

	// The inline HandleFunc closure is enriched directly from the func
	// literal at the registration site.
	reports := requireEndpoint(t, byKey, " /reports")
	requireParams(t, reports, []model.EndpointParameter{{Name: "format", Location: "query", TypeName: "string"}})
	if reports.ResponseType != "Report" {
		t.Fatalf("reports: expected responseType 'Report', got %q", reports.ResponseType)
	}
}

func TestShortTypeName(t *testing.T) {
	ginPkg := types.NewPackage("github.com/gin-gonic/gin", "gin")
	hNamed := types.NewNamed(
		types.NewTypeName(token.NoPos, ginPkg, "H", nil),
		types.NewMap(types.Typ[types.String], types.NewInterfaceType(nil, nil)),
		nil,
	)

	userPkg := types.NewPackage("example.com/acme/api", "api")
	userNamed := types.NewNamed(types.NewTypeName(token.NoPos, userPkg, "User", nil), types.NewStruct(nil, nil), nil)

	emptyInterface := types.NewInterfaceType(nil, nil).Complete()

	cases := []struct {
		name string
		typ  types.Type
		want string
	}{
		{"named user type", userNamed, "User"},
		{"pointer to user type", types.NewPointer(userNamed), "User"},
		{"slice of user type", types.NewSlice(userNamed), "[]User"},
		{"fixed array of user type", types.NewArray(userNamed, 4), "[]User"},
		{"gin.H alias", hNamed, "object"},
		{"slice of gin.H", types.NewSlice(hNamed), "[]object"},
		{"plain map", types.NewMap(types.Typ[types.String], types.Typ[types.String]), "object"},
		{"empty interface", emptyInterface, "any"},
		{"basic", types.Typ[types.Int], "int"},
		{"nil", nil, ""},
	}
	for _, tc := range cases {
		if got := shortTypeName(tc.typ); got != tc.want {
			t.Errorf("%s: shortTypeName = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestHandlerShortName(t *testing.T) {
	cases := map[string]string{
		"svc.Ping": "Ping",
		"health":   "health",
		"a.B.C":    "C",
		"":         "",
	}
	for got, want := range cases {
		if out := handlerShortName(got); out != want {
			t.Errorf("handlerShortName(%q) = %q, want %q", got, out, want)
		}
	}
}
