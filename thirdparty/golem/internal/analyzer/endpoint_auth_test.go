package analyzer

import (
	"strings"
	"testing"
)

// The three states the exposure contract distinguishes, per framework:
// a declared requirement, a route with none, and an explicit anonymity
// marker that must not read as a requirement.
//
// The negative halves are the point. "No authentication field" and
// "authentication: []" both mean UNKNOWN, never anonymous — a route may sit
// behind a filter golem does not model — so a test that only checked the
// positives would pass with a detector that marked everything authenticated.
func TestEndpointAuthentication(t *testing.T) {
	byKey := analyzeEndpointFixture(t, "../../testdata/endpoints-auth")

	declared := map[string]string{
		// gin: the GROUP carries it, and both of its routes inherit.
		"GET /api/users":  "middleware(requireAuth)",
		"POST /api/users": "middleware(requireAuth)",
		// gin: declared on the route itself, handler last.
		"GET /admin/users": "middleware(requireAuth)",
		// echo: the group.
		"GET /api/items": "middleware(echoAuth)",
		// echo: on the route, AFTER the handler — the opposite position
		// from gin, which is why the shape is read per framework.
		"GET /secure/items": "middleware(echoAuth)",
	}
	for key, want := range declared {
		ep := requireEndpoint(t, byKey, key)
		if len(ep.Authentication) == 0 {
			t.Errorf("%s: expected a declared requirement, got none", key)
			continue
		}
		found := false
		for _, a := range ep.Authentication {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected %q, got %v", key, want, ep.Authentication)
		}
		if ep.AuthenticationSource == "" {
			t.Errorf("%s: a declared requirement must name its source", key)
		}
	}

	// Nothing declared. A logging middleware is not authentication, and an
	// explicit anonymity marker is not a requirement either.
	silent := []string{
		"GET /open/health",   // gin, request logger only
		"GET /public/status", // gin, noAuth — the inverse marker
		"GET /health",        // echo, logging middleware after the handler
		" /metrics",          // net/http: no middleware vocabulary at all
	}
	for _, key := range silent {
		ep := requireEndpoint(t, byKey, key)
		if len(ep.Authentication) != 0 {
			t.Errorf("%s: expected no declaration, got %v", key, ep.Authentication)
		}
		if ep.AuthenticationSource != "" {
			t.Errorf("%s: expected no source, got %q", key, ep.AuthenticationSource)
		}
	}
}

// gin and fiber declare `GET(path, handlers ...HandlerFunc)` and run them in
// order, so the ENDPOINT is the LAST argument. Before the per-framework
// shape, a fixed handler index named the first middleware as the handler on
// every guarded route.
func TestGuardedRouteHandlerIsNotTheMiddleware(t *testing.T) {
	byKey := analyzeEndpointFixture(t, "../../testdata/endpoints-auth")

	ep := requireEndpoint(t, byKey, "GET /admin/users")
	if strings.Contains(ep.Handler, "requireAuth") {
		t.Fatalf("gin route handler must be the LAST argument, not the middleware; got %q", ep.Handler)
	}
	if !strings.Contains(ep.Handler, "listUsers") {
		t.Fatalf("expected the gin handler listUsers, got %q", ep.Handler)
	}

	// echo puts the handler at argument 1 with middleware after it, so the
	// same reasoning must NOT be applied there.
	echoEp := requireEndpoint(t, byKey, "GET /secure/items")
	if !strings.Contains(echoEp.Handler, "echoList") {
		t.Fatalf("expected the echo handler echoList, got %q", echoEp.Handler)
	}
}
