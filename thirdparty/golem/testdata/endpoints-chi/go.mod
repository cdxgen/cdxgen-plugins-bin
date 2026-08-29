module example.com/golem/endpoints-chi

go 1.25

require (
	github.com/go-chi/chi v0.0.0
	github.com/go-chi/render v0.0.0
)

replace github.com/go-chi/chi => ../framework-stubs/chi

replace github.com/go-chi/render => ../framework-stubs/chi-render
