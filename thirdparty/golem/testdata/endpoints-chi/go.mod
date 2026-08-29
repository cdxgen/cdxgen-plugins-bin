module example.com/golem/endpoints-chi

go 1.25

require (
	github.com/go-chi/chi/v5 v5.0.0
	github.com/go-chi/render v0.0.0
)

replace github.com/go-chi/chi/v5 => ../framework-stubs/chi

replace github.com/go-chi/render => ../framework-stubs/chi-render
