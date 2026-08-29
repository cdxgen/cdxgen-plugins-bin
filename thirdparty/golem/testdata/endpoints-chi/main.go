// Sample chi service used to verify golem's enriched endpoint discovery.
// Handlers use the idiomatic (w http.ResponseWriter, r *http.Request)
// signature and intentionally exercise:
//   - chi.URLParam for path parameters,
//   - r.URL.Query().Get for query parameters,
//   - render.DecodeJSON and render.JSON/Respond for request/response types,
//   - the stdlib json.NewDecoder(...).Decode / json.NewEncoder(...).Encode
//     pair on the same handler parameters.
package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

type Product struct {
	ID    int     `json:"id"`
	Name  string  `json:"name"`
	Price float64 `json:"price"`
}

type CreateProductRequest struct {
	Name  string  `json:"name"`
	Price float64 `json:"price"`
}

type Widget struct {
	SKU string `json:"sku"`
}

func listProducts(w http.ResponseWriter, r *http.Request) {
	limit := r.URL.Query().Get("limit")
	_ = limit
	_ = json.NewEncoder(w).Encode([]Product{{ID: 1, Name: "anvil", Price: 9.99}})
}

func getProduct(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_ = id
	render.JSON(w, r, Product{ID: 1})
}

func createProduct(w http.ResponseWriter, r *http.Request) {
	var req CreateProductRequest
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	render.Respond(w, r, Product{ID: 1, Name: req.Name})
}

func createWidget(w http.ResponseWriter, r *http.Request) {
	var widget Widget
	if err := json.NewDecoder(r.Body).Decode(&widget); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(widget)
}

func main() {
	r := chi.NewRouter()
	r.Get("/products", listProducts)
	r.Post("/products", createProduct)
	r.Get("/products/{id}", getProduct)
	r.Post("/widgets", createWidget)
	_ = http.ListenAndServe(":8080", r)
}
