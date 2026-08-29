// Sample net/http service used to verify golem's enriched endpoint
// discovery without any third-party framework. Handlers use the idiomatic
// (w http.ResponseWriter, r *http.Request) signature and intentionally
// exercise:
//   - r.PathValue for Go 1.22+ wildcard path parameters,
//   - r.URL.Query().Get for query parameters,
//   - json.NewDecoder(r.Body).Decode for the request body,
//   - json.NewEncoder(w).Encode for the response type.
package main

import (
	"encoding/json"
	"net/http"
)

type Ticket struct {
	ID      int    `json:"id"`
	Subject string `json:"subject"`
}

type CreateTicketRequest struct {
	Subject string `json:"subject"`
}

type Report struct {
	Format string `json:"format"`
}

func listTickets(w http.ResponseWriter, r *http.Request) {
	limit := r.URL.Query().Get("limit")
	_ = limit
	_ = json.NewEncoder(w).Encode([]Ticket{})
}

func getTicket(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = id
	_ = json.NewEncoder(w).Encode(Ticket{ID: 1})
}

func createTicket(w http.ResponseWriter, r *http.Request) {
	var req CreateTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(Ticket{ID: 1, Subject: req.Subject})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/tickets", listTickets)
	mux.HandleFunc("/tickets/{id}", getTicket)
	mux.HandleFunc("/tickets/new", createTicket)
	mux.HandleFunc("/reports", func(w http.ResponseWriter, r *http.Request) {
		format := r.URL.Query().Get("format")
		_ = format
		_ = json.NewEncoder(w).Encode(Report{Format: format})
	})
	_ = http.ListenAndServe(":8080", mux)
}
