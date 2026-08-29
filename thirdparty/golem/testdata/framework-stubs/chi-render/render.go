// A hermetic stub of github.com/go-chi/render — the request/response
// decoding helpers golem's handler-signature extractor recognizes.
package render

import (
	"io"
	"net/http"
)

// JSON writes the encoded value; the extractor reads the third argument to
// recover the response type.
func JSON(w http.ResponseWriter, r *http.Request, v any) {}

// Respond picks an encoder from the Accept header; same shape as JSON.
func Respond(w http.ResponseWriter, r *http.Request, v any) {}

// DecodeJSON reads the request body into v; the extractor reads v to
// recover the request body type.
func DecodeJSON(r io.ReadCloser, v any) error { return nil }

// Bind decodes based on the Content-Type header.
func Bind(r *http.Request, v any) error { return nil }
