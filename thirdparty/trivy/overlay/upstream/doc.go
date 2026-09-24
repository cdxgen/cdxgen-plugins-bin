// Package upstream holds tests that check the values overlay/patches inlines
// against the upstream Trivy packages they were copied from. It builds only
// against unpatched Trivy, so `make test` runs it in the plain `go test ./...`
// pass and leaves it out of the patched one.
package upstream
