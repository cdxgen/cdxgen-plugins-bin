package tlstrust

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
)

// negative: explicitly nil RootCAs keeps the system roots.
func nilRoots() {
	_ = &tls.Config{RootCAs: nil}
}

// negative: a plain TLS config customises nothing trust-related.
func plainConfig() {
	_ = &tls.Config{MinVersion: tls.VersionTLS13}
}

// negative: explicitly nil verification callback.
func nilVerify() {
	_ = &tls.Config{VerifyPeerCertificate: nil}
}

// negative: InsecureSkipVerify without a callback is reported by the existing
// INSECURE-SKIP-VERIFY rule, not by VERIFY-REPLACED.
func insecureOnly() {
	_ = &tls.Config{InsecureSkipVerify: true}
}

// negative: AppendCertsFromPEM from a non-embedded, non-package-level source.
func runtimePool(data []byte) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(data)
	_ = pool
}

// negative: a method call with one argument that is not AppendCertsFromPEM on
// a cert pool.
func notAPool(builder *strings.Builder) {
	builder.WriteString("x")
	_ = builder
}
