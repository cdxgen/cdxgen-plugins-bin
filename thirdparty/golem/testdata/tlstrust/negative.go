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

// negative: a look-alike struct with the same field names is not tls.Config.
type lookalikeConfig struct {
	RootCAs               *x509.CertPool
	VerifyPeerCertificate func([][]byte, [][]*x509.Certificate) error
}

func lookalike(pool *x509.CertPool) {
	_ = &lookalikeConfig{RootCAs: pool, VerifyPeerCertificate: verifyCallback}
}

// negative: a shadowed true is false, and fields copied from another
// configuration were reported where that one was customised.
func shadowedAndCopied(base *tls.Config) {
	true := false
	_ = &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: base.VerifyPeerCertificate, RootCAs: base.RootCAs}
}

// negative: resetting fields to nil, and verify options with intermediates
// only.
func resets(cfg *tls.Config, pool *x509.CertPool) {
	cfg.RootCAs = nil
	cfg.VerifyPeerCertificate = nil
	_ = x509.VerifyOptions{Intermediates: pool}
}
