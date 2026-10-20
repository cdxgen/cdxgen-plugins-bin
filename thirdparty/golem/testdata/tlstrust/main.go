package tlstrust

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"

	"example.com/golem/tlstrust/bundle"
)

//go:embed certs.pem
var embeddedPoolBytes []byte

// positive: tls.Config with a custom root pool (GOLEM-CRYPTO-TLS-CUSTOM-ROOTS).
func customRoots() {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(embeddedPoolBytes)
	_ = &tls.Config{RootCAs: pool}
}

// positive: x509.VerifyOptions with custom roots (GOLEM-CRYPTO-TLS-CUSTOM-ROOTS).
func verifyOptionsCustomRoots() {
	opts := x509.VerifyOptions{Roots: x509.NewCertPool()}
	_ = opts
}

// positive: custom verification callback (GOLEM-CRYPTO-TLS-CUSTOM-VERIFY).
func customVerify() {
	_ = &tls.Config{VerifyPeerCertificate: verifyCallback}
}

func verifyCallback(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return nil
}

// positive: callback plus InsecureSkipVerify (GOLEM-CRYPTO-TLS-VERIFY-REPLACED
// on top of GOLEM-CRYPTO-TLS-CUSTOM-VERIFY).
func verifyReplaced() {
	_ = &tls.Config{VerifyPeerCertificate: verifyCallback, InsecureSkipVerify: true}
}

// positive: an embedded pool fed to AppendCertsFromPEM
// (GOLEM-CRYPTO-X509-EMBEDDED-POOL).
func embeddedPool() {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(embeddedPoolBytes)
	_ = pool
}

type configAlias = tls.Config

// positive: an alias of tls.Config (GOLEM-CRYPTO-TLS-CUSTOM-ROOTS).
func aliasRoots(pool *x509.CertPool) {
	_ = &configAlias{RootCAs: pool}
}

const skip = true

func verifyConnection(tls.ConnectionState) error { return nil }

// positive: a constant InsecureSkipVerify with VerifyConnection
// (CUSTOM-VERIFY, VERIFY-REPLACED and INSECURE-SKIP-VERIFY).
func constSkip() {
	_ = &tls.Config{InsecureSkipVerify: (skip), VerifyConnection: verifyConnection}
}

// positive: fields set after construction (CUSTOM-ROOTS, CUSTOM-VERIFY,
// INSECURE-SKIP-VERIFY, and VERIFY-REPLACED across the statements).
func assignedAfter(pool *x509.CertPool) {
	cfg := &tls.Config{}
	cfg.RootCAs = pool
	cfg.InsecureSkipVerify = true
	cfg.VerifyPeerCertificate = verifyCallback
	_ = cfg
}

//go:embed certs.pem
var embeddedPoolString string

var (
	unrelated int

	//go:embed certs.pem

	groupedPoolBytes []byte
)

// positive: a string embed converted to []byte, a grouped var with a blank
// line after its directive, and another package's embed
// (GOLEM-CRYPTO-X509-EMBEDDED-POOL, three times).
func embeddedVariants(pool *x509.CertPool) {
	pool.AppendCertsFromPEM([]byte(embeddedPoolString))
	pool.AppendCertsFromPEM(groupedPoolBytes[:])
	pool.AppendCertsFromPEM([]byte(bundle.PEM))
	_ = unrelated
}
