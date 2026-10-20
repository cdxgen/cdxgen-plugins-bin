package tlstrust

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
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
