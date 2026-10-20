// Package bundle exports an embedded CA bundle, the layout the
// cross-package GOLEM-CRYPTO-X509-EMBEDDED-POOL case covers.
package bundle

import _ "embed"

//go:embed bundle.pem
var PEM string
