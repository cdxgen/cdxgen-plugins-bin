package analyzer

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

type cryptoClassification struct {
	assetType       string
	name            string
	primitive       string
	strength        string
	standard        string
	oid             string
	operationType   string
	materialType    string
	protocolType    string
	protocolName    string
	protocolVersion string
	ruleID          string
	severity        string
	summary         string
	recommendation  string
}

var cryptoImportFamilies = map[string]string{
	"crypto/aes":                     "symmetric",
	"crypto/cipher":                  "cipher-mode",
	"crypto/des":                     "symmetric-legacy",
	"crypto/dsa":                     "signature-legacy",
	"crypto/ecdh":                    "key-agreement",
	"crypto/ecdsa":                   "signature",
	"crypto/ed25519":                 "signature",
	"crypto/elliptic":                "curve",
	"crypto/hkdf":                    "kdf",
	"crypto/hmac":                    "mac",
	"crypto/md5":                     "hash-legacy",
	"crypto/mldsa":                   "signature-post-quantum",
	"crypto/mlkem":                   "key-encapsulation-post-quantum",
	"crypto/pbkdf2":                  "kdf",
	"crypto/rand":                    "random",
	"crypto/rc4":                     "stream-cipher-legacy",
	"crypto/rsa":                     "public-key",
	"crypto/sha1":                    "hash-legacy",
	"crypto/sha256":                  "hash",
	"crypto/sha3":                    "hash",
	"crypto/sha512":                  "hash",
	"crypto/subtle":                  "constant-time",
	"crypto/tls":                     "protocol",
	"crypto/x509":                    "certificate",
	"encoding/pem":                   "crypto-material",
	"golang.org/x/crypto/pbkdf2":     "kdf",
	"golang.org/x/crypto/curve25519": "key-agreement",
}
var cryptoSymbolCatalog = map[string]cryptoClassification{
	"crypto/md5.New":                   {assetType: "algorithm", name: "md5", primitive: "hash", strength: "weak", oid: "1.2.840.113549.2.5", operationType: "hash", ruleID: "GOLEM-CRYPTO-WEAK-MD5", severity: "high", summary: "MD5 cryptographic primitive detected.", recommendation: "Use SHA-256 or stronger unless this is explicitly non-security checksum logic."},
	"crypto/md5.Sum":                   {assetType: "algorithm", name: "md5", primitive: "hash", strength: "weak", oid: "1.2.840.113549.2.5", operationType: "hash", ruleID: "GOLEM-CRYPTO-WEAK-MD5", severity: "high", summary: "MD5 cryptographic primitive detected.", recommendation: "Use SHA-256 or stronger unless this is explicitly non-security checksum logic."},
	"crypto/sha1.New":                  {assetType: "algorithm", name: "sha-1", primitive: "hash", strength: "weak", oid: "2.16.840.1.113719.1.2.8.82", operationType: "hash", ruleID: "GOLEM-CRYPTO-WEAK-SHA1", severity: "high", summary: "SHA-1 cryptographic primitive detected.", recommendation: "Use SHA-256 or stronger unless compatibility requires SHA-1."},
	"crypto/sha1.Sum":                  {assetType: "algorithm", name: "sha-1", primitive: "hash", strength: "weak", oid: "2.16.840.1.113719.1.2.8.82", operationType: "hash", ruleID: "GOLEM-CRYPTO-WEAK-SHA1", severity: "high", summary: "SHA-1 cryptographic primitive detected.", recommendation: "Use SHA-256 or stronger unless compatibility requires SHA-1."},
	"crypto/sha256.New":                {assetType: "algorithm", name: "sha-256", primitive: "hash", strength: "strong", oid: "2.16.840.1.101.3.4.2.1", operationType: "hash"},
	"crypto/sha256.Sum256":             {assetType: "algorithm", name: "sha-256", primitive: "hash", strength: "strong", oid: "2.16.840.1.101.3.4.2.1", operationType: "hash"},
	"crypto/sha512.Sum512":             {assetType: "algorithm", name: "sha-512", primitive: "hash", strength: "strong", oid: "2.16.840.1.101.3.4.2.3", operationType: "hash"},
	"crypto/aes.NewCipher":             {assetType: "algorithm", name: "aes", primitive: "block-cipher", strength: "strong", standard: "FIPS 197", oid: "2.16.840.1.101.3.4.1", operationType: "encrypt/decrypt"},
	"crypto/des.NewCipher":             {assetType: "algorithm", name: "des", primitive: "block-cipher", strength: "weak", oid: "1.3.36.3.1.1", operationType: "encrypt/decrypt", ruleID: "GOLEM-CRYPTO-WEAK-DES", severity: "high", summary: "DES cryptographic primitive detected.", recommendation: "Use AES-GCM or another modern authenticated encryption mode."},
	"crypto/rsa.GenerateKey":           {assetType: "algorithm", name: "rsa", primitive: "pke", strength: "acceptable", oid: "2.5.8.1.1", operationType: "key-generation", materialType: "private-key"},
	"crypto/ed25519.Sign":              {assetType: "algorithm", name: "Ed25519", primitive: "signature", strength: "strong", oid: "1.3.101.112", operationType: "sign", materialType: "private-key"},
	"crypto/hmac.New":                  {assetType: "algorithm", name: "hmacSHA", primitive: "mac", strength: "strong", oid: "1.3.6.1.5.5.8.1.2", operationType: "mac"},
	"crypto/rand.Read":                 {assetType: "algorithm", name: "CSPRNG", primitive: "drbg", strength: "strong", operationType: "random"},
	"crypto/x509.ParseCertificate":     {assetType: "certificate", name: "X.509 certificate", operationType: "parse", materialType: "public-key"},
	"crypto/x509.ParsePKCS1PrivateKey": {assetType: "related-crypto-material", name: "PKCS#1 private key", operationType: "parse", materialType: "private-key"},
	"crypto/tls.LoadX509KeyPair":       {assetType: "protocol", name: "TLS", protocolName: "TLS", protocolType: "tls", operationType: "load-certificate-key-pair", materialType: "private-key"},
	"crypto/sha3.New256":               {assetType: "algorithm", name: "sha3-256", primitive: "hash", strength: "strong", oid: "2.16.840.1.101.3.4.2.8", operationType: "hash"},
	"crypto/sha3.Sum256":               {assetType: "algorithm", name: "sha3-256", primitive: "hash", strength: "strong", oid: "2.16.840.1.101.3.4.2.8", operationType: "hash"},
	"crypto/ecdsa.SignASN1":            {assetType: "algorithm", name: "ecdsa", primitive: "signature", strength: "strong", oid: "1.2.840.10045.4.3.2", operationType: "sign", materialType: "private-key"},
	"crypto/ecdsa.GenerateKey":         {assetType: "algorithm", name: "ecdsa", primitive: "signature", strength: "strong", oid: "1.2.840.10045.2.1", operationType: "key-generation", materialType: "private-key"},
	"crypto/ecdh.X25519":               {assetType: "algorithm", name: "curveX25519", primitive: "key-agree", strength: "strong", oid: "1.3.101.110", operationType: "key-agreement", materialType: "shared-secret"},
	"crypto/hkdf.Key":                  {assetType: "algorithm", name: "HKDF", primitive: "kdf", strength: "strong", standard: "RFC 5869", operationType: "key-derivation", materialType: "key"},
	"crypto/pbkdf2.Key":                {assetType: "algorithm", name: "PBKDF2", primitive: "kdf", strength: "acceptable", oid: "1.2.840.113549.1.5.12", operationType: "key-derivation", materialType: "key"},
	// Post-quantum: crypto/mlkem shipped in Go 1.24, crypto/mldsa in Go 1.27.
	// A CBOM consumer needs these to tell a quantum-ready build from a
	// classical one, so they are catalogued per parameter set.
	"crypto/mlkem.GenerateKey768":           {assetType: "algorithm", name: "ML-KEM-768", primitive: "kem", strength: "strong", standard: "FIPS 203", oid: "2.16.840.1.101.3.4.4.2", operationType: "key-generation", materialType: "private-key"},
	"crypto/mlkem.GenerateKey1024":          {assetType: "algorithm", name: "ML-KEM-1024", primitive: "kem", strength: "strong", standard: "FIPS 203", oid: "2.16.840.1.101.3.4.4.3", operationType: "key-generation", materialType: "private-key"},
	"crypto/mlkem.NewEncapsulationKey768":   {assetType: "algorithm", name: "ML-KEM-768", primitive: "kem", strength: "strong", standard: "FIPS 203", oid: "2.16.840.1.101.3.4.4.2", operationType: "encapsulate", materialType: "public-key"},
	"crypto/mlkem.NewEncapsulationKey1024":  {assetType: "algorithm", name: "ML-KEM-1024", primitive: "kem", strength: "strong", standard: "FIPS 203", oid: "2.16.840.1.101.3.4.4.3", operationType: "encapsulate", materialType: "public-key"},
	"crypto/mldsa.GenerateKey":              {assetType: "algorithm", name: "ML-DSA", primitive: "signature", strength: "strong", standard: "FIPS 204", oid: "2.16.840.1.101.3.4.3.18", operationType: "key-generation", materialType: "private-key"},
	"crypto/mldsa.NewPrivateKey":            {assetType: "related-crypto-material", name: "ML-DSA private key", standard: "FIPS 204", operationType: "parse", materialType: "private-key"},
	"crypto/mldsa.NewPublicKey":             {assetType: "related-crypto-material", name: "ML-DSA public key", standard: "FIPS 204", operationType: "parse", materialType: "public-key"},
	"crypto/mldsa.Verify":                   {assetType: "algorithm", name: "ML-DSA", primitive: "signature", strength: "strong", standard: "FIPS 204", oid: "2.16.840.1.101.3.4.3.18", operationType: "verify", materialType: "public-key"},
	"crypto/mldsa.MLDSA44":                  {assetType: "algorithm", name: "ML-DSA-44", primitive: "signature", strength: "strong", standard: "FIPS 204", oid: "2.16.840.1.101.3.4.3.17", operationType: "parameter-set"},
	"crypto/mldsa.MLDSA65":                  {assetType: "algorithm", name: "ML-DSA-65", primitive: "signature", strength: "strong", standard: "FIPS 204", oid: "2.16.840.1.101.3.4.3.18", operationType: "parameter-set"},
	"crypto/mldsa.MLDSA87":                  {assetType: "algorithm", name: "ML-DSA-87", primitive: "signature", strength: "strong", standard: "FIPS 204", oid: "2.16.840.1.101.3.4.3.19", operationType: "parameter-set"},
	"crypto/rc4.NewCipher":                  {assetType: "algorithm", name: "rc4", primitive: "stream-cipher", strength: "weak", oid: "1.2.840.113549.3.4", operationType: "encrypt/decrypt", ruleID: "GOLEM-CRYPTO-WEAK-RC4", severity: "high", summary: "RC4 cryptographic primitive detected.", recommendation: "Use AES-GCM or ChaCha20-Poly1305 instead."},
	"golang.org/x/crypto/pbkdf2.Key":        {assetType: "algorithm", name: "PBKDF2", primitive: "kdf", strength: "acceptable", oid: "1.2.840.113549.1.5.12", operationType: "key-derivation", materialType: "key"},
	"golang.org/x/crypto/curve25519.X25519": {assetType: "algorithm", name: "curveX25519", primitive: "key-agree", strength: "strong", oid: "1.3.101.110", operationType: "key-agreement", materialType: "shared-secret"},
}

func (a *Analyzer) cryptoEvidenceForFile(pkg *packages.Package, file *ast.File) *model.CryptoEvidence {
	crypto := &model.CryptoEvidence{}
	seenLibraries := map[string]bool{}
	seenAssets := map[string]bool{}
	seenOperations := map[string]bool{}
	seenMaterials := map[string]bool{}
	seenProtocols := map[string]bool{}
	seenFindings := map[string]bool{}
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, "\"")
		if family, ok := cryptoImportFamily(path); ok {
			r := a.nodeRange(spec)
			lib := model.CryptoLibrary{ID: stableID(pkg.ID, "crypto-library", path, r.Start.Filename, fmt.Sprint(r.Start.Line)), Path: path, Family: family, Standard: strings.HasPrefix(path, "crypto/"), UsageScope: fileRole(r.Start.Filename), PackagePath: pkg.PkgPath, Range: r}
			appendCryptoLibrary(crypto, seenLibraries, lib)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if class, ok := a.cryptoClassificationForSelector(pkg, x); ok {
				a.addCryptoClassification(crypto, pkg, x, class, seenAssets, seenOperations, seenMaterials, seenProtocols, seenFindings)
			}
		case *ast.KeyValueExpr:
			if ident, ok := x.Key.(*ast.Ident); ok && ident.Name == "InsecureSkipVerify" && insecureValue(pkg, x.Value) {
				a.addCryptoClassification(crypto, pkg, x, insecureSkipVerifyClass, seenAssets, seenOperations, seenMaterials, seenProtocols, seenFindings)
			}
		case *ast.CompositeLit:
			a.addTrustCustomisationFindings(crypto, pkg, x, seenFindings)
		case *ast.CallExpr:
			a.addEmbeddedPoolFinding(crypto, pkg, x, seenFindings)
		case *ast.FuncDecl:
			if x.Body != nil {
				a.addTrustAssignmentFindings(crypto, pkg, x.Body, seenFindings)
			}
		case *ast.ValueSpec:
			a.addLiteralCryptoMaterials(crypto, pkg, x.Names, x.Values, seenMaterials, seenFindings)
		case *ast.AssignStmt:
			// cfg.InsecureSkipVerify = true, set after construction.
			if len(x.Lhs) == len(x.Rhs) {
				for i, lhs := range x.Lhs {
					if selector, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok && selector.Sel.Name == "InsecureSkipVerify" && insecureValue(pkg, x.Rhs[i]) {
						if typePath, ok := fieldOwnerTypePath(pkg, selector); ok && typePath == "crypto/tls.Config" {
							a.addCryptoClassification(crypto, pkg, x, insecureSkipVerifyClass, seenAssets, seenOperations, seenMaterials, seenProtocols, seenFindings)
						}
					}
				}
			}
			names := []*ast.Ident{}
			for _, lhs := range x.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					names = append(names, ident)
				}
			}
			a.addLiteralCryptoMaterials(crypto, pkg, names, x.Rhs, seenMaterials, seenFindings)
		}
		return true
	})
	if len(crypto.Libraries) == 0 && len(crypto.Assets) == 0 && len(crypto.Operations) == 0 && len(crypto.Materials) == 0 && len(crypto.Protocols) == 0 && len(crypto.Findings) == 0 {
		return nil
	}
	return crypto
}

var insecureSkipVerifyClass = cryptoClassification{assetType: "protocol", name: "TLS", protocolName: "TLS", protocolType: "tls", operationType: "configure", ruleID: "GOLEM-CRYPTO-TLS-INSECURE-SKIP-VERIFY", severity: "critical", summary: "TLS certificate verification is disabled.", recommendation: "Do not set InsecureSkipVerify except in tightly controlled test code."}

// insecureValue reports whether an InsecureSkipVerify value is true: by its
// constant value when the package type-checked (so a const, or (true),
// counts and a shadowed true does not), else by the literal true.
func insecureValue(pkg *packages.Package, expr ast.Expr) bool {
	if pkg.TypesInfo != nil {
		if _, ok := pkg.TypesInfo.Types[expr]; ok {
			return isConstantTrue(pkg, expr)
		}
	}
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && ident.Name == "true"
}

func cryptoImportFamily(path string) (string, bool) {
	if family, ok := cryptoImportFamilies[path]; ok {
		return family, true
	}
	if strings.HasPrefix(path, "golang.org/x/crypto/") {
		return "x-crypto", true
	}
	return "", false
}

// Trust-customisation findings (PLAN section 4.6): code that replaces Go's
// default trust decisions. Types are resolved through TypesInfo, never by
// name, so aliases match and other packages' structs with the same field
// names do not; field values are judged by their constant value or nil-ness,
// not their spelling.

// trustSettings is what one crypto/tls.Config or crypto/x509.VerifyOptions
// literal, or one field assignment, does to trust.
type trustSettings struct {
	typePath                                string
	rootField                               string
	customRoots, customVerify, skipVerifies bool
}

// trustFields returns the trust fields of a crypto/tls.Config or
// crypto/x509.VerifyOptions type.
func trustFields(typePath string) (rootField string, verifyFields map[string]bool, ok bool) {
	switch typePath {
	case "crypto/tls.Config":
		return "RootCAs", map[string]bool{"VerifyPeerCertificate": true, "VerifyConnection": true}, true
	case "crypto/x509.VerifyOptions":
		return "Roots", nil, true
	}
	return "", nil, false
}

// literalTrustSettings reads the trust fields set in a composite literal.
func literalTrustSettings(pkg *packages.Package, lit *ast.CompositeLit) (trustSettings, bool) {
	typePath, ok := compositeLiteralTypePath(pkg, lit)
	if !ok {
		return trustSettings{}, false
	}
	rootField, verifyFields, ok := trustFields(typePath)
	if !ok {
		return trustSettings{}, false
	}
	settings := trustSettings{typePath: typePath, rootField: rootField}
	for _, elt := range lit.Elts {
		keyValue, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			// Unkeyed composite literals cannot be attributed to a field.
			return trustSettings{}, false
		}
		ident, ok := keyValue.Key.(*ast.Ident)
		if !ok {
			return trustSettings{}, false
		}
		settings.apply(pkg, ident.Name, keyValue.Value, verifyFields)
	}
	return settings, true
}

// apply records the effect of setting field to value.
func (s *trustSettings) apply(pkg *packages.Package, field string, value ast.Expr, verifyFields map[string]bool) {
	switch {
	case field == s.rootField:
		s.customRoots = s.customRoots || !isTrustNeutral(pkg, value, field)
	case verifyFields[field]:
		s.customVerify = s.customVerify || !isTrustNeutral(pkg, value, field)
	case field == "InsecureSkipVerify":
		s.skipVerifies = s.skipVerifies || isConstantTrue(pkg, value)
	}
}

func (a *Analyzer) addTrustCustomisationFindings(crypto *model.CryptoEvidence, pkg *packages.Package, lit *ast.CompositeLit, seenFindings map[string]bool) {
	if settings, ok := literalTrustSettings(pkg, lit); ok {
		a.addTrustFindings(crypto, pkg, lit, settings, seenFindings)
		if settings.customVerify && settings.skipVerifies {
			a.addVerifyReplacedFinding(crypto, pkg, lit, settings.typePath, seenFindings)
		}
	}
}

func (a *Analyzer) addTrustFindings(crypto *model.CryptoEvidence, pkg *packages.Package, node ast.Node, settings trustSettings, seenFindings map[string]bool) {
	if settings.customRoots {
		a.addCryptoFinding(crypto, pkg, node, seenFindings, model.CryptoFinding{
			RuleID:         "GOLEM-CRYPTO-TLS-CUSTOM-ROOTS",
			Severity:       "low",
			Confidence:     "type-resolved",
			Summary:        "TLS verification uses a custom trust root pool instead of the system roots.",
			Recommendation: "Review the custom root set: certificates distrusted by the platform or the Go toolchain can still be trusted here, and platform updates no longer apply.",
			Properties:     map[string]string{"field": settings.rootField, "type": settings.typePath},
		})
	}
	if settings.customVerify {
		a.addCryptoFinding(crypto, pkg, node, seenFindings, model.CryptoFinding{
			RuleID:         "GOLEM-CRYPTO-TLS-CUSTOM-VERIFY",
			Severity:       "medium",
			Confidence:     "type-resolved",
			Summary:        "TLS verification runs a custom callback.",
			Recommendation: "Review the callback: it runs after Go's standard verification, unless InsecureSkipVerify is also set, in which case it is the only verification left.",
			Properties:     map[string]string{"type": settings.typePath},
		})
	}
}

func (a *Analyzer) addVerifyReplacedFinding(crypto *model.CryptoEvidence, pkg *packages.Package, node ast.Node, typePath string, seenFindings map[string]bool) {
	a.addCryptoFinding(crypto, pkg, node, seenFindings, model.CryptoFinding{
		RuleID:         "GOLEM-CRYPTO-TLS-VERIFY-REPLACED",
		Severity:       "high",
		Confidence:     "type-resolved",
		Summary:        "InsecureSkipVerify is combined with a custom verify callback, fully replacing Go's certificate verification.",
		Recommendation: "The custom callback is the only verification left, and Go's distrust decisions no longer apply; make sure it validates chains itself, including any intermediates the server presents.",
		Properties:     map[string]string{"type": typePath},
	})
}

// trustTarget identifies the configuration a statement changes: the
// variable it is held in, or the expression for anything else (s.cfg).
type trustTarget struct {
	object types.Object
	expr   string
}

// trustState tracks one configuration through a function body: where it was
// made to skip verification and where it got a custom callback, and whether
// both came from a single literal (already reported).
type trustState struct {
	skipNode, verifyNode ast.Node
	sameLiteral          bool
}

// addTrustAssignmentFindings covers configurations changed after
// construction: cfg.RootCAs = pool, cfg.VerifyPeerCertificate = f,
// cfg.InsecureSkipVerify = true. Each such assignment is reported like the
// literal field it sets, and a configuration that, within one function body,
// both skips verification and gets a callback (in any mix of literals and
// assignments) is reported as GOLEM-CRYPTO-TLS-VERIFY-REPLACED.
func (a *Analyzer) addTrustAssignmentFindings(crypto *model.CryptoEvidence, pkg *packages.Package, body *ast.BlockStmt, seenFindings map[string]bool) {
	if pkg.TypesInfo == nil {
		return
	}
	states := map[trustTarget]*trustState{}
	var order []trustTarget
	state := func(target trustTarget) *trustState {
		if states[target] == nil {
			states[target] = &trustState{}
			order = append(order, target)
		}
		return states[target]
	}
	record := func(lhs, rhs ast.Expr, stmt ast.Node) {
		if lit := compositeLiteralOf(rhs); lit != nil {
			if settings, ok := literalTrustSettings(pkg, lit); ok && (settings.skipVerifies || settings.customVerify) {
				st := state(trustTargetOf(pkg, lhs))
				st.sameLiteral = settings.skipVerifies && settings.customVerify
				if settings.skipVerifies {
					st.skipNode = lit
				}
				if settings.customVerify {
					st.verifyNode = lit
				}
			}
			return
		}
		selector, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
		if !ok {
			return
		}
		typePath, ok := fieldOwnerTypePath(pkg, selector)
		if !ok {
			return
		}
		rootField, verifyFields, ok := trustFields(typePath)
		if !ok {
			return
		}
		settings := trustSettings{typePath: typePath, rootField: rootField}
		settings.apply(pkg, selector.Sel.Name, rhs, verifyFields)
		a.addTrustFindings(crypto, pkg, stmt, settings, seenFindings)
		if settings.skipVerifies || settings.customVerify {
			st := state(trustTargetOf(pkg, selector.X))
			st.sameLiteral = false
			if settings.skipVerifies {
				st.skipNode = stmt
			}
			if settings.customVerify {
				st.verifyNode = stmt
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i := range x.Lhs {
					record(x.Lhs[i], x.Rhs[i], x)
				}
			}
		case *ast.ValueSpec:
			if len(x.Names) == len(x.Values) {
				for i := range x.Names {
					record(x.Names[i], x.Values[i], x)
				}
			}
		}
		return true
	})
	for _, target := range order {
		st := states[target]
		if st.skipNode == nil || st.verifyNode == nil || st.sameLiteral {
			continue
		}
		node := st.verifyNode
		if st.skipNode.Pos() > node.Pos() {
			node = st.skipNode
		}
		a.addVerifyReplacedFinding(crypto, pkg, node, "crypto/tls.Config", seenFindings)
	}
}

// compositeLiteralOf returns the literal of T{...} or &T{...}.
func compositeLiteralOf(expr ast.Expr) *ast.CompositeLit {
	expr = ast.Unparen(expr)
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = ast.Unparen(unary.X)
	}
	lit, _ := expr.(*ast.CompositeLit)
	return lit
}

func trustTargetOf(pkg *packages.Package, expr ast.Expr) trustTarget {
	expr = ast.Unparen(expr)
	if ident, ok := expr.(*ast.Ident); ok {
		if object := pkg.TypesInfo.ObjectOf(ident); object != nil {
			return trustTarget{object: object}
		}
	}
	return trustTarget{expr: types.ExprString(expr)}
}

// fieldOwnerTypePath returns the "package/path.TypeName" of the struct a
// field selector reads (through pointers and aliases).
func fieldOwnerTypePath(pkg *packages.Package, selector *ast.SelectorExpr) (string, bool) {
	selection, ok := pkg.TypesInfo.Selections[selector]
	if !ok || selection.Kind() != types.FieldVal {
		return "", false
	}
	return namedTypePath(selection.Recv())
}

// isConstantTrue reports whether expr is a boolean constant equal to true
// (true, (true), a true-valued const); a shadowed identifier named true is
// not.
func isConstantTrue(pkg *packages.Package, expr ast.Expr) bool {
	tv, ok := pkg.TypesInfo.Types[expr]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.Bool && constant.BoolVal(tv.Value)
}

// isTrustNeutral reports whether setting field to expr leaves trust as it
// was: nil, or the same field copied from another configuration, which is
// reported where that one was customised.
func isTrustNeutral(pkg *packages.Package, expr ast.Expr, field string) bool {
	expr = ast.Unparen(expr)
	if tv, ok := pkg.TypesInfo.Types[expr]; ok && tv.IsNil() {
		return true
	}
	if selector, ok := expr.(*ast.SelectorExpr); ok && selector.Sel.Name == field {
		if typePath, ok := fieldOwnerTypePath(pkg, selector); ok {
			_, _, isTrustType := trustFields(typePath)
			return isTrustType
		}
	}
	return false
}

// addEmbeddedPoolFinding flags (*crypto/x509.CertPool).AppendCertsFromPEM
// calls whose argument is a package-level variable carrying a //go:embed
// directive (a []byte, or a string converted with []byte(...)), in this
// package or another one: a certificate pool compiled into the binary, which
// no store update can revoke.
func (a *Analyzer) addEmbeddedPoolFinding(crypto *model.CryptoEvidence, pkg *packages.Package, call *ast.CallExpr, seenFindings map[string]bool) {
	if pkg.TypesInfo == nil || len(call.Args) != 1 {
		return
	}
	var method *types.Func
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		method, _ = pkg.TypesInfo.Uses[fun.Sel].(*types.Func)
	case *ast.Ident:
		method, _ = pkg.TypesInfo.Uses[fun].(*types.Func)
	}
	if method == nil || method.Name() != "AppendCertsFromPEM" {
		return
	}
	signature, ok := method.Type().(*types.Signature)
	if !ok || signature.Recv() == nil || !isCertPoolType(signature.Recv().Type()) {
		return
	}
	variable := embeddedArgumentVariable(pkg, call.Args[0])
	if variable == nil || !a.varDeclHasGoEmbed(pkg, variable) {
		return
	}
	properties := map[string]string{"variable": variable.Name()}
	if variable.Pkg() != pkg.Types {
		properties["package"] = variable.Pkg().Path()
	}
	a.addCryptoFinding(crypto, pkg, call, seenFindings, model.CryptoFinding{
		RuleID:         "GOLEM-CRYPTO-X509-EMBEDDED-POOL",
		Severity:       "low",
		Confidence:     "type-resolved",
		Summary:        "A certificate pool is built from a //go:embed package variable compiled into the binary.",
		Recommendation: "Embedded trust pools ignore later CA updates and distrust decisions; load roots from the system store or a refreshable source instead.",
		Properties:     properties,
	})
}

// embeddedArgumentVariable unwraps parentheses, []byte(...) conversions and
// x[:] slices down to a package-level variable, or returns nil.
func embeddedArgumentVariable(pkg *packages.Package, expr ast.Expr) *types.Var {
	for {
		switch x := ast.Unparen(expr).(type) {
		case *ast.CallExpr:
			if tv, ok := pkg.TypesInfo.Types[x.Fun]; !ok || !tv.IsType() || len(x.Args) != 1 {
				return nil
			}
			expr = x.Args[0]
		case *ast.SliceExpr:
			expr = x.X
		case *ast.Ident:
			return packageLevelVar(pkg.TypesInfo.Uses[x])
		case *ast.SelectorExpr:
			return packageLevelVar(pkg.TypesInfo.Uses[x.Sel])
		default:
			return nil
		}
	}
}

func packageLevelVar(object types.Object) *types.Var {
	variable, ok := object.(*types.Var)
	if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
		return nil
	}
	return variable
}

func (a *Analyzer) addCryptoFinding(crypto *model.CryptoEvidence, pkg *packages.Package, node ast.Node, seenFindings map[string]bool, finding model.CryptoFinding) {
	r := a.nodeRange(node)
	finding.ID = stableID(pkg.ID, finding.RuleID, r.Start.Filename, fmt.Sprint(r.Start.Line), fmt.Sprint(r.Start.Column))
	finding.PackagePath = pkg.PkgPath
	finding.UsageScope = fileRole(r.Start.Filename)
	finding.Range = r
	appendCryptoFinding(crypto, seenFindings, finding)
}

// compositeLiteralTypePath resolves the named type of a composite literal and
// returns "package/path.TypeName".
func compositeLiteralTypePath(pkg *packages.Package, lit *ast.CompositeLit) (string, bool) {
	if pkg.TypesInfo == nil {
		return "", false
	}
	typeValue := pkg.TypesInfo.TypeOf(lit)
	if typeValue == nil {
		return "", false
	}
	return namedTypePath(typeValue)
}

// namedTypePath returns "package/path.TypeName" for a named type, a pointer
// to one, or an alias of either.
func namedTypePath(typeValue types.Type) (string, bool) {
	typeValue = types.Unalias(typeValue)
	if pointer, ok := typeValue.(*types.Pointer); ok {
		typeValue = types.Unalias(pointer.Elem())
	}
	named, ok := typeValue.(*types.Named)
	if !ok {
		return "", false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return "", false
	}
	return obj.Pkg().Path() + "." + obj.Name(), true
}

// isCertPoolType reports whether the type is *crypto/x509.CertPool.
func isCertPoolType(typeValue types.Type) bool {
	if _, ok := types.Unalias(typeValue).(*types.Pointer); !ok {
		return false
	}
	path, ok := namedTypePath(typeValue)
	return ok && path == "crypto/x509.CertPool"
}

// varDeclHasGoEmbed reports whether the variable is declared with a
// //go:embed directive. The directive belongs to the variable's own spec:
// in a grouped var ( ... ) block it sits above that spec, and blank lines
// between it and the declaration are allowed, as cmd/go allows them. The
// declaration is looked up in the variable's package, which may be an import
// of pkg.
func (a *Analyzer) varDeclHasGoEmbed(pkg *packages.Package, variable *types.Var) bool {
	declPkg := pkg
	if variable.Pkg() != pkg.Types {
		declPkg = pkg.Imports[variable.Pkg().Path()]
		if declPkg == nil {
			return false
		}
	}
	for _, file := range declPkg.Syntax {
		if file.Pos() > variable.Pos() || variable.Pos() > file.End() {
			continue
		}
		previousEnd := file.Name.End()
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.VAR || genDecl.End() < variable.Pos() {
				previousEnd = decl.End()
				continue
			}
			if genDecl.Pos() > variable.Pos() {
				return false
			}
			specStart := token.Pos(0)
			if genDecl.Lparen.IsValid() {
				previousEnd = genDecl.Lparen
			}
			for _, spec := range genDecl.Specs {
				valueSpec := spec.(*ast.ValueSpec)
				specStart = valueSpec.Pos()
				if !genDecl.Lparen.IsValid() {
					specStart = genDecl.Pos()
				}
				if valueSpec.End() < variable.Pos() {
					previousEnd = valueSpec.End()
					continue
				}
				for _, group := range file.Comments {
					if group.Pos() > previousEnd && group.End() <= specStart && commentGroupHasGoEmbed(group) {
						return true
					}
				}
				return false
			}
			return false
		}
	}
	return false
}

func commentGroupHasGoEmbed(group *ast.CommentGroup) bool {
	if group == nil {
		return false
	}
	for _, comment := range group.List {
		if strings.HasPrefix(strings.TrimSpace(comment.Text), "//go:embed") {
			return true
		}
	}
	return false
}

func (a *Analyzer) cryptoClassificationForSelector(pkg *packages.Package, sel *ast.SelectorExpr) (cryptoClassification, bool) {
	obj := pkg.TypesInfo.Uses[sel.Sel]
	if obj == nil || obj.Pkg() == nil {
		return cryptoClassification{}, false
	}
	symbol := obj.Pkg().Path() + "." + obj.Name()
	if class, ok := cryptoSymbolCatalog[symbol]; ok {
		return class, true
	}
	pkgPath := obj.Pkg().Path()
	if strings.HasPrefix(pkgPath, "crypto/tls") {
		return cryptoClassification{assetType: "protocol", name: "TLS", protocolName: "TLS", protocolType: "tls", operationType: "use"}, true
	}
	if strings.HasPrefix(pkgPath, "crypto/x509") {
		return cryptoClassification{assetType: "certificate", name: "X.509 certificate", operationType: "use", materialType: "public-key"}, true
	}
	return cryptoClassification{}, false
}
func (a *Analyzer) addCryptoClassification(crypto *model.CryptoEvidence, pkg *packages.Package, node ast.Node, class cryptoClassification, seenAssets map[string]bool, seenOperations map[string]bool, seenMaterials map[string]bool, seenProtocols map[string]bool, seenFindings map[string]bool) {
	r := a.nodeRange(node)
	usageScope := fileRole(r.Start.Filename)
	symbol := cryptoNodeSymbol(pkg, node)
	assetID := ""
	operationID := ""
	materialID := ""
	if class.assetType == "algorithm" && class.name != "" {
		asset := model.CryptoAsset{ID: stableID("crypto-asset", class.assetType, class.name, class.primitive, class.oid), Name: class.name, AssetType: class.assetType, Primitive: class.primitive, Strength: class.strength, Standard: class.standard, OID: class.oid, PackagePath: pkg.PkgPath, Symbol: symbol, UsageScope: usageScope, Range: r}
		appendCryptoAsset(crypto, seenAssets, asset)
		assetID = asset.ID
	} else if class.assetType == "certificate" {
		asset := model.CryptoAsset{ID: stableID("crypto-asset", class.assetType, class.name), Name: class.name, AssetType: class.assetType, PackagePath: pkg.PkgPath, Symbol: symbol, UsageScope: usageScope, Range: r}
		appendCryptoAsset(crypto, seenAssets, asset)
		assetID = asset.ID
	} else if class.assetType == "related-crypto-material" && class.materialType != "" {
		materialID = a.addCryptoMaterial(crypto, seenMaterials, pkg, node, class.materialType, firstNonEmptyCrypto(class.name, class.materialType), symbol)
	}
	if class.protocolType != "" {
		protocol := model.CryptoProtocol{ID: stableID("crypto-protocol", class.protocolType, class.protocolVersion), Name: firstNonEmptyCrypto(class.protocolName, class.name, strings.ToUpper(class.protocolType)), Type: class.protocolType, Version: class.protocolVersion, PackagePath: pkg.PkgPath, Symbol: symbol, UsageScope: usageScope, Range: r}
		appendCryptoProtocol(crypto, seenProtocols, protocol)
	}
	if class.operationType != "" {
		op := model.CryptoOperation{ID: stableID(pkg.ID, "crypto-operation", class.operationType, firstNonEmptyCrypto(class.name, class.protocolType), r.Start.Filename, fmt.Sprint(r.Start.Line), fmt.Sprint(r.Start.Column)), OperationType: class.operationType, Algorithm: class.name, AssetID: assetID, PackagePath: pkg.PkgPath, Symbol: symbol, UsageScope: usageScope, Range: r}
		appendCryptoOperation(crypto, seenOperations, op)
		operationID = op.ID
	}
	if class.materialType != "" && materialID == "" {
		materialID = a.addCryptoMaterial(crypto, seenMaterials, pkg, node, class.materialType, class.materialType, symbol)
	}
	if class.ruleID != "" {
		finding := model.CryptoFinding{ID: stableID(pkg.ID, class.ruleID, r.Start.Filename, fmt.Sprint(r.Start.Line), fmt.Sprint(r.Start.Column)), RuleID: class.ruleID, Severity: class.severity, Confidence: "type-resolved", Summary: class.summary, Recommendation: class.recommendation, PackagePath: pkg.PkgPath, UsageScope: usageScope, AssetID: assetID, OperationID: operationID, MaterialID: materialID, Range: r}
		appendCryptoFinding(crypto, seenFindings, finding)
	}
}
func (a *Analyzer) addCryptoMaterial(crypto *model.CryptoEvidence, seen map[string]bool, pkg *packages.Package, node ast.Node, materialType string, name string, symbol string) string {
	r := a.nodeRange(node)
	material := model.CryptoMaterial{ID: stableID(pkg.ID, "crypto-material", materialType, name, r.Start.Filename, fmt.Sprint(r.Start.Line), fmt.Sprint(r.Start.Column)), Type: materialType, Name: name, PackagePath: pkg.PkgPath, Symbol: symbol, UsageScope: fileRole(r.Start.Filename), Range: r}
	appendCryptoMaterial(crypto, seen, material)
	return material.ID
}
func (a *Analyzer) addLiteralCryptoMaterials(crypto *model.CryptoEvidence, pkg *packages.Package, names []*ast.Ident, values []ast.Expr, seenMaterials map[string]bool, seenFindings map[string]bool) {
	for i, name := range names {
		if name == nil || i >= len(values) || !containsStringLiteral(values[i]) {
			continue
		}
		materialType := materialTypeFromName(name.Name)
		if materialType == "" {
			continue
		}
		materialID := a.addCryptoMaterial(crypto, seenMaterials, pkg, name, materialType, name.Name, "literal")
		r := a.nodeRange(name)
		finding := model.CryptoFinding{ID: stableID(pkg.ID, "GOLEM-CRYPTO-LITERAL-MATERIAL", name.Name, r.Start.Filename, fmt.Sprint(r.Start.Line), fmt.Sprint(r.Start.Column)), RuleID: "GOLEM-CRYPTO-LITERAL-MATERIAL", Severity: "medium", Confidence: "name-and-literal", Summary: "Potential hardcoded cryptographic material indicator detected. The literal value is intentionally not emitted.", Recommendation: "Load cryptographic material from a managed secret store or protected file and avoid committing secret-bearing literals.", PackagePath: pkg.PkgPath, UsageScope: fileRole(r.Start.Filename), MaterialID: materialID, Range: r, Properties: map[string]string{"indicator": materialType}}
		appendCryptoFinding(crypto, seenFindings, finding)
	}
}

func containsStringLiteral(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			found = true
			return false
		}
		return true
	})
	return found
}
func materialTypeFromName(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "private") && strings.Contains(lower, "key"):
		return "private-key"
	case strings.Contains(lower, "public") && strings.Contains(lower, "key"):
		return "public-key"
	case strings.Contains(lower, "secret"):
		return "shared-secret"
	case strings.Contains(lower, "password") || strings.Contains(lower, "passwd"):
		return "password"
	case strings.Contains(lower, "token"):
		return "token"
	case strings.Contains(lower, "credential"):
		return "credential"
	case lower == "iv" || strings.Contains(lower, "nonce"):
		return "nonce"
	case strings.Contains(lower, "salt"):
		return "salt"
	case strings.Contains(lower, "key"):
		return "key"
	}
	return ""
}
func cryptoNodeSymbol(pkg *packages.Package, node ast.Node) string {
	if sel, ok := node.(*ast.SelectorExpr); ok && pkg.TypesInfo != nil {
		if obj := pkg.TypesInfo.Uses[sel.Sel]; obj != nil && obj.Pkg() != nil {
			return obj.Pkg().Path() + "." + obj.Name()
		}
	}
	return ""
}
func appendCryptoLibrary(crypto *model.CryptoEvidence, seen map[string]bool, value model.CryptoLibrary) {
	if !seen[value.ID] {
		seen[value.ID] = true
		crypto.Libraries = append(crypto.Libraries, value)
	}
}
func appendCryptoAsset(crypto *model.CryptoEvidence, seen map[string]bool, value model.CryptoAsset) {
	if !seen[value.ID] {
		seen[value.ID] = true
		crypto.Assets = append(crypto.Assets, value)
	}
}
func appendCryptoOperation(crypto *model.CryptoEvidence, seen map[string]bool, value model.CryptoOperation) {
	if !seen[value.ID] {
		seen[value.ID] = true
		crypto.Operations = append(crypto.Operations, value)
	}
}
func appendCryptoMaterial(crypto *model.CryptoEvidence, seen map[string]bool, value model.CryptoMaterial) {
	if !seen[value.ID] {
		seen[value.ID] = true
		crypto.Materials = append(crypto.Materials, value)
	}
}
func appendCryptoProtocol(crypto *model.CryptoEvidence, seen map[string]bool, value model.CryptoProtocol) {
	if !seen[value.ID] {
		seen[value.ID] = true
		crypto.Protocols = append(crypto.Protocols, value)
	}
}
func appendCryptoFinding(crypto *model.CryptoEvidence, seen map[string]bool, value model.CryptoFinding) {
	if !seen[value.ID] {
		seen[value.ID] = true
		crypto.Findings = append(crypto.Findings, value)
	}
}
func mergeCryptoEvidence(dst *model.CryptoEvidence, src *model.CryptoEvidence) *model.CryptoEvidence {
	if src == nil {
		return dst
	}
	if dst == nil {
		dst = &model.CryptoEvidence{}
	}
	libraries := map[string]bool{}
	assets := map[string]bool{}
	operations := map[string]bool{}
	materials := map[string]bool{}
	protocols := map[string]bool{}
	findings := map[string]bool{}
	for _, value := range dst.Libraries {
		libraries[value.ID] = true
	}
	for _, value := range dst.Assets {
		assets[value.ID] = true
	}
	for _, value := range dst.Operations {
		operations[value.ID] = true
	}
	for _, value := range dst.Materials {
		materials[value.ID] = true
	}
	for _, value := range dst.Protocols {
		protocols[value.ID] = true
	}
	for _, value := range dst.Findings {
		findings[value.ID] = true
	}
	for _, value := range src.Libraries {
		appendCryptoLibrary(dst, libraries, value)
	}
	for _, value := range src.Assets {
		appendCryptoAsset(dst, assets, value)
	}
	for _, value := range src.Operations {
		appendCryptoOperation(dst, operations, value)
	}
	for _, value := range src.Materials {
		appendCryptoMaterial(dst, materials, value)
	}
	for _, value := range src.Protocols {
		appendCryptoProtocol(dst, protocols, value)
	}
	for _, value := range src.Findings {
		appendCryptoFinding(dst, findings, value)
	}
	return dst
}
func sortCryptoEvidence(crypto *model.CryptoEvidence) {
	if crypto == nil {
		return
	}
	sort.Slice(crypto.Libraries, func(i, j int) bool { return crypto.Libraries[i].ID < crypto.Libraries[j].ID })
	sort.Slice(crypto.Assets, func(i, j int) bool { return crypto.Assets[i].ID < crypto.Assets[j].ID })
	sort.Slice(crypto.Operations, func(i, j int) bool { return crypto.Operations[i].ID < crypto.Operations[j].ID })
	sort.Slice(crypto.Materials, func(i, j int) bool { return crypto.Materials[i].ID < crypto.Materials[j].ID })
	sort.Slice(crypto.Protocols, func(i, j int) bool { return crypto.Protocols[i].ID < crypto.Protocols[j].ID })
	sort.Slice(crypto.Findings, func(i, j int) bool { return crypto.Findings[i].ID < crypto.Findings[j].ID })
}
func firstNonEmptyCrypto(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
