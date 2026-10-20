package analyzer

import (
	"fmt"
	"go/ast"
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
			if ident, ok := x.Key.(*ast.Ident); ok && ident.Name == "InsecureSkipVerify" {
				if lit, ok := x.Value.(*ast.Ident); ok && lit.Name == "true" {
					class := cryptoClassification{assetType: "protocol", name: "TLS", protocolName: "TLS", protocolType: "tls", operationType: "configure", ruleID: "GOLEM-CRYPTO-TLS-INSECURE-SKIP-VERIFY", severity: "critical", summary: "TLS certificate verification is disabled.", recommendation: "Do not set InsecureSkipVerify except in tightly controlled test code."}
					a.addCryptoClassification(crypto, pkg, x, class, seenAssets, seenOperations, seenMaterials, seenProtocols, seenFindings)
				}
			}
		case *ast.CompositeLit:
			a.addTrustCustomisationFindings(crypto, pkg, x, seenFindings)
		case *ast.CallExpr:
			a.addEmbeddedPoolFinding(crypto, pkg, file, x, seenFindings)
		case *ast.ValueSpec:
			a.addLiteralCryptoMaterials(crypto, pkg, x.Names, x.Values, seenMaterials, seenFindings)
		case *ast.AssignStmt:
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
// default trust decisions. A composite literal of type crypto/tls.Config or
// crypto/x509.VerifyOptions is resolved through TypesInfo, never by name, so
// aliases and other packages' structs with the same field names do not match.
func (a *Analyzer) addTrustCustomisationFindings(crypto *model.CryptoEvidence, pkg *packages.Package, lit *ast.CompositeLit, seenFindings map[string]bool) {
	typePath, ok := compositeLiteralTypePath(pkg, lit)
	if !ok {
		return
	}
	rootField, verifyFields := "", map[string]bool{}
	switch typePath {
	case "crypto/tls.Config":
		rootField = "RootCAs"
		verifyFields = map[string]bool{"VerifyPeerCertificate": true, "VerifyConnection": true}
	case "crypto/x509.VerifyOptions":
		rootField = "Roots"
	default:
		return
	}
	hasCustomRoots := false
	hasCustomVerify := false
	hasInsecureSkipVerify := false
	for _, elt := range lit.Elts {
		keyValue, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			// Unkeyed composite literals cannot be attributed to a field.
			return
		}
		ident, ok := keyValue.Key.(*ast.Ident)
		if !ok {
			return
		}
		switch {
		case ident.Name == rootField:
			if !isNilIdent(keyValue.Value) {
				hasCustomRoots = true
			}
		case verifyFields[ident.Name]:
			if !isNilIdent(keyValue.Value) {
				hasCustomVerify = true
			}
		case ident.Name == "InsecureSkipVerify":
			if value, ok := keyValue.Value.(*ast.Ident); ok && value.Name == "true" {
				hasInsecureSkipVerify = true
			}
		}
	}
	if hasCustomRoots {
		a.addCryptoFinding(crypto, pkg, lit, seenFindings, model.CryptoFinding{
			RuleID:         "GOLEM-CRYPTO-TLS-CUSTOM-ROOTS",
			Severity:       "low",
			Confidence:     "type-resolved",
			Summary:        "TLS verification uses a custom trust root pool instead of the system roots.",
			Recommendation: "Review the custom root set: certificates distrusted by the platform or the Go toolchain can still be trusted here, and platform updates no longer apply.",
			Properties:     map[string]string{"field": rootField, "type": typePath},
		})
	}
	if hasCustomVerify {
		a.addCryptoFinding(crypto, pkg, lit, seenFindings, model.CryptoFinding{
			RuleID:         "GOLEM-CRYPTO-TLS-CUSTOM-VERIFY",
			Severity:       "medium",
			Confidence:     "type-resolved",
			Summary:        "TLS verification is replaced with a custom callback.",
			Recommendation: "Review the callback: it must perform chain building and revocation checks itself, because the standard verifier no longer runs for this connection.",
			Properties:     map[string]string{"type": typePath},
		})
		if hasInsecureSkipVerify {
			a.addCryptoFinding(crypto, pkg, lit, seenFindings, model.CryptoFinding{
				RuleID:         "GOLEM-CRYPTO-TLS-VERIFY-REPLACED",
				Severity:       "high",
				Confidence:     "type-resolved",
				Summary:        "InsecureSkipVerify is combined with a custom verify callback, fully replacing Go's certificate verification.",
				Recommendation: "The custom callback is the only verification left; make sure it validates chains itself, including any intermediates the server presents.",
				Properties:     map[string]string{"type": typePath},
			})
		}
	}
}

// addEmbeddedPoolFinding flags (*crypto/x509.CertPool).AppendCertsFromPEM
// calls whose argument resolves to a package-level variable carrying a
// //go:embed directive: a certificate pool compiled into the binary, which
// no store update can revoke.
func (a *Analyzer) addEmbeddedPoolFinding(crypto *model.CryptoEvidence, pkg *packages.Package, file *ast.File, call *ast.CallExpr, seenFindings map[string]bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	method, ok := pkg.TypesInfo.Uses[selector.Sel].(*types.Func)
	if !ok {
		return
	}
	signature, ok := method.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return
	}
	if !isCertPoolType(signature.Recv().Type()) {
		return
	}
	if len(call.Args) != 1 {
		return
	}
	argument := ast.Unparen(call.Args[0])
	ident, ok := argument.(*ast.Ident)
	if !ok {
		return
	}
	variable, ok := pkg.TypesInfo.Uses[ident].(*types.Var)
	if !ok || variable.Parent() == nil || variable.Parent() != pkg.Types.Scope() {
		return
	}
	if !varDeclHasGoEmbed(pkg, variable.Name()) {
		return
	}
	a.addCryptoFinding(crypto, pkg, call, seenFindings, model.CryptoFinding{
		RuleID:         "GOLEM-CRYPTO-X509-EMBEDDED-POOL",
		Severity:       "low",
		Confidence:     "type-resolved",
		Summary:        "A certificate pool is built from a //go:embed package variable compiled into the binary.",
		Recommendation: "Embedded trust pools ignore later CA updates and distrust decisions; load roots from the system store or a refreshable source instead.",
		Properties:     map[string]string{"variable": variable.Name()},
	})
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
// returns "package/path.TypeName" for struct types from another package.
func compositeLiteralTypePath(pkg *packages.Package, lit *ast.CompositeLit) (string, bool) {
	if pkg.TypesInfo == nil {
		return "", false
	}
	typeValue := pkg.TypesInfo.TypeOf(lit)
	if typeValue == nil {
		return "", false
	}
	if pointer, ok := typeValue.(*types.Pointer); ok {
		typeValue = pointer.Elem()
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
	pointer, ok := typeValue.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "crypto/x509" && obj.Name() == "CertPool"
}

// isNilIdent reports whether the expression is the bare nil identifier
// (explicitly unset fields do not customise trust).
func isNilIdent(expr ast.Expr) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && ident.Name == "nil"
}

// varDeclHasGoEmbed reports whether a package-level variable of this name is
// declared with a //go:embed directive in its doc comment group, in any file
// of the package (the use may be in a different file than the declaration).
func varDeclHasGoEmbed(pkg *packages.Package, name string) bool {
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.VAR {
				continue
			}
			if !commentGroupHasGoEmbed(genDecl.Doc) {
				continue
			}
			for _, spec := range genDecl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, specName := range valueSpec.Names {
					if specName.Name == name {
						return true
					}
				}
			}
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
