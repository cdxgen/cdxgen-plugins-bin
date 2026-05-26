package analyzer

import (
	"fmt"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
	"go/ast"
	"go/token"
	"golang.org/x/tools/go/packages"
	"sort"
	"strings"
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
	"crypto/ed25519":                 "signature",
	"crypto/hmac":                    "mac",
	"crypto/md5":                     "hash-legacy",
	"crypto/rand":                    "random",
	"crypto/rsa":                     "public-key",
	"crypto/sha1":                    "hash-legacy",
	"crypto/sha256":                  "hash",
	"crypto/sha512":                  "hash",
	"crypto/tls":                     "protocol",
	"crypto/x509":                    "certificate",
	"encoding/pem":                   "crypto-material",
	"golang.org/x/crypto/pbkdf2":     "kdf",
	"golang.org/x/crypto/curve25519": "key-agreement",
}
var cryptoSymbolCatalog = map[string]cryptoClassification{
	"crypto/md5.New":                        {assetType: "algorithm", name: "md5", primitive: "hash", strength: "weak", oid: "1.2.840.113549.2.5", operationType: "hash", ruleID: "GOLEM-CRYPTO-WEAK-MD5", severity: "high", summary: "MD5 cryptographic primitive detected.", recommendation: "Use SHA-256 or stronger unless this is explicitly non-security checksum logic."},
	"crypto/md5.Sum":                        {assetType: "algorithm", name: "md5", primitive: "hash", strength: "weak", oid: "1.2.840.113549.2.5", operationType: "hash", ruleID: "GOLEM-CRYPTO-WEAK-MD5", severity: "high", summary: "MD5 cryptographic primitive detected.", recommendation: "Use SHA-256 or stronger unless this is explicitly non-security checksum logic."},
	"crypto/sha1.New":                       {assetType: "algorithm", name: "sha-1", primitive: "hash", strength: "weak", oid: "2.16.840.1.113719.1.2.8.82", operationType: "hash", ruleID: "GOLEM-CRYPTO-WEAK-SHA1", severity: "high", summary: "SHA-1 cryptographic primitive detected.", recommendation: "Use SHA-256 or stronger unless compatibility requires SHA-1."},
	"crypto/sha1.Sum":                       {assetType: "algorithm", name: "sha-1", primitive: "hash", strength: "weak", oid: "2.16.840.1.113719.1.2.8.82", operationType: "hash", ruleID: "GOLEM-CRYPTO-WEAK-SHA1", severity: "high", summary: "SHA-1 cryptographic primitive detected.", recommendation: "Use SHA-256 or stronger unless compatibility requires SHA-1."},
	"crypto/sha256.New":                     {assetType: "algorithm", name: "sha-256", primitive: "hash", strength: "strong", oid: "2.16.840.1.101.3.4.2.1", operationType: "hash"},
	"crypto/sha256.Sum256":                  {assetType: "algorithm", name: "sha-256", primitive: "hash", strength: "strong", oid: "2.16.840.1.101.3.4.2.1", operationType: "hash"},
	"crypto/sha512.Sum512":                  {assetType: "algorithm", name: "sha-512", primitive: "hash", strength: "strong", oid: "2.16.840.1.101.3.4.2.3", operationType: "hash"},
	"crypto/aes.NewCipher":                  {assetType: "algorithm", name: "aes", primitive: "block-cipher", strength: "strong", standard: "FIPS 197", oid: "2.16.840.1.101.3.4.1", operationType: "encrypt/decrypt"},
	"crypto/des.NewCipher":                  {assetType: "algorithm", name: "des", primitive: "block-cipher", strength: "weak", oid: "1.3.36.3.1.1", operationType: "encrypt/decrypt", ruleID: "GOLEM-CRYPTO-WEAK-DES", severity: "high", summary: "DES cryptographic primitive detected.", recommendation: "Use AES-GCM or another modern authenticated encryption mode."},
	"crypto/rsa.GenerateKey":                {assetType: "algorithm", name: "rsa", primitive: "pke", strength: "acceptable", oid: "2.5.8.1.1", operationType: "key-generation", materialType: "private-key"},
	"crypto/ed25519.Sign":                   {assetType: "algorithm", name: "Ed25519", primitive: "signature", strength: "strong", oid: "1.3.101.112", operationType: "sign", materialType: "private-key"},
	"crypto/hmac.New":                       {assetType: "algorithm", name: "hmacSHA", primitive: "mac", strength: "strong", oid: "1.3.6.1.5.5.8.1.2", operationType: "mac"},
	"crypto/rand.Read":                      {assetType: "algorithm", name: "CSPRNG", primitive: "drbg", strength: "strong", operationType: "random"},
	"crypto/x509.ParseCertificate":          {assetType: "certificate", name: "X.509 certificate", operationType: "parse", materialType: "public-key"},
	"crypto/x509.ParsePKCS1PrivateKey":      {assetType: "related-crypto-material", name: "PKCS#1 private key", operationType: "parse", materialType: "private-key"},
	"crypto/tls.LoadX509KeyPair":            {assetType: "protocol", name: "TLS", protocolName: "TLS", protocolType: "tls", operationType: "load-certificate-key-pair", materialType: "private-key"},
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
