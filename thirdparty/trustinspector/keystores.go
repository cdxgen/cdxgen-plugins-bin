package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// Java keystore readers (JKS and JCEKS) and the PKCS#12 trust store reader.
//
// JKS/JCEKS on-disk layout is read directly so trusted-certificate entries
// can be listed without decoding (or even having) any private key. Only the
// entry framing is parsed; the integrity digest at the end of the store is
// NOT verified, which is documented in the README.

// JavaKeyStore magic numbers, from the OpenJDK source (tag jdk-26-ga):
// https://github.com/openjdk/jdk/blob/jdk-26-ga/src/java.base/share/classes/sun/security/provider/JavaKeyStore.java
// (private static final int MAGIC = 0xfeedfeed) and
// https://github.com/openjdk/jdk/blob/jdk-26-ga/src/java.base/share/classes/com/sun/crypto/provider/JceKeyStore.java
// (private static final int JCEKS_MAGIC = 0xcececece).
const (
	jksMagic   = 0xFEEDFEED
	jceksMagic = 0xCECECECE
)

// entry tags follow the same sources: 1 = private key, 2 = trusted
// certificate, 3 = secret key (JCEKS only).
const (
	jksTagPrivateKey         = 1
	jksTagTrustedCertificate = 2
	jksTagSecretKey          = 3
)

// javaKeystoreMagic reports the keystore format from the 4-byte magic.
func javaKeystoreMagic(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	switch binary.BigEndian.Uint32(data[:4]) {
	case jksMagic:
		return "JKS", true
	case jceksMagic:
		return "JCEKS", true
	default:
		return "", false
	}
}

// jksReader is a bounds-checked big-endian reader matching the DataInputStream
// reads in the OpenJDK engineLoad implementation.
type jksReader struct {
	data   []byte
	offset int
	err    error
}

const (
	maxJKSEntries = 100000
	maxJKSBytes   = 64 << 20 // 64 MiB of claimed entry content at most
)

func (r *jksReader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

// take returns the next n bytes, or fails when fewer remain. n is unsigned
// so a 32-bit length can never turn negative on a 32-bit build.
func (r *jksReader) take(n uint64) []byte {
	if r.err != nil {
		return nil
	}
	if n > uint64(len(r.data)-r.offset) {
		r.fail(errors.New("jks: truncated entry"))
		return nil
	}
	value := r.data[r.offset : r.offset+int(n)]
	r.offset += int(n)
	return value
}

func (r *jksReader) readUint16() uint16 {
	if value := r.take(2); value != nil {
		return binary.BigEndian.Uint16(value)
	}
	return 0
}

func (r *jksReader) readUint32() uint32 {
	if value := r.take(4); value != nil {
		return binary.BigEndian.Uint32(value)
	}
	return 0
}

// readUTF matches DataInputStream.readUTF: an unsigned 2-byte length followed
// by that many bytes (modified UTF-8). Aliases are skipped, not decoded.
func (r *jksReader) skipUTF() {
	r.take(uint64(r.readUint16()))
}

// skipBytes consumes a 4-byte-length-prefixed field without decoding it; this
// is how private-key entries are skipped unread.
func (r *jksReader) skipBytes() {
	length := r.readUint32()
	if r.err == nil && length > maxJKSBytes {
		r.fail(fmt.Errorf("jks: implausible length %d", length))
		return
	}
	r.take(uint64(length))
}

// readCertificateBytes returns one certificate's DER: version 2 stores a
// certificate type string (e.g. "X.509") first, which is skipped.
func (r *jksReader) readCertificateBytes(version uint32) []byte {
	if version == 2 {
		r.skipUTF()
	}
	length := r.readUint32()
	if r.err == nil && (length == 0 || length > maxJKSBytes) {
		r.fail(fmt.Errorf("jks: implausible certificate length %d", length))
		return nil
	}
	return r.take(uint64(length))
}

// readJavaTrustStore lists the trusted-certificate entries of a JKS or JCEKS
// store. Private-key entries (tag 1) are skipped via their length prefixes
// without decoding the key or its chain. complete is false when the store
// could not be read to the end: a truncated or malformed entry stops the
// walk, and a JCEKS secret-key entry (tag 3) does too, because JceKeyStore
// writes it as a Java-serialized SealedObject with no length prefix to skip
// by. A trusted certificate Go cannot parse is skipped and also makes the
// store incomplete. The trailing integrity digest is not read or verified.
func readJavaTrustStore(data []byte) (certs []*x509.Certificate, complete bool) {
	reader := &jksReader{data: data, offset: 4}
	version := reader.readUint32()
	count := reader.readUint32()
	if reader.err != nil || (version != 1 && version != 2) || count > maxJKSEntries {
		return nil, false
	}
	complete = true
	for i := uint32(0); i < count; i++ {
		switch tag := reader.readUint32(); tag {
		case jksTagTrustedCertificate:
			reader.skipUTF() // alias
			reader.take(8)   // creation date
			der := reader.readCertificateBytes(version)
			if reader.err != nil {
				return certs, false
			}
			if cert, err := x509.ParseCertificate(der); err == nil {
				certs = append(certs, cert)
			} else {
				complete = false
			}
		case jksTagPrivateKey:
			// alias, date, protected key bytes, then the certificate chain.
			reader.skipUTF()
			reader.take(8)
			reader.skipBytes()
			chainLength := reader.readUint32()
			if reader.err == nil && chainLength > maxJKSEntries {
				return certs, false
			}
			for j := uint32(0); j < chainLength && reader.err == nil; j++ {
				reader.readCertificateBytes(version)
			}
		default:
			// jksTagSecretKey, or an unknown tag: the rest cannot be framed.
			return certs, false
		}
		if reader.err != nil {
			return certs, false
		}
	}
	return certs, complete
}

// PKCS#12 key-derivation bounds. go-pkcs12 runs the PBKDF for the MAC and for
// every encrypted safe, once per password tried, with whatever iteration
// count the file declares, so a 1 KiB file asking for 2^31 iterations would
// stall a scan for many minutes. Files declaring more than
// maxPKCS12Iterations are not decoded (keytool writes 10,000, or 50,000 and
// 100,000 before JDK 12; OpenSSL 2,048), and one scan spends at most
// pkcs12IterationBudget iterations in total.
var (
	maxPKCS12Iterations         = 200000
	pkcs12IterationBudget int64 = 20000000
)

var (
	oidPKCS7Data       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7Encrypted  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidPBES2           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBMAC1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	errPKCS12TooCostly = errors.New("pkcs12: key-derivation iteration count over the limit")
)

type pfxContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// pkcs12Cost is the key-derivation work a PFX declares: the largest
// iteration count of its MAC and encrypted safes, and how many derivations
// one password attempt runs (the MAC plus each encrypted safe).
type pkcs12Cost struct {
	maxIterations, derivations int
}

// pkcs12Iterations recognizes a PFX (RFC 7292 section 4: version 3 and a
// data-typed authSafe) and returns the key-derivation work it declares. ok is
// false when data is not a PFX. A parameter this reader cannot parse counts
// as over the limit.
func pkcs12Iterations(data []byte) (cost pkcs12Cost, ok bool) {
	var pfx struct {
		Version  int
		AuthSafe pfxContentInfo
		MacData  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(data, &pfx); err != nil || pfx.Version != 3 || !pfx.AuthSafe.ContentType.Equal(oidPKCS7Data) {
		return pkcs12Cost{}, false
	}
	tooCostly := pkcs12Cost{maxIterations: maxPKCS12Iterations + 1, derivations: 1}
	note := func(iterations int) {
		cost.derivations++
		cost.maxIterations = max(cost.maxIterations, iterations)
	}
	if len(pfx.MacData.FullBytes) > 0 {
		var macData struct {
			Mac struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}
			MacSalt    []byte
			Iterations int `asn1:"optional,default:1"`
		}
		if _, err := asn1.Unmarshal(pfx.MacData.FullBytes, &macData); err != nil {
			return tooCostly, true
		}
		note(macData.Iterations)
		if macData.Mac.Algorithm.Algorithm.Equal(oidPBMAC1) {
			var pbmac1 struct {
				KeyDerivationFunc pkix.AlgorithmIdentifier
				MessageAuthScheme pkix.AlgorithmIdentifier
			}
			if _, err := asn1.Unmarshal(macData.Mac.Algorithm.Parameters.FullBytes, &pbmac1); err != nil {
				return tooCostly, true
			}
			note(pbkdf2Iterations(pbmac1.KeyDerivationFunc))
		}
	}
	var authSafe []byte
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authSafe); err != nil {
		return tooCostly, true
	}
	var safes []pfxContentInfo
	if _, err := asn1.Unmarshal(authSafe, &safes); err != nil || len(safes) > 64 {
		return tooCostly, true
	}
	for _, safe := range safes {
		if !safe.ContentType.Equal(oidPKCS7Encrypted) {
			continue
		}
		var encrypted struct {
			Version              int
			EncryptedContentInfo struct {
				ContentType asn1.ObjectIdentifier
				Algorithm   pkix.AlgorithmIdentifier
				Content     asn1.RawValue `asn1:"tag:0,optional"`
			}
		}
		if _, err := asn1.Unmarshal(safe.Content.Bytes, &encrypted); err != nil {
			return tooCostly, true
		}
		note(pbeIterations(encrypted.EncryptedContentInfo.Algorithm))
	}
	cost.derivations = max(cost.derivations, 1)
	return cost, true
}

// pbeIterations reads the iteration count of a password-based encryption
// algorithm: PBES2 with PBKDF2 (RFC 8018), or a PKCS#12 PBE scheme
// (RFC 7292 appendix C: pkcs-12PbeParams ::= SEQUENCE { salt, iterations }).
// An unparseable parameter set returns a count over the limit.
func pbeIterations(algorithm pkix.AlgorithmIdentifier) int {
	if algorithm.Algorithm.Equal(oidPBES2) {
		var params struct {
			KeyDerivationFunc pkix.AlgorithmIdentifier
			EncryptionScheme  pkix.AlgorithmIdentifier
		}
		if _, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return maxPKCS12Iterations + 1
		}
		return pbkdf2Iterations(params.KeyDerivationFunc)
	}
	var params struct {
		Salt       []byte
		Iterations int
	}
	if _, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return maxPKCS12Iterations + 1
	}
	return params.Iterations
}

// pbkdf2Iterations reads PBKDF2-params (RFC 8018 appendix A.2).
func pbkdf2Iterations(kdf pkix.AlgorithmIdentifier) int {
	var params struct {
		Salt       asn1.RawValue
		Iterations int
	}
	if !kdf.Algorithm.Equal(oidPBKDF2) {
		return maxPKCS12Iterations + 1
	}
	if _, err := asn1.Unmarshal(kdf.Parameters.FullBytes, &params); err != nil {
		return maxPKCS12Iterations + 1
	}
	return params.Iterations
}

// readPKCS12TrustStore decodes a PKCS#12 trust store with the public JDK
// default password first, then the empty password (PLAN section 1, principle
// 7), unless its declared key-derivation work is over the limit or the scan's
// budget is spent. The retry runs on ANY error, not only a wrong-password
// error: JDK cacerts shipped since Java 9 are written without a MAC, and
// go-pkcs12 rejects a non-empty password on a MAC-less file with "no MAC in
// data" rather than ErrIncorrectPassword (observed against the Temurin 26
// cacerts; the check is in getSafeContents, pkcs12.go in
// software.sslmate.com/src/go-pkcs12 v0.7.4). DecodeTrustStore is used
// deliberately: it never returns private keys, and it refuses a key bag
// before decrypting it.
func readPKCS12TrustStore(data []byte, declared pkcs12Cost) ([]*x509.Certificate, error) {
	if declared.maxIterations > maxPKCS12Iterations {
		return nil, errPKCS12TooCostly
	}
	var err error
	for _, password := range []string{"changeit", ""} {
		// go-pkcs12 may derive once more internally for the empty password.
		cost := int64(declared.maxIterations) * int64(declared.derivations) * 2
		if pkcs12IterationBudget < cost {
			return nil, errPKCS12TooCostly
		}
		pkcs12IterationBudget -= cost
		var certs []*x509.Certificate
		if certs, err = pkcs12.DecodeTrustStore(data, password); err == nil {
			return certs, nil
		}
	}
	return nil, err
}
