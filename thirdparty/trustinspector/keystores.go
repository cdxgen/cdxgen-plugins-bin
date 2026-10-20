package main

import (
	"crypto/x509"
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
	limit  int // entry loop budget
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

func (r *jksReader) readUint16() uint16 {
	if r.err != nil || r.offset+2 > len(r.data) {
		r.fail(errors.New("jks: truncated header or entry"))
		return 0
	}
	value := binary.BigEndian.Uint16(r.data[r.offset:])
	r.offset += 2
	return value
}

func (r *jksReader) readUint32() uint32 {
	if r.err != nil || r.offset+4 > len(r.data) {
		r.fail(errors.New("jks: truncated header or entry"))
		return 0
	}
	value := binary.BigEndian.Uint32(r.data[r.offset:])
	r.offset += 4
	return value
}

func (r *jksReader) readUint64() uint64 {
	if r.err != nil || r.offset+8 > len(r.data) {
		r.fail(errors.New("jks: truncated entry"))
		return 0
	}
	value := binary.BigEndian.Uint64(r.data[r.offset:])
	r.offset += 8
	return value
}

// readUTF matches DataInputStream.readUTF: an unsigned 2-byte length followed
// by that many bytes (modified UTF-8; bytes are kept as-is, aliases are only
// used to keep the parse aligned).
func (r *jksReader) readUTF() string {
	if r.err != nil {
		return ""
	}
	length := int(r.readUint16())
	if r.err != nil || r.offset+length > len(r.data) {
		r.fail(errors.New("jks: truncated alias"))
		return ""
	}
	value := string(r.data[r.offset : r.offset+length])
	r.offset += length
	return value
}

// skipBytes consumes a length-prefixed field without decoding it; this is how
// private-key and secret-key entries are skipped unread.
func (r *jksReader) skipBytes() {
	if r.err != nil {
		return
	}
	length := int64(r.readUint32())
	if r.err != nil {
		return
	}
	if length < 0 || length > maxJKSBytes {
		r.fail(fmt.Errorf("jks: implausible length %d", length))
		return
	}
	if r.offset+int(length) > len(r.data) {
		r.fail(errors.New("jks: truncated entry data"))
		return
	}
	r.offset += int(length)
}

func (r *jksReader) readCertificate(version int) *x509.Certificate {
	if r.err != nil {
		return nil
	}
	if version == 2 {
		// Version 2 stores a certificate type string (e.g. "X.509") before
		// each certificate; it is skipped unread.
		r.readUTF()
	}
	if r.err != nil {
		return nil
	}
	length := int64(r.readUint32())
	if r.err != nil {
		return nil
	}
	if length <= 0 || length > maxJKSBytes || r.offset+int(length) > len(r.data) {
		r.fail(fmt.Errorf("jks: implausible certificate length %d", length))
		return nil
	}
	der := r.data[r.offset : r.offset+int(length)]
	r.offset += int(length)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		r.fail(fmt.Errorf("jks: bad certificate entry: %v", err))
		return nil
	}
	return cert
}

// readJavaTrustStore lists the trusted-certificate entries of a JKS or JCEKS
// store. Private-key (tag 1) and secret-key (tag 3) entries are skipped via
// their length prefixes without decoding their contents. The trailing
// integrity digest is not read or verified.
func readJavaTrustStore(data []byte) ([]*x509.Certificate, error) {
	if len(data) < 12 {
		return nil, errors.New("keystore: too short")
	}
	format, _ := javaKeystoreMagic(data)
	reader := &jksReader{data: data, offset: 4, limit: maxJKSEntries}
	version := int(reader.readUint32())
	if reader.err != nil {
		return nil, reader.err
	}
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("%s: unsupported version %d", format, version)
	}
	count := int(reader.readUint32())
	if reader.err != nil {
		return nil, reader.err
	}
	if count > maxJKSEntries {
		return nil, fmt.Errorf("%s: implausible entry count %d", format, count)
	}
	var certs []*x509.Certificate
	for i := 0; i < count; i++ {
		tag := int(reader.readUint32())
		if reader.err != nil {
			return nil, reader.err
		}
		switch tag {
		case jksTagTrustedCertificate:
			reader.readUTF()    // alias
			reader.readUint64() // creation date
			if cert := reader.readCertificate(version); cert != nil {
				certs = append(certs, cert)
			}
		case jksTagPrivateKey:
			// alias, date, protected key bytes, then the certificate chain.
			reader.readUTF()
			reader.readUint64()
			reader.skipBytes()
			if reader.err != nil {
				return nil, reader.err
			}
			chainLength := int(reader.readUint32())
			if reader.err != nil {
				return nil, reader.err
			}
			if chainLength < 0 || chainLength > maxJKSEntries {
				return nil, fmt.Errorf("%s: implausible chain length %d", format, chainLength)
			}
			for j := 0; j < chainLength; j++ {
				reader.readCertificate(version)
			}
		case jksTagSecretKey:
			// JCEKS only: alias, date, encrypted secret-key blob.
			reader.readUTF()
			reader.readUint64()
			reader.skipBytes()
		default:
			return nil, fmt.Errorf("%s: unrecognized entry tag %d", format, tag)
		}
		if reader.err != nil {
			return nil, reader.err
		}
	}
	if reader.err != nil {
		return nil, reader.err
	}
	return certs, nil
}

// readPKCS12TrustStore decodes a PKCS#12 trust store with the public JDK
// default password first, then the empty password (PLAN section 1, principle
// 7). DecodeTrustStore is used deliberately: it never returns private keys.
func readPKCS12TrustStore(data []byte) ([]*x509.Certificate, error) {
	certs, err := pkcs12.DecodeTrustStore(data, "changeit")
	if err == nil {
		return certs, nil
	}
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		return pkcs12.DecodeTrustStore(data, "")
	}
	// Wrong structure rather than wrong password; a second attempt with the
	// empty password would not help.
	return nil, err
}
