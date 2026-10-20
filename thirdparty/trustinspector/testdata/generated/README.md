# Generated fixtures

All files in this directory are produced by `../gen.sh` (never hand-edited)
with the real tools below. Private keys are generated in a scratch directory
and deleted; the committed trust stores contain trusted-certificate entries
only.

Tool versions at generation time (recorded on 2026-10-20):

- openssl: OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)
- keytool: JDK keytool 26.0.2
- trustinspector commit: 6f3b0533

Contents:

| File | What it is |
|---|---|
| demo-root.crt | self-signed RSA-2048 root CA (Inspector Root A) |
| demo-intermediate.crt | intermediate CA, pathlen:0, cross-signed twin A |
| demo-cross-signed.crt | same SPKI as demo-intermediate.crt, twin B |
| demo-leaf.crt | leaf with SANs |
| demo-leaf.der | leaf in DER form |
| demo-bundle.pem | PEM bundle: root + intermediate + leaf |
| demo-negative-serial.crt | certificate with serial -42 (rejected by Go's parser) |
| demo-trusted-reject.pem | CERTIFICATE then TRUSTED CERTIFICATE with `serverAuth` reject + alias |
| demo-trusted-alias.pem | TRUSTED CERTIFICATE with alias only |
| demo-bundle.p7b | PKCS#7 SignedData PEM with root + intermediate |
| demo-truststore.jks | JKS trust store (aliases inspector-int, inspector-root; password `changeit`) |
| demo-truststore.p12 | PKCS#12 trust store (alias inspector-int; password `changeit`) |

Keystore passwords are the public JDK default `changeit`; no other secret is
embedded in any fixture.
