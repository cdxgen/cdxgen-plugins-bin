// The remaining shipped mapping rows: deprecated symmetric (DESede),
// asymmetric transforms (RSA-OAEP), a weak digest (SHA-1) and a signature
// algorithm. NEGATIVES: algorithms this file deliberately avoids - a
// mapping row must appear when the code names it, and never otherwise.
// kosi:want crypto name=DESede/CBC/PKCS5Padding ciphermode=CBC padding=PKCS5Padding mode=resolved
// kosi:want crypto name=RSA/ECB/OAEPWithSHA-256AndMGF1Padding ciphermode=ECB padding=OAEPWithSHA-256AndMGF1Padding mode=resolved
// kosi:want crypto name=SHA-1 mode=resolved
// kosi:want crypto name=SHA256withRSA mode=resolved
// kosi:want-not crypto name=SHA-512 mode=resolved
// kosi:want-not crypto name=DES/ECB/PKCS5Padding mode=resolved
// kosi:want-not crypto name=SHA1withDSA mode=resolved
package fixtures.cryptoalgs

import java.security.MessageDigest
import java.security.Signature
import javax.crypto.Cipher

fun weakBlockCipher(input: ByteArray, key: ByteArray): ByteArray =
    Cipher.getInstance("DESede/CBC/PKCS5Padding").doFinal(input)

fun asymmetric(input: ByteArray, key: java.security.Key): ByteArray =
    Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").doFinal(input)

fun weakDigest(input: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-1").digest(input)

fun sign(input: ByteArray, privateKey: java.security.PrivateKey): ByteArray =
    Signature.getInstance("SHA256withRSA").apply {
        initSign(privateKey)
        update(input)
    }.sign()
