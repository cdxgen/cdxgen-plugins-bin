// Negative half first: the clean TLS path must not be conflated with the
// weak digest usage below.
// kosi:want-not usage name=javax.net.ssl.SSLContext
// kosi:want-not usage name=SecureRandom.getInstanceStrong
// kosi:want-not diagnostic code=parse-error
//
// Positive half.
// kosi:want usage name=Cipher.getInstance
// kosi:want usage name=MessageDigest.getInstance
// kosi:want declaration name=weakDigest kind=function
package fixtures.crypto

import javax.crypto.Cipher
import java.security.MessageDigest

fun weakDigest(input: ByteArray): ByteArray {
    val md5 = MessageDigest.getInstance("MD5")
    return md5.digest(input)
}

fun weakCipher(input: ByteArray, key: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    return cipher.doFinal(input)
}
