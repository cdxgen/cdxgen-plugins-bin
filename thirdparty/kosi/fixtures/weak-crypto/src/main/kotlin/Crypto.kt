// Negative half first. Each names something a *plausibly over-broad*
// implementation would emit from this exact file, so none of them can pass
// vacuously:
//   - `MessageDigest`: the bare receiver, which a renderer that reported
//     qualifier chains as usages in their own right would produce;
//   - `Cipher.getInstance` as a `reference`: it is present as a `call`, so
//     this fails the moment usageKind stops discriminating;
//   - `weakDigest` as a `property`: present as a `function`.
// kosi:want-not usage name=MessageDigest
// kosi:want-not usage name=Cipher.getInstance kind=reference
// kosi:want-not declaration name=weakDigest kind=property
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
