// Material by NAME births a hardcoded-secret fact at the store (the pack's
// literalSources rule); the crypto APIs are pack sinks, so the material ->
// crypto-API flows are ordinary slices and crypto-flow counting reads them
// from dataFlow.slices[].
// kosi:want flow source=hardcoded-secret sink=crypto-asset mode=resolved count=2
// kosi:want-not flow source=hardcoded-secret sink=sql-query mode=resolved
// kosi:want crypto name=HmacSHA256 mode=resolved
// kosi:want crypto name=PBKDF2WithHmacSHA256 mode=resolved
// kosi:want crypto name=EC mode=resolved
// kosi:want-not crypto name=DES mode=resolved
// kosi:want-not crypto name=SHA1 mode=resolved
package fixtures.cryptoflow

import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class TokenService {
    fun macPayload(payload: ByteArray): ByteArray {
        val signingKey = "0123456789abcdef0123456789abcdef"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(signingKey.toByteArray(), "HmacSHA256"))
        return mac.doFinal(payload)
    }

    fun deriveKey(password: ByteArray, salt: ByteArray): javax.crypto.SecretKey {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toString().toCharArray(), salt, 1000, 256)
        return factory.generateSecret(spec)
    }

    fun signingKey(): javax.crypto.SecretKey {
        val apiToken = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
        return SecretKeySpec(apiToken.toByteArray(), "HmacSHA256")
    }

    fun ephemeralKeys(): java.security.KeyPair {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        return generator.generateKeyPair()
    }
}
