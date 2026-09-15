// Every syntactic form Cipher.getInstance can take, with a NEGATIVE per
// form: the transform another form produced must not be attributed to this
// one, and an unresolvable form reports resolution=unresolved rather than
// guessing a default.
// kosi:want crypto name=AES/ECB/PKCS5Padding form=literal ciphermode=ECB padding=PKCS5Padding mode=resolved
// kosi:want crypto name=AES/GCM/NoPadding form=const ciphermode=GCM padding=NoPadding mode=resolved
// kosi:want crypto name=AES/CBC/PKCS5Padding form=template ciphermode=CBC padding=PKCS5Padding mode=resolved
// kosi:want crypto name=AES/CTR/NoPadding form=config ciphermode=CTR padding=NoPadding mode=resolved
// kosi:want crypto name=Cipher form=unresolved mode=resolved
// kosi:want-not crypto name=AES/GCM/NoPadding form=literal mode=resolved
// kosi:want-not crypto name=DESede/CBC/PKCS5Padding mode=resolved
// kosi:want-not crypto name=Blowfish mode=resolved
package fixtures.cryptoforms

import javax.crypto.Cipher

const val TRANSFORM_CONST = "AES/GCM/NoPadding"
const val AES_PREFIX = "AES"

fun literalForm(): Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")

fun constForm(): Cipher = Cipher.getInstance(TRANSFORM_CONST)

fun templateForm(): Cipher = Cipher.getInstance("$AES_PREFIX/CBC/PKCS5Padding")

fun configForm(props: java.util.Properties): Cipher =
    Cipher.getInstance(props.getProperty("cryptoforms.transform"))

fun unresolvedForm(props: java.util.Properties, key: String): Cipher? =
    Cipher.getInstance(props.getProperty(key))
