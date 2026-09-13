// TLS protocol assets: two modern, two deprecated (the mapping rows carry
// the findings), plus the Android keystore. NEGATIVES: the protocols and
// algorithms this file deliberately avoids.
// kosi:want crypto name=TLS mode=resolved
// kosi:want crypto name=TLSv1.2 mode=resolved
// kosi:want crypto name=TLSv1.3 mode=resolved
// kosi:want crypto name=SSL mode=resolved
// kosi:want crypto name=TLSv1.1 mode=resolved
// kosi:want crypto name=AndroidKeyStore mode=resolved
// kosi:want-not crypto name=TLSv1.0 mode=resolved
// kosi:want-not crypto name=RC4 mode=resolved
package fixtures.cryptotls

import java.security.KeyStore
import javax.net.ssl.SSLContext

fun genericTls(): SSLContext = SSLContext.getInstance("TLS")

fun modernTls(): SSLContext = SSLContext.getInstance("TLSv1.2")

fun newestTls(): SSLContext = SSLContext.getInstance("TLSv1.3")

fun deprecatedSsl(): SSLContext = SSLContext.getInstance("SSL")

fun deprecatedTls(): SSLContext = SSLContext.getInstance("TLSv1.1")

fun hardwareBackedStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore")
