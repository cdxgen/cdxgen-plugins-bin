// The trust-all pair: an EMPTY-CHECK manager body is the shape the finding
// names; a manager whose checks actually validate is not, and no second
// trust-all may be invented for it.
// kosi:want-not crypto name=X509TrustManager mode=resolved
// kosi:want-not crypto name=ValidatesChain mode=resolved
package fixtures.cryptotls

import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

class TrustEverything : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    override fun getAcceptedIssuers(): Array<X509Certificate?> = arrayOfNulls(0)
}

class ValidatesChain : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
        check(chain != null && chain.isNotEmpty()) { "empty chain" }
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
        check(chain != null && chain.isNotEmpty()) { "empty chain" }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate?> = arrayOfNulls(0)
}
