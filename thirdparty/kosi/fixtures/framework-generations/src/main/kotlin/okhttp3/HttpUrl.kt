// OkHttp 4/5's Kotlin generation: URL construction moved off the OkHttp 3
// Java static (`HttpUrl.parse`) onto companion extensions. The callableId
// — `okhttp3.HttpUrl.Companion.toHttpUrl` — is what a Kotlin caller's
// resolved call carries, and what the pack now matches.
package okhttp3

class HttpUrl private constructor() {
    companion object {
        fun String.toHttpUrl(): HttpUrl = HttpUrl()
        fun String.toHttpUrlOrNull(): HttpUrl? = HttpUrl()
    }
}
