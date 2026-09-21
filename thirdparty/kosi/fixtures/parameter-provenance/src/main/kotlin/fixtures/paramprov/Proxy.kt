// the depth report's PARAMETER bucket had never been non-zero —
// no bundled fixture had ever asked the folder for a value whose provenance
// is a HANDLER PARAMETER, which is the fold's honest boundary by definition
// (a parameter's value is the caller's; no amount of folding proves it).
// The zero was the shape waiting: a bucket nobody drives is a bucket
// nobody measures.
//
// The shape is the forward-proxy handler: the URL the code fetches is
// whatever the caller passed in. The outbound row's resolution is
// `unresolved` and its raw rendering is the register the lowering chose —
// the honest rendering of a value kosi cannot prove, and the same shape
// the defect made the whole fold fall back to.
//
// kosi:want-not diagnostic code=parse-error
//
// The parameter-provenance row itself: unresolved, never a guessed host.
// kosi:want service protocol=https resolution=unresolved mode=resolved
// kosi:want-not service protocol=https name=~upstream.example.internal mode=resolved
package fixtures.paramprov

import okhttp3.Request

/** `upstreamUrl` is the handler's parameter: its value is the CALLER's. */
fun forward(upstreamUrl: String) {
    Request.Builder().url(upstreamUrl)
}

class ProxyServlet {
    fun handle(upstreamUrl: String, count: Int) {
        repeat(count) {
            Request.Builder().url(upstreamUrl)
        }
    }
}
