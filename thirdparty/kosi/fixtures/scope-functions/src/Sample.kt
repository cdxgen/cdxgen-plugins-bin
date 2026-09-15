// Negative half (written first): symbols that must NOT be attributed.
// kosi:want-not usage name=java.util.ArrayList
// kosi:want-not diagnostic code=parse-error
// kosi:want-not declaration kind=interface
//
// Positive half: taint crosses `it` and the implicit receiver of scope
// functions; at the syntax tier the usage evidence must at least name them.
// kosi:want usage name=~.let
// kosi:want usage name=~.apply
// kosi:want usage name=~.run
// kosi:want declaration name=readConfig kind=function
// kosi:want declaration name=Server kind=data-class
package fixtures.scope

data class Server(val host: String, val port: Int) {
    fun url(): String = "http://$host:$port"
}

fun readConfig(raw: Map<String, String>): String {
    val server = raw["host"]?.let { Server(it, raw["port"]?.toIntOrNull() ?: 80) }
    return server?.apply { check(port in 1..65535) }?.run { url() } ?: "invalid"
}
