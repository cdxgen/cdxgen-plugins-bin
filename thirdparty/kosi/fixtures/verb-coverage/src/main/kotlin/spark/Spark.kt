// spark-core 2.9 by shape: Spark's static route builders.
package spark

fun interface Route {
    fun handle(request: Any, response: Any): Any
}

object Spark {
    @JvmStatic fun patch(path: String, route: Route) {}
    @JvmStatic fun head(path: String, route: Route) {}
    @JvmStatic fun options(path: String, route: Route) {}
    @JvmStatic fun trace(path: String, route: Route) {}
    @JvmStatic fun connect(path: String, route: Route) {}
}
