package io.javalin.config

class RouterConfig {
    var contextPath: String = "/"
}

class JavalinConfig {
    var contextPath: String = "/"
    val router: RouterConfig = RouterConfig()
}
