// micronaut-http by shape: the verb annotations and @CustomHttpMethod.
package io.micronaut.http.annotation

annotation class Controller(val value: String = "")
annotation class Head(val value: String = "")
annotation class Options(val value: String = "")
annotation class Trace(val value: String = "")
annotation class CustomHttpMethod(val method: String, val value: String = "")
