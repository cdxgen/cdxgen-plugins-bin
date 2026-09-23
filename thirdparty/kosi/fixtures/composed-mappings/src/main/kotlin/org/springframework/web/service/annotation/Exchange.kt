// spring-web 6.1 by shape: the HTTP-interface annotations, usable on
// server-side controllers too.
package org.springframework.web.service.annotation

annotation class HttpExchange(val value: String = "", val url: String = "", val method: String = "")
annotation class GetExchange(val value: String = "", val url: String = "")
annotation class PostExchange(val value: String = "", val url: String = "")
annotation class PutExchange(val value: String = "", val url: String = "")
annotation class PatchExchange(val value: String = "", val url: String = "")
annotation class DeleteExchange(val value: String = "", val url: String = "")
