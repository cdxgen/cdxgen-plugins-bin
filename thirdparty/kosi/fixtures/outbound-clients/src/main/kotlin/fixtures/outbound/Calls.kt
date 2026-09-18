// P19 §4: the outbound client rows the pack models, each called once with a
// distinct literal URL so the row is LIVE (removing it changes this
// fixture's services/urls) and the service row is pinned. The JDK clients
// (java.net.URI, java.net.http) need no stub; the rest carry minimal
// real-package stubs shaped as their call sites.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// kosi:want service protocol=mongodb name=mongodb://mongo.example.com resolution=literal mode=resolved
// kosi:want service protocol=grpc name=grpc://orders.example.com resolution=literal mode=resolved
// kosi:want service protocol=grpc name=grpc://inventory.example.com resolution=literal mode=resolved
// kosi:want service protocol=redis name=redis://cache.example.com resolution=literal mode=resolved
// kosi:want service protocol=uri name=uri://plain.example.com/path resolution=literal mode=resolved
// kosi:want service protocol=https name=cdn.example.com resolution=literal mode=resolved
// kosi:want service protocol=bolt name=bolt://graph.example.com resolution=literal mode=resolved
// kosi:want service protocol=https name=rest.example.com resolution=literal mode=resolved
// kosi:want service protocol=http name=webclient.example.com resolution=literal mode=resolved
// kosi:want service protocol=redis name=jedis.example.com resolution=literal mode=resolved
// kosi:want service protocol=https name=api.example.com resolution=literal mode=resolved
// kosi:want service protocol=https name=okhttp.example.com resolution=literal mode=resolved
// kosi:want service protocol=https name=ktor-client.example.com resolution=literal mode=resolved
// kosi:want service protocol=https name=ktor-post.example.com resolution=literal mode=resolved
package fixtures.outbound

import com.mongodb.ConnectionString
import io.grpc.ManagedChannelBuilder
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.lettuce.core.RedisClient
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import okhttp3.Request
import org.neo4j.driver.GraphDatabase
import org.springframework.web.client.RestTemplate
import org.springframework.web.reactive.function.client.WebClient
import redis.clients.jedis.JedisPool
import retrofit2.Retrofit

fun allCalls(): List<Any> = listOf(
    ConnectionString("mongodb://mongo.example.com"),
    ManagedChannelBuilder.forTarget("grpc://orders.example.com"),
    ManagedChannelBuilder.forAddress("grpc://inventory.example.com", 9000),
    RedisClient.create("redis://cache.example.com"),
    URI("uri://plain.example.com/path"),
    HttpRequest.newBuilder().uri(URI("https://cdn.example.com/assets")).build(),
    GraphDatabase.driver("bolt://graph.example.com"),
    RestTemplate().getForObject("https://rest.example.com/x", String::class.java),
    WebClient.create("http://webclient.example.com"),
    JedisPool("jedis.example.com", 6379),
    Retrofit.Builder().baseUrl("https://api.example.com/v1/"),
    Request.Builder().url("https://okhttp.example.com/download"),
    get("https://ktor-client.example.com/a"),
    post("https://ktor-post.example.com/b"),
    HttpClient.newHttpClient(),
)
