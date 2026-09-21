// — outbound as SERVICES: the annotated interface method IS the call.
//
// Retrofit and Feign declare remote calls as annotated methods on an
// interface the library implements at runtime: there is no body to walk and
// no call-site URL argument. The outbound row attaches at the CALL of the
// annotated method, with the path from the annotation's value where the
// pipeline carries it (resolution=literal) and the callee's FQN where it
// cannot (resolution=unresolved — never a guess).
//
// Positives (each interface method call must publish a services[] row):
// kosi:want service protocol=https path=users/{id} mode=resolved
// kosi:want service protocol=https path=orders mode=resolved
// kosi:want service protocol=https path=~users resolution=literal mode=resolved
// kosi:want service protocol=https name=api.example.com resolution=literal mode=resolved
//
// Negative: a same-SHAPED annotation in the wrong package is a different
// annotation — resolved-FQN matching, never name matching.
// kosi:want-not service protocol=https path=homonym/{x} mode=resolved
// kosi:want-not diagnostic code=parse-error
package fixtures.outbound

import feign.RequestLine
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST

interface UserService {
    @GET("users/{id}")
    fun user(id: String): String

    @POST("orders")
    fun create(body: String): String

    @DELETE("users/{id}/token")
    fun revoke(id: String)
}

interface AdminApi {
    @RequestLine("GET /users")
    fun users(): List<String>
}

fun callsRetrofit(users: UserService, id: String) {
    users.user(id)
    users.create("body")
    users.revoke(id)
}

fun callsFeign(api: AdminApi) {
    api.users()
}

fun baseUrlIsARow() {
    val retrofit = retrofit2.Retrofit.Builder().baseUrl("https://api.example.com/").build()
    retrofit.create(UserService::class.java)
}
