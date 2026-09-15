// Negative half first.
// kosi:want-not diagnostic code=parse-error
// kosi:want-not usage name=requireNotNull
// kosi:want-not declaration name=Unused kind=class
//
// Positive half.
// kosi:want usage name=plus
// kosi:want declaration name=findUser kind=function
// kosi:want declaration name=User kind=data-class
// kosi:want declaration name=display kind=function
package fixtures.nullsafety

data class User(val id: Int, val name: String?)

fun findUser(id: Int?): User? = id?.let { User(it, "u$it") }

fun display(user: User?): String {
    val label = user?.name ?: "anonymous"
    return "user: " + label
}
