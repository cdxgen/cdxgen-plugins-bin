// Negative half first.
// kosi:want-not declaration name=Unknown kind=sealed-class
// kosi:want-not usage name=println
// kosi:want-not diagnostic code=parse-error
//
// Positive half: sealed hierarchies give dispatch a closed target set.
// kosi:want declaration name=Event kind=sealed-class
// kosi:want declaration name=Login kind=data-class
// kosi:want declaration name=Logout kind=data-class
// kosi:want declaration name=handle kind=function
package fixtures.events

sealed class Event {
    data class Login(val user: String) : Event()
    data class Logout(val user: String) : Event()
}

fun handle(event: Event): Int = when (event) {
    is Event.Login -> 1
    is Event.Logout -> 2
}
