// Negative half: a homonym annotation in a DIFFERENT package is a different
// type. Name-matched detection would root BookingApi too; the type-resolved
// root must not. BookingApi is internal with no callers, so if this file's
// fixtures.api.GetMapping were mistaken for the framework annotation,
// `--roots exported` would root it and the want-not below would fail.
// kosi:want-not reachable symbol=~BookingApi.bookings mode=exported
// kosi:want-not diagnostic code=parse-error
package fixtures.api

annotation class GetMapping(val value: String = "")

internal class BookingApi {
    @GetMapping("/bookings")
    internal fun bookings(): List<String> = listOf("b1")
}
