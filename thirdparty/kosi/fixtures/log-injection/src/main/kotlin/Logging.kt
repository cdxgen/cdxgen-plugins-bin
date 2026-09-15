// Negative half first.
// kosi:want-not usage name=System.err.println
// kosi:want-not diagnostic code=parse-error
//
// Positive half: unsanitized input reaching logs.
// kosi:want usage name=println
// kosi:want declaration name=audit kind=function
package fixtures.logging

fun audit(actor: String, action: String) {
    println("AUDIT actor=$actor action=$action")
}
