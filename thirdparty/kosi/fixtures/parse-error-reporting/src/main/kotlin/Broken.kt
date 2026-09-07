// Negative half first: the broken file must not fabricate declarations.
// kosi:want-not declaration name=GhostFunction
// kosi:want-not diagnostic code=kotlin-language-version
//
// Positive half: the parse failure must surface as a diagnostic with a
// position, and the healthy file must still parse.
// kosi:want diagnostic code=parse-error count=1
// kosi:want declaration name=validFunction kind=function
package fixtures.broken

fun brokenFunction( {
    return "unreachable"
}
