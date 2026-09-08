// 08-VERSION-POLICY.md §4 fixture 3: syntax from the NEXT version. The 2.4.0
// stable parser cannot be expected to accept whatever 2.5 finalises; what is
// asserted (in the EAP CI job only) is that the kotlin-version diagnostic
// names the module and ceiling, and no resolution error is presented as a
// finding. The source uses 2.4's newest constructs, so an EAP compiler
// parses it and the job verifies resolution keeps working across the bump.
//
// Negative half: the version mismatch must never surface as a parse-error
// attributed to the user's code.
// kosi:want-not diagnostic code=parse-error
//
// Positive half.
// kosi:want diagnostic code=kotlin-version
// kosi:want declaration name=Holder kind=class
package fixtures.ahead

class Holder {
    val held: String
        field = "held"
}
