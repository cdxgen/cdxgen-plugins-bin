// Negative half first.
// kosi:want-not declaration name=Tester kind=class
// kosi:want-not diagnostic code=parse-error
//
// Positive half: workspace member discovery plus the version clamp.
// kosi:want module name=core platform=jvm
// kosi:want module name=app platform=jvm
// kosi:want diagnostic code=kotlin-language-version
// kosi:want declaration name=Validator kind=class
// kosi:want declaration name=bootstrap kind=function
// kosi:want usage name=~.validate
package fixtures.app

import fixtures.core.Validator

fun bootstrap(input: String): Boolean = Validator().validate(input)
