// Negative half first.
// kosi:want-not diagnostic code=parse-error
// kosi:want-not module name=meta:iosMain platform=native
//
// Positive half: expect/actual produces one logical declaration with
// per-target bodies; all three must be discovered with their platforms.
// kosi:want module name=meta:commonMain platform=common
// kosi:want module name=meta:androidMain platform=android
// kosi:want module name=meta:jvmMain platform=jvm
// kosi:want declaration name=platformName kind=function count=3
// kosi:want declaration name=platformName count=3
package fixtures.kmp

expect fun platformName(): String
