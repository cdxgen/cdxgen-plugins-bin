// Java signatures whose TYPE is a Kotlin declaration (atom-tools#95,
// follow-up): a Java field or method typed by a Kotlin interface or class
// makes the Analysis API build a cache shape no Kotlin-only fixture builds,
// and the native image died on it (`kosi: com.github.benmanes.caffeine.
// cache.WIA`, exit 3) while the JVM jar completed. On the native gate
// (scripts/native-subset.txt): the image must complete and agree.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want declaration name=Holder kind=class known-fail=syntax:2
// kosi:want declaration name=Returns kind=class known-fail=syntax:2
// kosi:want declaration name=Implements kind=class known-fail=syntax:2
// kosi:want declaration name=Service kind=interface
// kosi:want declaration name=Model kind=class
package fixtures.javasig

interface Service

class Model
