// Declared at their REAL fully-qualified names: framework matching is on
// resolved identity, so these resolve exactly as the real ones would.
package io.micronaut.http.annotation

@Target(AnnotationTarget.CLASS) annotation class Controller(val value: String = "")

@Target(AnnotationTarget.FUNCTION) annotation class Get(val value: String = "")

@Target(AnnotationTarget.FUNCTION) annotation class Post(val value: String = "")
