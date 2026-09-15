// Ktor's own annotation, at its real fully-qualified name.
package io.ktor.resources

@Target(AnnotationTarget.CLASS) annotation class Resource(val value: String = "")
