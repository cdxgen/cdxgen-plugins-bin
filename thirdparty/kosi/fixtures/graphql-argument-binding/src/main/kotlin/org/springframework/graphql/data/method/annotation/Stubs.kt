// Declared at their REAL fully-qualified names: framework matching is on
// resolved identity, so these resolve exactly as the real ones would.
package org.springframework.graphql.data.method.annotation

@Target(AnnotationTarget.FUNCTION) annotation class MutationMapping

@Target(AnnotationTarget.FUNCTION) annotation class QueryMapping

@Target(AnnotationTarget.VALUE_PARAMETER)
annotation class ContextValue(val value: String = "")

@Target(AnnotationTarget.VALUE_PARAMETER)
annotation class LocalContextValue(val value: String = "")
