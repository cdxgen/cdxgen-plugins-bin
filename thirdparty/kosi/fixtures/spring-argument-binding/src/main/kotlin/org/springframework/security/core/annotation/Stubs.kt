// Declared at their REAL fully-qualified names so the fixture needs no
// Spring or servlet jar: framework matching is on resolved identity.
package org.springframework.security.core.annotation

@Target(AnnotationTarget.VALUE_PARAMETER, AnnotationTarget.FUNCTION, AnnotationTarget.FIELD)
annotation class AuthenticationPrincipal

@Target(AnnotationTarget.VALUE_PARAMETER, AnnotationTarget.FUNCTION, AnnotationTarget.FIELD)
annotation class CurrentSecurityContext
