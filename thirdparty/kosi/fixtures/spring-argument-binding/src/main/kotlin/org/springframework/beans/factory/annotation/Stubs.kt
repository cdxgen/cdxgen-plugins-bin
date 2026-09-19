// Declared at their REAL fully-qualified names so the fixture needs no
// Spring or servlet jar: framework matching is on resolved identity.
package org.springframework.beans.factory.annotation

@Target(AnnotationTarget.VALUE_PARAMETER, AnnotationTarget.FUNCTION, AnnotationTarget.FIELD)
annotation class Autowired

@Target(AnnotationTarget.VALUE_PARAMETER, AnnotationTarget.FUNCTION, AnnotationTarget.FIELD)
annotation class Value
