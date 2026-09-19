// Spring Data's @Query at its real package; the value declares the query.
package org.springframework.data.repository.query

@Target(AnnotationTarget.FUNCTION)
annotation class Query(val value: String)
