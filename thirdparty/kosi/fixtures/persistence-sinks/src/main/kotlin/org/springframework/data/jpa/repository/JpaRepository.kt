// Spring Data JPA's base and its @Query, at their REAL package: `JpaRepository`
// and `@Query` live under `org.springframework.data.jpa.repository`, NOT under
// `org.springframework.data.repository` where the plain bases live. Stubbing
// them at the wrong package made the fixture and the pack row agree with each
// other and with nothing else — the self-certification P26 exists to end.
package org.springframework.data.jpa.repository

import org.springframework.data.repository.CrudRepository

interface JpaRepository<T, ID> : CrudRepository<T, ID>

@Target(AnnotationTarget.FUNCTION)
annotation class Query(val value: String)
