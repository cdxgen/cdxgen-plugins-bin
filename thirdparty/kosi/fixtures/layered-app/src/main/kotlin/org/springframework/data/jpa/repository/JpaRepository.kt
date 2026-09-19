package org.springframework.data.jpa.repository

import org.springframework.data.repository.CrudRepository

interface JpaRepository<T, ID> : CrudRepository<T, ID>

@Target(AnnotationTarget.FUNCTION)
annotation class Query(val value: String)
