// Spring Data's repository interface at its real fully-qualified name.
package org.springframework.data.repository

interface CrudRepository<T, ID> {
    fun findById(id: ID): T?
    fun save(entity: T): T
}
