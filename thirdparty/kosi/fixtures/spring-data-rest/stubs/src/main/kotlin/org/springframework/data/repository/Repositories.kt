// spring-data-commons 2.x, by shape: PagingAndSortingRepository still
// EXTENDS CrudRepository (3.0 split them); classpath.txt binds 2.6.4.
package org.springframework.data.repository

interface Repository<T, ID>

interface CrudRepository<T, ID> : Repository<T, ID> {
    fun <S : T> save(entity: S): S
    fun findById(id: ID): T?
    fun findAll(): Iterable<T>
    fun delete(entity: T)
    fun deleteById(id: ID)
}

interface PagingAndSortingRepository<T, ID> : CrudRepository<T, ID>
