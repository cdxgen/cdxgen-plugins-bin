// spring-data-commons 3.x, by shape: PagingAndSortingRepository extends
// Repository ALONE and declares only the paged findAll.
package org.springframework.data.repository

interface Repository<T, ID>

interface CrudRepository<T, ID> : Repository<T, ID> {
    fun <S : T> save(entity: S): S
    fun findById(id: ID): T?
    fun findAll(): Iterable<T>
    fun delete(entity: T)
}

interface PagingAndSortingRepository<T, ID> : Repository<T, ID> {
    fun findAll(page: Int): Iterable<T>
}
