// Spring Data's plain repository bases at their real package: user repository
// interfaces EXTEND these. Spring Data JPA's own base and @Query live one
// package deeper, under `org.springframework.data.jpa.repository`.
package org.springframework.data.repository

interface Repository<T, ID>

interface CrudRepository<T, ID> : Repository<T, ID> {
    fun <S : T> save(entity: S): S
    fun findById(id: ID): T
    fun findAll(): List<T>
    fun deleteById(id: ID)
}

interface PagingAndSortingRepository<T, ID> : Repository<T, ID>
