// Spring Data's repository bases at their real package, with the shapes
// the fixture exercises: user repository interfaces EXTEND these.
package org.springframework.data.repository

interface Repository<T, ID>

interface CrudRepository<T, ID> : Repository<T, ID> {
    fun <S : T> save(entity: S): S
    fun findById(id: ID): T
    fun findAll(): List<T>
    fun deleteById(id: ID)
}

interface JpaRepository<T, ID> : CrudRepository<T, ID>
