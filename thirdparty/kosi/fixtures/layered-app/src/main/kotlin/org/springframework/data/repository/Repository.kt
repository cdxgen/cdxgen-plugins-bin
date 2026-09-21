// Spring Data's plain bases live here; JpaRepository lives one package
// deeper, under org.springframework.data.jpa.repository.
package org.springframework.data.repository

interface Repository<T, ID>
interface CrudRepository<T, ID> : Repository<T, ID>
