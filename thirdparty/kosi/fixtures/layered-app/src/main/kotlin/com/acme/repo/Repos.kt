package com.acme.repo

import com.acme.dto.OrderRow
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query

/**
 * The SINK layer. A Spring Data repository interface: user code with no
 * body, matched on the base it extends.
 */
interface OrderRepository : JpaRepository<OrderRow, Long> {
    /** A DERIVED query: the method name is the query. */
    fun findByName(name: String): List<OrderRow>

    @Query("SELECT o FROM OrderRow o WHERE o.name = :name")
    fun searchByName(name: String): List<OrderRow>
}

/** The negative: same method shape, no repository base. */
interface NotARepository {
    fun findByName(name: String): List<OrderRow>
}
