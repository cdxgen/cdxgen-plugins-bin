package com.acme.service

import com.acme.dto.OrderCommand
import com.acme.dto.OrderRequest
import com.acme.dto.OrderRow
import com.acme.infra.Escaping
import com.acme.repo.OrderRepository
import org.springframework.stereotype.Service

/**
 * The service SEAM: an interface, two implementations, one of them
 * container-managed — the dispatch question answered.
 */
interface OrderService {
    fun place(request: OrderRequest): List<OrderRow>
    fun placeSafely(request: OrderRequest): List<OrderRow>
    val lastTrace: String
}

/** The mapper layer: fields move between objects (the object identity). */
object OrderMapper {
    fun toCommand(request: OrderRequest): OrderCommand =
        OrderCommand(request.customerName, request.note)

    /** A getter-shaped read — the channel. */
    fun nameOf(command: OrderCommand): String = command.name
}

@Service
class DefaultOrderService(private val repository: OrderRepository) : OrderService {

    private var trace: String = "none"

    /** The GETTER: a field of the receiver becomes the return. */
    override val lastTrace: String get() = trace

    override fun place(request: OrderRequest): List<OrderRow> {
        val command = OrderMapper.toCommand(request)
        trace = command.trace
        // Through a collection, then back out — the element channel.
        val batch = mutableListOf<String>()
        batch.add(OrderMapper.nameOf(command))
        return repository.findByName(batch[0])
    }

    /** The SANITIZED path: the same shape, cleaned before the sink. */
    override fun placeSafely(request: OrderRequest): List<OrderRow> {
        val command = OrderMapper.toCommand(request)
        return repository.searchByName(Escaping.escapeSql(OrderMapper.nameOf(command)))
    }
}

/** The unbound sibling: the container never wires it, so it never runs. */
class LoggingOrderService(private val repository: OrderRepository) : OrderService {
    override val lastTrace: String get() = "logging"
    override fun place(request: OrderRequest): List<OrderRow> =
        repository.findByName(request.customerName)
    override fun placeSafely(request: OrderRequest): List<OrderRow> = emptyList()
}

/**
 * The DECORATOR: `by`-delegation around the service seam. Every
 * member of OrderService exists on this class as a generated forwarder, and
 * the request reaching the sink has to cross one.
 */
class AuditedOrderService(
    private val inner: OrderService,
    private val auditTag: String,
) : OrderService by inner
