package com.acme.infra

import com.acme.repo.OrderRepository
import com.acme.service.AuditedOrderService
import com.acme.service.DefaultOrderService
import com.acme.service.OrderService

/**
 * The container's BINDING (P26 §2): the interface is bound to
 * DefaultOrderService, wrapped in the audit decorator. LoggingOrderService is
 * never bound, so nothing it does may appear in a finding.
 */
class Wiring {
    fun orderService(repository: OrderRepository): OrderService =
        AuditedOrderService(DefaultOrderService(repository), "audit")
}
