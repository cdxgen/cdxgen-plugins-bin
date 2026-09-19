// The layered application: handler -> service -> mapper -> repository ->
// JDBC, five real types in five files, an interface between service and
// repository with THREE implementations of which exactly one sinks, and a
// sanitized sibling request path that must report nothing.
//
// Negative half first: the sanitized sibling runs the SAME layers and the
// SAME sinking implementation, and differs only by the UUID.fromString
// sanitizer at the mapper - a propagation rule that ignores it fails here.
// kosi:want-not flow source=untrusted-input sink=sql-query fn=~handleSanitized
// kosi:want-not diagnostic code=parse-error
//
// Positive half: the deep flow, with its frame contract. Six frames minimum,
// naming the mapper and the sinking repository implementation in order.
// kosi:want flow source=untrusted-input sink=sql-query fn=~handle frames=6 via=fn:~OrderMapper.map,fn:~JdbcOrderRepository.query
package fixtures.deep.layered

class OrderHandler(private val service: OrderService) {
    fun handle(customerId: String) {
        val raw = readLine() ?: customerId
        val order = service.placeOrder(raw)
        requireNotNull(order) { "order rejected" }
    }

    fun handleSanitized(customerId: String) {
        val raw = readLine() ?: customerId
        val order = service.placeSanitized(raw)
        requireNotNull(order) { "order rejected" }
    }
}
