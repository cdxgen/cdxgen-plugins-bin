package fixtures.deep.layered

fun main() {
    val repository: OrderRepository = JdbcOrderRepository()
    val service = OrderService(OrderMapper(), repository)
    OrderHandler(service).handle("c-1234")
}
