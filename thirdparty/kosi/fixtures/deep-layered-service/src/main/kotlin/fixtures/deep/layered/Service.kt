package fixtures.deep.layered

class OrderService(private val mapper: OrderMapper, private val repository: OrderRepository) {
    fun placeOrder(raw: String): String? {
        val mapped = mapper.map(raw)
        return repository.query(mapped)
    }

    fun placeSanitized(raw: String): String? {
        val mapped = mapper.mapSanitized(raw)
        return repository.query(mapped)
    }
}
