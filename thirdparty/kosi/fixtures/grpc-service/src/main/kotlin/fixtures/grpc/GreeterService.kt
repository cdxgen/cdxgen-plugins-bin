// Positive half: every concrete method on the ImplBase subclass is an RPC
// endpoint with the /<Service>/<Method> path.
// kosi:want endpoint framework=grpc path=/Greeter/sayHello fn=~GreeterService.sayHello mode=resolved
// kosi:want endpoint framework=grpc path=/Greeter/streamGreetings fn=~GreeterService.streamGreetings mode=resolved
// The coroutine stub: the service is `Inventory`, never `InventoryCoroutine`.
// kosi:want endpoint framework=grpc path=/Inventory/listItems fn=~InventoryService.listItems mode=resolved
// kosi:want-not endpoint framework=grpc path=~/InventoryCoroutine/listItems mode=resolved
// kosi:want-not endpoint framework=grpc fn=~UserService.load mode=resolved
// kosi:want-not endpoint framework=grpc path=~/Unknown/rpc mode=resolved
package fixtures.grpc

class GreeterService : GreeterGrpcKt.GreeterImplBase() {
    override suspend fun sayHello(request: HelloRequest): HelloReply =
        HelloReply("hello " + request.name)

    override suspend fun streamGreetings(request: HelloRequest): HelloReply =
        HelloReply("hi")
}

/** A coroutine-stub service: `InventoryCoroutineImplBase`. */
class InventoryService : InventoryGrpcKt.InventoryCoroutineImplBase() {
    override suspend fun listItems(request: HelloRequest): HelloReply =
        HelloReply("items for " + request.name)
}
