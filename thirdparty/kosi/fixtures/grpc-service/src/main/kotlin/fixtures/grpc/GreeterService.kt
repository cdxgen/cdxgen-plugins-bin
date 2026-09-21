// Positive half: every concrete method on the ImplBase subclass is an RPC
// endpoint with the /<Service>/<Method> path.
// kosi:want endpoint framework=grpc path=/Greeter/sayHello fn=~GreeterService.sayHello mode=resolved
// the observer arm — request seeds (want), observer does not
// (want-not), both under handlerInput=all with StreamObserver declared.
// kosi:want endpoint framework=grpc path=/Greeter/sayHello fn=~ObserverGreeterService.sayHello mode=resolved
// Exactly ONE flow out of this function (request -> exec): the count is
// the pin — a seeded observer would make it two.
// kosi:want flow source=untrusted-input sink=process-exec fn=~ObserverGreeterService.sayHello count=1 mode=endpoint
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

/**
 * The grpc-JAVA shape — the response observer rides beside the
 * request as the framework's own parameter. Only the REQUEST may seed; the
 * observer reaching a sink is the negative pin.
 */
class ObserverGreeterService : GreeterGrpcKt.GreeterImplBase() {
    override fun sayHello(
        request: HelloRequest,
        responseObserver: io.grpc.stub.StreamObserver<HelloReply>,
    ) {
        Runtime.getRuntime().exec(request.name)
        Runtime.getRuntime().exec(responseObserver.toString())
    }
}
