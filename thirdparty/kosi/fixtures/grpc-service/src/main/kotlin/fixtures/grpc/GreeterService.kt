// Positive half: every OVERRIDE on the ImplBase subclass is an RPC, at its
// wire path `/{Service-Name}/{method}` (grpc PROTOCOL-HTTP2.md) where the
// service name carries the proto package and the method its proto spelling:
// `/helloworld.Greeter/SayHello`, never the stub's `/Greeter/sayHello`.
// kosi:want endpoint framework=grpc path=/helloworld.Greeter/SayHello fn=~.GreeterService.sayHello pathunresolved=none mode=resolved
// the observer arm — request seeds (want), observer does not
// (want-not), both under handlerInput=all with StreamObserver declared.
// kosi:want endpoint framework=grpc path=/helloworld.Greeter/SayHello fn=~ObserverGreeterService.sayHello mode=resolved
// Exactly ONE flow out of this function (request -> exec): the count is
// the pin — a seeded observer would make it two.
// kosi:want flow source=untrusted-input sink=process-exec fn=~ObserverGreeterService.sayHello count=1 mode=endpoint
// kosi:want endpoint framework=grpc path=/helloworld.Greeter/StreamGreetings fn=~GreeterService.streamGreetings mode=resolved
// The coroutine stub: the service is `Inventory`, never `InventoryCoroutine`.
// No .proto declares it, so its path is best-effort and says so.
// kosi:want endpoint framework=grpc path=/Inventory/ListItems fn=~InventoryService.listItems pathunresolved=~proto mode=resolved
// kosi:want-not endpoint framework=grpc path=~/InventoryCoroutine/listItems mode=resolved
// kosi:want-not endpoint framework=grpc fn=~UserService.load mode=resolved
// kosi:want-not endpoint framework=grpc path=~/Unknown/rpc mode=resolved
// kosi:want-not endpoint framework=grpc path=/Greeter/sayHello
// kosi:want-not endpoint framework=grpc fn=~GreeterService.helper
package fixtures.grpc

class GreeterService : GreeterGrpcKt.GreeterImplBase() {
    override suspend fun sayHello(request: HelloRequest): HelloReply =
        HelloReply("hello " + request.name)

    override suspend fun streamGreetings(request: HelloRequest): HelloReply =
        HelloReply("hi")

    /** A helper on the service class: not in the service descriptor, not an RPC. */
    fun helper(): String = "not-an-rpc"
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
