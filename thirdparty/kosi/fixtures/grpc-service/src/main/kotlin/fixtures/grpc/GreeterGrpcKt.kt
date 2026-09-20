// The generated gRPC Kotlin base, in the shape grpc-kotlin emits it: a
// file-level holder class with the abstract ImplBase. The detector keys on
// the supertype NAME (contains Grpc, ends ImplBase), resolved as a real
// type here.
package fixtures.grpc

class HelloRequest(val name: String = "")
class HelloReply(val message: String = "")

object GreeterGrpcKt {
    abstract class GreeterImplBase {
        open suspend fun sayHello(request: HelloRequest): HelloReply = HelloReply()

        /**
         * P28 §2: the grpc-JAVA signature (grpc.io generated-code docs:
         * "unaryExample(RequestType request, StreamObserver<ResponseType>
         * responseObserver)") — the response observer rides beside the
         * request as the framework's own parameter.
         */
        open fun sayHello(request: HelloRequest, responseObserver: io.grpc.stub.StreamObserver<HelloReply>) {}
    }
}

/**
 * The shape grpc-kotlin ACTUALLY emits for a coroutine service:
 * `<Service>GrpcKt.<Service>CoroutineImplBase`. Stripping only `ImplBase`
 * names the service `InventoryCoroutine` — a service that exists in no
 * proto and matches no traffic.
 */
object InventoryGrpcKt {
    abstract class InventoryCoroutineImplBase {
        open suspend fun listItems(request: HelloRequest): HelloReply = HelloReply()
    }
}
