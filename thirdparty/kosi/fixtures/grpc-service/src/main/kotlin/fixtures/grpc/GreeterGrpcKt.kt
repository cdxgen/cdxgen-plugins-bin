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
    }
}
