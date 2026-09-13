// Negative half: a homonym ImplBase WITHOUT the Grpc marker in its
// supertype name. The marker+suffix rule must refuse it even though the
// suffix matches; a commented-out rpc stays commented.
// kosi:want-not endpoint framework=grpc path=~/User/load mode=resolved
package fixtures.grpcbad

abstract class UserImplBase {
    open fun load(id: String): String = ""
}

class UserService : UserImplBase() {
    override fun load(id: String): String = "u"
    // fun unknownRpc(id: String): String = "nope"
}
