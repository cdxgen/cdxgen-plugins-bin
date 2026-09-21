// grpc-java's response channel (grpc.io docs, generated code:
// "public void unaryExample(RequestType request,
// StreamObserver<ResponseType> responseObserver)"). The observer is
// the framework's own parameter — responses travel OUT through it — and a
// declared context type under handlerInput=all.
package io.grpc.stub

interface StreamObserver<V> {
    fun onNext(value: V)
}
