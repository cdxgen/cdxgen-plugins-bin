// AWS Lambda's handler interfaces (aws-lambda-java-core 1.4.0, the artifact
// the symbol-evidence extract pins): implementing one is the event entry
// point — a supertype-shaped endpoint, like gRPC's ImplBase.
package com.amazonaws.services.lambda.runtime

fun interface RequestHandler<I, O> {
    fun handleRequest(input: I, context: Any): O
}

fun interface RequestStreamHandler {
    fun handleRequest(input: java.io.InputStream, output: java.io.OutputStream, context: Any)
}
