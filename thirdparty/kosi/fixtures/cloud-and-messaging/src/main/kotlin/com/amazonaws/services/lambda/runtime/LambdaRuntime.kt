// AWS Lambda's handler interfaces (aws-lambda-java-core 1.4.0, the artifact
// the symbol-evidence extract pins): implementing one is the event entry
// point — a supertype-shaped endpoint, like gRPC's ImplBase.
package com.amazonaws.services.lambda.runtime

fun interface RequestHandler<I, O> {
    fun handleRequest(input: I, context: Context): O
}

fun interface RequestStreamHandler {
    fun handleRequest(input: java.io.InputStream, output: java.io.OutputStream, context: Context)
}

/**
 * P28 §2: the runtime's own Context (AWS Lambda Java docs: "the context
 * object is of type com.amazonaws.services.lambda.runtime.Context, and is
 * the second argument of the main handler function") — a collaborator the
 * framework supplies, never event data. Stubbed as a class with a FIELD so
 * the fixture can read a field off it: a seeded context would then carry
 * taint into a sink (the FQN — the spelling the pack matches — is the real
 * one; the kind is the stub's own).
 */
open class Context(val functionName: String)
