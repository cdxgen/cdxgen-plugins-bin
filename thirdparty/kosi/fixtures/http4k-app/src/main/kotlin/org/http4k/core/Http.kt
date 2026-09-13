package org.http4k.core

class Method private constructor(val name: String) {
    companion object {
        val GET = Method("GET")
        val POST = Method("POST")
    }
}

class Request
class Response(val body: String = "")
