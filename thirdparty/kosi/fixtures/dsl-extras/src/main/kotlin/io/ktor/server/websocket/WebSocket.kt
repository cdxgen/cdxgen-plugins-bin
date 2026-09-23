package io.ktor.server.websocket

import io.ktor.server.routing.Route

class WebSocketServerSession
fun Route.webSocketRaw(path: String, handler: suspend WebSocketServerSession.() -> Unit) {}
