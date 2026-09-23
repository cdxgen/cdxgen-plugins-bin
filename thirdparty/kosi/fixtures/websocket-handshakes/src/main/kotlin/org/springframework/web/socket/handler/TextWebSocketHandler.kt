package org.springframework.web.socket.handler

import org.springframework.web.socket.TextMessage
import org.springframework.web.socket.WebSocketHandler
import org.springframework.web.socket.WebSocketSession

abstract class TextWebSocketHandler : WebSocketHandler {
    protected open fun handleTextMessage(session: WebSocketSession, message: TextMessage) {}
}
