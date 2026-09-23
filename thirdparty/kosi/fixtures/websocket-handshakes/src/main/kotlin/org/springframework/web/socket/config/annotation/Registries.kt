// spring-websocket 6.x org.springframework.web.socket.config.annotation by
// shape (API docs): the two registries, their fluent registrations.
package org.springframework.web.socket.config.annotation

import org.springframework.web.socket.WebSocketHandler

interface SockJsServiceRegistration

interface StompWebSocketEndpointRegistration {
    fun setAllowedOrigins(vararg origins: String): StompWebSocketEndpointRegistration
    fun withSockJS(): SockJsServiceRegistration
}

interface StompEndpointRegistry {
    fun addEndpoint(vararg paths: String): StompWebSocketEndpointRegistration
}

interface WebSocketHandlerRegistration {
    fun withSockJS(): SockJsServiceRegistration
}

interface WebSocketHandlerRegistry {
    fun addHandler(handler: WebSocketHandler, vararg paths: String): WebSocketHandlerRegistration
}

interface WebSocketMessageBrokerConfigurer {
    fun registerStompEndpoints(registry: StompEndpointRegistry) {}
}

interface WebSocketConfigurer {
    fun registerWebSocketHandlers(registry: WebSocketHandlerRegistry)
}
