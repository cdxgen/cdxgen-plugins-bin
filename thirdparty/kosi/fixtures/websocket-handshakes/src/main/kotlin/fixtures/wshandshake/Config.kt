// WebSocket handshakes registered in code (docs.spring.io websocket
// reference): a STOMP endpoint and a raw handler, each an HTTP GET that
// upgrades; `.withSockJS()` also serves the SockJS transports.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=spring-mvc path=/portfolio method=GET fn=~registerStompEndpoints mode=resolved
// kosi:want endpoint framework=spring-mvc path=/portfolio/info method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/portfolio/{server}/{session}/{transport} method=POST mode=resolved
// kosi:want endpoint framework=spring-mvc path=/stomp-plain method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/echo method=GET fn=~EchoHandler.handleTextMessage mode=resolved
//
// Negative half: SockJS URLs exist only where withSockJS() is chained; a
// handshake is a GET, never a POST.
// kosi:want-not endpoint framework=spring-mvc path=/stomp-plain/info
// kosi:want-not endpoint framework=spring-mvc path=/echo/info
// kosi:want-not endpoint framework=spring-mvc path=/echo method=POST
// A handshake path read at run time is kept, unresolved.
// kosi:want endpoint framework=spring-mvc pathunresolved=~fold fn=~registerStompEndpoints mode=resolved
package fixtures.wshandshake

import org.springframework.web.socket.TextMessage
import org.springframework.web.socket.WebSocketSession
import org.springframework.web.socket.config.annotation.StompEndpointRegistry
import org.springframework.web.socket.config.annotation.WebSocketConfigurer
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer
import org.springframework.web.socket.handler.TextWebSocketHandler

class EchoHandler : TextWebSocketHandler() {
    override fun handleTextMessage(session: WebSocketSession, message: TextMessage) {}
}

class StompConfig : WebSocketMessageBrokerConfigurer {
    override fun registerStompEndpoints(registry: StompEndpointRegistry) {
        registry.addEndpoint("/portfolio").setAllowedOrigins("*").withSockJS()
        registry.addEndpoint("/stomp-plain")
        registry.addEndpoint(System.getenv("WS_PATH") ?: "/ws")
    }
}

class RawConfig : WebSocketConfigurer {
    override fun registerWebSocketHandlers(registry: WebSocketHandlerRegistry) {
        registry.addHandler(EchoHandler(), "/echo")
    }
}
