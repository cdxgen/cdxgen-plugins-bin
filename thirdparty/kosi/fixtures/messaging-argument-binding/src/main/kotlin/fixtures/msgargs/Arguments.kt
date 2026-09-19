// P27 §2 — spring-messaging's ARGUMENT BINDING rule, one handler per framework-supplied type.
//
// From web/websocket/stomp/handle-annotations.html, verbatim:
//
//   "The presence of this annotation is not required since it is, by default, assumed if no other argument is matched."
//
// kosi had this framework as handlerInput=annotated, which seeds NOTHING for
// a handler that binds without annotations. Each want-not below is one
// framework-supplied type: drop its pack entry and that handler reports.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_messaging_Message
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_messaging_MessageHeaders
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_messaging_support_MessageHeaderAccessor
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_messaging_simp_SimpMessageHeaderAccessor
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_org_springframework_messaging_simp_stomp_StompHeaderAccessor
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~ctx_java_security_Principal
// kosi:want flow source=untrusted-input sink=process-exec fn=~unannotatedIsBound mode=endpoint
package fixtures.msgargs

/** What the framework binds from the request. */
class Command {
    var value: String = ""
}

class ArgumentApi {

    @org.springframework.messaging.handler.annotation.MessageMapping("/m")
    fun ctx_org_springframework_messaging_Message(arg: org.springframework.messaging.Message<String>): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.messaging.handler.annotation.MessageMapping("/m")
    fun ctx_org_springframework_messaging_MessageHeaders(arg: org.springframework.messaging.MessageHeaders): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.messaging.handler.annotation.MessageMapping("/m")
    fun ctx_org_springframework_messaging_support_MessageHeaderAccessor(arg: org.springframework.messaging.support.MessageHeaderAccessor): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.messaging.handler.annotation.MessageMapping("/m")
    fun ctx_org_springframework_messaging_simp_SimpMessageHeaderAccessor(arg: org.springframework.messaging.simp.SimpMessageHeaderAccessor): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.messaging.handler.annotation.MessageMapping("/m")
    fun ctx_org_springframework_messaging_simp_stomp_StompHeaderAccessor(arg: org.springframework.messaging.simp.stomp.StompHeaderAccessor): Process =
        ProcessBuilder(arg.toString()).start()

    @org.springframework.messaging.handler.annotation.MessageMapping("/m")
    fun ctx_java_security_Principal(arg: java.security.Principal): Process =
        ProcessBuilder(arg.toString()).start()

    /**
     * The rule this fixture exists for: an unannotated parameter is bound
     * from the request, so it carries attacker input.
     */
    @org.springframework.messaging.handler.annotation.MessageMapping("/m2")
    fun unannotatedIsBound(payload: Command): Process = ProcessBuilder(payload.value).start()
}
