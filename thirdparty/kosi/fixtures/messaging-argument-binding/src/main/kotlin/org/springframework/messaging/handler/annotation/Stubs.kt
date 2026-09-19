// Declared at their REAL fully-qualified names: framework matching is on
// resolved identity, so these resolve exactly as the real ones would.
package org.springframework.messaging.handler.annotation

@Target(AnnotationTarget.FUNCTION) annotation class MessageMapping(val value: String = "")
