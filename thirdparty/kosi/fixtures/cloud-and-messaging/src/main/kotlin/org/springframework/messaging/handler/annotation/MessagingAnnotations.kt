package org.springframework.messaging.handler.annotation

annotation class MessageMapping(val value: String = "")

annotation class Payload

annotation class DestinationVariable(val value: String = "")

annotation class Header(val value: String = "")
