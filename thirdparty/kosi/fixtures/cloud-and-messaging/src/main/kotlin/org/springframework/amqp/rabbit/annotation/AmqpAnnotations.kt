package org.springframework.amqp.rabbit.annotation

annotation class RabbitListener(val queues: Array<String> = [])
