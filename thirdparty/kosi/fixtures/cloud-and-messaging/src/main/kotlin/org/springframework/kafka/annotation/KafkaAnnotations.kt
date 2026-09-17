package org.springframework.kafka.annotation

annotation class KafkaListener(val topics: Array<String> = [])
