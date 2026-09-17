package io.awspring.cloud.sqs.annotation

annotation class SqsListener(val queueNames: Array<String> = [])
