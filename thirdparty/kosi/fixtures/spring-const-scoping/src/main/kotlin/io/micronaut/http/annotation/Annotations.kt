package io.micronaut.http.annotation

annotation class Controller(val value: String = "", val produces: Array<String> = [])
annotation class Get(val value: String = "")
annotation class Post(val value: String = "")
