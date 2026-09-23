package io.micronaut.http.annotation

annotation class Controller(val value: String = "")
annotation class Get(val value: String = "", val uri: String = "", val uris: Array<String> = [])
