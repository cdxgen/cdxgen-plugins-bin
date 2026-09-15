package io.micronaut.http.annotation

annotation class Controller(val value: String)
annotation class Get(val value: String)
annotation class Consumes(val value: Array<String>)
annotation class Produces(val value: Array<String>)
