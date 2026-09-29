package org.springframework.web.bind.annotation

annotation class GetMapping(vararg val value: String = [], val path: Array<String> = [])
annotation class RestController
annotation class RequestParam(val value: String = "")
annotation class PathVariable(val value: String = "")
