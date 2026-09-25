package io.cdxgen.kosi.endpoints

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Templates found converting http4k to OpenAPI (atom-tools#95): a
 * placeholder that names nothing is not a path parameter.
 */
class PathTemplateTest {

    @Test
    fun `http4k end anchor is not a segment or a parameter`() {
        assertEquals("/a", EndpointDetector.normalizePath("/a{$}"))
        assertEquals(emptyList(), EndpointDetector.pathParametersOf("/a{$}"))
    }

    @Test
    fun `an anonymous regex placeholder is not a parameter`() {
        assertEquals(emptyList(), EndpointDetector.pathParametersOf("/{.*}"))
        assertEquals(listOf("id"), EndpointDetector.pathParametersOf("/x/{id}/{.+}"))
    }

    @Test
    fun `named parameters keep their names`() {
        assertEquals(listOf("user-id"), EndpointDetector.pathParametersOf("/users/{user-id}"))
        assertEquals(listOf("id"), EndpointDetector.pathParametersOf("/items/{id: [0-9]+}"))
    }
}
