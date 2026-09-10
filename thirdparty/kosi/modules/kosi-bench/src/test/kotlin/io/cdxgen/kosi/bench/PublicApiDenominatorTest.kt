package io.cdxgen.kosi.bench

import io.cdxgen.kosi.schema.Declaration
import io.cdxgen.kosi.schema.Position
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * R49: the exported-reach denominator must come from a source the call graph
 * did not produce. Counting public GRAPH NODES made the gate a tautology —
 * the exported root selector picks exactly the public local nodes and a root
 * is reached at distance 0, so numerator and denominator were the same set
 * and the fraction was 1.0000 on every fixture and all five pinned repos.
 *
 * Negative first: a public callable the graph never turned into a node must
 * cost a point, because that is the failure the gate exists to catch.
 */
class PublicApiDenominatorTest {

    private fun decl(
        canonicalName: String,
        kind: String,
        visibility: String,
    ): Declaration = Declaration(
        id = canonicalName,
        name = canonicalName.substringAfterLast('.'),
        qualifiedName = ".:$canonicalName",
        canonicalName = canonicalName,
        jvmOwner = null,
        jvmDescriptor = null,
        kind = kind,
        modulePath = ".",
        purl = "pkg:generic/t@unspecified",
        filePath = "src/main/kotlin/T.kt",
        signature = null,
        returnType = null,
        extensionReceiverType = null,
        visibility = visibility,
        modifiers = emptyList(),
        annotations = emptyList(),
        overrides = emptyList(),
        supertypes = emptyList(),
        position = Position("src/main/kotlin/T.kt", 1, 1),
        generated = null,
    )

    /** A library surface with every visibility shape the rule must separate. */
    private fun declarations(): List<Declaration> = listOf(
        decl("t.Api", "class", "public"),
        decl("t.Api.run", "method", "public"),
        decl("t.Api.hook", "method", "protected"),
        decl("t.Api.helper", "method", "private"),
        decl("t.Hidden", "class", "internal"),
        // Public member of a non-public class: not API, whatever it says.
        decl("t.Hidden.row", "method", "public"),
        decl("t.topLevel", "function", "public"),
        decl("t.internalTopLevel", "function", "internal"),
        // Not callable: a property is not a graph node.
        decl("t.Api.field", "property", "public"),
    )

    @Test
    fun theDenominatorCountsOnlyConsumerNameableCallables() {
        val names = GraphMetrics.publicCallableNames(declarations())
        assertEquals(setOf("t.Api.run", "t.Api.hook", "t.topLevel"), names)
    }

    @Test
    fun aPublicMemberOfANonPublicClassIsNotApi() {
        assertTrue("t.Hidden.row" !in GraphMetrics.publicCallableNames(declarations()))
    }

    @Test
    fun anAbsentVisibilityFactWidensTheDenominatorRatherThanShrinkingIt() {
        // Missing facts must never make the gate easier to pass: an
        // `unknown` visibility counts IN, so a resolution shortfall shows up
        // as a reach shortfall instead of quietly deleting the obligation.
        val withUnknown = declarations() + decl("t.mystery", "function", "unknown")
        assertTrue("t.mystery" in GraphMetrics.publicCallableNames(withUnknown))
    }
}
