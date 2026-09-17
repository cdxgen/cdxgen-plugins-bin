package io.cdxgen.kosi.graph

import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.schema.RootScope
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * P20 §4: name what kosi treats as an ENTRYPOINT, and pin it — "an
 * entrypoint set that includes every public callable makes `reachable`
 * mean `exists`", so the scopes' definitions are a consumer contract, not
 * an implementation detail. Three facts are pinned:
 *
 *  1. `handlers` roots EXACTLY the annotation-declared handlers of the
 *     Spring / JAX-RS / Micronaut / messaging families — and NOT the DSL
 *     frameworks (Ktor, Vert.x, Javalin, http4k), whose routes carry no
 *     annotation at all. That gap is named, not papered over: for the DSL
 *     frameworks the taint engine's endpoint seeding (the endpoints pack's
 *     detected handlers) is the entrypoint set, and the graph's
 *     `handlers` scope deliberately does not approximate it.
 *  2. `exported` roots every public/protected callable: in the `exported`
 *     slot, `reachableFromRoots` is the fact that a function EXISTS in the
 *     workspace, never that anything calls it. Pinned by a public orphan —
 *     a root at distance zero with no caller anywhere.
 *  3. `main` and `android` are the narrow scopes they claim: the top-level
 *     `main` only, and the Android component supertypes only.
 */
class RootsVocabularyTest {

    private fun nodesWith(vararg functions: io.cdxgen.kosi.kir.KirFunction): GraphNodes {
        val nodes = GraphNodes(CallGraphBuilder.Attribution.NONE)
        for (fn in functions) nodes.localNode(fn)
        return nodes
    }

    private fun rootNames(scope: RootScope, nodes: GraphNodes): Set<String> {
        val (byScope, _) = Roots.select(listOf(scope to null), nodes.list())
        return byScope.getValue(scope).mapNotNull { key -> nodes.list().firstOrNull { it.key == key }?.canonicalName }.toSet()
    }

    @Test
    fun handlersScopeIsExactlyTheAnnotationDeclaredFamilies() {
        val nodes = nodesWith(
            GraphFixtures.function(
                canonicalName = "t springHandler",
                annotations = listOf("org.springframework.web.bind.annotation.GetMapping"),
            ),
            GraphFixtures.function(
                canonicalName = "t jaxHandler",
                annotations = listOf("jakarta.ws.rs.GET"),
            ),
            GraphFixtures.function(
                canonicalName = "t micronautHandler",
                annotations = listOf("io.micronaut.http.annotation.Controller"),
            ),
            GraphFixtures.function(
                canonicalName = "t messageHandler",
                annotations = listOf("org.springframework.kafka.annotation.KafkaListener"),
            ),
        )
        val roots = rootNames(RootScope.HANDLERS, nodes)
        assertEquals(
            setOf("t springHandler", "t jaxHandler", "t micronautHandler", "t messageHandler"),
            roots,
        )
    }

    @Test
    fun dslFrameworkHandlersAreNotGraphRootsByTheHandlersScope() {
        // The named gap: a Ktor/Vert.x/Javalin/http4k route is a LAMBDA
        // passed to a DSL call — no annotation exists for this scope to
        // read. Their entrypoints live in the endpoints pack's handler set
        // (which the taint engine seeds), and the phase report says so;
        // this pin keeps the graph scope from silently pretending.
        val nodes = nodesWith(
            GraphFixtures.function(
                canonicalName = "t ktorRoute",
                annotations = listOf("io.ktor.server.routing.get"),
            ),
            GraphFixtures.function(
                canonicalName = "t vertxHandler",
                annotations = listOf("io.vertx.ext.web.handler.BasicAuthHandler"),
            ),
        )
        assertTrue(
            rootNames(RootScope.HANDLERS, nodes).isEmpty(),
            "the handlers scope matched a DSL-framework symbol it does not actually declare — " +
                " Roots.FRAMEWORK_ANNOTATIONS grew without the contract growing",
        )
    }

    @Test
    fun exportedScopeRootsEveryPublicCallableOrphanIncluded() {
        val nodes = nodesWith(
            GraphFixtures.function(canonicalName = "t orphan", visibility = "public"),
            GraphFixtures.function(canonicalName = "t hidden", visibility = "private"),
            GraphFixtures.function(
                canonicalName = "t synthetic",
                visibility = "public",
                modifiers = setOf(),
            ),
        )
        val roots = rootNames(RootScope.EXPORTED, nodes)
        assertTrue(
            "t orphan" in roots,
            "a public callable with no callers is an exported root at distance zero — in this slot " +
                "`reachable` means `exists`, which is exactly the semantics the report documents",
        )
        assertTrue("t hidden" !in roots, "a private callable is not API")
    }

    @Test
    fun mainScopeIsTheTopLevelMainOnly() {
        val nodes = nodesWith(
            GraphFixtures.function(canonicalName = "main"),
            GraphFixtures.function(canonicalName = "t.runMain"),
            GraphFixtures.function(canonicalName = "t.main", enclosingClass = "t.App"),
        )
        assertEquals(setOf("main"), rootNames(RootScope.MAIN, nodes))
    }

    @Test
    fun androidScopeIsTheComponentSupertypesOnly() {
        val nodes = nodesWith(
            GraphFixtures.function(
                canonicalName = "t activity",
                enclosingClass = "t.MainActivity",
                supertypes = listOf("android.app.Activity"),
            ),
            GraphFixtures.function(
                canonicalName = "t plain",
                enclosingClass = "t.Plain",
                supertypes = listOf("kotlin.Any"),
            ),
        )
        assertEquals(setOf("t activity"), rootNames(RootScope.ANDROID, nodes))
    }

    @Test
    fun theFrameworkAnnotationVocabularyIsTheDocumentedThreePlusMessaging() {
        // The families the handlers scope claims, spelled out so a new
        // annotation lands here FIRST and the doc grows with it.
        val claimed = listOf(
            "org.springframework.web.bind.annotation.RestController",
            "org.springframework.messaging.handler.annotation.MessageMapping",
            "org.springframework.kafka.annotation.KafkaListener",
            "jakarta.ws.rs.GET",
            "javax.ws.rs.Path",
            "io.micronaut.http.annotation.Controller",
        )
        for (annotation in claimed) {
            assertTrue(Roots.isFrameworkAnnotated(listOf(annotation)), "$annotation must be a handlers root")
        }
        assertFalse(Roots.isFrameworkAnnotated(listOf("io.ktor.server.routing.get")))
        assertFalse(Roots.isFrameworkAnnotated(listOf("kotlin.Any")))
    }
}
