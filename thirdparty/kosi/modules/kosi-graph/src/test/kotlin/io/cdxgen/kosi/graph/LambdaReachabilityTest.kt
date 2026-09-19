package io.cdxgen.kosi.graph

import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.KirReturn
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * R175: an extracted lambda BODY must be reachable from the function that
 * installs it.
 *
 * A lambda does not run where it is written. `setOnClickListener { … }`
 * stores it and the framework runs it later, so there is no call to it and —
 * before this — no edge either: AndroGoat's graph carried 72 lambda nodes
 * and ZERO incoming edges to any of them. For reachability the distinction
 * does not matter (a handler that is installed may run), and the mode whose
 * whole job is to intersect findings with reached code was therefore
 * discarding them: `--dataflow security` published 17 findings on AndroGoat
 * and `--dataflow reachable` published 1, the other 16 all sinks inside
 * `onCreate$lambda<N>`.
 *
 * Restoring the defect (dropping the KirLambda arm of the body walk) makes
 * both assertions below fail: no edge, and the body unreached.
 */
class LambdaReachabilityTest {

    private fun result(): CallGraphBuilder.Result {
        val handler = GraphFixtures.function(
            canonicalName = "t.Screen.onCreate\$lambda0",
            body = listOf(KirReturn(null)),
        )
        val installer = GraphFixtures.function(
            canonicalName = "t.Screen.onCreate",
            body = listOf(
                KirLambda("t0", "t.Screen.onCreate\$lambda0", emptyList()),
                KirReturn(null),
            ),
        )
        return GraphFixtures.build(
            GraphFixtures.module(installer, handler),
            GraphFixtures.options(),
        )
    }

    @Test
    fun theInstallingFunctionHasAnEdgeToTheLambdaBody() {
        val types = GraphFixtures.edgeByNames(result(), "onCreate", "onCreate\$lambda0")
        assertEquals(
            listOf("lambda-value"),
            types,
            "installing a lambda must carry a reachability edge, labelled so a reader can tell " +
                "it from a call — the body runs later, but it runs",
        )
    }

    @Test
    fun theLambdaBodyIsReachedFromTheInstaller() {
        val result = result()
        val byId = result.callGraph.nodes.associateBy { it.id }
        val reached = result.callGraph.reachability
            .filter { it.reached }
            .mapNotNull { byId[it.nodeId]?.canonicalName }
            .toSet()
        assertTrue(
            "t.Screen.onCreate\$lambda0" in reached,
            "the lambda body must be reachable once its installer is; reached = $reached",
        )
    }
}
