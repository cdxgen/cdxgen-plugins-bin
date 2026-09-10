package io.cdxgen.kosi.graph

import io.cdxgen.kosi.kir.CallKind
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * R51, negative first: `--roots all` is the UNION of the concrete scopes,
 * never "every node". Rooting the stdlib and every dependency would make
 * reachability say "everything runs" and hand every connectivity denominator
 * a free pass — a root needs no edge to be reached.
 */
class RootsTest {

    private fun moduleWithAnExternalCallee(): GraphNodes {
        val nodes = GraphNodes(CallGraphBuilder.Attribution.NONE)
        nodes.localNode(
            GraphFixtures.function(
                canonicalName = "t.main",
                body = listOf(GraphFixtures.call("t0", "kotlin.io.println", CallKind.STATIC)),
            ),
        )
        nodes.localNode(GraphFixtures.function(canonicalName = "t.exported"))
        nodes.externalNode("kotlin.io.println", null)
        return nodes
    }

    @Test
    fun rootsAllNeverRootsANonWorkspaceNode() {
        val nodes = moduleWithAnExternalCallee()
        val (byScope, _) = Roots.select(
            listOf(io.cdxgen.kosi.schema.RootScope.ALL to null),
            nodes.list(),
        )
        val roots = byScope.getValue(io.cdxgen.kosi.schema.RootScope.ALL)
        val names = nodes.list().filter { it.key in roots }.map { it.canonicalName }.toSet()
        assertTrue(
            "kotlin.io.println" !in names,
            "`all` rooted the stdlib: reachability would claim every library function runs — $names",
        )
        assertTrue(nodes.list().none { it.key in roots && !it.local }, "every root must be a workspace node")
    }

    @Test
    fun rootsAllIsExactlyTheUnionOfTheConcreteScopes() {
        val nodes = moduleWithAnExternalCallee()
        val all = Roots.select(listOf(io.cdxgen.kosi.schema.RootScope.ALL to null), nodes.list())
            .first.getValue(io.cdxgen.kosi.schema.RootScope.ALL)
        val union = listOf(
            io.cdxgen.kosi.schema.RootScope.MAIN,
            io.cdxgen.kosi.schema.RootScope.EXPORTED,
            io.cdxgen.kosi.schema.RootScope.HANDLERS,
            io.cdxgen.kosi.schema.RootScope.TESTS,
            io.cdxgen.kosi.schema.RootScope.ANDROID,
        ).flatMap { scope ->
            Roots.select(listOf(scope to null), nodes.list()).first[scope].orEmpty()
        }.toSet()
        assertEquals(union, all)
    }
}
