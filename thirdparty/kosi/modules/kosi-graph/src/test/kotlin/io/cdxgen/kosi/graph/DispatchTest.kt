package io.cdxgen.kosi.graph

import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.schema.CallGraphMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Dispatch resolution (02-ARCHITECTURE.md §5), negative cases first: every
 * test names the plausibly-wrong shape it forbids — a sealed site labelled as
 * an open hierarchy, a library-interface call stranded on the library leaf,
 * an open dispatch narrowed by a guess, dead code given edges by RTA.
 */
class DispatchTest {

    private val basePrice = GraphFixtures.function(
        canonicalName = "t.Ticket.price",
        enclosingClass = "t.Ticket",
        modifiers = setOf("abstract"),
        ownerFlags = setOf("sealed", "abstract"),
        body = null,
    )
    private val walkupPrice = GraphFixtures.function(
        canonicalName = "t.Ticket.Walkup.price",
        enclosingClass = "t.Ticket.Walkup",
        modifiers = setOf("final"),
        overrides = listOf("t.Ticket.price"),
        ownerFlags = setOf("object", "final"),
    )
    private val advancePrice = GraphFixtures.function(
        canonicalName = "t.Ticket.Advance.price",
        enclosingClass = "t.Ticket.Advance",
        modifiers = setOf("final"),
        overrides = listOf("t.Ticket.price"),
    )

    @Test
    fun aSealedSiteWithTwoLiveTargetsIsSealedBoundedNotInterfaceCha() {
        val constructorCaller = GraphFixtures.function(
            canonicalName = "t.order",
            body = listOf(GraphFixtures.call("t0", "t.Ticket.Advance", CallKind.CONSTRUCTOR)),
        )
        val caller = GraphFixtures.function(
            canonicalName = "t.total",
            body = listOf(GraphFixtures.call("t0", "t.Ticket.price", CallKind.VIRTUAL, receiver = "%0")),
        )
        val result = GraphFixtures.build(
            GraphFixtures.module(basePrice, walkupPrice, advancePrice, constructorCaller, caller),
            GraphFixtures.options(),
        )
        val types = GraphFixtures.edgeByNames(result, "t.total", "price")
        assertEquals(2, types.size, "both implementations of the closed hierarchy are live targets")
        assertTrue(
            types.all { it == "sealed-bounded" } && types.isNotEmpty(),
            "the closed set must be labelled as such, got $types",
        )
    }

    @Test
    fun aDispatchThroughALibraryInterfaceReachesTheWorkspaceImplementation() {
        val impl = GraphFixtures.function(
            canonicalName = "t.AuditTrail.run",
            enclosingClass = "t.AuditTrail",
            overrides = listOf("java.lang.Runnable.run"),
        )
        val ctor = GraphFixtures.function(
            canonicalName = "t.make",
            body = listOf(GraphFixtures.call("t0", "t.AuditTrail", CallKind.CONSTRUCTOR)),
        )
        val caller = GraphFixtures.function(
            canonicalName = "t.runAudit",
            body = listOf(GraphFixtures.call("t1", "java.lang.Runnable.run", CallKind.VIRTUAL, receiver = "%0")),
        )
        val result = GraphFixtures.build(
            GraphFixtures.module(impl, ctor, caller),
            GraphFixtures.options(),
        )
        assertEquals(
            listOf("interface-cha"),
            GraphFixtures.edgeByNames(result, "t.runAudit", "AuditTrail.run"),
            "the call must dispatch to the workspace implementation",
        )
        assertTrue(
            GraphFixtures.edgeByNames(result, "t.runAudit", "java.lang.Runnable.run").isEmpty(),
            "the call must not strand on the library leaf when a workspace implementation exists",
        )
    }

    @Test
    fun rtaWithNoLiveImplementationEmitsNoDispatchEdge() {
        // Same call, but the implementation is private dead code: nothing
        // constructs its owner, so RTA must refuse to invent an execution.
        val impl = GraphFixtures.function(
            canonicalName = "t.AuditTrail.run",
            enclosingClass = "t.AuditTrail",
            visibility = "private",
            overrides = listOf("java.lang.Runnable.run"),
        )
        val caller = GraphFixtures.function(
            canonicalName = "t.runAudit",
            body = listOf(GraphFixtures.call("t1", "java.lang.Runnable.run", CallKind.VIRTUAL, receiver = "%0")),
        )
        val result = GraphFixtures.build(
            GraphFixtures.module(impl, caller),
            GraphFixtures.options(),
        )
        assertTrue(GraphFixtures.edgeByNames(result, "t.runAudit", "AuditTrail.run").isEmpty())
    }

    @Test
    fun staticModeDeclinesOpenDispatchInsteadOfGuessingOneTarget() {
        val caller = GraphFixtures.function(
            canonicalName = "t.pay",
            enclosingClass = "t.Payroll",
            body = listOf(GraphFixtures.call("t0", "t.Payslip.net", CallKind.VIRTUAL, receiver = "%0")),
        )
        val salaried = GraphFixtures.function(
            canonicalName = "t.Salaried.net",
            enclosingClass = "t.Salaried",
            overrides = listOf("t.Payslip.net"),
        )
        val hourly = GraphFixtures.function(
            canonicalName = "t.Hourly.net",
            enclosingClass = "t.Hourly",
            overrides = listOf("t.Payslip.net"),
        )
        val result = GraphFixtures.build(
            GraphFixtures.module(caller, salaried, hourly),
            GraphFixtures.options(mode = CallGraphMode.STATIC),
        )
        assertTrue(
            GraphFixtures.edgeByNames(result, "t.pay", "net").isEmpty(),
            "static mode models dispatch-free calls only",
        )
        // ... and cha keeps both.
        val cha = GraphFixtures.build(
            GraphFixtures.module(caller, salaried, hourly),
            GraphFixtures.options(mode = CallGraphMode.CHA),
        )
        assertEquals(
            2,
            GraphFixtures.edgeByNames(cha, "t.pay", "net").size,
            "cha keeps the full open-hierarchy candidate set",
        )
    }

    @Test
    fun anUnknownOwnerIsNeverTreatedAsExact() {
        // Facts unavailable: visibility unknown, no owner flags, no modality.
        // The declared callee must still dispatch to its override set rather
        // than collapse to one target.
        val declared = GraphFixtures.function(
            canonicalName = "t.Shape.area",
            enclosingClass = "t.Shape",
            visibility = "unknown",
            modifiers = emptySet(),
        )
        val impl = GraphFixtures.function(
            canonicalName = "t.Square.area",
            enclosingClass = "t.Square",
            overrides = listOf("t.Shape.area"),
        )
        val caller = GraphFixtures.function(
            canonicalName = "t.draw",
            body = listOf(GraphFixtures.call("t0", "t.Shape.area", CallKind.VIRTUAL, receiver = "%0")),
        )
        // CHA: the complete-graph mode, so the shape tests the override
        // index and the exactness rule, not RTA instantiation facts.
        val result = GraphFixtures.build(
            GraphFixtures.module(declared, impl, caller),
            GraphFixtures.options(mode = CallGraphMode.CHA),
        )
        // Two candidate edges (the implementation AND the concrete declared
        // function), not one collapsed static edge: missing facts widen the
        // candidate set, they never narrow it.
        val types = GraphFixtures.edgeByNames(result, "t.draw", "area")
        assertEquals(2, types.size, types.toString())
        assertTrue(types.none { it == "static" }, "unknown facts must not read as exact dispatch")
    }
}

private fun GraphFixtures.kirReturn(): io.cdxgen.kosi.kir.KirIns = io.cdxgen.kosi.kir.KirReturn(null)
