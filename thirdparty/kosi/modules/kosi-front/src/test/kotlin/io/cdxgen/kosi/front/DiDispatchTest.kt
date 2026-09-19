package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.CallGraphMode
import io.cdxgen.kosi.schema.DataflowMode
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * P25 §2: the container's binding is dispatch evidence.
 *
 * The `di-bound-dispatch` fixture is the service boundary every Spring,
 * Micronaut, Hilt or CDI application has: an interface with three
 * implementations, none of them constructed by user code, one of them
 * carrying a stereotype. Two properties are asserted here because neither
 * is expressible as a corpus annotation:
 *
 *  1. the finding lands on the BOUND implementation and on neither sibling
 *     (the want-nots cover the siblings, but only this test can state that
 *     the target set narrowed rather than that a sink happened not to fire);
 *  2. the narrowing REASON published on the hop is `di-binding` — not
 *     `single-impl`, which would claim the interface had one implementation
 *     when it has three. A narrowing that rests on an annotation is
 *     different evidence from one that rests on a `new`, and a wrong binding
 *     is a different defect from a wrong type.
 *
 * Restoring the defect (dropping DI classes from the instantiated set) makes
 * the first assertion fail with two findings — the pre-P25 smear — and the
 * second with no `di-binding` hop at all.
 */
class DiDispatchTest {

    private val fixture: Path = run {
        var current: Path? = Path.of("").toAbsolutePath()
        while (current != null) {
            val candidate = current.resolve("fixtures/di-bound-dispatch")
            if (Files.isDirectory(candidate)) return@run candidate
            current = current.parent
        }
        error("fixtures/di-bound-dispatch not found upward from the working directory")
    }

    private fun report() = Analyzer.analyze(
        fixture,
        AnalyzeOptions(
            backend = Backend.RESOLVED,
            dataflow = DataflowMode.SECURITY,
            callgraph = CallGraphMode.AUTO,
        ),
        commit = "test",
    )

    @Test
    fun theBoundImplementationCarriesTheFindingAndTheSiblingsDoNot() {
        val slices = report().dataFlow?.slices.orEmpty()
        assertEquals(
            listOf("fixtures.di.JdbcStore.save"),
            slices.map { it.sinkFunction }.sorted(),
            "the container binds JdbcStore; LoggingStore and InMemoryStore are implementations this " +
                "application never wires, and a finding on either is the CHA smear this phase removed",
        )
    }

    @Test
    fun theNarrowingSaysItWasTheBinding() {
        val reasons = report().dataFlow?.slices.orEmpty()
            .flatMap { it.frames }
            .mapNotNull { it.dispatchNarrowedBy }
        assertTrue(
            "di-binding" in reasons,
            "the hop through AuditStore must name the container's binding as what narrowed it; got $reasons",
        )
    }
}
