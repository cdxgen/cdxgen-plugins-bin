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
 * P26 §2: the container's BINDING METHODS are dispatch evidence.
 *
 * P25 read the annotated half of the wiring (a stereotype is a construction
 * site the framework performs). This phase reads the other half — the
 * mapping a module class DECLARES — in the four spellings a real app uses:
 *
 *  - `@Binds` (Dagger): the parameter type is the implementation; no
 *    construction site exists anywhere in user code;
 *  - `@Bean`/`@Provides` returning a parameter (the `@Inject`-constructor
 *    idiom): same absence of a construction site;
 *  - Koin's provider lambdas (`single<Api> { ApiImpl() }`, both the 3.x and
 *    2.x package spellings): the construction is inside a lambda the
 *    container invokes;
 *  - TWO bindings of one interface: the honest publication is BOTH targets,
 *    a dispatch width of 2, and the narrowing reason `di-binding`.
 *
 * And the negative half `di-bound-dispatch` lacked: a container that binds
 * the NON-sinking implementation must produce no finding at all. Before this
 * phase the parameter-form binding was invisible, nothing was instantiated,
 * and RTA fell back to the whole candidate set — the finding landed on the
 * sinking sibling the binding never wired.
 */
class DiBindingFormsTest {

    private fun fixture(name: String): Path = run {
        var current: Path? = Path.of("").toAbsolutePath()
        while (current != null) {
            val candidate = current.resolve("fixtures/$name")
            if (Files.isDirectory(candidate)) return@run candidate
            current = current.parent
        }
        error("fixtures/$name not found upward from the working directory")
    }

    private fun slicesOf(name: String) = Analyzer.analyze(
        fixture(name),
        AnalyzeOptions(
            backend = Backend.RESOLVED,
            dataflow = DataflowMode.SECURITY,
            callgraph = CallGraphMode.AUTO,
        ),
        commit = "test",
    ).dataFlow?.slices.orEmpty()

    @Test
    fun bindsProvidedBeanAndKoinSpellingsAllNarrowToTheBoundImplementation() {
        val sinks = slicesOf("di-module-bindings").map { it.sinkFunction }.sorted()
        assertEquals(
            listOf(
                "fixtures.di.EmailNotifier.notify",
                "fixtures.di.JdbcAuditStore.save",
                "fixtures.di.RealHealthApi.ping",
                "fixtures.di.RealUserApi.fetch",
                "fixtures.di.SlackNotifier.notify",
                "fixtures.di.StripeGateway.charge",
            ),
            sinks,
            "one finding per bound implementation: @Binds (JdbcAuditStore), @Bean-by-parameter " +
                "(StripeGateway), Koin 3.x and 2.x provider lambdas (RealUserApi, RealHealthApi), " +
                "and both of the doubly-bound Notifiers — and none on NoopAuditStore, " +
                "SandboxGateway or PagerNotifier",
        )
    }

    @Test
    fun twoBindingsPublishBothTargetsWithDiBindingAtWidthTwo() {
        val frames = slicesOf("di-module-bindings")
            .filter { it.sinkFunction.startsWith("fixtures.di.SlackNotifier") ||
                it.sinkFunction.startsWith("fixtures.di.EmailNotifier") }
            .flatMap { it.frames }
        val hop = frames.firstOrNull {
            it.dispatchNarrowedBy == "di-binding" && it.dispatchWidth == 2
        }
        assertTrue(
            hop != null,
            "the Notifier site considered three implementations and kept the two the container " +
                "bound; the hop must say width 2 narrowed by di-binding. Frames: " +
                frames.joinToString("; ") { "${it.function}/${it.role} w=${it.dispatchWidth} by=${it.dispatchNarrowedBy}" },
        )
        assertEquals(
            listOf("fixtures.di.EmailNotifier.notify", "fixtures.di.SlackNotifier.notify"),
            frames.map { it.function }.filter { it.contains("Notifier") }.distinct().sorted(),
            "the applied targets are exactly the two bound implementations",
        )
    }

    @Test
    fun aContainerBindingTheNonSinkingImplementationProducesNoFindingAtAll() {
        val sinks = slicesOf("di-bound-dispatch").map { it.sinkFunction }.sorted()
        assertEquals(
            listOf("fixtures.di.JdbcStore.save"),
            sinks,
            "the container binds ConsoleNotifier, so SmtpNotifier's sink never runs and the " +
                "fixture's only finding is the original JdbcStore one — a finding on " +
                "SmtpNotifier.send is the pre-P26 smear",
        )
    }

    /**
     * The Koin arm's unique decision is the LABEL, not the narrowing: a
     * `single { Impl() }` lambda's construction already instantiates the
     * implementation for RTA, so the target set narrows without any
     * container knowledge — but the narrowing REASON is `cha`-anonymous
     * unless the provider lambda is read as a binding (the survivors are
     * container-MANAGED, and that is what `di-binding` claims). With the
     * Koin read disabled this test fails with no di-binding hop on the
     * UserApi dispatch, which is exactly the difference the arm makes.
     */
    @Test
    fun aKoinProviderDispatchIsNarrowedByTheBindingNotByLuck() {
        val frames = slicesOf("di-module-bindings")
            .filter { it.sinkFunction.startsWith("fixtures.di.RealUserApi") ||
                it.sinkFunction.startsWith("fixtures.di.RealHealthApi") }
            .flatMap { it.frames }
        val koinHops = frames.filter {
            it.dispatchNarrowedBy == "di-binding" &&
                (it.dispatchTargets.contains("fixtures.di.RealUserApi.fetch") ||
                    it.dispatchTargets.contains("fixtures.di.RealHealthApi.ping"))
        }
        assertTrue(
            koinHops.isNotEmpty(),
            "the UserApi/HealthApi dispatches narrowed to the provider's implementation must say " +
                "di-binding — construction inside the provider lambda is container wiring, not an " +
                "accidental `new`. Frames: " +
                frames.joinToString("; ") { "${it.function}/${it.role} w=${it.dispatchWidth} by=${it.dispatchNarrowedBy}" },
        )
    }
}
