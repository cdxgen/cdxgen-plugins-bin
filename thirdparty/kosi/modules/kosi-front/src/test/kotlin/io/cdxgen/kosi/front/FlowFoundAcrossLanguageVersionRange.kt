package io.cdxgen.kosi.front

import io.cdxgen.kosi.corpus.Annotation
import io.cdxgen.kosi.corpus.AnnotationParser
import io.cdxgen.kosi.corpus.Evaluator
import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * 08-VERSION-POLICY.md §4, the test that enforces the version policy: the
 * taint fixture is analysed with `--language-version` at EVERY value the
 * bundled compiler accepts — enumerated from `LanguageVersion` at runtime, so
 * the test grows itself when the pin bumps — and must report the same flow at
 * each.
 *
 * P4 semantics: the intraprocedural engine is live, so "reports the same
 * flow" is enforced as "the fixture's positive flow expectation PASSES at
 * every accepted version, with no violated negative anywhere". Until P4 this
 * asserted XFAIL everywhere (defect 1) and the ratchet forced this rewrite
 * the moment the engine landed. The old-language-version fixture additionally
 * carries the clamp diagnostic (languageVersion = 1.9, below
 * FIRST_SUPPORTED), so every version here also exercises the clamp path.
 */
class FlowFoundAcrossLanguageVersionRange {

    private val fixtureDir: Path
        get() = Path.of(System.getProperty("user.dir")).parent!!.parent!!
            .resolve("fixtures/old-language-version")

    private fun analyzeAt(languageVersion: String?): io.cdxgen.kosi.schema.KosiReport =
        Analyzer.analyze(
            fixtureDir,
            AnalyzeOptions(
                backend = Backend.RESOLVED,
                languageVersion = languageVersion,
            ),
            commit = "test",
        )

    private fun annotations(): List<Annotation> {
        val parsed = AnnotationParser.parseDir(fixtureDir, fixtureDir)
        val failures = parsed.filterIsInstance<AnnotationParser.Failure>()
        assertTrue(failures.isEmpty(), "fixture annotations must parse: $failures")
        return parsed.filterIsInstance<AnnotationParser.Success>().map { it.annotation }
    }

    @Test
    fun flowOutcomeAndResolvedFactsAreIdenticalAcrossTheBand() {
        val versions = CompilerInfo.versionBand().allAccepted
        assertTrue(versions.isNotEmpty(), "the bundled compiler must accept at least one language version")

        val annotations = annotations()
        val flowAnnotations = annotations.filter {
            it.kind == Annotation.Kind.FLOW && it.want
        }
        assertTrue(
            flowAnnotations.isNotEmpty(),
            "the fixture must carry a flow expectation for this test to mean anything; parsed " +
                "${annotations.size}: ${annotations.map { it.kind.id to it.knownFailAll }}",
        )

        var baseline: String? = null
        for (version in versions) {
            val report = analyzeAt(version)
            val evaluation = Evaluator.evaluate(report, annotations, mode = "all", backend = Backend.RESOLVED.id)

            // The flow expectation must PASS at every accepted language
            // version, and no negative expectation may be violated: the
            // engine's verdict on this fixture is version-independent.
            val flowOutcomes = evaluation.outcomes
                .filter { it.annotation.kind == Annotation.Kind.FLOW && it.annotation.want }
                .map { it.status }
            assertEquals(
                List(flowAnnotations.size) { Evaluator.Status.PASS },
                flowOutcomes,
                "flow outcome changed at language-version=$version",
            )
            assertEquals(
                emptyList(),
                evaluation.violatedNegatives().map { it.annotation.kind.id },
                "a negative expectation was violated at language-version=$version",
            )

            // The version diagnostics: the fixture declares 1.9, so the clamp
            // fires regardless of the override; the override itself is
            // recorded once per run.
            assertTrue(
                report.diagnostics.any { it.code == io.cdxgen.kosi.schema.DiagnosticCodes.KOTLIN_LANGUAGE_VERSION },
                "the clamp diagnostic must survive every language-version override ($version)",
            )

            // The resolved front-end facts are stable across the band.
            val facts = report.declarations.map { it.canonicalName to it.kind }.sortedWith(compareBy({ it.first }, { it.second })).toString() +
                "|" + report.stats.resolvedCallRatio
            if (baseline == null) {
                baseline = facts
            } else {
                assertEquals(baseline, facts, "resolved facts differ at language-version=$version")
            }
        }
    }

    @Test
    fun theBandIsReadFromTheBundledCompilerNotHardCoded() {
        val band = CompilerInfo.versionBand()
        assertEquals(band.allAccepted.last(), band.latestStable)
        assertEquals(band.allAccepted.first(), band.first)
        // 08-VERSION-POLICY.md: the range narrows with each release; whatever
        // it is today, it must come from the compiler's own constants.
        assertTrue(
            band.first == CompilerInfo.firstSupported() && band.latestStable == CompilerInfo.latestStable(),
            "versionBand must mirror LanguageVersion constants",
        )
    }
}
