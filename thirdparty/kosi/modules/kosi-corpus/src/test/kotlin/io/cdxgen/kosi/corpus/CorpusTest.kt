package io.cdxgen.kosi.corpus

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AnnotationParserTest {

    private fun parseOne(line: String): Annotation =
        AnnotationParser.parseFileText("// $line", "test.kt")
            .filterIsInstance<AnnotationParser.Success>()
            .single().annotation

    private fun expectFailure(line: String, contains: String) {
        val results = AnnotationParser.parseFileText("// $line", "test.kt")
        val failure = results.filterIsInstance<AnnotationParser.Failure>().singleOrNull()
            ?: throw AssertionError("expected a parse failure for: $line")
        assertTrue(
            failure.error.contains(contains),
            "expected error containing '$contains', got '${failure.error}'",
        )
    }

    // ---- negative tests first ---------------------------------------------

    @Test
    fun unknownKindFails() = expectFailure("kosi:want frob name=x", "unknown kind")

    @Test
    fun unknownKeyFails() = expectFailure("kosi:want usage nam=x", "unknown key")

    @Test
    fun flowWithoutCategoriesFailsValidation() = expectFailure("kosi:want flow source=x", "sink=")

    @Test
    fun unknownCategoryFailsValidation() =
        expectFailure("kosi:want flow source=nope-1 sink=procss-exec", "unknown category")

    @Test
    fun duplicateScopedKnownFailFails() =
        expectFailure("kosi:want usage name=x known-fail=syntax:1 known-fail=syntax:2", "duplicate")

    @Test
    fun unknownKnownFailBackendFails() =
        expectFailure("kosi:want usage name=x known-fail=jvm:1", "unknown backend")

    @Test
    fun badModeFails() = expectFailure("kosi:want usage name=x mode=sometimes", "mode must be")

    @Test
    fun wantNotNeedsKind() = expectFailure("kosi:frobnicate", "expected want")

    // ---- positive parsing ---------------------------------------------------

    @Test
    fun flowAnnotationParses() {
        val a = parseOne("kosi:want flow source=untrusted-input sink=process-exec count=2 mode=security")
        assertEquals(Annotation.Kind.FLOW, a.kind)
        assertEquals("untrusted-input", a.source)
        assertEquals("process-exec", a.sink)
        assertEquals(2, a.count)
        assertEquals("security", a.mode)
        assertEquals(false, a.isNegative)
    }

    @Test
    fun scopedKnownFailParses() {
        val a = parseOne("kosi:want usage name=x known-fail=resolved:12")
        assertEquals(12, a.knownFailFor("resolved"))
        // Scoped markers do NOT leak to other backends; unscoped ones do
        // (see unscopedKnownFailAppliesToAllBackends).
        assertEquals(null, a.knownFailFor("syntax"))
        assertEquals(null, a.knownFailFor("deps"))
    }

    @Test
    fun unscopedKnownFailAppliesToAllBackends() {
        val a = parseOne("kosi:want usage name=x known-fail=7")
        assertEquals(7, a.knownFailFor("syntax"))
        assertEquals(7, a.knownFailFor("resolved"))
    }

    @Test
    fun wantNotParses() {
        val a = parseOne("kosi:want-not usage name=~executors")
        assertTrue(a.isNegative)
        assertEquals("~executors", a.name)
    }

    @Test
    fun fnScopesAFlowExpectation() {
        val a = parseOne("kosi:want flow source=untrusted-input sink=sql-query fn=~sibling")
        assertEquals("~sibling", a.fn)
        assertTrue(a.validate().isEmpty())
    }

    @Test
    fun fnIsInvalidOutsideFlow() = expectFailure("kosi:want usage name=x fn=y", "fn=")
}

class CorpusManifestTest {

    @Test
    fun repoWithoutShaFails() {
        val ex = assertFailsWith<IllegalArgumentException> {
            CorpusManifest.parse(
                """
                [[fixtures]]
                slug = "x"
                tier = "small"
                repo = "https://example.com/x"
                """.trimIndent(),
            )
        }
        assertTrue(ex.message!!.contains("sha"))
    }

    @Test
    fun unknownSectionFails() {
        assertFailsWith<IllegalArgumentException> {
            CorpusManifest.parse("[[benchmarks]]\nslug = \"x\"\n")
        }
    }

    @Test
    fun fixtureEntriesParseInOrder() {
        val manifest = CorpusManifest.parse(
            """
            # leading comment
            [[fixtures]]
            slug = "a"
            tier = "fixtures"
            path = "fixtures/a"
            capabilities = ["sqli", "crypto"]

            [[fixtures]]
            slug = "b"
            tier = "small"
            repo = "https://github.com/x/y"
            sha = "abc123"
            expected_flows = "expected.jsonl"
            """.trimIndent(),
        )
        assertEquals(listOf("a", "b"), manifest.entries.map { it.slug })
        assertEquals(listOf("sqli", "crypto"), manifest.entries[0].capabilities)
        assertEquals("abc123", manifest.entries[1].sha)
        assertEquals(listOf("a"), manifest.select(setOf("fixtures")).map { it.slug })
    }

    /**
     * R116's regression pin: `tolerated_resolution_errors` ABSENT must parse
     * as null (ungated — repo tiers), and an EMPTY list must stay empty (a
     * positive "typechecks clean" declaration). The `list()` helper coerces
     * absent keys to emptyList, which collapsed the two and gated every
     * repo row on its legitimate resolution classes; corpusFull caught it.
     */
    @Test
    fun absentToleranceIsNullAndEmptyStaysEmpty() {
        val manifest = CorpusManifest.parse(
            """
            [[fixtures]]
            slug = "repo-shape"
            tier = "medium"
            repo = "https://example/x"
            sha = "0000000000000000000000000000000000000000"

            [[fixtures]]
            slug = "clean-fixture"
            tier = "fixtures"
            path = "fixtures/clean"
            capabilities = []
            tolerated_resolution_errors = []
            """.trimIndent(),
        )
        val repo = manifest.entries.first { it.slug == "repo-shape" }
        val fixture = manifest.entries.first { it.slug == "clean-fixture" }
        assertEquals(null, repo.toleratedResolutionErrors, "absent field must parse as null (ungated), not emptyList")
        assertEquals(emptyList(), fixture.toleratedResolutionErrors, "an explicit empty list is a declaration")
    }
}

/**
 * P24 §1 (10-DEEP-EVIDENCE.md §2): the deep tier's two annotation forms.
 * `frames=N` demands named hops; `via=fn:...,fn:...` demands named
 * intermediate frames in order — and a segment that cannot match any
 * function is an ANNOTATION ERROR (evaluated in `Evaluator`), never a
 * vacuous pass on the negative half.
 */
class DeepAnnotationFormsTest {

    @Test
    fun framesAndViaParseAndCarryTheirValues() {
        val good = AnnotationParser.parseFileText(
            "// kosi:want flow source=untrusted-input sink=process-exec frames=6 via=fn:Repo.query,fn:~Mapper.map\n",
            "T.kt",
        )
        assertEquals(1, good.size, "a well-formed deep expectation parses")
        val annotation = (good[0] as AnnotationParser.Success).annotation
        assertEquals(6, annotation.frames)
        assertEquals(listOf("fn:Repo.query", "fn:~Mapper.map"), annotation.via)
    }

    @Test
    fun theNewKeysAreFlowOnly() {
        val bad = AnnotationParser.parseFileText("// kosi:want usage name=X frames=2\n", "T.kt")
        assertTrue(bad[0] is AnnotationParser.Failure, "frames= is flow-only")
        val badVia = AnnotationParser.parseFileText("// kosi:want usage name=X via=fn:Y\n", "T.kt")
        assertTrue(badVia[0] is AnnotationParser.Failure, "via= is flow-only")
    }

    @Test
    fun aViaSegmentMustNameAFunction() {
        val bad = AnnotationParser.parseFileText(
            "// kosi:want flow source=untrusted-input sink=process-exec via=Repo.query\n",
            "T.kt",
        )
        assertTrue(bad[0] is AnnotationParser.Failure, "a via segment must be fn:-prefixed")
        val badFrames = AnnotationParser.parseFileText(
            "// kosi:want flow source=untrusted-input sink=process-exec frames=0\n",
            "T.kt",
        )
        assertTrue(badFrames[0] is AnnotationParser.Failure, "frames must be >= 1")
    }

    @Test
    fun viaSegmentsSeparateOnCommasWithinOneToken() {
        val parsed = AnnotationParser.parseFileText(
            "// kosi:want-not flow source=untrusted-input sink=process-exec via=fn:A,fn:B\n",
            "T.kt",
        )
        val annotation = (parsed[0] as AnnotationParser.Success).annotation
        assertEquals(listOf("fn:A", "fn:B"), annotation.via)
    }
}
