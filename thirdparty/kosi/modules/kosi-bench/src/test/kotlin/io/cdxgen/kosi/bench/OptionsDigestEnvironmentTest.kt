package io.cdxgen.kosi.bench

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * A gate that compares two environments cannot compare option values
 * that name one of them. `classpath` entries and `jdkHome` are absolute by
 * construction when they are set at all; an explicitly absolute
 * `classpathFile` is the same choice. The digest replaces each absolute
 * value with a fixed marker — the REPORT still records the effective option
 * verbatim for reproduction, so the exclusion lives at the digest boundary.
 *
 * The standing proof shape (rule 8): restore the defect — digest the option
 * raw — and the two-environment equality these tests assert breaks.
 */
class OptionsDigestEnvironmentTest {

    private fun reportJson(classpath: String, jdkHome: String?, classpathFile: String?): String = """
        {"options":{"backend":"resolved","classpath":$classpath,"classpathFile":$classpathFile,"jdkHome":$jdkHome},"sources":[]}
    """.trimIndent()

    private fun normalized(json: String) = Digests.compute(json)["options"]
    private fun raw(json: String) = Digests.compute(json, normalizeEnvironmentNaming = false)["options"]

    @Test
    fun twoEnvironmentsWithDifferentAbsolutePinsDigestEqual() {
        // Machine A and machine B ran the same analysis with their own
        // absolute jars and JDKs: every difference between the two option
        // sets names one machine, so the digests must agree.
        val a = normalized(
            reportJson(
                classpath = """["/home/a/.gradle/caches/x.jar","libs/pinned.jar"]""",
                jdkHome = "\"/Users/a/tools/jdk\"",
                classpathFile = null,
            ),
        )
        val b = normalized(
            reportJson(
                classpath = """["/opt/b/cache/y.jar","libs/pinned.jar"]""",
                jdkHome = "\"/opt/b/jdk\"",
                classpathFile = null,
            ),
        )
        assertEquals(a, b, "absolute option values must not reach the digest")
    }

    @Test
    fun rawDigestsOfTheSameReportsDiffer() {
        // The same two reports digested RAW differ — the marker is doing the
        // work, and the golden gate's portability comparison (which digests
        // raw on purpose) still sees location-naming values.
        val a = raw(
            reportJson(
                classpath = """["/home/a/.gradle/caches/x.jar"]""",
                jdkHome = "\"/Users/a/tools/jdk\"",
                classpathFile = null,
            ),
        )
        val b = raw(
            reportJson(
                classpath = """["/opt/b/cache/y.jar"]""",
                jdkHome = "\"/opt/b/jdk\"",
                classpathFile = null,
            ),
        )
        assertNotEquals(a, b)
    }

    @Test
    fun settingAnEnvironmentNamingOptionStillDiffersFromLeavingItUnset() {
        // The marker must not collapse "configured differently per machine"
        // into "not configured at all": an unset option and a set one digest
        // differently, so a run cannot silently lose its pin.
        val unset = normalized(reportJson(classpath = "[]", jdkHome = null, classpathFile = null))
        val set = normalized(
            reportJson(
                classpath = """["/home/a/.gradle/caches/x.jar"]""",
                jdkHome = null,
                classpathFile = null,
            ),
        )
        assertNotEquals(unset, set)
    }

    @Test
    fun relativeValuesTravelAndStayDigestedAsGiven() {
        // A relative pin travels between machines, so it is real analysis
        // input, not an environment name: it must stay in the digest
        // verbatim — two different relative pins digest differently.
        val pinA = normalized(reportJson(classpath = "[]", jdkHome = null, classpathFile = "\"classpath.txt\""))
        val pinB = normalized(reportJson(classpath = "[]", jdkHome = null, classpathFile = "\"pins/classpath.txt\""))
        val pinAbsolute = normalized(reportJson(classpath = "[]", jdkHome = null, classpathFile = "\"/etc/kosi/classpath.txt\""))
        assertNotEquals(pinA, pinB, "the pin's NAME is digested input")
        assertEquals(pinAbsolute, pinAbsolute, "sanity")
    }

    @Test
    fun theShippedSlotOptionsDigestUnchangedByTheNormalization() {
        // The bench slots set none of the three members (empty classpath,
        // null jdkHome, entry-relative classpathFile), so normalized and raw
        // agree: the 450 checked-in goldens did not move for this change.
        // If a slot ever starts carrying an absolute value, this test forces
        // the decision to be revisited instead of silently re-basing.
        for (slot in Matrix.defaultMatrix()) {
            val options = slot.options()
            val w = io.cdxgen.kosi.schema.JsonWriter()
            options.copy(classpathFile = "classpath.txt").writeJson(w)
            val json = """{"options":${w.render()},"sources":[]}"""
            assertEquals(
                Digests.compute(json, normalizeEnvironmentNaming = false)["options"],
                Digests.compute(json)["options"],
                "slot ${slot.label} carries an option value the digest normalizes — the goldens moved",
            )
        }
    }
}
