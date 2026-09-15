package io.cdxgen.kosi.models

import io.cdxgen.kosi.schema.JsonValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ModelPackTest {

    // Negative tests first: a corrupt or half-written pack must fail loudly,
    // not silently produce an empty pack (golem's pattern-notation lesson).
    @Test
    fun missingPatternFieldFails() {
        val ex = assertFailsWith<IllegalStateException> {
            ModelPacks.parse("""{"sources":[{"category":"x"}]}""", "broken")
        }
        assertTrue(ex.message!!.contains("sources[].pattern"), ex.message)
    }

    @Test
    fun malformedJsonFails() {
        assertFailsWith<JsonValue.JsonParseException> { ModelPacks.parse("""{"sources":[}""", "broken") }
    }

    @Test
    fun missingResourceFails() {
        assertFailsWith<IllegalStateException> { ModelPacks.loadResource("/models/does-not-exist.json", "nope") }
    }

    @Test
    fun builtinPackLoadsAndIsValid() {
        val pack = ModelPacks.loadBuiltin()
        assertTrue(pack.sources.isNotEmpty(), "builtin pack has no sources")
        assertTrue(pack.sinks.isNotEmpty(), "builtin pack has no sinks")
        // Every category used by the pack must be a known category.
        for (category in pack.categories) {
            assertTrue(Categories.isValid(category), "pack category not registered: $category")
        }
    }

    @Test
    fun categoryValidationIsTwoSided() {
        assertTrue(Categories.isValid("process-exec"))
        assertTrue(Categories.isValid("untrusted-input"))
        assertTrue(Categories.isValid("~crypto"))
        assertEquals(false, Categories.isValid("procss-exec"))
        assertEquals(false, Categories.isValid("totally-made-up"))
    }

    @Test
    fun patternMatchingIsSuffixSegment() {
        // The pattern's segments must be a suffix of the symbol's segments.
        assertTrue(PatternMatcher.matches("executeQuery", "stmt.executeQuery"))
        assertTrue(PatternMatcher.matches("Statement.executeQuery", "java.sql.Statement.executeQuery"))
        assertTrue(PatternMatcher.matches("stmt.executeQuery", "stmt.executeQuery"))
        // A pattern with more segments than the symbol can never match: this
        // is why corpus annotations use the shortest form that still names the
        // target unambiguously, and why full pack patterns are matched against
        // canonical names (which always carry the package).
        assertEquals(false, PatternMatcher.matches("java.sql.Statement.executeQuery", "stmt.executeQuery"))
        assertEquals(false, PatternMatcher.matches("java.sql.Statement.executeQuery", "Query.executeQuery"))
        assertEquals(false, PatternMatcher.matches("executeQuery", "notExecuteQuery"))
    }

    @Test
    fun mergePrefersUserPackOnSamePattern() {
        val base = ModelPacks.parse(
            """{"sinks":[{"pattern":"a.b.c","category":"x","relevantArguments":[0]}]}""",
            "base",
        )
        val user = ModelPacks.parse(
            """{"sinks":[{"pattern":"a.b.c","category":"y","relevantArguments":[1]}]}""",
            "user",
        )
        val merged = ModelPacks.merge(base, listOf(user))
        assertEquals(1, merged.sinks.size)
        assertEquals("y", merged.sinks.single().category)
        assertEquals(listOf(1), merged.sinks.single().relevantArguments)
    }
}
