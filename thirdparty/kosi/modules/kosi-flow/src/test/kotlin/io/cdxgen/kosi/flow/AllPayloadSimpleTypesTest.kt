package io.cdxgen.kosi.flow

import io.cdxgen.kosi.models.EndpointModels
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * `ALL_PAYLOAD_SIMPLE_TYPES` is a hand-written twin of a fact the
 * pack already carries — the `simpleParameterTypes` rows transcribed
 * from Spring's `BeanUtils.isSimpleProperty` and verified against the vendor
 * page. Two spellings of one fact is the shape, and this copy had already
 * drifted: it said `java.lang.Char`, which is not a JVM type (the boxed char is
 * `Character`), so a boxed-char payload under `handlerInput=all` seeded
 * field-bearing instead of simple.
 *
 * Nothing could see that. No fixture has a boxed-char handler, so no want
 * disagreed with the wrong spelling — exactly: a wrong FQN agreeing only
 * with itself. The gate is therefore not a fixture but a CONSISTENCY check
 * between the two lists: every type the flow engine treats as simple must be a
 * type the doc-derived pack rows also spell, character for character.
 *
 * Restore the defect (`java.lang.Character` -> `java.lang.Char`) and this
 * fails, naming the unknown spelling.
 */
class AllPayloadSimpleTypesTest {

    @Test
    fun everyBuiltinSimpleTypeIsSpelledTheWayThePackSpellsIt() {
        val pack = EndpointModels.loadBuiltin()
        val packSpellings = pack.frameworks.flatMap { it.simpleParameterTypes }.toSet()
        assertTrue(
            packSpellings.isNotEmpty(),
            "no framework declares simpleParameterTypes; this check would pass vacuously",
        )
        val unknown = ALL_PAYLOAD_SIMPLE_TYPES - packSpellings
        assertTrue(
            unknown.isEmpty(),
            "the flow engine's `all`-payload simple types contain spellings the doc-derived pack rows do not " +
                "know: $unknown. Either the type is real and belongs in the pack's simpleParameterTypes, or " +
                "it is a typo — `java.lang.Char` was one (the boxed char is `Character`).",
        )
    }
}
