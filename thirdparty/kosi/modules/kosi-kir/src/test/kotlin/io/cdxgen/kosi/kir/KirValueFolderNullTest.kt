package io.cdxgen.kosi.kir

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * P19 §1: the folder's null contract. "The register provably holds null"
 * and "the value could not be proved" are different facts, and until the
 * P18 review every null literal folded as the STRING "null" — so no caller
 * could have told them apart even if it had tried. [KirValueFolder.ValueStatus.NULL]
 * is the distinction; these properties pin it from both sides, because a
 * consumer that branches on it (route paths, outbound raw renderings) has
 * no other way to be sure which fact it received.
 */
class KirValueFolderNullTest {

    private fun function(vararg instructions: KirIns): KirFunction = KirFunction(
        canonicalName = "f",
        jvmDescriptor = null,
        purl = "",
        file = "f.kt",
        line = 1,
        column = 1,
        params = listOf(),
        returnType = null,
        modifiers = setOf(),
        visibility = "public",
        enclosingClass = null,
        overrides = listOf(),
        overriddenBy = listOf(),
        annotations = listOf(),
        syntheticCause = null,
        body = KirBody(listOf(KirBlock("b0", entry = true, instructions = listOf(*instructions)))),
    )

    private fun folder(fn: KirFunction): KirValueFolder = KirValueFolder(KirModule(listOf(fn)))

    @Test
    fun aNullLiteralFoldsToTheNullStatusNotTheString() {
        val fn = function(KirLoad("t0", KirConstant.Null))
        val folded = folder(fn).valueAt(fn, fn.body!!.blocks[0], 1, "t0")!!
        assertEquals(KirValueFolder.ValueStatus.NULL, folded.status)
        assertNull(folded.value, "null is the absence of a value, not the four characters \"null\"")
        assertFalse(folded.resolved)
    }

    @Test
    fun aTypedNonNullLiteralStillFoldsAsALiteral() {
        val fn = function(
            KirLoad("t0", KirConstant.Bool(true)),
            KirLoad("t1", KirConstant.IntConst(5)),
            KirLoad("t2", KirConstant.FloatConst(1.5)),
        )
        val f = folder(fn)
        val block = fn.body!!.blocks[0]
        assertEquals("true", f.valueAt(fn, block, 1, "t0")!!.value)
        assertEquals("5", f.valueAt(fn, block, 2, "t1")!!.value)
        assertEquals("1.5", f.valueAt(fn, block, 3, "t2")!!.value)
    }

    @Test
    fun anUnprovableRegisterReturnsNothingAtAll() {
        // A parameter's value cannot be proved from the module. Since P20
        // §0 the miss is a NAMED failure (PARAMETER) rather than a silent
        // null — the depth report counts it as a folding boundary, not a
        // folding miss — but the value is absent either way, which is what
        // every consumer reads.
        val fn = function(KirAssign("t0", "%0")).let {
            it.copy(params = listOf(KirParam("%0", "p", "kotlin.String", receiver = false)))
        }
        val folded = folder(fn).valueAt(fn, fn.body!!.blocks[0], 1, "%0")!!
        assertFalse(folded.resolved)
        assertNull(folded.value)
        assertEquals(KirValueFolder.FoldFailure.PARAMETER, folded.failure)
    }

    @Test
    fun aConcatOverANullPartIsNotProvable() {
        // `"$x"` with a provably-null part does not fold to a string that
        // contains "null": the concat's value is not provable, which is the
        // conservative half of the same contract.
        val fn = function(
            KirLoad("t0", KirConstant.Null),
            KirStringConcat("t1", listOf("\"a\"", "t0")),
        )
        val folded = folder(fn).valueAt(fn, fn.body!!.blocks[0], 2, "t1")!!
        assertEquals(KirValueFolder.ValueStatus.UNRESOLVED, folded.status)
        assertNull(folded.value)
        assertFalse(folded.resolved)
    }

    @Test
    fun aCleanConcatStillFolds() {
        val fn = function(
            KirLoad("t0", KirConstant.Str("\"a\"")),
            KirStringConcat("t1", listOf("\"x\"", "t0")),
        )
        val folded = folder(fn).valueAt(fn, fn.body!!.blocks[0], 2, "t1")!!
        // The raw fragment keeps its quotes (only a direct Str LOAD strips
        // them); the register part contributes its folded value.
        assertEquals("\"x\"a", folded.value)
        assertTrue(folded.resolved)
    }
}
