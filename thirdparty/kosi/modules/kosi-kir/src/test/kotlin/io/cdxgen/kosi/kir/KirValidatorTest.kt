package io.cdxgen.kosi.kir

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Negative-first: the validator must FAIL a body whose lowering emitted an
 * unreachable block, and must pass a loop-and-join CFG that only looks
 * suspicious. These tests are the "test that fails if the check is removed"
 * the P2 gate asks for: delete the reachability walk in KirValidator and the
 * first test here fails.
 */
class KirValidatorTest {

    private fun branchAndJoin(): KirBody = KirBody(
        listOf(
            KirBlock("b0", entry = true, instructions = listOf(KirLoad("t0", KirConstant.Bool(true)), KirBranch("t0", "b1", "b2"))),
            KirBlock("b1", entry = false, instructions = listOf(KirLoad("t1", KirConstant.IntConst(1)))),
            KirBlock("b2", entry = false, instructions = listOf(KirLoad("t2", KirConstant.IntConst(2)))),
            KirBlock(
                "b3",
                entry = false,
                instructions = listOf(KirPhi("t3", mapOf("b1" to "t1", "b2" to "t2")), KirReturn("t3")),
            ),
        ),
    )

    @Test
    fun aLoopAndJoinBodyPasses() {
        // A loop: entry branches to body, body falls through back? Fallthrough
        // only goes forward, so a real loop needs an explicit edge; the KIR
        // expresses loops as branch + phi with the back edge as a branch whose
        // targets include an earlier block.
        val body = KirBody(
            listOf(
                KirBlock(
                    "b0",
                    entry = true,
                    instructions = listOf(
                        KirLoad("t0", KirConstant.IntConst(0)),
                        KirStore("v i", "t0"),
                        KirLoad("t1", KirConstant.IntConst(10)),
                    ),
                ),
                KirBlock(
                    "b1",
                    entry = false,
                    instructions = listOf(
                        KirPhi("t2", mapOf("b0" to "t1", "b3" to "t4")),
                        KirFieldGet("t3", "v i", AccessPath.field("v i")),
                        KirBranch("t3", "b2", "b4"),
                    ),
                ),
                KirBlock("b2", entry = false, instructions = listOf(KirCall(null, KirCallee("kotlin.io.println", null, CallKind.STATIC), null, listOf("t3")))),
                KirBlock("b3", entry = false, instructions = listOf(KirLoad("t4", KirConstant.IntConst(9)), KirBranch("t4", "b1", "b1"))),
                KirBlock("b4", entry = false, instructions = listOf(KirReturn(null))),
            ),
        )
        assertEquals(emptyList(), KirValidator.validateBody("loop", body))
    }

    @Test
    fun anUnreachableEmittedBlockIsAFinding() {
        val body = KirBody(
            listOf(
                KirBlock("b0", entry = true, instructions = listOf(KirLoad("t0", KirConstant.Bool(true)), KirBranch("t0", "b1", "b1"))),
                KirBlock("b1", entry = false, instructions = listOf(KirReturn(null))),
                // b2 is emitted but nothing reaches it — a lowering bug shape.
                KirBlock("b2", entry = false, instructions = listOf(KirLoad("t9", KirConstant.Null))),
            ),
        )
        val findings = KirValidator.validateBody("dead", body)
        assertTrue(
            findings.any { it.block == "b2" && "unreachable" in it.problem },
            "the unreachable block must be a finding: $findings",
        )
    }

    @Test
    fun aMissingBranchTargetIsAFinding() {
        val body = KirBody(
            listOf(
                KirBlock("b0", entry = true, instructions = listOf(KirBranch("t0", "b1", "nowhere"))),
                KirBlock("b1", entry = false, instructions = listOf(KirReturn(null))),
            ),
        )
        val findings = KirValidator.validateBody("dangling", body)
        assertTrue(findings.any { "nowhere" in it.problem }, "dangling branch target must be found: $findings")
    }

    @Test
    fun aPlainBranchAndJoinBodyPasses() {
        assertEquals(emptyList(), KirValidator.validateBody("join", branchAndJoin()))
    }

    @Test
    fun instructionsAfterATerminatorAreAFinding() {
        // Unreachable code one level below the block: the dead-block walk
        // cannot see it, because the block itself is perfectly reachable.
        val body = KirBody(
            listOf(
                KirBlock(
                    "b0",
                    entry = true,
                    instructions = listOf(
                        KirReturn(null),
                        KirLoad("t9", KirConstant.Null),
                    ),
                ),
            ),
        )
        val findings = KirValidator.validateBody("after-terminator", body)
        assertTrue(
            findings.any { it.block == "b0" && "after the terminator" in it.problem },
            "an instruction after a return must be a finding: $findings",
        )
    }

    @Test
    fun aBodyWithNoBlocksIsAFinding() {
        val findings = KirValidator.validateBody("empty", KirBody(emptyList()))
        assertTrue(findings.isNotEmpty(), "a blockless body must be a finding")
    }
}
