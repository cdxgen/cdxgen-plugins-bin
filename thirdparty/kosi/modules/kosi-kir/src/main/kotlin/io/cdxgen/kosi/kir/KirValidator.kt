package io.cdxgen.kosi.kir

/**
 * Structural checks over lowered bodies. The dead-block rule is the P2
 * gate's "CFG has no unreachable-but-emitted blocks": the lowering emits
 * blocks as it rewrites control flow, and a block that no edge reaches is
 * not dead code from the source — it is a lowering bug that would silently
 * carry stale registers into any dataflow. The validator is what fails when
 * the check is removed (KirValidatorTest disables it and asserts the
 * injected dead block is caught).
 */
object KirValidator {

    /** One structural finding, itemised by function and block. */
    data class Finding(val function: String, val block: String?, val problem: String)

    fun validate(module: KirModule): List<Finding> {
        val findings = mutableListOf<Finding>()
        val seen = HashSet<String>()
        for (function in module.functions) {
            if (!seen.add(function.canonicalName)) {
                findings.add(Finding(function.canonicalName, null, "duplicate function"))
            }
            val body = function.body ?: continue
            findings.addAll(validateBody(function.canonicalName, body))
        }
        return findings
    }

    fun validateBody(function: String, body: KirBody): List<Finding> {
        val findings = mutableListOf<Finding>()
        if (body.blocks.isEmpty()) {
            findings.add(Finding(function, null, "body has no blocks"))
            return findings
        }
        val byId = body.blocks.associateBy { it.id }
        if (byId.size != body.blocks.size) {
            findings.add(Finding(function, null, "duplicate block ids"))
        }
        val entry = body.blocks.first()
        if (!entry.entry) findings.add(Finding(function, entry.id, "first block is not marked entry"))
        for (block in body.blocks.drop(1)) {
            if (block.entry) findings.add(Finding(function, block.id, "extra block marked entry"))
        }
        // Structural edge integrity: explicit targets must exist.
        for (block in body.blocks) {
            for (ins in block.instructions) {
                when (ins) {
                    is KirBranch -> {
                        if (ins.thenBlock !in byId) findings.add(Finding(function, block.id, "branch target ${ins.thenBlock} missing"))
                        if (ins.elseBlock !in byId) findings.add(Finding(function, block.id, "branch target ${ins.elseBlock} missing"))
                    }
                    is KirPhi -> {
                        for (input in ins.inputs.keys) {
                            if (input !in byId) findings.add(Finding(function, block.id, "phi input from missing block $input"))
                        }
                    }
                    else -> {}
                }
            }
        }
        // THE dead-block check: every emitted block must be reachable from
        // the entry over explicit branch edges and list-order fallthrough.
        // Fallthrough stops at a terminator: a block that returned, threw or
        // branched has no implicit edge to the next block.
        val reachable = HashSet<String>()
        val work = ArrayDeque<String>()
        work.add(entry.id)
        while (work.isNotEmpty()) {
            val id = work.removeFirst()
            if (!reachable.add(id)) continue
            val block = byId[id] ?: continue
            var terminates = false
            for (ins in block.instructions) {
                if (ins is KirBranch) {
                    work.add(ins.thenBlock)
                    work.add(ins.elseBlock)
                    terminates = true
                } else if (ins is KirReturn || ins is KirThrow) {
                    terminates = true
                }
            }
            if (terminates) continue
            body.blocks.getOrNull(body.blocks.indexOf(block) + 1)?.let { work.add(it.id) }
        }
        for (block in body.blocks) {
            if (block.id !in reachable) {
                findings.add(Finding(function, block.id, "unreachable-but-emitted block"))
            }
        }
        return findings
    }
}
