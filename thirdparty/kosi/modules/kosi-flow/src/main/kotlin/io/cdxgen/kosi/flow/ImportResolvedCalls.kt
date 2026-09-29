package io.cdxgen.kosi.flow

import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCallee
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.models.ModelPack
import io.cdxgen.kosi.models.PatternMatcher

/**
 * Unresolved calls read at the callee their file's imports name
 * ([KirDynamicCall.importedCallees]) when the model pack has an entry for it.
 *
 * A run without the project's jars — the tier cdxgen runs by default — lowers
 * `jdbc.queryForList(sql)` on an unresolvable `JdbcTemplate` to a dynamic call
 * no pack pattern can match, so the SQL sink vanished and the report said
 * nothing about it. The import is the language's own rule for what a name
 * means (the same one `annotation-import-resolved` applies to annotations),
 * so such a call becomes the pack call it spells. A candidate the pack does
 * not name changes nothing: the call stays dynamic and moves taint by the
 * unknown-call default, which `taint-unresolved-call` counts and names.
 */
internal object ImportResolvedCalls {

    /** The rewritten module and, per matched callee FQN, how many sites were read at it. */
    class Rewrite(val module: KirModule, val matched: Map<String, Int>)

    fun rewrite(module: KirModule, pack: ModelPack): Rewrite {
        val matched = java.util.TreeMap<String, Int>()
        var changed = false
        val functions = module.functions.map { function ->
            val body = function.body ?: return@map function
            var bodyChanged = false
            val blocks = body.blocks.map { block ->
                val instructions = block.instructions.map { ins ->
                    if (ins !is KirDynamicCall) return@map ins
                    val call = asPackCall(ins, pack) ?: return@map ins
                    matched.merge(call.callee.fqn, 1, Int::plus)
                    bodyChanged = true
                    call
                }
                if (bodyChanged) block.copy(instructions = instructions) else block
            }
            if (!bodyChanged) return@map function
            changed = true
            function.copy(body = body.copy(blocks = blocks))
        }
        return Rewrite(if (changed) KirModule(functions) else module, matched)
    }

    private fun asPackCall(ins: KirDynamicCall, pack: ModelPack): KirCall? {
        val fqn = ins.importedCallees.firstOrNull { candidate -> named(pack, candidate) } ?: return null
        // A bare `HttpGet(url)` names its class: the constructor. A class-name
        // qualifier (`Jsoup.connect(url)`) is no receiver: static.
        val constructor = ins.receiver == null && !ins.importedStatic &&
            fqn.substringAfterLast('.') == ins.name && ins.name.firstOrNull()?.isUpperCase() == true
        val receiver = if (ins.importedStatic) null else ins.receiver
        val kind = when {
            constructor -> CallKind.CONSTRUCTOR
            receiver != null -> CallKind.VIRTUAL
            else -> CallKind.STATIC
        }
        return KirCall(ins.result, KirCallee(fqn, null, kind), receiver, ins.args, ins.line, ins.typeArguments)
    }

    private fun named(pack: ModelPack, fqn: String): Boolean {
        fun matches(pattern: String) = PatternMatcher.matches(pattern, fqn)
        return pack.sinks.any { matches(it.pattern) } ||
            pack.sources.any { matches(it.pattern) } ||
            pack.sanitizers.any { matches(it.pattern) } ||
            pack.passthroughs.any { matches(it.pattern) } ||
            pack.effects.any { matches(it.pattern) } ||
            pack.deserializers.any { matches(it.pattern) }
    }

    /**
     * The class an unresolved call is made on, as the diagnostic names it:
     * the imported owner of the callee, the constructor's class itself, or —
     * with no import to go on — the call's own name.
     */
    fun ownerOf(ins: KirDynamicCall): String {
        val owners = ins.importedCallees.map { candidate ->
            val constructor = ins.receiver == null && !ins.importedStatic &&
                candidate.substringAfterLast('.') == ins.name && ins.name.firstOrNull()?.isUpperCase() == true
            if (constructor) candidate else candidate.substringBeforeLast('.')
        }.distinct()
        return when {
            owners.isEmpty() -> "${ins.name}()"
            owners.size == 1 -> owners.single()
            else -> owners.joinToString(" or ")
        }
    }
}
