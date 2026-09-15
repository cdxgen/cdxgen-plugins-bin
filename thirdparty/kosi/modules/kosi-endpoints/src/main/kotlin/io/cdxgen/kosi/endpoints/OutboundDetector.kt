package io.cdxgen.kosi.endpoints

import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirValueFolder
import io.cdxgen.kosi.models.EndpointsPack
import io.cdxgen.kosi.schema.Position

/**
 * Outbound service and URL detection (P7): client calls the pack names, with
 * the base URL where it can be resolved and the config key (or env key, or
 * raw template) where it cannot. Every value carries its resolution status;
 * a value kosi cannot prove is `unresolved`, never a guess.
 */
object OutboundDetector {

    data class Outbound(
        val protocol: String,
        val clientLibrary: String,
        /** The resolved endpoint value, when provable. */
        val endpoint: String?,
        /** What the code literally names: the resolved value, config key, `${ENV}` or raw register. */
        val raw: String,
        val resolution: String,
        val enclosingSymbol: String,
        val position: Position,
    )

    /** The scheme the value itself names (`https://...`), when readable. */
    private fun schemeOf(value: String): String? =
        Regex("^([a-z][a-z0-9+.-]*):").find(value)?.groupValues?.get(1)

    fun detect(
        module: KirModule,
        folder: KirValueFolder,
        pack: EndpointsPack = io.cdxgen.kosi.models.EndpointModels.loadBuiltin(),
    ): List<Outbound> {
        val out = mutableListOf<Outbound>()
        val functions = module.functions.sortedWith(
            compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }, { it.file }, { it.line }),
        )
        for (fn in functions) {
            val body = fn.body ?: continue
            for (block in body.blocks) {
                for ((index, ins) in block.instructions.withIndex()) {
                    if (ins !is KirCall) continue
                    val model = pack.outbound.firstOrNull { o ->
                        EndpointDetector.matches(ins.callee.fqn, o.pattern)
                    } ?: continue
                    if (model.urlArgument < 0) continue
                    val argReg = ins.args.getOrNull(model.urlArgument) ?: continue
                    val folded = folder.valueAt(fn, block, index, argReg)
                    val position = Position(
                        fn.file,
                        if (ins.line > 0) ins.line else fn.line,
                        fn.line,
                    )
                    val foldedValue = folded?.value
                    when {
                        // An env read names the KEY, never the value: kosi
                        // never reads the analysed build's environment.
                        folded != null && folded.status == KirValueFolder.ValueStatus.ENV ->
                            out.add(
                                Outbound(
                                    protocol = model.protocol,
                                    clientLibrary = model.clientLibrary,
                                    endpoint = null,
                                    raw = "\${" + (folded.detail ?: "env") + "}",
                                    resolution = "env",
                                    enclosingSymbol = fn.canonicalName,
                                    position = position,
                                ),
                            )

                        foldedValue != null && folded.status != KirValueFolder.ValueStatus.UNRESOLVED ->
                            out.add(
                                Outbound(
                                    protocol = schemeOf(foldedValue) ?: model.protocol,
                                    clientLibrary = model.clientLibrary,
                                    endpoint = foldedValue,
                                    raw = foldedValue,
                                    resolution = folded.status.toResolution(),
                                    enclosingSymbol = fn.canonicalName,
                                    position = position,
                                ),
                            )

                        else ->
                            out.add(
                                Outbound(
                                    protocol = model.protocol,
                                    clientLibrary = model.clientLibrary,
                                    endpoint = null,
                                    raw = rawRendering(fn, block, index, argReg, folder),
                                    resolution = "unresolved",
                                    enclosingSymbol = fn.canonicalName,
                                    position = position,
                                ),
                            )
                    }
                }
            }
        }
        return out
    }

    /**
     * The honest raw rendering of an unresolvable argument: an env read
     * renders `${KEY}` (the key is the evidence, the value is never read),
     * a config key renders `${key}`, anything else renders its constant or
     * the register.
     */
    private fun rawRendering(fn: KirFunction, block: KirBlock, index: Int, register: String, folder: KirValueFolder): String {
        val folded = folder.valueAt(fn, block, index, register)
        val detail = folded?.detail
        return when {
            folded?.status == KirValueFolder.ValueStatus.ENV -> "\${" + (detail ?: register) + "}"
            folded?.status == KirValueFolder.ValueStatus.UNRESOLVED && detail != null -> "\${" + detail + "}"
            else -> folded?.value ?: register
        }
    }

    private fun KirValueFolder.ValueStatus.toResolution(): String = when (this) {
        KirValueFolder.ValueStatus.LITERAL -> "literal"
        KirValueFolder.ValueStatus.FOLDED_CONST, KirValueFolder.ValueStatus.FOLDED_TEMPLATE -> "folded"
        KirValueFolder.ValueStatus.CONFIG -> "config"
        KirValueFolder.ValueStatus.ENV -> "env"
        KirValueFolder.ValueStatus.UNRESOLVED -> "unresolved"
    }
}
