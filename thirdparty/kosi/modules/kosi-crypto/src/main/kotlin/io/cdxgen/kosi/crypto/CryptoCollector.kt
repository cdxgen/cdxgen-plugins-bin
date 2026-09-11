package io.cdxgen.kosi.crypto

import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirConstant
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.kir.KirValueFolder
import io.cdxgen.kosi.models.CryptoMappingModels
import io.cdxgen.kosi.models.CryptoMappings
import io.cdxgen.kosi.models.EndpointsPack
import io.cdxgen.kosi.schema.CryptoAsset
import io.cdxgen.kosi.schema.CryptoFinding
import io.cdxgen.kosi.schema.CryptoMaterial
import io.cdxgen.kosi.schema.CryptoOperation
import io.cdxgen.kosi.schema.Position

/**
 * The crypto/CBOM collector (P8). Transform strings and algorithm names are
 * resolved through the shipped mapping table DATA — the collector invents no
 * family, no mode, no padding and no finding. `AES` alone is reported as
 * `AES` without a mode or padding, because the JCA's defaults are the JCA's
 * business, not something kosi should assert about the code; a transform
 * whose parts cannot all be proved is `resolution: unresolved`.
 *
 * Secret MATERIAL is detected BY NAME and published as a name, a kind, a
 * file and a position — never a value. The same name rule feeds the flow
 * engine's `hardcoded-secret` literal sources (the pack's data), whose
 * slices to `crypto-asset`/`insecure-tls` sinks are the crypto-flow slices
 * the bench counts from `dataFlow.slices[]`.
 */
object CryptoCollector {

    class Input(
        val module: KirModule,
        val sourceTexts: Map<String, String>,
        val configValues: Map<String, String>,
        val configKeys: Set<String>,
    )

    data class Result(
        val assets: List<CryptoAsset>,
        val operations: List<CryptoOperation>,
        val materials: List<CryptoMaterial>,
        val findings: List<CryptoFinding>,
        val protocols: List<String>,
        val libraries: List<String>,
        /** Mode/padding extraction counts per FORM (literal, const, template, config). */
        val modePaddingByForm: Map<String, Pair<Int, Int>>,
    )

    fun collect(
        input: Input,
        mappings: CryptoMappings = CryptoMappingModels.loadBuiltin(),
        endpointPack: EndpointsPack = io.cdxgen.kosi.models.EndpointModels.loadBuiltin(),
    ): Result {
        val folder = KirValueFolder(
            module = input.module,
            constValues = ConstTable.fromSources(input.sourceTexts),
            configReaders = endpointPack.configReaders.map { it.pattern to it.argument },
            configTable = input.configValues,
        )
        val assets = mutableListOf<CryptoAsset>()
        val operations = mutableListOf<CryptoOperation>()
        val materials = mutableListOf<CryptoMaterial>()
        val findings = mutableListOf<CryptoFinding>()
        val protocols = sortedSetOf<String>()
        val libraries = sortedSetOf<String>()
        // form -> (extracted, total) for Cipher transforms.
        val modePaddingByForm = sortedMapOf(
            FORM_LITERAL to (0 to 0),
            FORM_CONST to (0 to 0),
            FORM_TEMPLATE to (0 to 0),
            FORM_CONFIG to (0 to 0),
        )

        val functions = input.module.functions.sortedWith(
            compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }, { it.file }, { it.line }),
        )

        // KeyGenerator/KeyPairGenerator `init` tracking: the receiver register
        // of an `init` call within the same block, after the getInstance.
        data class GeneratorInit(val algorithm: String, val assetName: String)

        for (fn in functions) {
            val body = fn.body ?: continue
            for (block in body.blocks) {
                for ((index, ins) in block.instructions.withIndex()) {
                    when (ins) {
                        is KirCall -> {
                            collectCryptoCall(
                                fn, block, index, ins, input, folder, mappings,
                                assets, operations, findings, protocols, modePaddingByForm,
                            )
                        }

                        is KirNew -> collectNew(fn, block, index, ins, input, findings, assets)

                        is KirLoad -> {
                            // Material by name: a literal stored into a
                            // material-named local or parameter.
                            val name = literalSourceName(fn, block, index, ins) ?: continue
                            val category = MaterialNames.categoryOf(name)
                            materials.add(
                                CryptoMaterial(
                                    name = name,
                                    kind = category,
                                    filePath = fn.file,
                                    position = Position(fn.file, fn.line, fn.line),
                                ),
                            )
                        }

                        else -> {}
                    }
                }
            }
            // Library detection: which crypto libraries the body actually calls.
            for (block in body.blocks) {
                for (ins in block.instructions) {
                    if (ins !is KirCall) continue
                    CryptoLibraries.nameOf(ins.callee.fqn)?.let { libraries.add(it) }
                }
            }
            // A custom TrustManager whose check methods accept everything.
            collectTrustAll(fn, findings)
        }

        // Android Keystore: KeyStore.getInstance("AndroidKeyStore") arrives
        // through collectCryptoCall; the "AndroidKeyStore" mapping row carries
        // the keystore family.

        return Result(
            assets = assets,
            operations = operations,
            materials = materials.distinctBy { it.name to it.filePath to it.position.line },
            findings = findings,
            protocols = protocols.toList(),
            libraries = libraries.toList(),
            modePaddingByForm = modePaddingByForm.mapValues { it.value },
        )
    }

    // ---- the JCA/JCE entry points --------------------------------------------

    private fun collectCryptoCall(
        fn: KirFunction,
        block: KirBlock,
        index: Int,
        ins: KirCall,
        input: Input,
        folder: KirValueFolder,
        mappings: CryptoMappings,
        assets: MutableList<CryptoAsset>,
        operations: MutableList<CryptoOperation>,
        findings: MutableList<CryptoFinding>,
        protocols: MutableSet<String>,
        modePaddingByForm: MutableMap<String, Pair<Int, Int>>,
    ) {
        val fqn = ins.callee.fqn
        val api = CryptoApis.of(fqn) ?: return
        // An env-resolved or argument-shaped value: fold the naming argument.
        val folded = ins.args.getOrNull(api.argument)?.let { folder.valueAt(fn, block, index, it) }
        val value = folded?.value
        val position = Position(fn.file, if (ins.line > 0) ins.line else fn.line, fn.line)
        val filePathForReport = fn.file

        when (api.op) {
            "Cipher", "MessageDigest", "Mac", "Signature", "SecretKeyFactory", "SSLContext", "KeyStore" -> {
                val form = formOf(folded)
                if (api.op == "Cipher") {
                    val total = modePaddingByForm[form] ?: (0 to 0)
                    modePaddingByForm[form] = total.first to total.second + 1
                }
                val asset = assetFor(value, api.op, folded?.status, mappings)
                if (asset != null) {
                    assets.add(asset)
                    if (api.op == "Cipher") {
                        val counts = modePaddingByForm[form] ?: (0 to 0)
                        val extracts = if (asset.mode != null || asset.padding != null) counts.first + 1 else counts.first
                        modePaddingByForm[form] = extracts to counts.second
                    }
                    for (finding in mappingFindings(asset.name, mappings, asset.mode)) {
                        findings.add(
                            CryptoFinding(
                                code = finding,
                                severity = "high",
                                message = findingMessage(finding, asset.name),
                                asset = asset.name,
                                filePath = filePathForReport,
                                position = position,
                            ),
                        )
                    }
                }
                operations.add(
                    CryptoOperation(
                        kind = api.op,
                        asset = asset?.name ?: value ?: api.op,
                        function = fn.canonicalName,
                        modulePath = "",
                        filePath = filePathForReport,
                        position = position,
                    ),
                )
                if (api.op == "SSLContext" && value != null) {
                    val algorithm = mappings.algorithms.firstOrNull { it.name == value }
                    if (algorithm?.family == "tls") protocols.add(value)
                }
            }

            else -> {}
            }
    }

    /** The syntactic form the value was read in (the per-form gate's key). */
    private fun formOf(folded: KirValueFolder.FoldedValue?): String = when (folded?.status) {
        KirValueFolder.ValueStatus.LITERAL -> FORM_LITERAL
        KirValueFolder.ValueStatus.FOLDED_CONST -> FORM_CONST
        KirValueFolder.ValueStatus.FOLDED_TEMPLATE -> FORM_TEMPLATE
        KirValueFolder.ValueStatus.CONFIG -> FORM_CONFIG
        KirValueFolder.ValueStatus.ENV -> FORM_CONFIG
        else -> FORM_UNRESOLVED
    }

    /** The transform/algorithm mapping resolved for a folded value, or a structural parse. */
    private fun assetFor(
        value: String?,
        op: String,
        status: KirValueFolder.ValueStatus?,
        mappings: CryptoMappings,
    ): CryptoAsset? {
        if (value == null) {
            return CryptoAsset(
                name = op,
                algorithmFamily = null,
                primitive = null,
                mode = null,
                padding = null,
                keySizeBits = null,
                curve = null,
                position = null,
                resolution = "unresolved",
                operation = op,
            )
        }
        val transform = mappings.transforms.firstOrNull { it.transform == value }
        val resolution = when (status) {
            KirValueFolder.ValueStatus.LITERAL -> "literal"
            KirValueFolder.ValueStatus.FOLDED_CONST, KirValueFolder.ValueStatus.FOLDED_TEMPLATE -> "folded"
            KirValueFolder.ValueStatus.CONFIG -> "config"
            KirValueFolder.ValueStatus.ENV -> "env"
            else -> "unresolved"
        }
        return if (transform != null) {
            CryptoAsset(
                name = value,
                algorithmFamily = transform.family,
                primitive = transform.primitive,
                mode = transform.mode,
                padding = transform.padding,
                keySizeBits = null,
                curve = null,
                position = null,
                resolution = resolution,
                operation = op,
                form = formOfName(status),
            )
        } else {
            // Structural parse through the vocabularies, then the algorithm
            // table. An unknown algorithm still reports its name.
            val segments = value.split('/')
            val algorithmName = segments.firstOrNull() ?: value
            val mode = segments.getOrNull(1)?.takeIf { it in mappings.modeVocabulary }
            val padding = segments.getOrNull(2)?.takeIf { it in mappings.paddingVocabulary }
            val algorithm = mappings.algorithms.firstOrNull { it.name == algorithmName }
            CryptoAsset(
                name = value,
                algorithmFamily = algorithm?.family,
                primitive = algorithm?.primitive,
                mode = mode,
                padding = padding,
                keySizeBits = algorithm?.keySizeBits,
                curve = null,
                position = null,
                resolution = resolution,
                operation = op,
                form = formOfName(status),
            )
        }
    }

    private fun formOfName(status: KirValueFolder.ValueStatus?): String = when (status) {
        KirValueFolder.ValueStatus.LITERAL -> FORM_LITERAL
        KirValueFolder.ValueStatus.FOLDED_CONST -> FORM_CONST
        KirValueFolder.ValueStatus.FOLDED_TEMPLATE -> FORM_TEMPLATE
        KirValueFolder.ValueStatus.CONFIG -> FORM_CONFIG
        KirValueFolder.ValueStatus.ENV -> FORM_CONFIG
        else -> FORM_UNRESOLVED
    }

    /** Findings carried by the mapping rows this asset matched. */
    private fun mappingFindings(name: String, mappings: CryptoMappings, mode: String?): List<String> {
        val out = mutableListOf<String>()
        mappings.transforms.firstOrNull { it.transform == name }?.let { out.addAll(it.findings) }
        mappings.algorithms.firstOrNull { it.name == name }?.let { out.addAll(it.findings) }
        if (mode == "ECB") out.add("ecb-mode")
        return out.distinct()
    }

    private fun findingMessage(finding: String, name: String): String = when (finding) {
        "ecb-mode" -> "ECB mode provides no semantic security; the same plaintext block always encrypts to the same ciphertext block"
        "weak-digest" -> "$name is a broken or deprecated hash and must not be used in new designs"
        "weak-cipher" -> "$name is a deprecated cipher; prefer AES in an authenticated mode"
        "insecure-tls-version" -> "$name is a deprecated TLS protocol version"
        "jwt-alg-none" -> "JWT signed with alg=none carries no integrity protection"
        "trust-all-manager" -> "an X509TrustManager whose check methods accept every certificate disables certificate validation"
        "predictable-random" -> "java.util.Random is not cryptographically strong; key or token material from it is predictable"
        "low-iteration-pbkdf2" -> "PBKDF2 iteration count below the shipped minimum weakens the derived key"
        else -> finding
    }

    private fun collectNew(
        fn: KirFunction,
        block: KirBlock,
        index: Int,
        ins: KirNew,
        input: Input,
        findings: MutableList<CryptoFinding>,
        assets: MutableList<CryptoAsset>,
    ) {
        // Named EC curves: `ECGenParameterSpec("secp256r1")` — the curve is
        // reported only when the literal names one the table carries.
        if (ins.type.endsWith("ECGenParameterSpec")) {
            val folder = KirValueFolder(
                module = input.module,
                constValues = ConstTable.fromSources(input.sourceTexts),
            )
            val folded = ins.args.firstOrNull()?.let { folder.valueAt(fn, block, index, it) }
            val curveName = folded?.value
            if (curveName != null) {
                val curve = CryptoMappingModels.loadBuiltin().curves.firstOrNull { it.name == curveName }
                val ec = CryptoMappingModels.loadBuiltin().algorithms.firstOrNull { it.name == "EC" }
                if (curve != null) {
                    assets.add(
                        CryptoAsset(
                            name = "EC",
                            algorithmFamily = ec?.family,
                            primitive = ec?.primitive,
                            mode = null,
                            padding = null,
                            keySizeBits = curve.keySizeBits,
                            curve = curve.name,
                            position = null,
                            resolution = "literal",
                            operation = "KeyPairGenerator",
                            form = FORM_LITERAL,
                        ),
                    )
                }
            }
            return
        }
        // PBEKeySpec(pass, salt, iterations, ...): the iteration count is a
        // provable constant or the finding's reason says the count could not
        // be proven. Nothing is inferred below the threshold without one.
        if (!ins.type.endsWith("PBEKeySpec")) return
        val iterationArg = ins.args.getOrNull(2) ?: return
        val iterations = constantInt(block, index, iterationArg) ?: return
        val mappings = CryptoMappingModels.loadBuiltin()
        if (iterations < mappings.pbkdf2MinIterations) {
            findings.add(
                CryptoFinding(
                    code = "low-iteration-pbkdf2",
                    severity = "medium",
                    message = "PBKDF2 runs $iterations iteration(s), below the shipped minimum ${mappings.pbkdf2MinIterations}",
                    asset = "PBKDF2WithHmacSHA256",
                    filePath = fn.file,
                    position = Position(fn.file, fn.line, fn.line),
                ),
            )
        }
    }

    private fun constantInt(block: KirBlock, index: Int, register: String): Int? {
        for (i in index - 1 downTo 0) {
            val ins = block.instructions.getOrNull(i) ?: continue
            if (ins is KirLoad && ins.result == register) {
                return (ins.constant as? KirConstant.IntConst)?.value?.toInt()
            }
        }
        return null
    }

    /** An X509TrustManager whose check methods have empty bodies: trust-everything. */
    private fun collectTrustAll(fn: KirFunction, findings: MutableList<CryptoFinding>) {
        if (fn.syntheticCause != null) return
        val isTrustManager = fn.supertypes.any { it.substringAfterLast('.').contains("X509TrustManager") } ||
            fn.ownerAnnotations.isEmpty() && fn.supertypes.isEmpty() && false
        if (!isTrustManager) return
        val check = fn.canonicalName.substringAfterLast('.')
        if (check !in setOf("checkServerTrusted", "checkClientTrusted")) return
        val instructions = fn.body?.blocks?.sumOf { it.instructions.size } ?: return
        if (instructions == 0) {
            findings.add(
                CryptoFinding(
                    code = "trust-all-manager",
                    severity = "critical",
                    message = "${fn.canonicalName} accepts every certificate: the check body is empty",
                    asset = null,
                    filePath = fn.file,
                    position = Position(fn.file, fn.line, fn.line),
                ),
            )
        }
    }

    /** The material name a literal load feeds, when its target matches the material name rule. */
    private fun literalSourceName(fn: KirFunction, block: KirBlock, index: Int, ins: KirLoad): String? {
        // Find the store of this register (same block, below the load).
        for (j in index + 1 until block.instructions.size) {
            val candidate = block.instructions.getOrNull(j) ?: continue
            if (candidate is io.cdxgen.kosi.kir.KirStore && candidate.value == ins.result) {
                val name = candidate.target.removePrefix("v")
                return if (MaterialNames.matches(name)) name else null
            }
            if ((candidate as? io.cdxgen.kosi.kir.KirAssign)?.result == ins.result) return null
        }
        // A parameter-bound literal: the load feeds a parameter store.
        return null
    }
}

internal object MaterialNames {

    private val PATTERN = Regex(
        """(?i).*(password|passwd|pwd|secret|apikey|api[_-]?key|token|private[_-]?key|signing[_-]?key|encryption[_-]?key).*""",
    )

    fun matches(name: String): Boolean = PATTERN.matches(name)

    /** The material kind the name suggests (name-shaped evidence, never the value). */
    fun categoryOf(name: String): String = when {
        name.contains("password", true) || name.contains("passwd", true) || name.contains("pwd", true) -> "password"
        name.contains("token", true) -> "token"
        else -> "key"
    }
}

internal object CryptoLibraries {
    private val LIBRARIES = listOf(
        "org.bouncycastle" to "BouncyCastle",
        "com.google.crypto.tink" to "Tink",
        "io.jsonwebtoken" to "jjwt",
        "com.nimbusds.jose" to "nimbus-jose-jwt",
        "com.auth0.jwt" to "java-jwt",
        "org.springframework.security" to "spring-security-crypto",
    )

    fun nameOf(calleeFqn: String): String? =
        LIBRARIES.firstOrNull { calleeFqn.startsWith(it.first) }?.second
}

/**
 * The JCA's own entry points, keyed by operation. These are the Java
 * platform's fixed API surface — collector logic, not project model data;
 * the mapping table (DATA) decides what each algorithm MEANS.
 */
internal data class CryptoApi(val op: String, val argument: Int)

internal object CryptoApis {
    private val APIS = listOf(
        CryptoApi("Cipher", 0) to "javax.crypto.Cipher.getInstance",
        CryptoApi("MessageDigest", 0) to "java.security.MessageDigest.getInstance",
        CryptoApi("Mac", 0) to "javax.crypto.Mac.getInstance",
        CryptoApi("Signature", 0) to "java.security.Signature.getInstance",
        CryptoApi("SecretKeyFactory", 0) to "javax.crypto.SecretKeyFactory.getInstance",
        CryptoApi("SSLContext", 0) to "javax.net.ssl.SSLContext.getInstance",
        CryptoApi("KeyStore", 0) to "java.security.KeyStore.getInstance",
        CryptoApi("KeyGenerator", 0) to "javax.crypto.KeyGenerator.getInstance",
        CryptoApi("KeyPairGenerator", 0) to "java.security.KeyPairGenerator.getInstance",
    )

    private val byFqn = APIS.associate { (api, fqn) -> fqn to api }

    fun of(fqn: String): CryptoApi? = byFqn[fqn]
}

internal const val FORM_LITERAL = "literal"
internal const val FORM_CONST = "const"
internal const val FORM_TEMPLATE = "template"
internal const val FORM_CONFIG = "config"
internal const val FORM_UNRESOLVED = "unresolved"

/** Workspace `const val` name -> value, only for names with a UNIQUE value. */
object ConstTable {
    private val PATTERN = Regex(
        """(?:\bconst\s+val\s+|\bpublic\s+static\s+final\s+String\s+|\bstatic\s+final\s+String\s+)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"""",
    )

    fun fromSources(sourceTexts: Map<String, String>): Map<String, String> {
        val byName = HashMap<String, MutableSet<String>>()
        for (text in sourceTexts.values) {
            for (match in PATTERN.findAll(text)) {
                byName.getOrPut(match.groupValues[1]) { mutableSetOf() }.add(match.groupValues[2])
            }
        }
        return byName.filterValues { it.size == 1 }.mapValues { (_, vs) -> vs.first() }
    }
}
