package io.cdxgen.kosi.bytecode

import io.cdxgen.kosi.models.EndpointModels
import io.cdxgen.kosi.schema.JsonReader
import io.cdxgen.kosi.schema.JsonWriter
import io.cdxgen.kosi.schema.JsonValue
import org.jetbrains.org.objectweb.asm.ClassReader
import org.jetbrains.org.objectweb.asm.ClassVisitor
import org.jetbrains.org.objectweb.asm.MethodVisitor
import org.jetbrains.org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * the symbol-kind gate travels. the EndpointsPackSymbolKindTest
 * checked the pack against whatever framework evidence the LOCAL machine
 * held; on a machine without the warm cache every check skipped and the
 * verdict table still printed, so the gate's real coverage was "whatever
 * the corpus machine holds, and nobody else can run it" (the class,
 * one level up).
 *
 * The evidence is now COMMITTED — a pinned extract of exactly what the pack
 * asserts about each framework's artifacts (class kinds, member tables,
 * facade statics), derived from the held jars/sources and pinned to their
 * versions, never the jars themselves:
 *
 *  - CHECK A runs EVERYWHERE: every pack symbol in a channel the extract
 *    covers must have a committed fact of the kind its channel assumes
 *    (constructible for constructor channels, static for factories,
 *    declared for DSL members/functions). (a sealed class in a
 *    constructor channel) and (FQNs that do not exist) fail here
 *    on any machine.
 *  - CHECK B runs where the pinned evidence is HELD: the extract is
 *    re-derived and must equal the committed bytes, so a pack or artifact
 *    drift the extract did not record fails instead of silently aging.
 *  - the verdict table COUNTS, per framework: how many symbols the extract
 *    checks, how many this machine re-derived, and how many are recorded
 *    gaps — never "KIND-CHECKED" as an inference from an artifact's
 *    presence.
 *
 * Regenerate after a deliberate pack or evidence change:
 *
 *   KOSI_UPDATE_SYMBOL_EVIDENCE=1 ./gradlew :kosi-bytecode:test \
 *       --tests 'io.cdxgen.kosi.bytecode.EndpointsPackSymbolEvidenceTest'
 *
 * The generator refuses to record a FAILURE (a pack symbol the held
 * evidence contradicts) — those are defects to fix, not evidence to pin.
 */
class EndpointsPackSymbolEvidenceTest {

    private val repoRoot = Path.of("..", "..").toAbsolutePath().normalize()
    private val pack = EndpointModels.loadBuiltin()
    private val extractFile = Path.of("src/test/resources/symbol-evidence/endpoints-pack-symbols.json")

    // ---- evidence discovery -------------------------------------------------

    private fun modules2(): Path? =
        Path.of(System.getProperty("user.home"), ".gradle", "caches", "modules-2", "files-2.1")
            .takeIf { Files.isDirectory(it) }

    private fun jars(group: String, artifact: String): List<Path> {
        val base = modules2()?.resolve(group)?.resolve(artifact) ?: return emptyList()
        if (!Files.isDirectory(base)) return emptyList()
        return Files.list(base).use { dirs ->
            dirs.filter { Files.isDirectory(it) }.toList()
        }.sortedByDescending { it.fileName.toString() }.flatMap { versionDir ->
            Files.walk(versionDir).use { stream ->
                stream.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".jar") }.toList()
            }
        }
    }

    private fun pinnedJars(coordinate: Coordinate): List<Path> =
        jars(coordinate.group, coordinate.artifact).filter { it.toString().contains(coordinate.version) }

    private fun jarClass(jar: Path, fqn: String): Boolean =
        ZipFile(jar.toFile()).use { zip -> zip.getEntry(fqn.replace('.', '/') + ".class") != null }

    private class ClassFacts(val kind: String, val constructible: Boolean, val staticMethods: Set<String>, val methods: Set<String>)

    private fun classFacts(jar: Path, fqn: String): ClassFacts? {
        val bytes = ZipFile(jar.toFile()).use { zip -> zip.getEntry(fqn.replace('.', '/') + ".class") }?.let {
            ZipFile(jar.toFile()).use { z -> z.getInputStream(it).readBytes() }
        } ?: return null
        var access = 0
        val statics = mutableSetOf<String>()
        val all = mutableSetOf<String>()
        ClassReader(bytes).accept(
            object : ClassVisitor(Opcodes.ASM9) {
                override fun visit(version: Int, accessFlags: Int, name: String?, signature: String?, superName: String?, interfaces: Array<out String>?) {
                    access = accessFlags
                }

                override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor? {
                    if (name != null) {
                        all.add(name)
                        if ((access and Opcodes.ACC_STATIC) != 0) statics.add(name)
                    }
                    return null
                }
            },
            ClassReader.SKIP_CODE,
        )
        val isInterface = (access and Opcodes.ACC_INTERFACE) != 0
        val isAnnotation = (access and Opcodes.ACC_ANNOTATION) != 0
        val isEnum = (access and Opcodes.ACC_ENUM) != 0
        val isAbstract = (access and Opcodes.ACC_ABSTRACT) != 0
        val kind = when {
            isAnnotation -> "annotation"
            isInterface -> "interface"
            isEnum -> "enum"
            else -> "class"
        }
        return ClassFacts(kind, kind == "class" && !isAbstract, statics, all)
    }

    /** The top-level Kotlin facades (`*Kt`, no `$`) of [packageFqn] in [jar]. */
    private fun facades(jar: Path, packageFqn: String): List<String> =
        ZipFile(jar.toFile()).use { zip ->
            zip.entries().asSequence()
                .map { it.name }
                .filter { it.endsWith("Kt.class") && !it.contains('$') }
                .filter { it.removeSuffix(".class").replace('/', '.').let { fqn -> fqn.substringBeforeLast('.') == packageFqn } }
                .map { it.removeSuffix(".class").replace('/', '.') }
                .toList()
        }

    private val http4kClone = repoRoot.resolve(".corpus-cache").resolve("http4k")
    private val HTTP4K_PINNED_SHA = "b051f89d35ab9190385a244e9e77149e77c55f4d"

    private fun http4kEvidence(): Path? {
        if (!Files.isDirectory(http4kClone.resolve("core"))) return null
        val head = Files.readString(http4kClone.resolve(".git").resolve("HEAD")).trim()
        val sha = if (head.startsWith("ref:")) {
            Files.readString(http4kClone.resolve(".git").resolve(head.removePrefix("ref: ").trim())).trim()
        } else head
        assertEquals(HTTP4K_PINNED_SHA, sha, "http4k corpus clone is not at the SHA the pack was sourced from")
        return http4kClone
    }

    private fun http4kSources(clone: Path): List<Path> =
        Files.walk(clone).use { s -> s.filter { Files.isRegularFile(it) && it.toString().endsWith(".kt") }.toList() }

    /** The declaration modifiers of `class|interface|object <simple>` in its own file, or null when absent. */
    private fun http4kDeclarationModifiers(clone: Path, fqn: String): Pair<String, String>? {
        val simple = fqn.substringAfterLast('.')
        val file = fqn.removePrefix("org.http4k.").replace('.', '/')
            .let { rel -> fqn.split('.').dropLast(1).fold(clone) { acc, seg -> acc.resolve(seg) } }
            .resolve("$simple.kt")
        val candidates = sequenceOf(file) + http4kSources(clone)
        for (candidate in candidates.distinct()) {
            if (!Files.isRegularFile(candidate)) continue
            val decl = Regex("""(?m)^\s*((?:(?:public|internal|private|protected)\s+)?((?:[a-zA-Z]+\s+)*)(class|interface|object)\s+$simple\b.*)$""")
                .find(Files.readString(candidate)) ?: continue
            return decl.groupValues[2].trim() to decl.groupValues[3]
        }
        return null
    }

    private fun isConstructible(modifiers: String, kind: String): Boolean =
        kind == "class" && modifiers.split(Regex("\\s+")).none {
            it in setOf("sealed", "abstract", "annotation", "enum", "fun")
        }

    // ---- the derivation -----------------------------------------------------

    private data class Coordinate(val group: String, val artifact: String, val version: String) {
        val id get() = "$group:$artifact:$version"
    }

    private data class MemberFact(val owner: String, val member: String, val static: Boolean)

    private class Derived(
        val sources: List<String>,
        val covers: List<String>,
        val types: List<List<Any>>,
        val members: List<MemberFact>,
        val functions: List<Pair<String, String>>,
        val gaps: List<String>,
        val failures: List<String>,
    ) {
        val held: Boolean get() = sources.isNotEmpty()
    }

    /** Channels whose entries are type FQNs (existence + kind recorded). */
    private val typeChannels = listOf(
        "mappingAnnotations", "mediaAnnotations", "authenticationAnnotations", "parameterAnnotations",
        "classMarkers", "classMappingAnnotations", "pathPrefixAnnotations", "applicationPathAnnotations",
        "supertypeMarkers", "repositorySupertypes", "securityConstructors", "resourceAnnotations",
    )

    /** Channels whose entries are member calls on an owner class. */
    private val memberChannels = listOf("dslFunctions", "mediaDsl", "handlerDsl", "authHandlerFactories", "contextReaders", "mountFunctions")

    /** Channels whose entries are top-level functions (packages, no owner class). */
    private val functionChannels = listOf("contractDsl", "routeMetaDsl", "bindFunctions", "authenticationDsl")

    private fun fw(id: String) = pack.frameworks.first { it.id == id }

    private fun patterns(id: String, channel: String): List<String> {
        val f = fw(id)
        return when (channel) {
            "mappingAnnotations" -> f.mappingAnnotations.map { it.pattern }
            "mediaAnnotations" -> f.mediaAnnotations.map { it.pattern }
            "authenticationAnnotations" -> f.authenticationAnnotations.map { it.pattern }
            "parameterAnnotations" -> f.parameterAnnotations.map { it.pattern }
            "classMarkers" -> f.classMarkers
            "classMappingAnnotations" -> f.classMappingAnnotations
            "pathPrefixAnnotations" -> f.pathPrefixAnnotations
            "applicationPathAnnotations" -> f.applicationPathAnnotations
            "supertypeMarkers" -> f.supertypeMarkers
            "repositorySupertypes" -> f.repositorySupertypes
            "securityConstructors" -> f.securityConstructors
            "resourceAnnotations" -> f.resourceAnnotations
            "dslFunctions" -> f.dslFunctions.map { it.pattern }
            "mediaDsl" -> f.mediaDsl.map { it.pattern }
            "handlerDsl" -> f.handlerDsl
            "authHandlerFactories" -> f.authHandlerFactories
            "contextReaders" -> f.contextReaders.map { it.pattern }
            "contractDsl" -> f.contractDsl
            "routeMetaDsl" -> f.routeMetaDsl
            "bindFunctions" -> f.bindFunctions.map { it.pattern }
            "mountFunctions" -> f.mountFunctions
            "authenticationDsl" -> f.authenticationDsl
            else -> error("unknown channel $channel")
        }
    }

    /** A JVM getter name for a Kotlin property, the shape a `val` compiles to. */
    private fun getterOf(member: String): String =
        (if (member.length == 1) member.uppercase() else member[0].uppercase() + member.substring(1)).let { "get$it" }

    /** owner.member when the second-to-last segment names a class; a package-level function otherwise. */
    private fun isOwnerMember(pattern: String): Boolean =
        pattern.split('.').dropLast(1).lastOrNull()?.firstOrNull()?.isUpperCase() == true

    private fun deriveJarFramework(
        id: String,
        coords: List<Coordinate>,
        covers: List<String>,
    ): Derived {
        val held = coords.map { c -> pinnedJars(c) }.map { jars -> if (jars.isEmpty()) null else jars }
        if (held.all { it == null }) {
            return Derived(emptyList(), covers, emptyList(), emptyList(), emptyList(),
                covers.flatMap { ch -> patterns(id, ch).map { "$it: no held jar for ${coords.joinToString(",") { c -> c.id }}" } }, emptyList())
        }
        val missing = coords.filterIndexed { i, c -> held[i] == null }
        if (missing.isNotEmpty()) {
            // Partial evidence would pin facts derived from a SUBSET of the
            // artifacts the pack models; the extract records none rather
            // half the truth.
            return Derived(emptyList(), covers, emptyList(), emptyList(), emptyList(),
                covers.flatMap { ch -> patterns(id, ch).map { "$it: partial evidence (${missing.joinToString(",") { it.id }} absent)" } }, emptyList())
        }
        val jars = held.filterNotNull().flatten()
        val types = mutableListOf<List<Any>>()
        val members = mutableListOf<MemberFact>()
        val functions = mutableListOf<Pair<String, String>>()
        val gaps = mutableListOf<String>()
        val failures = mutableListOf<String>()
        val factsByFqn = HashMap<String, ClassFacts>()
        fun facts(fqn: String): ClassFacts? {
            factsByFqn[fqn]?.let { return it }
            val f = jars.firstNotNullOfOrNull { jar -> classFacts(jar, fqn) }
            if (f != null) factsByFqn[fqn] = f
            return f
        }
        for (channel in covers) {
            for (pattern in patterns(id, channel)) {
                when {
                    channel in typeChannels -> {
                        if (!pattern.contains('.') || pattern.any { it == '*' || it == '<' } || pattern.split('.').size < 3) {
                            gaps += "$pattern: not a checkable FQN ($channel)"
                            continue
                        }
                        val f = facts(pattern)
                        when {
                            f == null && jars.any { jarCoversFamily(it, pattern) } ->
                                failures += "$id: $pattern ($channel) — a held ${coords.joinToString(",") { it.id }} covers its package family but has no such class"
                            f == null -> gaps += "$pattern: no held jar covers its package family"
                            else -> types += listOf(pattern, f.kind, f.constructible)
                        }
                    }
                    channel in memberChannels && isOwnerMember(pattern) -> {
                        val owner = pattern.substringBeforeLast('.')
                        val member = pattern.substringAfterLast('.')
                        val f = facts(owner)
                        when {
                            f == null -> gaps += "$pattern: owner $owner not in any held ${coords.joinToString(",") { c -> c.artifact }}"
                            member !in f.methods && getterOf(member) !in f.methods ->
                                failures += "$id: $pattern ($channel) — $owner declares no member `$member` (nor its JVM getter) in ${coords.joinToString(",") { it.id }}; the OWNER'S METHOD TABLE, not a constant-pool substring"
                            channel == "authHandlerFactories" && member !in f.staticMethods ->
                                failures += "$id: $pattern ($channel) — a factory channel needs a static, and $owner's `$member` is not one"
                            else -> members += MemberFact(owner, member, member in f.staticMethods)
                        }
                    }
                    else -> {
                        // A package-level Kotlin function: the JVM owner is
                        // some `*Kt` facade of the same package; file names
                        // are not part of the API so the check is
                        // owner-agnostic (the rule, kept).
                        val pkg = pattern.substringBeforeLast('.')
                        val fn = pattern.substringAfterLast('.')
                        val allFacades = jars.flatMap { jar -> facades(jar, pkg) }
                        when {
                            allFacades.any { f -> facts(f)?.staticMethods?.contains(fn) == true } -> functions += pkg to fn
                            allFacades.isEmpty() -> gaps += "$pattern: package $pkg has no facade in any held ${coords.joinToString(",") { c -> c.artifact }} (artifact absent)"
                            else -> failures += "$id: $pattern ($channel) — $pkg facades exist in ${coords.joinToString(",") { it.id }} but none declares a static `$fn`"
                        }
                    }
                }
            }
        }
        return Derived(coords.map { it.id }, covers, types.sortedBy { (it[0] as String) },
            members.sortedWith(compareBy({ it.owner }, { it.member })),
            functions.sortedWith(compareBy({ it.first }, { it.second })), gaps.sorted(), failures)
    }

    private fun jarCoversFamily(jar: Path, fqn: String): Boolean {
        val segments = fqn.split('.')
        if (segments.size < 4) return false
        val family = segments.take(3).joinToString("/")
        return ZipFile(jar.toFile()).use { zip ->
            zip.entries().asSequence().any { it.name.endsWith(".class") && it.name.startsWith("$family/") }
        }
    }

    private fun deriveHttp4k(): Derived {
        val clone = http4kEvidence() ?: return Derived(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(),
            (typeChannels + memberChannels + functionChannels).flatMap { ch -> patterns("http4k", ch).map { "$it: corpus clone absent (.corpus-cache/http4k)" } }, emptyList())
        val sources = http4kSources(clone).filter { it.toString().contains("/contract/") || it.toString().contains("/core/") }
        val types = mutableListOf<List<Any>>()
        val members = mutableListOf<MemberFact>()
        val functions = mutableListOf<Pair<String, String>>()
        val gaps = mutableListOf<String>()
        val failures = mutableListOf<String>()
        val covers = listOf("securityConstructors", "contractDsl", "routeMetaDsl", "bindFunctions", "contextReaders")
        for (fqn in fw("http4k").securityConstructors) {
            val decl = http4kDeclarationModifiers(clone, fqn)
            when {
                decl == null -> failures += "http4k: $fqn — declares no ${fqn.substringAfterLast('.')} anywhere in the clone (the shape)"
                !isConstructible(decl.first, decl.second) -> failures += "http4k: $fqn is ${decl.second} ${decl.first.trim()} — a constructor channel needs a constructible class"
                else -> types += listOf(fqn, decl.second, true)
            }
        }
        for ((channel, pats) in listOf(
            "contractDsl" to fw("http4k").contractDsl,
            "routeMetaDsl" to fw("http4k").routeMetaDsl,
        )) {
            for (fqn in pats) {
                val name = fqn.substringAfterLast('.')
                if (sources.any { Regex("""fun\s+(infix\s+)?(String\.)?$name\s*[<(]""").containsMatchIn(Files.readString(it)) }) {
                    functions += fqn.substringBeforeLast('.') to name
                } else {
                    failures += "http4k: $fqn ($channel) — no `fun $name` in the clone"
                }
            }
        }
        for (m in fw("http4k").bindFunctions) {
            // The pack spells bind functions as BARE names (`bind`) matched
            // on the call's last segment; the extract records them with an
            // empty package so no fake `bind.bind` FQN is ever pinned.
            val name = m.pattern.substringAfterLast('.')
            if (sources.any { Regex("""fun\s+(infix\s+)?String\.$name\s*[<(]""").containsMatchIn(Files.readString(it)) }) {
                functions += "" to name
            } else {
                failures += "http4k: String.$name — the clone declares no String-receiver bind function"
            }
        }
        for (reader in fw("http4k").contextReaders) {
            val pattern = reader.pattern
            val member = pattern.substringAfterLast('.')
            if (!isOwnerMember(pattern)) {
                // A top-level extension (`org.http4k.routing.path`): the
                // "owner" is a package and the function is declared at its
                // top level — the same shape the ktor facades carry, and a
                // member fact would claim a class that does not exist.
                val pkg = pattern.substringBeforeLast('.')
                val found = sources.any { source ->
                    val text = Files.readString(source)
                    Regex("""(?m)^\s*(suspend\s+)?(infix\s+)?fun\s+$member\s*[<(]""").containsMatchIn(text) ||
                        Regex("""(?m)^\s*(suspend\s+)?(infix\s+)?fun\s+[<(A-Za-z][^=\n]*\.$member\s*[<(]""").containsMatchIn(text)
                }
                if (found) {
                    functions += pkg to member
                } else {
                    gaps += "$pattern: no top-level `fun $member` in the clone's core/contract sources"
                }
                continue
            }
            val owner = pattern.substringBeforeLast('.')
            val ownerFile = clone.resolve(owner.removePrefix("org.http4k.").replace('.', '/')).let {
                it.resolve("${owner.substringAfterLast('.')}.kt")
            }
            val declared = (if (Files.isRegularFile(ownerFile)) listOf(ownerFile) else emptyList()) + sources
            val found = declared.any {
                Regex("""(?m)^\s*(suspend\s+)?fun\s+$member\s*[<(]""").containsMatchIn(Files.readString(it)) ||
                    Regex("""(?m)^\s*(override\s+)?val\s+$member\b""").containsMatchIn(Files.readString(it))
            }
            if (found) {
                members += MemberFact(owner, member, false)
            } else {
                gaps += "$pattern: not declared as `fun/val $member` on $owner in the clone (extension or inherited shape)"
            }
        }
        return Derived(listOf("github.com/http4k/http4k@$HTTP4K_PINNED_SHA"), covers,
            types.sortedBy { (it[0] as String) },
            members.sortedWith(compareBy({ it.owner }, { it.member })),
            functions.sortedWith(compareBy({ it.first }, { it.second })),
            gaps.sorted(), failures)
    }

    private fun derive(): Map<String, Derived> {
        val jarCoordinates = mapOf(
            "vertx" to listOf(Coordinate("io.vertx", "vertx-web", "5.1.7")),
            // Ratpack 1.9.0 is the 1.x generation, which is what the
            // `ratpack.handling` / `ratpack.http` rows model. The 2.x rows
            // (`ratpack.core.*`, the JPMS rename in 2.0.0-rc-1) are NOT in
            // this artifact and are recorded as unheld rather than inferred
            // from the 1.x ones — that inference is exactly.
            "ratpack" to listOf(Coordinate("io.ratpack", "ratpack-core", "1.9.0")),
            "ktor" to listOf(
                Coordinate("io.ktor", "ktor-server-core-jvm", "3.5.2"),
                Coordinate("io.ktor", "ktor-server-auth-jvm", "3.5.2"),
                Coordinate("io.ktor", "ktor-http-jvm", "3.5.2"),
            ),
            "spring-mvc" to listOf(
                Coordinate("org.springframework", "spring-webmvc", "5.3.18"),
                Coordinate("org.springframework", "spring-web", "5.3.18"),
                Coordinate("org.springframework", "spring-context", "5.3.18"),
            ),
            "spring-webflux" to listOf(
                Coordinate("org.springframework", "spring-webflux", "5.3.18"),
                Coordinate("org.springframework", "spring-web", "5.3.18"),
                Coordinate("org.springframework", "spring-context", "5.3.18"),
            ),
            "spring-messaging" to listOf(Coordinate("org.springframework", "spring-context", "5.3.18")),
            "graphql" to listOf(Coordinate("org.springframework", "spring-context", "5.3.18")),
            "micronaut" to listOf(Coordinate("io.micronaut", "micronaut-http", "4.10.23")),
            "quarkus" to listOf(Coordinate("jakarta.ws.rs", "jakarta.ws.rs-api", "4.0.0")),
            "servlet" to listOf(
                Coordinate("jakarta.servlet", "jakarta.servlet-api", "4.0.4"),
                // javax generations: the pack models both; the javax
                // artifact is not held, so those rows stay recorded gaps.
            ),
            "aws-lambda" to listOf(Coordinate("com.amazonaws", "aws-lambda-java-core", "1.4.0")),
            "azure-functions" to listOf(Coordinate("com.microsoft.azure.functions", "azure-functions-java-library", "3.3.0")),
        )
        val covers = mapOf(
            "vertx" to listOf("dslFunctions", "mediaDsl", "handlerDsl", "authHandlerFactories", "contextReaders", "mountFunctions"),
            "ktor" to listOf("dslFunctions", "authenticationDsl", "contextReaders"),
            // Ratpack's two channels ARE checkable against the held 1.x
            // jar — the Handler supertype and the six Request readers. Listing
            // them is the difference between a committed record that verifies
            // the pack and an empty one that verifies nothing.
            "ratpack" to listOf("supertypeMarkers", "contextReaders"),
            "spring-mvc" to typeChannels,
            "spring-webflux" to typeChannels,
            "spring-messaging" to typeChannels,
            "graphql" to typeChannels,
            "micronaut" to typeChannels,
            "quarkus" to typeChannels,
            "servlet" to typeChannels,
            "aws-lambda" to typeChannels,
            "azure-functions" to typeChannels,
        )
        val out = sortedMapOf<String, Derived>()
        out["http4k"] = deriveHttp4k()
        for ((id, coords) in jarCoordinates) {
            out[id] = deriveJarFramework(id, coords, covers[id] ?: emptyList())
        }
        // Frameworks with NO class-symbol channels, and frameworks whose
        // artifacts nobody holds: recorded, never silently skipped.
        val nonSymbol = mapOf(
            "android" to "manifest components: no class symbols to check",
            "spring-actuator" to "dependency markers are artifact coordinates; the committed marker jars are presence-only stubs",
            "springdoc" to "dependency markers are artifact coordinates; the committed marker jars are presence-only stubs",
            "grpc" to "supertype suffix/substring markers (ImplBase, CoroutineImplBase, Grpc, GrpcKt), not FQNs; grpc-stub ${if (jars("io.grpc", "grpc-stub").isNotEmpty()) "held but carries no modelled FQN" else "not held"}",
            "javalin" to "io.javalin absent from the warm cache — channels unchecked",
            "sparkjava" to "com.sparkjava absent from the warm cache — channels unchecked",
        )
        for ((id, reason) in nonSymbol) {
            if (pack.frameworks.none { it.id == id }) continue // deleted from the pack (the liveness sweep)
            val channels = (typeChannels + memberChannels + functionChannels).filter { patterns(id, it).isNotEmpty() }
            out[id] = Derived(emptyList(), emptyList(), emptyList(), emptyList(), emptyList(),
                channels.flatMap { ch -> patterns(id, ch).map { "$it: $reason" } }, emptyList())
        }
        return out
    }

    // ---- serialisation ------------------------------------------------------

    private fun derivedToJson(derived: Map<String, Derived>): String {
        val sb = StringBuilder()
        sb.append("{\n  \"format\": \"kosi symbol evidence 1\",\n  \"frameworks\": [\n")
        val entries = derived.entries.filter { (id, _) -> pack.frameworks.any { it.id == id } }
        entries.forEachIndexed { index, (id, d) ->
            sb.append("    {\n      \"id\": ").append(JsonWriter.renderString(id)).append(",\n")
            sb.append("      \"sources\": [")
            sb.append(d.sources.joinToString(", ") { JsonWriter.renderString(it) })
            sb.append("],\n")
            sb.append("      \"covers\": [")
            sb.append(d.covers.joinToString(", ") { JsonWriter.renderString(it) })
            sb.append("],\n")
            sb.append("      \"types\": [")
            sb.append(d.types.joinToString(", ") { t -> "{\"fqn\": ${JsonWriter.renderString(t[0] as String)}, \"kind\": ${JsonWriter.renderString(t[1] as String)}, \"constructible\": ${t[2]}}" })
            sb.append("],\n")
            sb.append("      \"members\": [")
            sb.append(d.members.joinToString(", ") { "{\"owner\": ${JsonWriter.renderString(it.owner)}, \"member\": ${JsonWriter.renderString(it.member)}, \"static\": ${it.static}}" })
            sb.append("],\n")
            sb.append("      \"functions\": [")
            sb.append(d.functions.joinToString(", ") { "{\"package\": ${JsonWriter.renderString(it.first)}, \"function\": ${JsonWriter.renderString(it.second)}}" })
            sb.append("],\n")
            sb.append("      \"gaps\": [")
            sb.append(d.gaps.joinToString(", ") { JsonWriter.renderString(it) })
            sb.append("]\n    }")
            if (index != entries.size - 1) sb.append(",")
            sb.append("\n")
        }
        sb.append("  ]\n}\n")
        return sb.toString()
    }

    // ---- CHECK A: the pack against the COMMITTED extract (runs everywhere) --

    @Test
    fun everyModelledSymbolInTheCoveredChannelsHasACommittedFact() {
        val committed = loadCommitted()
        val uncovered = mutableListOf<String>()
        for (fw in pack.frameworks) {
            val entry = committed[fw.id]
            assertTrue(entry != null, "framework ${fw.id} has no committed evidence record — derive one (see the class doc) or record why it cannot be checked")
            val types = entry.types
            val members = entry.members
            val functions = entry.functions
            val gaps = entry.gaps
            for (channel in entry.covers) {
                for (pattern in patterns(fw.id, channel)) {
                    val key = "$fw.id/$channel/$pattern"
                    when {
                        channel in typeChannels -> {
                            val fact = types.firstOrNull { it.fqn == pattern }
                            if (fact == null && gaps.none { it.startsWith("$pattern:") }) {
                                uncovered += "$key — no committed type fact (the shape: a modelled symbol with no evidence)"
                            }
                            if (channel == "securityConstructors" && fact != null && !fact.constructible) {
                                uncovered += "$key — committed fact says the class is not constructible"
                            }
                        }
                        channel in memberChannels && isOwnerMember(pattern) -> {
                            val owner = pattern.substringBeforeLast('.')
                            val member = pattern.substringAfterLast('.')
                            val fact = members.firstOrNull { it.owner == owner && it.member == member }
                            if (fact == null && gaps.none { it.startsWith("$pattern:") }) {
                                uncovered += "$key — no committed member fact (the shape: a member the framework does not declare)"
                            }
                            if (channel == "authHandlerFactories" && fact != null && !fact.static) {
                                uncovered += "$key — committed fact says the factory is not static"
                            }
                        }
                        else -> {
                            val pkg = pattern.substringBeforeLast('.')
                            val fn = pattern.substringAfterLast('.')
                            val matched = if (pattern.contains('.')) {
                                functions.any { it.first == pkg && it.second == fn }
                            } else {
                                functions.any { it.second == fn }
                            }
                            if (!matched && gaps.none { it.startsWith("$pattern:") }) {
                                uncovered += "$key — no committed function fact"
                            }
                        }
                    }
                }
            }
        }
        assertTrue(uncovered.isEmpty(), "modelled symbols without committed evidence:\n${uncovered.joinToString("\n")}")
    }

    // ---- CHECK B: re-derive where the pinned evidence is held ---------------

    @Test
    fun theCommittedExtractMatchesWhatTheHeldEvidenceDerives() {
        val derived = derive()
        // Regeneration may also be what CREATES the file (first derivation):
        // a missing extract is only a failure when nobody asked for it.
        if (!Files.isRegularFile(extractFile)) {
            assertTrue(derived.values.none { it.failures.isNotEmpty() },
                "refusing to generate evidence the held artifacts CONTRADICT:\n" + derived.values.flatMap { it.failures }.joinToString("\n"))
            if (System.getenv("KOSI_UPDATE_SYMBOL_EVIDENCE") == "1") {
                Files.createDirectories(extractFile.parent)
                Files.writeString(extractFile, derivedToJson(derived))
                println("symbol-evidence: GENERATED ${extractFile}")
                return
            }
        }
        val failures = mutableListOf<String>()
        for ((id, d) in derived) {
            if (!d.held) continue
            val committed = loadCommitted()[id] ?: error("$id derived from held evidence but has no committed entry")
            val derivedTypes = d.types.map { TypeFact(it[0] as String, it[1] as String, it[2] as Boolean) }
            if (committed.types != derivedTypes) {
                failures += "$id: committed type facts differ from the re-derived ones (pack or artifact drift)"
            }
            if (committed.members != d.members) {
                failures += "$id: committed member facts differ from the re-derived ones"
            }
            if (committed.functions != d.functions) {
                failures += "$id: committed function facts differ from the re-derived ones"
            }
            if (committed.gaps != d.gaps) {
                failures += "$id: committed gaps differ from the re-derived ones"
            }
            assertTrue(d.failures.isEmpty(), "$id: the held evidence CONTRADICTS the pack:\n${d.failures.joinToString("\n")}")
        }
        assertTrue(failures.isEmpty(), "committed symbol evidence has drifted:\n${failures.joinToString("\n")}")
        // Regeneration switch (see the class doc): writes ONLY what the held
        // evidence derived, and refuses when any pack symbol FAILED — a
        // contradiction is a defect, not evidence.
        if (System.getenv("KOSI_UPDATE_SYMBOL_EVIDENCE") == "1") {
            Files.createDirectories(extractFile.parent)
            Files.writeString(extractFile, derivedToJson(derived))
            println("symbol-evidence: REGENERATED ${extractFile}")
        }
    }

    // ---- the verdict table, counted ------------------------------------------

    @Test
    fun everyFrameworkHasACountedEvidenceVerdict() {
        val committed = loadCommitted()
        val derived = derive()
        val verdicts = sortedMapOf<String, String>()
        for (fw in pack.frameworks) {
            val entry = committed[fw.id] ?: continue
            val symbols = entry.covers.sumOf { patterns(fw.id, it).size }
            val allChannels = (typeChannels + memberChannels + functionChannels).filter { patterns(fw.id, it).isNotEmpty() }
            val allSymbols = allChannels.sumOf { patterns(fw.id, it).size }
            val checked = entry.types.size + entry.members.size + entry.functions.size
            val gaps = entry.gaps.size
            val rederived = derived[fw.id]?.takeIf { it.held }?.let { d -> d.types.size + d.members.size + d.functions.size } ?: 0
            verdicts[fw.id] = when {
                entry.sources.isEmpty() && allSymbols == 0 -> "NON-SYMBOL channels only (${entry.gaps.firstOrNull()?.substringAfter(':')?.trim() ?: "no class symbols"})"
                entry.sources.isEmpty() -> "UNSOURCED: 0/$allSymbols symbols checkable — ${gaps} recorded gap(s): ${entry.gaps.firstOrNull()?.substringAfter(':')?.trim()}"
                else -> "KIND-CHECKED $checked/$allSymbols symbols vs COMMITTED EXTRACT (${entry.sources.joinToString(", ")}); $gaps recorded gap(s); re-derived $rederived here"
            }
        }
        verdicts.forEach { (id, verdict) -> println("symbol-evidence: $id -> $verdict") }
        assertEquals(pack.frameworks.size, verdicts.size, "every framework needs a counted verdict")
    }

    // ---- the teeth, kept permanent ----------------------------------------

    @Test
    fun theKindCheckRejectsTheSealedParentR109Modelled() {
        val clone = http4kEvidence() ?: return
        val decl = http4kDeclarationModifiers(clone, "org.http4k.security.OAuthSecurity")
            ?: error("OAuthSecurity.kt is not where the pack comment says it is")
        assertFalse(isConstructible(decl.first, decl.second), "OAuthSecurity must remain sealed for this check to have teeth")
        val fw = pack.frameworks.first { it.id == "http4k" }
        assertTrue(fw.securityConstructors.isNotEmpty())
        assertFalse(
            fw.securityConstructors.any { it.endsWith("OAuthSecurity") && !it.contains("AuthCode") && !it.contains("Implicit") && !it.contains("Credentials") && !it.contains("DeviceCode") },
            "the sealed OAuthSecurity parent is modelled in a constructor channel (regress)",
        )
    }

    // ---- helpers --------------------------------------------------------------

    private class Entry(
        val sources: List<String>,
        val covers: List<String>,
        val types: List<TypeFact>,
        val members: List<MemberFact>,
        val functions: List<Pair<String, String>>,
        val gaps: List<String>,
    )

    private data class TypeFact(val fqn: String, val kind: String, val constructible: Boolean)

    private fun loadCommitted(): Map<String, Entry> {
        assertTrue(Files.isRegularFile(extractFile), "committed symbol evidence missing: $extractFile")
        val root = JsonReader.parse(Files.readString(extractFile)).asObject()
        assertEquals("kosi symbol evidence 1", root.str("format"), "unknown extract format")
        val out = sortedMapOf<String, Entry>()
        for (fw in root.arr("frameworks")!!.objects()) {
            val types = fw.arr("types")!!.objects().map {
                TypeFact(it.str("fqn")!!, it.str("kind")!!, it.bool("constructible") == true)
            }
            val members = fw.arr("members")!!.objects().map {
                MemberFact(it.str("owner")!!, it.str("member")!!, it.bool("static") == true)
            }
            val functions = fw.arr("functions")!!.objects().map { it.str("package")!! to it.str("function")!! }
            out[fw.str("id")!!] = Entry(
                fw.arr("sources")?.strings() ?: emptyList(),
                fw.arr("covers")?.strings() ?: emptyList(),
                types, members, functions,
                fw.arr("gaps")?.strings() ?: emptyList(),
            )
        }
        return out
    }
}
