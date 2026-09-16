package io.cdxgen.kosi.bytecode

import io.cdxgen.kosi.models.EndpointModels
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
 * P18 §2: a modelled symbol must be a thing that can exist in the framework
 * — R109 modelled `OAuthSecurity`, a SEALED class, in a CONSTRUCTOR channel,
 * so the entry could never match and the fallback named the block's scheme
 * with confidence. Nothing checked "constructible", "static" or "function"
 * because the pack stores strings.
 *
 * This test asserts, per channel KIND, that every modelled symbol EXISTS in
 * framework sources or jars the corpus machine holds, and is of the kind the
 * channel assumes:
 *
 *  - a CONSTRUCTOR channel needs a constructible type (class, not
 *    sealed/abstract/interface/object);
 *  - a FACTORY channel needs a static method on a real type;
 *  - a DSL channel needs a function — a member function when the FQN names
 *    `Owner.member`, or a static on SOME `*Kt` facade class of the FQN's
 *    package when it names a Kotlin top-level function;
 *  - an ANNOTATION/MARKER FQN needs a class entry in a held jar when any
 *    held jar covers the FQN's package family; when the corpus holds
 *    nothing that could contain it, that is a RECORDED GAP, not a pass.
 *
 * Evidence lives on the corpus machine (the warm Gradle cache and the
 * SHA-pinned http4k clone under .corpus-cache). On a machine without them
 * the checks skip LOUDLY — the per-framework verdict table at the bottom
 * always runs and prints exactly what could and could not be checked, so
 * the gap is never implicit.
 */
class EndpointsPackSymbolKindTest {

    private val repoRoot = Path.of("..", "..").toAbsolutePath().normalize()
    private val pack = EndpointModels.loadBuiltin()

    // ---- evidence discovery -------------------------------------------------

    private fun modules2(): Path? =
        Path.of(System.getProperty("user.home"), ".gradle", "caches", "modules-2", "files-2.1")
            .takeIf { Files.isDirectory(it) }

    /** Every version of `group:artifact` in the warm cache, newest first. */
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

    private fun jarClass(jar: Path, fqn: String): Boolean =
        ZipFile(jar.toFile()).use { zip -> zip.getEntry(fqn.replace('.', '/') + ".class") != null }

    /** True when [jar] contains ANY class under the FQN's three-segment family prefix. */
    private fun jarCoversFamily(jar: Path, fqn: String): Boolean {
        val segments = fqn.split('.')
        if (segments.size < 4) return false
        val family = segments.take(3).joinToString("/")
        return ZipFile(jar.toFile()).use { zip ->
            zip.entries().asSequence().any { it.name.endsWith(".class") && it.name.startsWith("$family/") }
        }
    }

    /** Every method [fqn] declares in [jar], static or not. */
    private fun methodNames(jar: Path, fqn: String): Set<String> = declaredMethods(jar, fqn, staticOnly = false)

    private fun staticMethodNames(jar: Path, fqn: String): Set<String> = declaredMethods(jar, fqn, staticOnly = true)

    private fun declaredMethods(jar: Path, fqn: String, staticOnly: Boolean): Set<String> {
        val entry = ZipFile(jar.toFile()).use { zip -> zip.getEntry(fqn.replace('.', '/') + ".class") }
            ?: return emptySet()
        val names = mutableSetOf<String>()
        ClassReader(ZipFile(jar.toFile()).use { zip -> zip.getInputStream(entry).readBytes() }).accept(
            object : ClassVisitor(Opcodes.ASM9) {
                override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor? {
                    if (name != null && (!staticOnly || (access and Opcodes.ACC_STATIC) != 0)) names.add(name)
                    return null
                }
            },
            ClassReader.SKIP_CODE,
        )
        return names
    }

    /** The top-level Kotlin facades (`*Kt`, no `$`) of [packageFqn] in [jar]. */
    private fun facades(jar: Path, packageFqn: String): List<String> =
        ZipFile(jar.toFile()).use { zip ->
            zip.entries().asSequence()
                .map { it.name }
                .filter { it.endsWith("Kt.class") && !it.contains('$') }
                .filter { it.removeSuffix(".class").replace('/', '.') .let { fqn -> fqn.substringBeforeLast('.') == packageFqn } }
                .map { it.removeSuffix(".class").replace('/', '.') }
                .toList()
        }

    // ---- http4k: SOURCES at the pinned clone ---------------------------------

    private val http4kClone = repoRoot.resolve(".corpus-cache").resolve("http4k")
    private val HTTP4K_PINNED_SHA = "b051f89d35ab9190385a244e9e77149e77c55f4d"

    private fun http4kEvidence(): Path? {
        if (!Files.isDirectory(http4kClone.resolve("core"))) return null
        // The evidence is only evidence at the SHA it was sourced at.
        val head = Files.readString(http4kClone.resolve(".git").resolve("HEAD")).trim()
        val sha = if (head.startsWith("ref:")) {
            Files.readString(http4kClone.resolve(".git").resolve(head.removePrefix("ref: ").trim())).trim()
        } else head
        assertEquals(HTTP4K_PINNED_SHA, sha, "http4k corpus clone is not at the SHA the pack was sourced from")
        return http4kClone
    }

    /** The declaration modifiers of `class|interface|object <simple>` in its own file, or null when absent. */
    private fun http4kDeclarationModifiers(clone: Path, fqn: String): Pair<String, String>? {
        val simple = fqn.substringAfterLast('.')
        val rel = fqn.removePrefix("org.http4k.").replace('.', '/')
        val file = fqn.split('.').dropLast(1).fold(clone) { acc, seg -> acc.resolve(seg) }
            .resolve("$simple.kt")
        // Several classes share one file (the five OAuth schemes all live
        // in OAuthSecurity.kt), so the declaration is searched across every
        // .kt file, not just "$simple.kt".
        val candidates = sequenceOf(file) + Files.walk(clone).use { s ->
            s.filter { Files.isRegularFile(it) && it.toString().endsWith(".kt") }.toList()
        }
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

    @Test
    fun http4kSecurityConstructorsAreConstructibleClasses() {
        val clone = http4kEvidence() ?: run {
            println("symbol-kind: SKIP http4k securityConstructors — no corpus clone at .corpus-cache/http4k")
            return
        }
        val fw = pack.frameworks.first { it.id == "http4k" }
        assertTrue(fw.securityConstructors.isNotEmpty())
        for (fqn in fw.securityConstructors) {
            val decl = http4kDeclarationModifiers(clone, fqn)
                ?: error("http4k declares no ${fqn.substringAfterLast('.')} anywhere in the clone — a modelled constructor with no type (R109's shape)")
            assertTrue(
                isConstructible(decl.first, decl.second),
                "$fqn is ${decl.second} ${decl.first.trim()} — a constructor channel needs a constructible class",
            )
        }
    }

    @Test
    fun theKindCheckRejectsTheSealedParentR109Modelled() {
        // R109's own defect is the teeth: OAuthSecurity IS sealed in the
        // pinned clone, so the checker must reject it, and the pack must not
        // carry it in securityConstructors.
        val clone = http4kEvidence() ?: return
        val decl = http4kDeclarationModifiers(clone, "org.http4k.security.OAuthSecurity")
            ?: error("OAuthSecurity.kt is not where the pack comment says it is")
        assertFalse(isConstructible(decl.first, decl.second), "OAuthSecurity must remain sealed for this check to have teeth")
        val fw = pack.frameworks.first { it.id == "http4k" }
        assertFalse(
            fw.securityConstructors.any { it.endsWith("OAuthSecurity") && !it.contains("AuthCode") && !it.contains("Implicit") && !it.contains("Credentials") && !it.contains("DeviceCode") },
            "the sealed OAuthSecurity parent is modelled in a constructor channel (R109 regress)",
        )
    }

    @Test
    fun http4kDslSymbolsAreFunctions() {
        val clone = http4kEvidence() ?: run {
            println("symbol-kind: SKIP http4k DSL channels — no corpus clone")
            return
        }
        val fw = pack.frameworks.first { it.id == "http4k" }
        // Top-level `contract` / `meta` — declared as functions somewhere in
        // the contract sources; `meta` is the String extension the route
        // spelling uses, `bind`/`bindContract` likewise (extensions.kt).
        val sources = Files.walk(clone).use { s ->
            s.filter { Files.isRegularFile(it) && it.toString().endsWith(".kt") }.toList()
        }.filter { it.toString().contains("/contract/") || it.toString().contains("/core/") }
        for (fqn in fw.contractDsl + fw.routeMetaDsl) {
            val name = fqn.substringAfterLast('.')
            assertTrue(
                sources.any { Regex("""fun\s+(infix\s+)?(String\.)?$name\s*[<(]""").containsMatchIn(Files.readString(it)) },
                "$fqn: no `fun $name` in the http4k clone — a DSL channel needs a function",
            )
        }
        for (m in fw.bindFunctions) {
            val name = m.pattern.substringAfterLast('.')
            assertTrue(
                sources.any { Regex("""fun\s+(infix\s+)?String\.$name\s*[<(]""").containsMatchIn(Files.readString(it)) },
                "String.$name: http4k declares no String-receiver bind function — a DSL channel needs a function",
            )
        }
    }

    // ---- vertx: the pinned jar ------------------------------------------------

    private val VERTX_PINNED = "5.1.7"

    @Test
    fun vertxAuthHandlerFactoriesAreStaticsOnRealClasses() {
        val jars = jars("io.vertx", "vertx-web")
        if (jars.isEmpty()) {
            println("symbol-kind: SKIP vertx authHandlerFactories — vertx-web not in the warm cache")
            return
        }
        assertTrue(
            jars.any { it.toString().contains(VERTX_PINNED) },
            "vertx-web evidence drifted: the pack was sourced at $VERTX_PINNED, the cache holds ${jars.map { it.parent.fileName }}",
        )
        val fw = pack.frameworks.first { it.id == "vertx" }
        assertTrue(fw.authHandlerFactories.isNotEmpty())
        for (pattern in fw.authHandlerFactories) {
            val owner = pattern.substringBeforeLast('.')
            val factory = pattern.substringAfterLast('.')
            val found = jars.filter { it.toString().contains(VERTX_PINNED) }.any { jar ->
                jarClass(jar, owner) && staticMethodNames(jar, owner).contains(factory)
            }
            assertTrue(found, "$pattern: no static `$factory` on $owner in vertx-web $VERTX_PINNED — a factory channel needs a static")
        }
    }

    @Test
    fun vertxDslChannelsNameRealMemberFunctions() {
        val jars = jars("io.vertx", "vertx-web").filter { it.toString().contains(VERTX_PINNED) }
        if (jars.isEmpty()) {
            println("symbol-kind: SKIP vertx DSL channels — vertx-web $VERTX_PINNED not in the warm cache")
            return
        }
        val fw = pack.frameworks.first { it.id == "vertx" }
        // dslFunctions/handlerDsl/mediaDsl FQNs are `Owner.member` shapes:
        // the OWNER class must exist and declare the member (non-static is
        // fine — the KIR lowers member calls against the owner).
        for (m in fw.dslFunctions.map { it.pattern } + fw.mediaDsl.map { it.pattern }) {
            val owner = m.substringBeforeLast('.')
            val member = m.substringAfterLast('.')
            // The owner's METHOD TABLE, not its bytes: a substring search
            // over the class file passes on any constant-pool mention —
            // another method's signature, a string literal, the name of a
            // member that was REMOVED but still appears in a generic
            // signature. R112 (`mountSubRouter`, gone in Vert.x 5) is
            // exactly what this check exists to catch, so it may not be
            // satisfiable by an accident of encoding (P18 review).
            val memberDeclared = jars.any { jar -> methodNames(jar, owner).contains(member) }
            assertTrue(
                memberDeclared,
                "$m: $owner declares no member `$member` in vertx-web $VERTX_PINNED — the DSL names a shape the framework does not have",
            )
        }
        for (h in fw.handlerDsl) {
            val owner = h.substringBeforeLast('.')
            assertTrue(jars.any { jarClass(it, owner) }, "$h: owner $owner absent from vertx-web $VERTX_PINNED")
        }
    }

    // ---- ktor: top-level DSL functions in held artifacts ----------------------

    @Test
    fun ktorDslSymbolsAreTopLevelFunctions() {
        val coreJars = jars("io.ktor", "ktor-server-core-jvm") + jars("io.ktor", "ktor-server-core")
        val authJars = jars("io.ktor", "ktor-server-auth-jvm") + jars("io.ktor", "ktor-server-auth")
        if (coreJars.isEmpty() && authJars.isEmpty()) {
            println("symbol-kind: SKIP ktor DSL channels — no ktor-server artifacts in the warm cache")
            return
        }
        val fw = pack.frameworks.first { it.id == "ktor" }
        // A top-level function's FQN names no class: the JVM owner is a
        // `*Kt` facade of the same package. ANY facade declaring a static
        // with the function's name satisfies the kind — file names are not
        // part of the API (`authenticate` moved facades between ktor
        // generations), so the check is deliberately owner-agnostic.
        // A package with NO facades in any held jar means the artifact that
        // declares it is not in the cache (ktor-server-resources is not):
        // that is a recorded GAP, not a verdict — absence of evidence is
        // not evidence of absence when the jar itself is missing.
        val gaps = mutableListOf<String>()
        val failures = mutableListOf<String>()
        for (m in fw.dslFunctions.map { it.pattern } + fw.authenticationDsl) {
            val pkg = m.substringBeforeLast('.')
            val fn = m.substringAfterLast('.')
            val allFacades = (coreJars + authJars).flatMap { jar -> facades(jar, pkg) }
            when {
                allFacades.any { f -> (coreJars + authJars).any { jar -> staticMethodNames(jar, f).contains(fn) } } -> {}
                allFacades.isEmpty() -> gaps += "$m: package $pkg has no facade in any held ktor artifact (artifact not in the warm cache)"
                else -> failures += "$m: $pkg facades exist but none declares a static `$fn` — a DSL channel needs a function"
            }
        }
        gaps.forEach { println("symbol-kind: GAP ktor $it") }
        assertTrue(failures.isEmpty(), "ktor DSL symbols missing from held artifacts:\n${failures.joinToString("\n")}")
    }

    // ---- annotations: FQN existence wherever the corpus covers the family -----

    /** Frameworks whose annotation/marker FQNs can be checked against held jars. */
    private val annotationEvidence: Map<String, List<Pair<String, String>>> = mapOf(
        "spring-mvc" to listOf("org.springframework" to "spring-webmvc", "org.springframework" to "spring-web", "org.springframework" to "spring-context"),
        "spring-webflux" to listOf("org.springframework" to "spring-webflux", "org.springframework" to "spring-web", "org.springframework" to "spring-context"),
        "spring-messaging" to listOf("org.springframework" to "spring-context"),
        "graphql" to listOf("org.springframework" to "spring-context"),
        "micronaut" to listOf("io.micronaut" to "micronaut-http"),
        "quarkus" to listOf("jakarta.ws.rs" to "jakarta.ws.rs-api"),
        "servlet" to listOf("jakarta.servlet" to "jakarta.servlet-api"),
        "aws-lambda" to listOf("com.amazonaws" to "aws-lambda-java-core"),
        "azure-functions" to listOf(
            "com.microsoft.azure.functions" to "azure-functions-java-library",
            "com.microsoft.azure.functions" to "azure-functions-java-core-library",
        ),
    )

    @Test
    fun modelledAnnotationFqnsExistWhereverAHeldJarCouldContainThem() {
        val gaps = mutableListOf<String>()
        val failures = mutableListOf<String>()
        for ((frameworkId, coords) in annotationEvidence) {
            val fw = pack.frameworks.first { it.id == frameworkId }
            val fqns = (
                fw.mappingAnnotations.map { it.pattern } + fw.mediaAnnotations.map { it.pattern } +
                    fw.authenticationAnnotations.map { it.pattern } + fw.parameterAnnotations.map { it.pattern } +
                    fw.classMarkers + fw.classMappingAnnotations + fw.pathPrefixAnnotations +
                    fw.applicationPathAnnotations + fw.supertypeMarkers + fw.repositorySupertypes
                ).filter { it.contains('.') && it.first().isLowerCase() || it.split('.').first().length > 1 }
                .filter { fqn -> fqn.split('.').size >= 3 && fqn.none { c -> c == '*' || c == '<' } }
                .distinct()
            val held = coords.flatMap { (g, a) -> jars(g, a) }
            if (held.isEmpty()) {
                gaps += "$frameworkId: no artifact held for ${coords.map { "${it.first}:${it.second}" }}"
                continue
            }
            for (fqn in fqns) {
                when {
                    held.any { jarClass(it, fqn) } -> {}
                    held.any { jarCoversFamily(it, fqn) } -> failures += "$frameworkId: $fqn not in any held ${coords.map { "${it.second}" }} — a modelled symbol the framework does not have (R109's shape)"
                    else -> gaps += "$frameworkId: $fqn — no held jar covers its package family"
                }
            }
        }
        failures.forEach { println("symbol-kind: FAIL $it") }
        gaps.forEach { println("symbol-kind: GAP $it") }
        assertTrue(failures.isEmpty(), "modelled annotations missing from held jars:\n${failures.joinToString("\n")}")
    }

    // ---- the per-framework verdict table ---------------------------------------

    /**
     * Every framework in the pack gets a verdict — kind-checked, annotation-
     * checked, or a NAMED gap. A framework nobody can add without recording
     * what the corpus does and does not hold to check it against: R109
     * happened because `securityConstructors: ["...OAuthSecurity"]` looked
     * exactly as valid as the constructible entries beside it.
     */
    /** How many of ktor's modelled DSL symbols this machine could actually check. */
    private fun ktorVerdict(): String {
        val jars = jars("io.ktor", "ktor-server-core-jvm") + jars("io.ktor", "ktor-server-core") +
            jars("io.ktor", "ktor-server-auth-jvm") + jars("io.ktor", "ktor-server-auth")
        val fw = pack.frameworks.first { it.id == "ktor" }
        val symbols = fw.dslFunctions.map { it.pattern } + fw.authenticationDsl
        val checked = symbols.count { m ->
            val pkg = m.substringBeforeLast('.')
            jars.flatMap { jar -> facades(jar, pkg) }
                .any { f -> jars.any { jar -> staticMethodNames(jar, f).contains(m.substringAfterLast('.')) } }
        }
        return if (checked == 0) {
            "NO EVIDENCE: 0/${symbols.size} DSL symbols checkable — no held ktor artifact declares their packages"
        } else {
            "KIND-CHECKED $checked/${symbols.size} DSL symbols vs held ktor-server artifacts (facade statics)"
        }
    }

    @Test
    fun everyFrameworkHasAnEvidenceVerdict() {
        val verdicts = sortedMapOf<String, String>()
        for (fw in pack.frameworks) {
            val id = fw.id
            verdicts[id] = when {
                id == "http4k" ->
                    if (http4kEvidence() != null) "KIND-CHECKED vs sources at $HTTP4K_PINNED_SHA (constructors + DSL)"
                    else "NO EVIDENCE: corpus clone absent (.corpus-cache/http4k)"
                id == "vertx" ->
                    if (jars("io.vertx", "vertx-web").isNotEmpty()) "KIND-CHECKED vs vertx-web $VERTX_PINNED (factories + DSL)"
                    else "NO EVIDENCE: vertx-web absent from the warm cache"
                // Counted, not inferred from "an artifact is present": a
                // ktor jar in the cache does not mean the PACKAGES the pack
                // models are in it (ktor-server-core-jvm holds no
                // io.ktor.server.routing facade on a machine that has only
                // the client artifacts), and a verdict line that says
                // KIND-CHECKED while every symbol was a GAP is the P18
                // review's own mistake: one machine's evidence state
                // reported as the gate's (P18 review).
                id == "ktor" -> ktorVerdict()
                annotationEvidence.containsKey(id) -> "ANNOTATION-CHECKED vs ${annotationEvidence[id]!!.map { "${it.first}:${it.second}" }}"
                id == "grpc" ->
                    if (jars("io.grpc", "grpc-stub").isNotEmpty()) "SUFFIX markers; CoroutineImplBase existence checked in CI-held grpc-stub"
                    else "NO EVIDENCE: grpc-stub absent from the warm cache"
                id == "compose-navigation" -> "NO EVIDENCE: androidx.navigation:navigation-compose not in the warm cache (only common/runtime/testing are)"
                id == "javalin" -> "NO EVIDENCE: io.javalin absent from the warm cache — channels unchecked"
                id == "sparkjava" -> "NO EVIDENCE: com.sparkjava absent from the warm cache — channels unchecked"
                id == "mcp" -> "NO EVIDENCE: io.modelcontextprotocol absent from the warm cache — channels unchecked"
                id == "spring-actuator" || id == "springdoc" ->
                    "DEPENDENCY MARKERS (artifact coordinates, not class symbols): the committed marker jars in fixtures/implicit-routes are presence-only stubs; no class kind to check"
                id == "android" -> "MANIFEST components: no class symbols to check"
                else -> "NO EVIDENCE RECORDED — update the table when adding a framework"
            }
        }
        verdicts.forEach { (id, verdict) -> println("symbol-kind: $id -> $verdict") }
        assertEquals(
            pack.frameworks.size,
            verdicts.size,
            "every framework needs a verdict; the table is the record of what the corpus can and cannot check",
        )
        assertTrue(
            verdicts.values.none { it.startsWith("NO EVIDENCE RECORDED") },
            "a framework landed in the pack without an evidence verdict",
        )
    }
}
