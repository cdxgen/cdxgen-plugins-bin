package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path

/**
 * Parses Gradle projects: settings.gradle(.kts) for the workspace member list,
 * each member's build.gradle(.kts) for plugins, compiler settings and source
 * sets, including Android build types/flavors and Kotlin Multiplatform source
 * sets. Everything is textual; nothing is executed.
 */
object GradleDiscovery {

    private val KMP_SOURCE_SET_PLATFORMS = listOf(
        Triple("commonMain", DiscoveredModule.PLATFORM_COMMON, setOf<String>()),
        Triple("jvmMain", DiscoveredModule.PLATFORM_JVM, setOf("jvm")),
        Triple("androidMain", DiscoveredModule.PLATFORM_ANDROID, setOf("android")),
        Triple("jsMain", DiscoveredModule.PLATFORM_JS, setOf("js")),
    )

    private val NATIVE_SOURCE_SET = Regex("""^(ios|macos|tvos|watchos|linux|mingw)[A-Za-z0-9]*(Main|Test)$""")

    data class Member(
        val dir: Path,
        val gradlePath: String,
        val name: String,
        val buildFile: Path?,
    )

    fun discover(root: Path): DiscoveryResult {
        val settingsText = readIfExists(root, "settings.gradle.kts")
            ?: readIfExists(root, "settings.gradle")
            ?: readIfExists(root, "settings.gradle.dcl")
        val rootName = settingsText?.let { TextScan.assignment(it, "rootProject.name") } ?: root.fileName.toString()
        val members = collectMembers(root, settingsText, rootName)
        val group = members.firstNotNullOfOrNull { m ->
            m.buildFile?.let { bf -> groupFromBuildFile(bf) } ?: groupFromProperties(m.dir)
        } ?: groupFromProperties(root)
        val version = members.firstNotNullOfOrNull { m ->
            m.buildFile?.let { bf -> TextScan.assignment(readText(bf) ?: "", "version") }
        } ?: versionFromProperties(root)

        val modules = mutableListOf<DiscoveredModule>()
        for (member in members) {
            val buildText = member.buildFile?.let { readText(it) } ?: ""
            modules.addAll(memberModules(root, member, buildText, group, version))
        }
        return DiscoveryResult(modules, buildSystem = "gradle")
    }

    private fun collectMembers(root: Path, settingsText: String?, rootName: String): List<Member> {
        val members = mutableListOf(Member(root, ":", rootName, findBuildFile(root)))
        if (settingsText != null) {
            val includeRegex = Regex("""include\s*\(\s*(\"[^\"]+\"(?:\s*,\s*\"[^\"]+\")*)\s*\)""")
            for (match in includeRegex.findAll(settingsText)) {
                for (quotePart in match.groupValues[1].split(',')) {
                    val gradlePath = quotePart.trim().removeSurrounding("\"")
                    if (gradlePath.isEmpty()) continue
                    val rel = gradlePath.removePrefix(":").replace(':', '/')
                    if (rel.isEmpty()) continue
                    val dir = root.resolve(rel)
                    if (!Files.isDirectory(dir)) continue
                    val name = gradlePath.substringAfterLast(':')
                    members.add(Member(dir, gradlePath, name, findBuildFile(dir)))
                }
            }
        }
        return members
    }

    private fun findBuildFile(dir: Path): Path? =
        listOf("build.gradle.kts", "build.gradle").firstNotNullOfOrNull { f ->
            Files.isRegularFile(dir.resolve(f)).takeIf { it }?.let { dir.resolve(f) }
        }

    private fun groupFromBuildFile(buildFile: Path): String? =
        readText(buildFile)?.let { TextScan.assignment(it, "group") }

    private fun groupFromProperties(dir: Path): String? =
        readIfExists(dir, "gradle.properties")?.let { TextScan.assignment(it, "group") }

    private fun versionFromProperties(dir: Path): String? =
        readIfExists(dir, "gradle.properties")?.let { TextScan.assignment(it, "version") }

    private fun memberModules(
        root: Path,
        member: Member,
        buildText: String,
        group: String?,
        version: String?,
    ): List<DiscoveredModule> {
        if (buildText.isBlank()) {
            // A member with no build file still contributes sources under the
            // standard layout.
            return listOf(
                DiscoveredModule(
                    name = member.name,
                    modulePath = rel(root, member.dir),
                    platform = DiscoveredModule.PLATFORM_JVM,
                    workspaceMember = member.gradlePath,
                    sourceRoots = standardRoots(root, member.dir),
                    declaredLanguageVersion = null,
                    declaredApiVersion = null,
                    jvmTarget = null,
                    purl = purl(group, member.name, version),
                ),
            )
        }

        val isAndroid = buildText.contains("com.android.application") ||
            buildText.contains("com.android.library") ||
            buildText.contains("com.android.kotlin.multiplatform.library")
        val isMultiplatform = buildText.contains("kotlin-multiplatform") ||
            buildText.contains("kotlin(\"multiplatform\")")
        val isJvm = buildText.contains("kotlin-jvm") || buildText.contains("kotlin(\"jvm\")") ||
            buildText.contains("org.jetbrains.kotlin.jvm")

        val platformBase = when {
            isAndroid -> DiscoveredModule.PLATFORM_ANDROID
            isMultiplatform -> DiscoveredModule.PLATFORM_COMMON
            isJvm || buildText.contains("java") -> DiscoveredModule.PLATFORM_JVM
            else -> DiscoveredModule.PLATFORM_JVM
        }

        val languageVersion = compilerSetting(buildText, "languageVersion")
        val apiVersion = compilerSetting(buildText, "apiVersion")
        val jvmTarget = compilerSetting(buildText, "jvmTarget") ?: TextScan.assignment(buildText, "jvmToolchain")

        val modulePath = rel(root, member.dir)
        val defaultRoots = standardRoots(root, member.dir)
        val purlValue = purl(group, member.name, version)

        val modules = mutableListOf<DiscoveredModule>()

        if (isMultiplatform) {
            // KMP: each source set becomes its own ModuleRef so commonMain and
            // per-target actuals are distinguishable (03-SCHEMA.md).
            val sourceSetBlocks = TextScan.allBlocks(buildText, "sourceSets")
            val declared = LinkedHashSet<String>()
            for ((_, body) in sourceSetBlocks) {
                Regex("""(?:val|by getting|getting\()\s*([A-Za-z0-9_]+)""").findAll(body).forEach {
                    declared.add(it.groupValues[1])
                }
                Regex("""create\(\"([A-Za-z0-9_]+)\"""").findAll(body).forEach { declared.add(it.groupValues[1]) }
            }
            // Also include the conventional sets whenever their directories exist.
            val conventional = listOf("commonMain", "commonTest", "jvmMain", "jvmTest", "androidMain", "androidTest", "jsMain", "jsTest")
            for (name in conventional) {
                if (Files.isDirectory(member.dir.resolve("src").resolve(name))) declared.add(name)
            }
            if (declared.isEmpty()) declared.add("commonMain")
            for (sourceSet in declared.sorted()) {
                val platform = platformOfSourceSet(sourceSet)
                val roots = sourceSetRoots(root, member.dir, sourceSet, buildText)
                if (roots.isEmpty()) continue
                modules.add(
                    DiscoveredModule(
                        name = if (member.name.isEmpty()) sourceSet else "${member.name}:$sourceSet",
                        modulePath = modulePath,
                        platform = platform,
                        workspaceMember = member.gradlePath,
                        sourceRoots = roots,
                        declaredLanguageVersion = languageVersion,
                        declaredApiVersion = apiVersion,
                        jvmTarget = jvmTarget,
                        purl = purlValue,
                    ),
                )
            }
            return modules
        }

        // JVM / Android: one module, roots = defaults + extra srcDirs +
        // Android variant directories that exist on disk.
        val roots = LinkedHashSet(defaultRoots)
        Regex("""srcDir\s*\(\s*\"([^\"]+)\"\s*\)""").findAll(buildText).forEach {
            val dir = it.groupValues[1]
            if (Files.isDirectory(member.dir.resolve(dir))) roots.add(dir)
        }
        if (isAndroid) {
            for (variant in androidVariants(buildText)) {
                val dir = "src/$variant"
                if (TextScan.isDirectory(member.dir, dir)) roots.add(dir)
            }
        }
        if (roots.isEmpty()) {
            // No recognizable source root: fall back to the module directory
            // itself so stray sources are still visible (and diagnosable).
            roots.add(modulePath)
        }
        modules.add(
            DiscoveredModule(
                name = member.name,
                modulePath = modulePath,
                platform = platformBase,
                workspaceMember = member.gradlePath,
                sourceRoots = roots.toList(),
                declaredLanguageVersion = languageVersion,
                declaredApiVersion = apiVersion,
                jvmTarget = jvmTarget,
                purl = purlValue,
            ),
        )
        return modules
    }

    /** Variant directory names derived textually from buildTypes and flavors. */
    fun androidVariants(buildText: String): List<String> {
        val variants = LinkedHashSet<String>()
        val buildTypesBlock = TextScan.block(buildText, "buildTypes")
        if (buildTypesBlock != null) {
            Regex("""(?m)^\s*(\w+)\s*\{""").findAll(buildTypesBlock).forEach {
                val n = it.groupValues[1]
                if (n != "get") variants.add(n)
            }
        }
        val flavorsBlock = TextScan.block(buildText, "productFlavors")
            ?: TextScan.block(buildText, "flavorDimensions")
        if (flavorsBlock != null) {
            Regex("""create\(\"(\w+)\"""").findAll(flavorsBlock).forEach { variants.add(it.groupValues[1]) }
            Regex("""(?m)^\s*(\w+)\s*\{\s*$""").findAll(flavorsBlock).forEach { variants.add(it.groupValues[1]) }
        }
        return variants.toList()
    }

    private fun platformOfSourceSet(name: String): String {
        for ((prefix, platform, _) in KMP_SOURCE_SET_PLATFORMS) {
            if (name == prefix) return platform
        }
        if (NATIVE_SOURCE_SET.containsMatchIn(name)) return DiscoveredModule.PLATFORM_NATIVE
        if (name.startsWith("android")) return DiscoveredModule.PLATFORM_ANDROID
        if (name.startsWith("jvm")) return DiscoveredModule.PLATFORM_JVM
        if (name.startsWith("js")) return DiscoveredModule.PLATFORM_JS
        if (name.startsWith("common")) return DiscoveredModule.PLATFORM_COMMON
        return DiscoveredModule.PLATFORM_JVM
    }

    private fun sourceSetRoots(root: Path, memberDir: Path, sourceSet: String, buildText: String): List<String> {
        val roots = LinkedHashSet<String>()
        // Textual srcDirs declared inside a named source-set block.
        for ((label, body) in TextScan.allBlocks(buildText, sourceSet)) {
            if (!label.contains(sourceSet)) continue
            Regex("""srcDirs?\s*\(\s*\"([^\"]+)\"\s*\)""").findAll(body).forEach {
                val dir = it.groupValues[1]
                if (Files.isDirectory(memberDir.resolve(dir))) roots.add(dir)
            }
        }
        val default = "src/$sourceSet/kotlin"
        if (Files.isDirectory(memberDir.resolve(default))) roots.add(default)
        val javaFallback = "src/$sourceSet/java"
        if (Files.isDirectory(memberDir.resolve(javaFallback))) roots.add(javaFallback)
        return roots.toList()
    }

    /**
     * Reads a compiler setting from the several shapes Gradle builds use:
     * kotlin { compilerOptions { languageVersion.set(...) } }, kotlinOptions
     * { languageVersion = ... }, tasks.withType<KotlinCompile> { ... }, and
     * top-level jvmToolchain.
     */
    private fun compilerSetting(buildText: String, setting: String): String? {
        for (blockName in listOf("compilerOptions", "kotlinOptions", "freeCompilerArgs")) {
            val block = TextScan.block(buildText, blockName) ?: continue
            TextScan.versionValue(TextScan.assignment(block, setting))?.let { return it }
        }
        // tasks.withType<KotlinCompile> { compilerOptions { ... } } nesting.
        val withType = TextScan.block(buildText, "withType")
        if (withType != null) {
            for (blockName in listOf("compilerOptions", "kotlinOptions")) {
                val block = TextScan.block(withType, blockName) ?: continue
                TextScan.versionValue(TextScan.assignment(block, setting))?.let { return it }
            }
        }
        // Bare `languageVersion = KotlinVersion.KOTLIN_2_0` at any depth.
        Regex("""(?m)^\s*$setting\s*=\s*(.+)$""").find(buildText)?.let {
            return TextScan.versionValue(it.groupValues[1])
        }
        return null
    }

    private fun standardRoots(root: Path, memberDir: Path): List<String> {
        val roots = mutableListOf<String>()
        for (dir in listOf("src/main/kotlin", "src/main/java", "src/kotlin")) {
            if (TextScan.isDirectory(memberDir, dir)) roots.add(dir)
        }
        return roots
    }

    fun purl(group: String?, name: String, version: String?): String {
        val v = version?.takeIf { it.isNotBlank() } ?: "unspecified"
        return if (group.isNullOrBlank()) {
            "pkg:generic/$name@$v"
        } else {
            "pkg:maven/$group/$name@$v"
        }
    }

    private fun rel(root: Path, dir: Path): String {
        val r = root.toAbsolutePath().normalize()
        val d = dir.toAbsolutePath().normalize()
        if (r == d) return "."
        return r.relativize(d).toString().replace('\\', '/')
    }

    private fun readIfExists(dir: Path, name: String): String? {
        val p = dir.resolve(name)
        return if (Files.isRegularFile(p)) Files.readString(p) else null
    }

    private fun readText(file: Path): String? =
        if (Files.isRegularFile(file)) Files.readString(file) else null
}
