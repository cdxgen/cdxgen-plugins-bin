package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path

/**
 * Orchestrates project discovery. Decision order: Gradle (settings or build
 * file) → Maven (pom.xml) → plain source tree with a diagnostic, so an
 * unrecognized layout is visible rather than silently mis-scoped
 * (07-REVIEW-PROTOCOL.md failure mode 9).
 */
object ProjectDiscovery {

    fun discover(root: Path): DiscoveryResult {
        val hasGradleSettings = Files.isRegularFile(root.resolve("settings.gradle.kts")) ||
            Files.isRegularFile(root.resolve("settings.gradle")) ||
            Files.isRegularFile(root.resolve("settings.gradle.dcl"))
        val hasGradleBuild = Files.isRegularFile(root.resolve("build.gradle.kts")) ||
            Files.isRegularFile(root.resolve("build.gradle"))
        val hasPom = Files.isRegularFile(root.resolve("pom.xml"))
        return when {
            hasGradleSettings || hasGradleBuild -> GradleDiscovery.discover(root)
            hasPom -> MavenDiscovery.discover(root)
            else -> plainTree(root)
        }
    }

    /**
     * No build files: analyse the tree as a single JVM module. This keeps
     * `kosi analyze` useful on a random directory while stating plainly that
     * no build metadata was found.
     */
    fun plainTree(root: Path): DiscoveryResult {
        val modulePath = "."
        val roots = if (TextScan.isDirectory(root, "src")) {
            listOf("src")
        } else if (hasSourceFiles(root)) {
            listOf(modulePath)
        } else {
            emptyList()
        }
        val module = DiscoveredModule(
            name = root.fileName.toString(),
            modulePath = modulePath,
            platform = DiscoveredModule.PLATFORM_JVM,
            workspaceMember = modulePath,
            sourceRoots = roots,
            declaredLanguageVersion = null,
            declaredApiVersion = null,
            jvmTarget = null,
            purl = GradleDiscovery.purl(null, root.fileName.toString(), null),
        )
        return DiscoveryResult(listOf(module), buildSystem = "none")
    }

    private fun hasSourceFiles(root: Path): Boolean =
        Files.walk(root).use { stream ->
            stream.anyMatch { p ->
                val n = p.fileName.toString()
                Files.isRegularFile(p) && (n.endsWith(".kt") || n.endsWith(".java"))
            }
        }
}

/**
 * Collects the source files of a module list. Exclusions cover generated and
 * third-party trees; they are policy, not heuristics, and every excluded tree
 * category is documented in JSON_ATTRIBUTE_REFERENCE.md.
 */
object SourceCollector {

    val EXCLUDED_DIRS = setOf(
        "build", "target", ".git", ".gradle", ".idea", ".corpus-cache",
        "node_modules", ".kosi", "out",
    )

    data class CollectedFile(
        val absolutePath: Path,
        val relativePath: String,
        val modulePath: String,
        val modulePurl: String,
        val language: String,
    )

    fun collect(root: Path, modules: List<DiscoveredModule>): List<CollectedFile> {
        val files = mutableListOf<CollectedFile>()
        for (module in modules) {
            for (sourceRoot in module.sourceRoots.sorted()) {
                val rootDir = root.resolve(sourceRoot)
                if (!Files.isDirectory(rootDir)) continue
                Files.walk(rootDir).use { stream ->
                    stream.filter { Files.isRegularFile(it) }
                        .filter { p -> !isInExcludedDir(root, p) }
                        .forEach { p ->
                            val name = p.fileName.toString()
                            val language = when {
                                // .kts files are Gradle build scripts, not
                                // application sources; they are never parsed.
                                name.endsWith(".kt") -> FileEvidence_LANGUAGE_KOTLIN
                                name.endsWith(".java") -> FileEvidence_LANGUAGE_JAVA
                                else -> return@forEach
                            }
                            val rel = root.toAbsolutePath().normalize()
                                .relativize(p.toAbsolutePath().normalize()).toString().replace('\\', '/')
                            files.add(
                                CollectedFile(
                                    // Normalized: a module root of "." produces
                                    // "/./" segments that would break any
                                    // consumer matching these paths against
                                    // paths derived elsewhere.
                                    absolutePath = p.toAbsolutePath().normalize(),
                                    relativePath = rel,
                                    modulePath = module.modulePath,
                                    modulePurl = module.purl,
                                    language = language,
                                ),
                            )
                        }
                }
            }
        }
        return files.sortedBy { it.relativePath }.distinctBy { it.relativePath }
    }

    private fun isInExcludedDir(root: Path, file: Path): Boolean =
        root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize())
            .takeWhile { it.fileName != null }
            .any { it.toString() in EXCLUDED_DIRS }

    private const val FileEvidence_LANGUAGE_KOTLIN = "kotlin"
    private const val FileEvidence_LANGUAGE_JAVA = "java"
}
