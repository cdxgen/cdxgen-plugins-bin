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
                // Submodule roots can arrive MODULE-RELATIVE (`src/main/kotlin`
                // of `:producer`), so a root-relative miss falls back to the
                // module's own directory — the Gradle twin of the R5 Maven
                // defect, and with the same face: a submodule whose sources
                // are silently collected by nobody but the root sweep.
                var rootDir = root.resolve(sourceRoot)
                if (!Files.isDirectory(rootDir) && module.modulePath != ".") {
                    val moduleDir = root.resolve(module.modulePath).resolve(sourceRoot)
                    if (Files.isDirectory(moduleDir)) rootDir = moduleDir
                }
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
        // A file reachable from SEVERAL modules (the root module's inferred
        // roots sweep the whole tree; a submodule's roots are precise) is
        // attributed to the MOST SPECIFIC module — the longest modulePath.
        // Distinct-by-path alone kept whichever module enumerated first, so
        // every multi-module file silently attributed to "." and per-module
        // consumers (cross-module slice flags among them) read one blob.
        return files
            .sortedWith(
                compareByDescending<CollectedFile> { it.modulePath.length }
                    .thenBy { it.modulePath }
                    .thenBy { it.modulePurl }
                    .thenBy { it.relativePath },
            )
            .distinctBy { it.relativePath }
            .sortedBy { it.relativePath }
    }

    private fun isInExcludedDir(root: Path, file: Path): Boolean =
        root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize())
            .takeWhile { it.fileName != null }
            .any { it.toString() in EXCLUDED_DIRS }

    private const val FileEvidence_LANGUAGE_KOTLIN = "kotlin"
    private const val FileEvidence_LANGUAGE_JAVA = "java"
}
