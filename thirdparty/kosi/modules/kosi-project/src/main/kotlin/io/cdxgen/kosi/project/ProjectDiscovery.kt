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
                    // SORTED: Files.walk yields directory-entry order, which
                    // the filesystem defines — the same tree at two locations
                    // (or materialised twice, by git and by cp) can iterate
                    // differently, and the collected order assigns the dfn
                    // ids. Discovery order is part of "two machines compare
                    // equal byte for byte", so it must be a function of the
                    // TREE, not of the filesystem it sits on.
                    stream.filter { Files.isRegularFile(it) }
                        .filter { p -> !isInExcludedDir(root, p) }
                        .sorted()
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
        //
        // closes the two escapes that attribution left open, both
        // found by asking what a build file can do to the collector's root:
        // (1) a `srcDir("../..")` or absolute `srcDir("/x")` makes
        // `root.resolve(sourceRoot)` point OUTSIDE the analysis root, so a
        // report could carry another project's code — the THREAT_MODEL.md
        // claim, broken by data; out-of-root files are DROPPED, never
        // collected. (2) the same file reachable at two relative paths (a
        // root sweeping "." beside a module's precise roots) was collected
        // TWICE — duplicated slices in one report — because the dedup keyed
        // on the relative path; the dedup key is the ABSOLUTE path now.
        val rootAbs = root.toAbsolutePath().normalize()
        return files
            .filter { it.absolutePath.startsWith(rootAbs) }
            .sortedWith(
                compareByDescending<CollectedFile> { it.modulePath.length }
                    .thenBy { it.modulePath }
                    .thenBy { it.modulePurl }
                    .thenBy { it.relativePath },
            )
            .distinctBy { it.absolutePath }
            .sortedBy { it.relativePath }
    }

    private fun isInExcludedDir(root: Path, file: Path): Boolean =
        root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize())
            .takeWhile { it.fileName != null }
            .any { it.toString() in EXCLUDED_DIRS }

    /**
     * How many `.kt`/`.java` files exist under the analysed root
     * under the SAME exclusion policy as [collect] — the denominator of
     * source coverage. A report that discovered 1 file where 1 039 exist
     * must be able to say so; without this number the two are the same
     * report. `.kts` stays excluded for the same reason [collect] excludes
     * it: build scripts are not application sources.
     */
    fun presentCount(root: Path): Int = presentCounts(root).first

    /**
     * Directory names that mark test sources, in every layout kosi reads:
     * Maven/Gradle (`src/test/...`), Android (`androidTest`), Kotlin
     * Multiplatform (`commonTest`, `jvmTest`, ...) and the kotlinx
     * convention (`<module>/<set>/test`).
     */
    private val TEST_DIRS = setOf(
        "test", "tests", "androidTest", "androidUnitTest", "testFixtures",
        "integrationTest", "sharedTest", "jmh",
    )

    private fun isTestPath(root: Path, file: Path): Boolean =
        root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize())
            .takeWhile { it.fileName != null }
            .any { segment ->
                val s = segment.toString()
                s in TEST_DIRS || (s.endsWith("Test") && s.first().isLowerCase())
            }

    /** Total present files, and how many of them are test sources. */
    fun presentCounts(root: Path): Pair<Int, Int> {
        val rootAbs = root.toAbsolutePath().normalize()
        return try {
            Files.walk(rootAbs).use { stream ->
                var total = 0
                var tests = 0
                stream.filter { Files.isRegularFile(it) }
                    .filter { p -> !isInExcludedDir(root, p) }
                    .filter { p ->
                        val n = p.fileName.toString()
                        n.endsWith(".kt") || n.endsWith(".java")
                    }
                    .forEach { p ->
                        total++
                        if (isTestPath(root, p)) tests++
                    }
                total to tests
            }
        } catch (_: Exception) {
            0 to 0
        }
    }

    private const val FileEvidence_LANGUAGE_KOTLIN = "kotlin"
    private const val FileEvidence_LANGUAGE_JAVA = "java"
}
