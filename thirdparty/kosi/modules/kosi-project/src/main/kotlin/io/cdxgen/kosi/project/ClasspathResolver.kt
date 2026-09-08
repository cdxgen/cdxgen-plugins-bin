package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.streams.toList

/**
 * Offline classpath resolution for the resolved tier (02-ARCHITECTURE.md §3,
 * acquisition order): explicit `--classpath`/`--classpath-file` jars first,
 * then coordinates parsed as text from the project's own build files located
 * in the local Gradle/Maven caches and project-local build outputs. Nothing is
 * downloaded and no build is executed; every coordinate that cannot be found
 * is reported to the caller so the analysis can emit a `classpath-partial`
 * diagnostic naming it — a partial classpath is never silent.
 */
object ClasspathResolver {

    /** A `group:artifact:version` dependency coordinate parsed from build files. */
    data class Coordinate(val group: String, val artifact: String, val version: String?) {
        override fun toString(): String = "$group:$artifact:${version ?: "?"}"
    }

    data class ResolvedJar(val jar: Path, val purl: String, val coordinate: Coordinate?)

    data class Result(
        val jars: List<ResolvedJar>,
        /** Coordinates named by build files but not found in any local cache. */
        val missing: List<String>,
        /** True when the classpath came from explicit flags rather than discovery. */
        val fromExplicitFlags: Boolean,
    )

    fun resolve(
        root: Path,
        explicitJars: List<Path>,
        explicitFile: Path?,
        moduleDirs: List<Path>,
    ): Result {
        val jars = linkedMapOf<String, ResolvedJar>()
        val missing = mutableSetOf<String>()

        fun add(jar: Path, purl: String, coordinate: Coordinate?) {
            val key = jar.toAbsolutePath().normalize().toString()
            if (!jars.containsKey(key)) jars[key] = ResolvedJar(jar, purl, coordinate)
        }

        var explicit = false
        if (explicitJars.isNotEmpty() || explicitFile != null) {
            explicit = true
            val paths = buildList {
                addAll(explicitJars)
                if (explicitFile != null && Files.isRegularFile(explicitFile)) {
                    for (line in explicitFile.toFile().readLines()) {
                        val trimmed = line.trim()
                        if (trimmed.isNotEmpty() && !trimmed.startsWith("#")) add(Path.of(trimmed))
                    }
                }
            }
            for (p in paths) {
                if (Files.isRegularFile(p)) {
                    add(p, GradleDiscovery.purl(null, p.fileName.toString().removeSuffix(".jar"), null), null)
                } else {
                    missing.add(p.toString())
                }
            }
        } else {
            val coordinates = LinkedHashSet<Coordinate>()
            val moduleSet = moduleDirs.toSet()
            for (dir in moduleDirs) {
                collectBuildFiles(root, dir, moduleSet).forEach { file ->
                    coordinates.addAll(scan(file))
                }
            }
            for (coordinate in coordinates) {
                val found = locate(coordinate, root, moduleSet)
                if (found == null) {
                    missing.add(coordinate.toString())
                } else {
                    add(found, GradleDiscovery.purl(coordinate.group, coordinate.artifact, coordinate.version), coordinate)
                }
            }
            // Project-local build outputs: jars this workspace itself produced.
            for (dir in moduleDirs) {
                val libs = dir.resolve("build/libs")
                if (Files.isDirectory(libs)) {
                    val names = Files.list(libs).use { it.toList() }
                        .map { it.fileName.toString() }
                        .filter { it.endsWith(".jar") }
                        .filter { !it.endsWith("-sources.jar") && !it.endsWith("-javadoc.jar") }
                        .sorted()
                    for (name in names) {
                        val jar = libs.resolve(name)
                        add(jar, GradleDiscovery.purl(null, name.removeSuffix(".jar"), null), null)
                    }
                }
            }
        }

        return Result(
            jars = jars.values.sortedBy { it.purl },
            missing = missing.toList().sorted(),
            fromExplicitFlags = explicit,
        )
    }

    // ---- build-file collection ------------------------------------------

    private fun collectBuildFiles(root: Path, moduleDir: Path, moduleSet: Set<Path>): List<Path> {
        val files = mutableListOf<Path>()
        for (name in listOf("build.gradle.kts", "build.gradle")) {
            val f = moduleDir.resolve(name)
            if (Files.isRegularFile(f)) files.add(f)
        }
        val pom = moduleDir.resolve("pom.xml")
        if (Files.isRegularFile(pom)) files.add(pom)
        // Version catalogs live in the root project's gradle/ directory; every
        // module that references `libs.*` resolves its coordinates through one.
        val gradleDir = root.resolve("gradle")
        if (Files.isDirectory(gradleDir)) {
            val names = Files.list(gradleDir).use { it.toList() }
                .map { it.fileName.toString() }
                .filter { it.startsWith("libs.versions.toml") }
                .sorted()
            for (name in names) files.add(gradleDir.resolve(name))
        }
        // A parent pom's <dependencyManagement> governs module poms without
        // their own versions; include ancestor poms of nested modules.
        var parent = moduleDir.parent
        while (parent != null && moduleSet.contains(parent)) {
            val pom = parent.resolve("pom.xml")
            if (Files.isRegularFile(pom)) files.add(pom)
            parent = parent.parent
        }
        return files
    }

    // ---- text scanning ----------------------------------------------------

    /**
     * Scans one build file for dependency coordinates. This is a *parse*, not
     * an execution: string literals and XML elements only, so no build script
     * code ever runs (02-ARCHITECTURE.md §10).
     */
    fun scan(file: Path): List<Coordinate> {
        val text = try {
            Files.readString(file)
        } catch (_: Exception) {
            return emptyList()
        }
        return when {
            file.fileName.toString().endsWith(".toml") -> scanVersionsToml(text)
            file.fileName.toString() == "pom.xml" -> scanPom(text)
            else -> scanGradle(text)
        }
    }

    /** `group:artifact:version` string literals in Gradle build scripts. */
    private fun scanGradle(text: String): List<Coordinate> {
        val out = mutableListOf<Coordinate>()
        for (match in GRADLE_COORDINATE.findAll(text)) {
            val parts = match.groupValues[1].split(':')
            if (parts.size < 2) continue
            val version = parts.getOrNull(2)?.takeUnless { it.isEmpty() }
                ?.takeIf { !it.contains('$') && !it.contains('{') }
            out.add(Coordinate(parts[0], parts[1], version))
        }
        return out
    }

    /** `name = "group:artifact:version"` entries under `[libraries]`. */
    private fun scanVersionsToml(text: String): List<Coordinate> {
        val out = mutableListOf<Coordinate>()
        var inLibraries = false
        for (raw in text.lines()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            if (line.startsWith("[")) {
                inLibraries = line == "[libraries]"
                continue
            }
            if (!inLibraries) continue
            val value = line.substringAfter('=').trim().trim('"', '\'')
            val parts = value.split(':')
            if (parts.size >= 2 && parts[0].contains('.')) {
                out.add(Coordinate(parts[0], parts[1], parts.getOrNull(2)))
            }
        }
        return out
    }

    /** `<dependency>` blocks in a pom, including `<dependencyManagement>`. */
    private fun scanPom(text: String): List<Coordinate> {
        val project = XmlElement.parse(text)
        val out = mutableListOf<Coordinate>()
        val dependencies = project.findRecursive("dependencies") ?: return emptyList()
        for (dep in dependencies.childrenNamed("dependency")) {
            val group = dep.textOr("groupId") ?: continue
            val artifact = dep.textOr("artifactId") ?: continue
            val version = dep.textOr("version")
            val scope = dep.textOr("scope")
            // test-scoped dependencies stay on the classpath: kosi analyses
            // test sources too, and resolution is read-only.
            if (scope == "provided" || scope == "import") continue
            out.add(Coordinate(group, artifact, version?.takeIf { !it.contains('$') && !it.contains('{') }))
        }
        return out
    }

    // ---- cache locators ----------------------------------------------------

    /** Locates a coordinate in the local caches and project build outputs. */
    fun locate(coordinate: Coordinate, root: Path, moduleDirs: Set<Path>): Path? {
        val version = coordinate.version
        if (version != null) {
            for (candidate in locatedByVersion(coordinate, version, root)) {
                if (Files.isRegularFile(candidate)) return candidate
            }
        } else {
            // Unknown version (build-script indirection): pick the highest
            // version the cache holds for group:artifact, deterministically.
            for (dir in gradleCacheRoots(root)) {
                val artifactDir = dir.resolve(coordinate.group).resolve(coordinate.artifact)
                if (!Files.isDirectory(artifactDir)) continue
                val best = Files.list(artifactDir).use { it.toList() }
                    .map { it.fileName.toString() }
                    .filter { Files.isDirectory(artifactDir.resolve(it)) }
                    .maxWithOrNull { a, b -> compareVersions(a, b) }
                if (best != null) {
                    for (candidate in gradleHashDirs(artifactDir.resolve(best), coordinate.artifact, best)) {
                        if (Files.isRegularFile(candidate)) return candidate
                    }
                }
            }
            val m2Root = Path.of(System.getProperty("user.home"), ".m2", "repository")
            val m2ArtifactDir = m2Root.resolve(coordinate.group.replace('.', '/')).resolve(coordinate.artifact)
            if (Files.isDirectory(m2ArtifactDir)) {
                val best = Files.list(m2ArtifactDir).use { it.toList() }
                    .map { it.fileName.toString() }
                    .filter { Files.isDirectory(m2ArtifactDir.resolve(it)) }
                    .maxWithOrNull { a, b -> compareVersions(a, b) }
                if (best != null) {
                    val jar = m2ArtifactDir.resolve(best).resolve("${coordinate.artifact}-$best.jar")
                    if (Files.isRegularFile(jar)) return jar
                }
            }
        }
        // Project-local outputs named after the artifact.
        for (dir in moduleDirs) {
            val libs = dir.resolve("build/libs")
            if (!Files.isDirectory(libs)) continue
            val match = Files.list(libs).use { it.toList() }
                .map { it.fileName.toString() }
                .filter { it.startsWith("${coordinate.artifact}-") && it.endsWith(".jar") }
                .filter { !it.endsWith("-sources.jar") && !it.endsWith("-javadoc.jar") }
                .sorted()
                .firstOrNull()
            if (match != null) return libs.resolve(match)
        }
        return null
    }

    private fun locatedByVersion(coordinate: Coordinate, version: String, root: Path): List<Path> {
        val out = mutableListOf<Path>()
        for (cache in gradleCacheRoots(root)) {
            val artifactDir = cache.resolve(coordinate.group).resolve(coordinate.artifact)
            out.addAll(gradleHashDirs(artifactDir.resolve(version), coordinate.artifact, version))
        }
        val m2 = Path.of(System.getProperty("user.home"), ".m2", "repository")
            .resolve(coordinate.group.replace('.', '/'))
            .resolve(coordinate.artifact)
            .resolve(version)
        out.add(m2.resolve("${coordinate.artifact}-$version.jar"))
        return out
    }

    /**
     * Gradle's modules-2 layout stores each version under content hashes:
     * <cache>/<group>/<artifact>/<version>/<hash>/<artifact>-<version>.jar.
     */
    private fun gradleHashDirs(versionDir: Path, artifact: String, version: String): List<Path> {
        if (!Files.isDirectory(versionDir)) return emptyList()
        val hashDirs = Files.list(versionDir).use { it.toList() }
            .filter { Files.isDirectory(it) }
            .sortedBy { it.fileName.toString() }
        return hashDirs.mapNotNull { hashDir ->
            val jar = hashDir.resolve("$artifact-$version.jar")
            jar.takeIf { Files.isRegularFile(it) }
        }
    }

    private fun gradleCacheRoots(root: Path): List<Path> {
        val roots = mutableListOf<Path>()
        val home = Path.of(System.getProperty("user.home"), ".gradle", "caches", "modules-2", "files-2.1")
        if (Files.isDirectory(home)) roots.add(home)
        // A project-local .gradle cache (Gradle reuses the global one, but the
        // directory is part of the documented search order).
        val local = root.resolve(".gradle")
        if (Files.isDirectory(local)) roots.add(local)
        return roots
    }

    /** Dotted-numeric version comparison: 2 > 10-lexicographically is false. */
    fun compareVersions(a: String, b: String): Int {
        val pa = a.split('.').map { it.trim().toIntOrNull() ?: 0 }
        val pb = b.split('.').map { it.trim().toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val va = pa.getOrElse(i) { 0 }
            val vb = pb.getOrElse(i) { 0 }
            if (va != vb) return va.compareTo(vb)
        }
        return a.compareTo(b)
    }

    private val GRADLE_COORDINATE = Regex("""["']([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.${'$'}{}-]+)?(?::[^"']*)?)["']""")

    // ---- jar package index (for imports[].purl attribution) ---------------

    /**
     * Maps each resolved jar to the package prefixes it declares, so an
     * import can be attributed to the purl of the library that ships it.
     * Longest-prefix wins; the index is built from jar entries only.
     */
    fun packageIndex(jars: List<ResolvedJar>): Map<String, String> {
        val index = mutableMapOf<String, String>()
        for (resolved in jars) {
            val prefix = packagePrefixOf(resolved.jar) ?: continue
            val existing = index[prefix]
            if (existing == null || existing.length < resolved.purl.length) {
                index[prefix] = resolved.purl
            }
        }
        return index
    }

    /** The deepest common package of a jar's classes, capped at 3 segments. */
    private fun packagePrefixOf(jar: Path): String? {
        return try {
            java.util.zip.ZipFile(jar.toFile()).use { zip ->
                val packages = mutableSetOf<String>()
                for (entry in zip.entries()) {
                    val name = entry.name
                    if (!name.endsWith(".class") || name.contains('$')) continue
                    val pkg = name.removeSuffix(".class").substringBeforeLast('/')
                    if (pkg.isNotEmpty()) packages.add(pkg)
                    if (packages.size > 4096) break
                }
                if (packages.isEmpty()) return null
                // Deepest common prefix among observed packages.
                var prefix = packages.first()
                for (pkg in packages) {
                    while (!pkg.startsWith(prefix) ||
                        (pkg.getOrNull(prefix.length) ?: '.') != '.'
                    ) {
                        prefix = prefix.substringBeforeLast('.', "")
                        if (prefix.isEmpty()) return null
                    }
                }
                prefix.takeIf { it.isNotBlank() }
            }
        } catch (_: Exception) {
            null
        }
    }

    /** Attributes an imported fully-qualified name to a purl, longest prefix wins. */
    fun purlForImport(fqName: String, index: Map<String, String>): String? {
        var best: Pair<Int, String>? = null
        for ((prefix, purl) in index) {
            if (fqName == prefix || fqName.startsWith("$prefix.")) {
                val candidate = prefix.length
                if (best == null || candidate > best.first) best = candidate to purl
            }
        }
        return best?.second
    }
}
