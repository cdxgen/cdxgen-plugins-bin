package io.cdxgen.kosi.project

import io.cdxgen.kosi.schema.ClasspathStrategy
import java.nio.file.Files
import java.nio.file.Path
import kotlin.streams.toList

/**
 * Offline classpath resolution for the resolved tier (02-ARCHITECTURE.md §3,
 * acquisition order): explicit `--classpath`/`--classpath-file` jars first,
 * then a classpath file already present in the analysed tree (`classpath.txt`,
 * an Eclipse `.classpath`), then a jar directory (`libs/`), then coordinates
 * parsed as text from the project's own build files located in the local
 * Gradle/Maven caches and project-local build outputs. Nothing is downloaded
 * and no build is executed; every coordinate that cannot be found is reported
 * to the caller so the analysis can emit a `classpath-partial` diagnostic
 * naming it — a partial classpath is never silent.
 *
 * P28 §1: the strategies are a NAMED CHAIN, not one silent path. Each
 * attempt is recorded with whether it fired; the winner — or `none` — is
 * published in `stats.classpath` so a classpath-less run and a run that
 * found nothing are distinguishable in the report (R173/R179's zero).
 */
object ClasspathResolver {

    /** A `group:artifact:version` dependency coordinate parsed from build files. */
    data class Coordinate(val group: String, val artifact: String, val version: String?) {
        override fun toString(): String = "$group:$artifact:${version ?: "?"}"
    }

    data class ResolvedJar(val jar: Path, val purl: String, val coordinate: Coordinate?)

    /** One acquisition attempt; `jars > 0` means it fired. */
    data class Attempt(val strategy: String, val jars: Int, val note: String?)

    data class Result(
        val jars: List<ResolvedJar>,
        /** Coordinates named by the fired strategy but not found in any local cache. */
        val missing: List<String>,
        /** True when the classpath came from explicit flags rather than discovery. */
        val fromExplicitFlags: Boolean,
        /** The winning [ClasspathStrategy] id, or `none` when nothing attached. */
        val strategy: String,
        /** Every strategy the chain tried, in order, with its outcome. */
        val attempts: List<Attempt>,
    )

    /** One strategy's isolated collection: jars + what it could not attach. */
    private class AttemptRun {
        val jars = linkedMapOf<String, ResolvedJar>()
        val missing = mutableSetOf<String>()

        fun add(jar: Path, purl: String, coordinate: Coordinate?) {
            val key = jar.toAbsolutePath().normalize().toString()
            if (!jars.containsKey(key)) jars[key] = ResolvedJar(jar, purl, coordinate)
        }
    }

    fun resolve(
        root: Path,
        explicitJars: List<Path>,
        explicitFile: Path?,
        moduleDirs: List<Path>,
        strategy: ClasspathStrategy = ClasspathStrategy.AUTO,
    ): Result {
        // The chain. Explicit flags are AUTHORITATIVE: when the caller named
        // jars, explicit is the only strategy that runs (flags say exactly
        // what the classpath is — mixing a failed flag with discovery would
        // attach jars the caller never named, silently). Discovery runs only
        // flag-less: file -> jars -> cache, first to attach a jar wins.
        val chain: List<ClasspathStrategy> = when (strategy) {
            ClasspathStrategy.AUTO ->
                if (explicitJars.isNotEmpty() || explicitFile != null) listOf(ClasspathStrategy.EXPLICIT)
                else listOf(ClasspathStrategy.FILE, ClasspathStrategy.JARS, ClasspathStrategy.CACHE)
            ClasspathStrategy.NONE -> emptyList()
            else -> listOf(strategy)
        }

        val attempts = mutableListOf<Attempt>()
        var winner: Pair<ClasspathStrategy, AttemptRun>? = null
        var lastRun: AttemptRun? = null
        for (step in chain) {
            val run = AttemptRun()
            val note = when (step) {
                ClasspathStrategy.EXPLICIT -> runExplicit(run, explicitJars, explicitFile, root, moduleDirs.toSet())
                ClasspathStrategy.FILE -> runPresentFile(run, root, moduleDirs)
                ClasspathStrategy.JARS -> runJarDirectory(run, root, moduleDirs)
                ClasspathStrategy.CACHE -> runCacheScan(run, root, moduleDirs)
                else -> null
            }
            attempts.add(Attempt(step.id, run.jars.size, note))
            lastRun = run
            if (run.jars.isNotEmpty()) {
                winner = step to run
                break
            }
        }

        // Nothing fired: the run that DIDN'T fire last still owns the missing
        // list — the offline scan's unlocatable coordinates are the honest
        // `classpath-partial` diagnostic, and dropping them because zero jars
        // attached would report a clean classpath-less run (the R73 shape).
        val (winningStrategy, run) = winner ?: (ClasspathStrategy.NONE to (lastRun ?: AttemptRun()))
        return Result(
            jars = run.jars.values.sortedBy { it.purl },
            missing = run.missing.toList().sorted(),
            fromExplicitFlags = winningStrategy == ClasspathStrategy.EXPLICIT,
            strategy = winningStrategy.id,
            attempts = attempts,
        )
    }

    // ---- explicit flags -----------------------------------------------------

    private fun runExplicit(
        run: AttemptRun,
        explicitJars: List<Path>,
        explicitFile: Path?,
        root: Path,
        moduleDirs: Set<Path>,
    ): String? {
        if (explicitJars.isEmpty() && explicitFile == null) {
            return "no flags given"
        }
        for (p in explicitJars) {
            if (Files.isRegularFile(p)) {
                run.add(p, GradleDiscovery.purl(null, p.fileName.toString().removeSuffix(".jar"), null), null)
            } else {
                run.missing.add(p.toString())
            }
        }
        var lines = 0
        if (explicitFile != null && Files.isRegularFile(explicitFile)) {
            lines = applyClasspathFileLines(run, explicitFile, root, moduleDirs)
        }
        return "flags: ${explicitJars.size} jar path(s), $lines classpath-file line(s)"
    }

    // ---- a classpath file already present in the analysed tree ---------------

    /**
     * `classpath.txt` at the analysed root (the warmed-corpus convention: jar
     * paths and `g:a:v` coordinates, `#` comments — the same grammar the
     * `--classpath-file` flag accepts), then an Eclipse `.classpath` whose
     * `<classpathentry kind="lib">` rows name jars relative to the project
     * root. `kind="var"`/`"container"`/`"output"`/`"src"` rows are not jar
     * locations and are skipped.
     */
    private fun runPresentFile(run: AttemptRun, root: Path, moduleDirs: List<Path>): String? {
        val notes = mutableListOf<String>()
        val classpathTxt = root.resolve("classpath.txt")
        if (Files.isRegularFile(classpathTxt)) {
            applyClasspathFileLines(run, classpathTxt, root, moduleDirs.toSet())
            notes.add("classpath.txt")
        }
        val eclipse = root.resolve(".classpath")
        if (Files.isRegularFile(eclipse)) {
            val libs = eclipseLibEntries(eclipse)
            for (jar in libs) {
                val resolved = if (jar.isAbsolute) jar else root.resolve(jar)
                if (Files.isRegularFile(resolved)) {
                    run.add(resolved, GradleDiscovery.purl(null, resolved.fileName.toString().removeSuffix(".jar"), null), null)
                } else {
                    run.missing.add(jar.toString())
                }
            }
            notes.add(".classpath: ${libs.size} lib entries")
        }
        if (notes.isEmpty()) return "no classpath.txt or .classpath at the analysed root"
        return notes.joinToString("; ")
    }

    /**
     * The classpath-file grammar shared by `--classpath-file` and a discovered
     * `classpath.txt`. P17 (R105) lives here: a coordinate BOUND to a
     * committed jar (`g:a:v=libs/foo.jar`) attaches the jar WITH the
     * coordinate — dependency markers, purls and diagnostics are identical on
     * every machine — while a bare `g:a:v` line resolves against the
     * machine-local caches. Gradle tree lines can carry
     * `requested -> resolved` chains as `g:a:v1:v2`; the resolved (last)
     * version is what the cache holds. Version-less lines cannot be located;
     * ignoring them keeps the missing list meaningful. Returns how many
     * non-comment lines the file carried.
     */
    private fun applyClasspathFileLines(run: AttemptRun, file: Path, root: Path, moduleDirs: Set<Path>): Int {
        val boundCoordinates = LinkedHashMap<Coordinate, Path>()
        val fileCoordinates = LinkedHashMap<Coordinate, Int>()
        val jarLines = mutableListOf<Path>()
        var lines = 0
        for (line in file.toFile().readLines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            lines++
            val parts = trimmed.split(':')
            when {
                trimmed.endsWith(".jar") && trimmed.contains('=') && trimmed.substringBefore('=').split(':').size >= 3 -> {
                    val coord = trimmed.substringBefore('=').split(':')
                    val raw = Path.of(trimmed.substringAfter('='))
                    // RELATIVE entries resolve against the classpath file's
                    // own directory, so a committed fixture file stays
                    // portable (warm repo files carry absolute paths and
                    // are unaffected).
                    val resolved = if (raw.isAbsolute) raw else {
                        file.toAbsolutePath().normalize().parent?.resolve(raw) ?: raw
                    }
                    boundCoordinates.putIfAbsent(Coordinate(coord[0], coord[1], coord.last()), resolved)
                }
                trimmed.endsWith(".jar") -> {
                    val raw = Path.of(trimmed)
                    jarLines.add(if (raw.isAbsolute) raw else file.toAbsolutePath().normalize().parent?.resolve(raw) ?: raw)
                }
                parts.size >= 3 -> fileCoordinates.putIfAbsent(Coordinate(parts[0], parts[1], parts.last()), 0)
            }
        }
        for (p in jarLines) {
            if (Files.isRegularFile(p)) {
                run.add(p, GradleDiscovery.purl(null, p.fileName.toString().removeSuffix(".jar"), null), null)
            } else {
                run.missing.add(p.fileName.toString())
            }
        }
        for ((coordinate, jar) in boundCoordinates) {
            if (Files.isRegularFile(jar)) {
                run.add(jar, GradleDiscovery.purl(coordinate.group, coordinate.artifact, coordinate.version), coordinate)
            } else {
                run.missing.add("${coordinate}=${jar.fileName}")
            }
        }
        for (coordinate in fileCoordinates.keys) {
            val found = locate(coordinate, root, moduleDirs)
            if (found == null) {
                run.missing.add(coordinate.toString())
            } else {
                run.add(found, GradleDiscovery.purl(coordinate.group, coordinate.artifact, coordinate.version), coordinate)
            }
        }
        return lines
    }

    private fun eclipseLibEntries(file: Path): List<Path> {
        val document = try {
            XmlElement.parse(Files.readString(file))
        } catch (_: Exception) {
            return emptyList()
        }
        // parse() yields a #document wrapper whose child is <classpath>; the
        // entries can also sit deeper in a hand-merged file, so the recursive
        // scan is the robust spelling either way.
        val entries = mutableListOf<XmlElement>()
        fun walk(element: XmlElement) {
            entries.addAll(element.childrenNamed("classpathentry"))
            element.children.forEach(::walk)
        }
        walk(document)
        return entries
            .filter { it.attr("kind") == "lib" }
            .mapNotNull { it.attr("path")?.takeIf { p -> p.isNotBlank() }?.let(Path::of) }
    }

    // ---- a jar directory ------------------------------------------------------

    /**
     * `libs/` directories at the analysed root and under the discovered
     * module directories (the Android convention ships plain jars there),
     * excluding `-sources`/`-javadoc`. Root first, then modules in sorted
     * order; deterministic everywhere.
     */
    private fun runJarDirectory(run: AttemptRun, root: Path, moduleDirs: List<Path>): String? {
        val dirs = (listOf(root) + moduleDirs).distinct()
        var jarDirs = 0
        for (dir in dirs) {
            val libs = dir.resolve("libs")
            if (!Files.isDirectory(libs)) continue
            jarDirs++
            val names = Files.list(libs).use { it.toList() }
                .map { it.fileName.toString() }
                .filter { it.endsWith(".jar") }
                .filter { !it.endsWith("-sources.jar") && !it.endsWith("-javadoc.jar") }
                .sorted()
            for (name in names) {
                val jar = libs.resolve(name)
                run.add(jar, GradleDiscovery.purl(null, name.removeSuffix(".jar"), null), null)
            }
        }
        if (jarDirs == 0) return "no libs/ directory at the root or a module"
        return "libs/: $jarDirs dir(s)"
    }

    // ---- the offline cache scan ----------------------------------------------

    private fun runCacheScan(run: AttemptRun, root: Path, moduleDirs: List<Path>): String? {
        val coordinates = LinkedHashSet<Coordinate>()
        val moduleSet = moduleDirs.toSet()
        for (dir in moduleDirs) {
            collectBuildFiles(root, dir, moduleSet).forEach { file ->
                coordinates.addAll(scan(file))
            }
        }
        // P28: NESTED INDEPENDENT BUILDS. A repo whose root has no build file
        // (`koin`: `projects/` and `examples/` each carry their own
        // settings.gradle) is discovered as a plain tree, so the module scan
        // above sees zero build files and the cache strategy reports `none`
        // against a tree full of declarations. The fallback only fires when
        // the primary scan found NOTHING — a normal repo's nested samples
        // are not merged into its classpath.
        var nested = 0
        if (coordinates.isEmpty() && collectBuildFiles(root, root, moduleSet).isEmpty()) {
            val nestedFiles = findNestedBuildFiles(root)
            nested = nestedFiles.size
            nestedFiles.forEach { coordinates.addAll(scan(it)) }
        }
        for (coordinate in coordinates) {
            val found = locate(coordinate, root, moduleSet)
            if (found == null) {
                run.missing.add(coordinate.toString())
            } else {
                run.add(found, GradleDiscovery.purl(coordinate.group, coordinate.artifact, coordinate.version), coordinate)
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
                    run.add(jar, GradleDiscovery.purl(null, name.removeSuffix(".jar"), null), null)
                }
            }
        }
        val nestedNote = if (nested > 0) ", $nested nested build file(s)" else ""
        return "${coordinates.size} coordinate(s) declared in build files$nestedNote"
    }

    /**
     * Build files of nested independent builds (dirs with their own
     * settings/build file below the analysed root), bounded in depth and
     * excluding the same trees source discovery excludes, sorted for
     * determinism. Capped at 200 files — a monorepo's full tree is not a
     * dependency declaration of the thing being analysed.
     */
    private fun findNestedBuildFiles(root: Path): List<Path> {
        val out = mutableListOf<Path>()
        val maxDepth = 4
        val seen = HashSet<Path>()
        fun walk(dir: Path, depth: Int) {
            if (out.size >= 200) return
            val entries = try {
                Files.list(dir).use { it.toList() }.sortedBy { it.fileName.toString() }
            } catch (_: Exception) {
                return
            }
            for (entry in entries) {
                val name = entry.fileName.toString()
                if (Files.isDirectory(entry)) {
                    if (name in NESTED_SCAN_EXCLUDED || depth >= maxDepth) continue
                    walk(entry, depth + 1)
                } else if (name == "build.gradle.kts" || name == "build.gradle" || name == "pom.xml") {
                    if (seen.add(entry.toAbsolutePath().normalize())) out.add(entry)
                }
            }
        }
        walk(root, 0)
        return out
    }

    private val NESTED_SCAN_EXCLUDED = setOf(
        "build", "target", ".git", ".gradle", ".idea", ".corpus-cache",
        "node_modules", ".kosi", "out", "buildSrc",
    )

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

    /**
     * Version-catalog `[libraries]` entries in BOTH forms Gradle documents
     * (gradle docs, "Centralized declaration of versions": the short form
     * `name = "group:artifact:version"` and the map form
     * `name = { group = "...", name = "...", version = "..." }`), with
     * `version.ref = "alias"` resolved against the catalog's `[versions]`
     * table. A `version.ref` whose alias carries no literal (rich versions,
     * `{ strictly = ... }` — P28 found `exposed` declaring its whole
     * dependency set this way) yields a version-less coordinate: the
     * locator's highest-cached-version rule applies, same as a build-script
     * property indirection.
     */
    private fun scanVersionsToml(text: String): List<Coordinate> {
        val out = mutableListOf<Coordinate>()
        var inVersions = false
        var inLibraries = false
        // [versions] aliases with a literal value, for version.ref lookups.
        val versionAliases = mutableMapOf<String, String>()
        for (raw in text.lines()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            if (line.startsWith("[")) {
                inVersions = line == "[versions]"
                inLibraries = line == "[libraries]"
                continue
            }
            if (inVersions) {
                val alias = line.substringBefore('=').trim()
                val value = line.substringAfter('=', "").trim()
                val literal = TOML_STRING.find(value)?.groupValues?.get(1)
                if (literal != null && !literal.startsWith("{")) versionAliases[alias] = literal
                continue
            }
            if (!inLibraries) continue
            val value = line.substringAfter('=', "").trim()
            // Short form: alias = "g:a[:v]" — a bare quoted string.
            if (value.startsWith("\"")) {
                val literal = value.trim('"', '\'')
                val parts = literal.split(':')
                if (parts.size >= 2 && parts[0].contains('.')) {
                    val version = parts.getOrNull(2)?.takeUnless { it.isEmpty() }
                        ?.takeIf { !it.contains('$') && !it.contains('{') }
                    out.add(Coordinate(parts[0], parts[1], version))
                }
                continue
            }
            // Map form, module spelling: { module = "g:a[:v]", version = ... }
            val moduleShort = TOML_MODULE.find(value)?.groupValues?.get(1)
            if (moduleShort != null) {
                val parts = moduleShort.split(':')
                if (parts.size >= 2 && parts[0].contains('.')) {
                    val version = parts.getOrNull(2)?.takeUnless { it.isEmpty() }
                        ?: TOML_VERSION_REF.find(value)?.groupValues?.get(1)?.let { ref -> versionAliases[ref] }
                    out.add(Coordinate(parts[0], parts[1], version))
                }
                continue
            }
            // Map form, group/name spelling: { group = "...", name = "...", version[.ref] = "..." }
            val group = TOML_GROUP.find(value)?.groupValues?.get(1) ?: continue
            val name = TOML_NAME.find(value)?.groupValues?.get(1) ?: continue
            if (!group.contains('.')) continue
            val versionRef = TOML_VERSION_REF.find(value)?.groupValues?.get(1)
            val versionLiteral = TOML_VERSION.find(value)?.groupValues?.get(1)
            val version = when {
                versionLiteral != null && versionLiteral.contains('.') -> versionLiteral
                versionRef != null -> versionAliases[versionRef]
                else -> null
            }
            out.add(Coordinate(group, name, version))
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

    /**
     * Locates a coordinate in the local caches and project build outputs.
     * Kotlin multiplatform artifacts declare the UMBRELLA coordinate
     * (`kotlinx-coroutines-core`) while the caches store the JVM variant
     * under the `-jvm`-suffixed module name; without the fallback every
     * coroutines/ktor dependency read `classpath-partial` even against a
     * warm cache. The DECLARED coordinate keeps naming the purl.
     *
     * P15 adds the next layer, both driven by nowinandroid's 266 named
     * unlocatable coordinates: (1) Gradle Module Metadata — a publisher may
     * name its artifact file anything (`androidx.window:window-core-android`
     * ships `window-core.aar`, `app.cash.turbine:turbine-jvm` ships
     * `Turbine-jvm.jar`), and the `.module` file beside the artifact is the
     * publisher's own declaration of those names; (2) AndroidX multiplatform
     * publishing — the same API ships under sibling variant modules
     * (`animation`, `animation-android` AAR, `animation-desktop` jar,
     * `animation-jvmstubs` jar), and a variant whose binary was never
     * downloaded may still be locatable through a sibling that was. The
     * sibling chain only strips/extends the KNOWN variant suffixes, so a
     * different library in the same group is never picked up.
     */
    fun locate(coordinate: Coordinate, root: Path, moduleDirs: Set<Path>): Path? {
        val artifactNames = if (coordinate.artifact.endsWith("-jvm")) {
            listOf(coordinate.artifact)
        } else {
            listOf(coordinate.artifact, coordinate.artifact + "-jvm")
        }
        for (artifact in artifactNames) {
            val found = locateArtifact(coordinate.copy(artifact = artifact), root, moduleDirs)
            if (found != null) return found
        }
        // Same-base variant siblings, in preference order: the real JVM
        // implementation first (desktop), then the plain JVM variant, the
        // umbrella, the JVM API stubs AndroidX publishes, and finally the
        // Android AAR (extracted by [usableArtifact]). The declared
        // coordinate was already tried above, so a sibling only wins when
        // the requested variant itself has no binary on disk.
        val base = variantBase(coordinate.artifact)
        for (suffix in VARIANT_SIBLING_SUFFIXES) {
            val sibling = base + suffix
            if (sibling == coordinate.artifact) continue
            val found = locateArtifact(coordinate.copy(artifact = sibling), root, moduleDirs)
            if (found != null) return found
        }
        return null
    }

    /**
     * The multiplatform variant suffixes: `animation-android` and the
     * umbrella `animation` share the base `animation`. An unsuffixed
     * artifact is its own base, and the suffix STRIPPING only applies once,
     * so `foo-android-release` is not mangled.
     */
    private fun variantBase(artifact: String): String {
        for (suffix in listOf("-androidRelease", "-android", "-jvmstubs", "-desktop", "-jvm")) {
            if (artifact.endsWith(suffix) && artifact.length > suffix.length) {
                return artifact.removeSuffix(suffix)
            }
        }
        return artifact
    }

    /** Sibling variant order: real JVM code first, API stubs before extraction. */
    private val VARIANT_SIBLING_SUFFIXES = listOf("-desktop", "-jvm", "", "-jvmstubs", "-android")

    private fun locateArtifact(coordinate: Coordinate, root: Path, moduleDirs: Set<Path>): Path? {
        val version = coordinate.version
        if (version != null) {
            for (candidate in locatedByVersion(coordinate, version, root)) {
                if (!Files.isRegularFile(candidate)) continue
                return usableArtifact(candidate)
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
     * Android libraries are published as AARs; the FIR session reads jars,
     * so the AAR's classes.jar is extracted next to the cache entry
     * (deterministic path, reused across runs) and returned instead.
     */
    private fun usableArtifact(path: Path): Path {
        if (!path.fileName.toString().endsWith(".aar")) return path
        val stamp = path.toAbsolutePath().normalize().toString().hashCode().toUInt().toString()
        // A FIXED directory, so the extraction is genuinely reused across
        // runs. `createTempDirectory` returns a fresh unique directory every
        // call, which re-extracted every AAR on every run (hundreds of them
        // on an Android repo, times every matrix slot) and leaked each one.
        val dir = Path.of(System.getProperty("java.io.tmpdir"), "kosi-aar", stamp)
        val target = dir.resolve("classes.jar")
        if (Files.isRegularFile(target)) return target
        return try {
            Files.createDirectories(dir)
            java.util.zip.ZipFile(path.toFile()).use { zip ->
                val entry = zip.getEntry("classes.jar") ?: return path
                zip.getInputStream(entry).use { input ->
                    Files.copy(input, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                }
            }
            target
        } catch (_: Exception) {
            // An unreadable AAR falls back to the AAR itself, which the
            // session will reject as a binary root — reported as an
            // unresolvable coordinate by the caller rather than pretended away.
            path
        }
    }

    /**
     * Gradle's modules-2 layout stores each version under content hashes:
     * <cache>/<group>/<artifact>/<version>/<hash>/<artifact>-<version>.jar.
     *
     * A KOTLIN MULTIPLATFORM library breaks that name. `io.ktor:ktor-server-core`
     * resolves, for a JVM consumer, to the artifact `ktor-server-core-jvm` —
     * and Gradle files it under the PARENT's directory, so the jar sitting in
     * `ktor-server-core/1.6.7/<hash>/` is called
     * `ktor-server-core-jvm-1.6.7.jar`. Looking only for the exact name meant
     * every multiplatform dependency was reported as an unlocatable
     * coordinate even with the jar already in the cache — and that is most of
     * the modern Kotlin ecosystem: all of Ktor, all of kotlinx. A real Ktor
     * application analysed against a fully warmed classpath still resolved a
     * third of its calls, because its own framework was missing.
     *
     * The platform-suffixed name is accepted only when the exact one is
     * absent, and only for the suffixes Kotlin's own publishing emits, so a
     * differently-named neighbour in the same directory is never picked up.
     */
    private fun gradleHashDirs(versionDir: Path, artifact: String, version: String): List<Path> {
        if (!Files.isDirectory(versionDir)) return emptyList()
        val hashDirs = Files.list(versionDir).use { it.toList() }
            .filter { Files.isDirectory(it) }
            .sortedBy { it.fileName.toString() }
        val exact = hashDirs.flatMap { hashDir ->
            listOf("$artifact-$version.jar", "$artifact-$version.aar").mapNotNull { name ->
                hashDir.resolve(name).takeIf { Files.isRegularFile(it) }
            }
        }
        if (exact.isNotEmpty()) return exact
        val suffixed = hashDirs.flatMap { hashDir ->
            KMP_TARGET_SUFFIXES.flatMap { suffix ->
                listOf("$artifact-$suffix-$version.jar", "$artifact-$suffix-$version.aar").mapNotNull { name ->
                    hashDir.resolve(name).takeIf { Files.isRegularFile(it) }
                }
            }
        }
        if (suffixed.isNotEmpty()) return suffixed
        // The publisher's own file names, from the Gradle Module Metadata
        // beside the artifact (P15): `window-core.aar`, `Turbine-jvm.jar`,
        // `roborazzi-painter-jvm.jar` — none derivable from the module
        // name, all declared in the `.module` file a warm cache always
        // carries. Variants whose usage is metadata-only (kotlin-metadata,
        // docs) are skipped: their files are not binary roots. Gradle
        // stores EACH file under its own content hash, so the `.module`
        // and the artifact it names usually sit in DIFFERENT hash
        // directories — the declared names are searched across the whole
        // version directory, not beside the metadata file.
        val declaredNames = hashDirs.flatMap { hashDir -> moduleDeclaredArtifactNames(hashDir) }
        if (declaredNames.isNotEmpty()) {
            val found = hashDirs.flatMap { hashDir ->
                declaredNames.mapNotNull { name -> hashDir.resolve(name).takeIf { Files.isRegularFile(it) } }
            }
            if (found.isNotEmpty()) return found
        }
        return emptyList()
    }

    /**
     * Artifact FILE names the `.module` metadata in [hashDir] declares,
     * jar before aar, deterministic. A `.module` that is absent or
     * unparseable declares nothing — the caller falls through to the next
     * rule. Metadata-only and docs variants are excluded: their declared
     * files (kotlin-metadata jars, apiLevels.json, aggregated sources) are
     * not binary roots a session can load.
     */
    private fun moduleDeclaredArtifactNames(hashDir: Path): List<String> {
        val module = runCatching { Files.list(hashDir).use { it.toList() } }.getOrElse { emptyList() }
            .filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".module") }
            .sortedBy { it.fileName.toString() }
            .firstOrNull() ?: return emptyList()
        val declared = try {
            val root = io.cdxgen.kosi.schema.JsonReader.parse(Files.readString(module)).asObject()
            (root.arr("variants")?.objects() ?: emptyList())
                .filterNot { variant ->
                    val usage = variant.obj("attributes")?.str("org.gradle.usage") ?: ""
                    usage.contains("metadata") || usage.contains("docs")
                }
                .flatMap { variant -> variant.arr("files")?.objects() ?: emptyList() }
                .mapNotNull { file -> file.str("name") }
        } catch (_: Exception) {
            return emptyList()
        }
        return declared
            .filter { it.endsWith(".jar") || it.endsWith(".aar") }
            .filter { !it.endsWith("-sources.jar") && !it.endsWith("-javadoc.jar") }
            .sortedWith(compareBy({ !it.endsWith(".jar") }, { it }))
            .distinct()
    }

    /** Kotlin multiplatform target suffixes a JVM consumer can load. */
    private val KMP_TARGET_SUFFIXES = listOf("jvm", "android", "androidRelease")

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

    private val TOML_MODULE = Regex("""module\s*=\s*"([^"]+)"""")
    private val TOML_GROUP = Regex("""\bgroup\s*=\s*"([^"]+)"""")
    private val TOML_NAME = Regex("""\bname\s*=\s*"([^"]+)"""")
    private val TOML_VERSION_REF = Regex("""version\.ref\s*=\s*"([^"]+)"""")
    private val TOML_VERSION = Regex("""\bversion\s*=\s*"([^"]+)"""")
    private val TOML_STRING = Regex("""^\s*"([^"]+)"\s*$""")

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
            // Two jars can share a package prefix (a library split across
            // artifacts). The tie-break is the lexicographically smallest
            // purl: an arbitrary-but-stated rule, so attribution is the same
            // on every machine. Comparing purl *lengths* — the previous rule
            // — orders on nothing at all.
            if (existing == null || resolved.purl < existing) {
                index[prefix] = resolved.purl
            }
        }
        return index
    }

    /**
     * The deepest common package of a jar's classes. Computed as a running
     * common prefix over EVERY class entry: sampling the first N packages
     * would report a deeper prefix than the jar actually has, silently
     * misattributing (or dropping) imports with no diagnostic to say so.
     */
    private fun packagePrefixOf(jar: Path): String? {
        return try {
            java.util.zip.ZipFile(jar.toFile()).use { zip ->
                var prefix: String? = null
                for (entry in zip.entries()) {
                    val name = entry.name
                    if (!name.endsWith(".class") || name.contains('$')) continue
                    val pkg = name.removeSuffix(".class").substringBeforeLast('/').replace('/', '.')
                    if (pkg.isEmpty()) continue
                    var current = prefix ?: pkg
                    while (!pkg.startsWith(current) || (pkg.getOrNull(current.length) ?: '.') != '.') {
                        current = current.substringBeforeLast('.', "")
                        if (current.isEmpty()) return null
                    }
                    prefix = current
                }
                prefix?.takeIf { it.isNotBlank() }
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
