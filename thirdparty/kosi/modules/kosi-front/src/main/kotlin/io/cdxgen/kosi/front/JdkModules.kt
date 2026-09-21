package io.cdxgen.kosi.front

import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.SortedMap
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * How the resolved tier sees the JDK, per substrate.
 *
 * On the JVM the Analysis API's `addBinaryRootsFromJdkHome` reads a modular
 * JDK through the jrt NIO filesystem provider, which the running JVM
 * registers itself. A native image registers no jrt provider
 * (`ProviderNotFoundException: Provider "jrt" not found`), and the JDK's own
 * standalone provider (`lib/jrt-fs.jar`) cannot rescue the image: its
 * `newFileSystem` re-loads its implementation classes from the TARGET JDK's
 * jrt-fs.jar through a URLClassLoader at run time, and bytecode unknown at
 * image build time cannot execute in an image (the image also disables the
 * `jar:` URL protocol that loader needs). Those are substrate facts, probed
 * against the pinned GraalVM — see docs/KOSI.md defect 3.
 *
 * So in an image kosi reads `<jdk>/lib/modules` DIRECTLY through the image's
 * own `jdk.internal.jimage.BasicImageReader` (part of the image runtime's
 * java.base; reflection entries live in the checked-in reachability metadata
 * and the image build opens the package) and materializes ONE JAR PER
 * MODULE, handed to the SDK module as plain `.jar` binary roots — the root
 * shape library jars already use, which the platform reads on every
 * substrate without jrt.
 *
 * The per-module split is not an optimization: the roots feed the search
 * scope's package trie, which derives a class's name from its path relative
 * to its root. A single merged jar would turn `java/lang/String.class` of
 * java.base into the package `java.base.java.lang`, and nothing would
 * resolve (observed, not theorized). One root per module is also exactly
 * the shape `addBinaryRootsFromJdkHome` produces on the JVM.
 *
 * Coverage, stated plainly: every module in `lib/modules` — the complete
 * JDK (public and `jdk.internal` classes, all modules) — strictly more than
 * `ct.sym` (documented API of past releases only) and the same content the
 * jrt filesystem exposes. Entries under the jrt `packages` link tree are
 * skipped: they are links, not content.
 */
internal object JdkModules {

    /** Top-level jimage segments that are link trees, not module content. */
    private val NON_MODULE_SEGMENTS = setOf("packages")

    /**
     * Where a JDK home comes from, in order: the explicit `--jdk-home` flag,
     * the running JVM's `java.home` (set on the JVM, unset in an image), the
     * `JAVA_HOME` environment, the `java` launcher on `PATH`, and finally
     * the platform's conventional install roots. A home that names no
     * modular JDK is [Resolution.Invalid] — a flag that cannot work must be
     * rejected with the reason, never silently downgraded to a partial
     * classpath.
     *
     * Everything after `JAVA_HOME` exists because of what a missing JDK
     * costs in an IMAGE, where `java.home` is structurally unset. A resolved
     * run with no JDK does not fail: it resolves every `java.*` symbol to
     * nothing and reports a warning. Measured against the fat jar with
     * `JAVA_HOME` unset: `fixtures/java-interop` 1 of 2 calls resolved
     * against the JVM's 2, and `fixtures/kosi-vulnerable-service` 15 of 25
     * with ZERO sinks and zero slices against the JVM's 2 and 1 — the
     * security fixture finding nothing, at exit 0. A shell with no
     * `JAVA_HOME` is the ordinary case for
     * someone running the published binary, not an exotic one, so the
     * locations a JDK is actually installed in are searched rather than
     * waited for.
     */
    sealed interface Resolution {
        data class Found(val home: Path, val exploded: Boolean) : Resolution
        data class NotFound(val tried: String) : Resolution

        /** `--jdk-home` was given but names no usable JDK: a usage error. */
        data class Invalid(val message: String) : Resolution
    }

    fun resolve(
        explicit: Path?,
        property: (String) -> String? = { System.getProperty(it) },
        env: (String) -> String? = { System.getenv(it) },
        installed: () -> List<Path> = { installedHomes(env) },
    ): Resolution {
        if (explicit != null) {
            return classifyCandidate(explicit) ?: Resolution.Invalid(
                "--jdk-home $explicit is not a modular JDK home: no lib/modules image and no " +
                    "exploded modules/ tree. kosi resolves the JDK from a modular (9+) JDK home; " +
                    "the resolved backend cannot attach a JDK from this path.",
            )
        }
        val tried = mutableListOf<String>()
        val prop = property("java.home")
        if (prop != null) {
            classifyCandidate(Path.of(prop))?.let { return it }
            tried.add("java.home=$prop (not a modular JDK home)")
        } else {
            tried.add("java.home is unset")
        }
        val envHome = env("JAVA_HOME")
        if (envHome != null) {
            classifyCandidate(Path.of(envHome))?.let { return it }
            tried.add("JAVA_HOME=$envHome (not a modular JDK home)")
        } else {
            tried.add("JAVA_HOME is unset")
        }
        val scanned = installed()
        for (candidate in scanned) {
            classifyCandidate(candidate)?.let { return it }
        }
        tried.add(
            if (scanned.isEmpty()) {
                "no java launcher on PATH and no JDK in the conventional install roots"
            } else {
                "${scanned.size} installed location(s) hold no modular JDK"
            },
        )
        return Resolution.NotFound(
            "no JDK home found (${tried.joinToString("; ")}); pass --jdk-home to name one",
        )
    }

    /**
     * Homes a JDK is plausibly installed at, most authoritative first: the
     * `java` launcher on `PATH` (which covers sdkman, asdf, homebrew, apt
     * and a hand-unpacked tarball alike, because all of them put the
     * launcher there), then the per-platform install roots, newest name
     * first so the choice does not depend on directory enumeration order.
     * No subprocess is spawned — a static-analysis binary that shells out to
     * find its own JDK is a worse trade than reading `PATH`.
     *
     * [roots] is a parameter because this function reads the HOST, and a
     * test that asserts it finds nothing is otherwise a test of the machine
     * it runs on: one written against a Mac with no `/usr/lib/jvm` passed
     * here and failed on a Linux runner that has one.
     */
    internal fun installedHomes(
        env: (String) -> String? = { System.getenv(it) },
        roots: List<String> = INSTALL_ROOTS,
    ): List<Path> {
        val out = mutableListOf<Path>()
        for (entry in (env("PATH") ?: "").split(java.io.File.pathSeparatorChar)) {
            if (entry.isBlank()) continue
            for (exe in listOf("java", "java.exe")) {
                val launcher = Path.of(entry).resolve(exe)
                if (!Files.isRegularFile(launcher)) continue
                // <home>/bin/java, through however many symlinks the
                // version manager put in the way.
                val real = try {
                    launcher.toRealPath()
                } catch (_: IOException) {
                    launcher.toAbsolutePath().normalize()
                }
                real.parent?.parent?.let(out::add)
            }
        }
        for (root in roots) {
            val dir = Path.of(root)
            if (!Files.isDirectory(dir)) continue
            val children = try {
                Files.list(dir).use { stream -> stream.filter { Files.isDirectory(it) }.toList() }
            } catch (_: IOException) {
                continue
            }
            out.addAll(children.sortedByDescending { it.fileName.toString() })
        }
        return out.distinct()
    }

    /**
     * Conventional per-platform install roots, each holding one directory
     * per installed JDK. Listing all of them on every platform costs one
     * `isDirectory` per miss and removes a per-OS branch.
     */
    private val INSTALL_ROOTS = listOf(
        "/Library/Java/JavaVirtualMachines",
        "/usr/lib/jvm",
        "/usr/java",
        "/opt/java",
        "C:\\Program Files\\Java",
        "C:\\Program Files\\Eclipse Adoptium",
    )

    /**
     * A home, or the macOS bundle that holds one at `Contents/Home` — the
     * shape every macOS JDK distribution unpacks to, and the shape a user
     * who sets `JAVA_HOME` to the unpacked directory gets wrong.
     */
    private fun classifyCandidate(home: Path): Resolution.Found? =
        classify(home) ?: classify(home.resolve("Contents").resolve("Home"))

    /** Modular (`lib/modules` image) or exploded (`modules/java.base` tree); null for neither. */
    private fun classify(home: Path): Resolution.Found? = when {
        Files.isRegularFile(home.resolve("lib").resolve("modules")) -> Resolution.Found(home, exploded = false)
        Files.isDirectory(home.resolve("modules").resolve("java.base")) -> Resolution.Found(home, exploded = true)
        else -> null
    }

    /**
     * SDK binary roots for a found JDK home, or null to fall back to the
     * Analysis API's own `addBinaryRootsFromJdkHome` (the JVM path, where
     * the jrt provider exists). In a native image the per-module extracted
     * jars are the only route that works. An exploded JDK needs no jrt
     * anywhere: its module directories are handed over as plain roots on
     * every substrate.
     */
    fun sdkBinaryRoots(home: Path): List<Path>? {
        val found = classify(home) ?: return null
        if (found.exploded) {
            return Files.list(home.resolve("modules")).use { stream ->
                stream.filter { Files.isDirectory(it) }.sorted().toList()
            }
        }
        if (!Analyzer.isNativeImage()) return null
        return extractedModuleJars(home)
    }

    // ---- image extraction ----------------------------------------------------

    /**
     * One jar per module of the module image, under
     * `$TMPDIR/kosi-jdk/<stamp>/`, keyed by (path, size, mtime) so a JDK
     * that changed on disk re-extracts and an unchanged one reuses the
     * previous jars across processes. Each jar is written to a temp file and
     * moved into place atomically, so a name that exists is always a
     * complete jar — the same reuse-or-fail contract as the AAR cache.
     */
    internal fun extractedModuleJars(home: Path): List<Path> {
        val image = home.resolve("lib").resolve("modules")
        val stamp = sha256(
            "$home|${Files.size(image)}|${Files.getLastModifiedTime(image).toMillis()}",
        ).substring(0, 24)
        val dir = Path.of(System.getProperty("java.io.tmpdir"), "kosi-jdk", stamp)
        // A warm cache must skip the READ, not just the write. Reading the
        // module image materializes every class of every JDK module in
        // memory (hundreds of MB) before the loop below discovers it has
        // nothing to write — so the cache saved nothing on the path that
        // matters. The manifest is written last, after every jar is in
        // place, so its presence means the whole set is complete.
        val manifest = dir.resolve("modules.list")
        if (Files.isRegularFile(manifest)) {
            val cached = Files.readAllLines(manifest).filter { it.isNotBlank() }.map { dir.resolve(it) }
            if (cached.isNotEmpty() && cached.all { Files.isRegularFile(it) }) return cached.sorted()
        }
        val jars = readModuleEntries(image)
        val out = mutableListOf<Path>()
        for ((module, entries) in jars) {
            val target = dir.resolve("module-$module.jar")
            if (!Files.isRegularFile(target)) {
                Files.createDirectories(dir)
                val temp = Files.createTempFile(dir, "module-", ".tmp")
                try {
                    writeZip(entries, temp)
                    try {
                        Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE)
                    } catch (_: AtomicMoveNotSupportedException) {
                        Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING)
                    }
                } finally {
                    Files.deleteIfExists(temp)
                }
            }
            out.add(target)
        }
        // Deterministic root order regardless of image enumeration order.
        val sorted = out.sorted()
        // Written last and atomically: a readable manifest means every jar it
        // names is already complete on disk.
        if (!Files.isRegularFile(manifest)) {
            Files.createDirectories(dir)
            val temp = Files.createTempFile(dir, "modules-", ".tmp")
            try {
                Files.writeString(temp, sorted.joinToString("\n") { it.fileName.toString() } + "\n")
                try {
                    Files.move(temp, manifest, StandardCopyOption.ATOMIC_MOVE)
                } catch (_: AtomicMoveNotSupportedException) {
                    Files.move(temp, manifest, StandardCopyOption.REPLACE_EXISTING)
                }
            } finally {
                Files.deleteIfExists(temp)
            }
        }
        return sorted
    }

    /**
     * Module entries of the jimage, grouped by module: `<module>` to its
     * `<path-within-module> to bytes` map, modules sorted by name. The JVM
     * reads through the public jrt filesystem (no internals, no flags); a
     * native image has no jrt provider and reads through its own
     * `jdk.internal.jimage.BasicImageReader` (reflection metadata +
     * `--add-opens`, build-time facts). Both routes see the same entries.
     */
    private fun readModuleEntries(image: Path): Map<String, Map<String, ByteArray>> =
        if (Analyzer.isNativeImage()) readViaImageReader(image) else readViaJrt(image)

    /** The public jrt filesystem, opened against the TARGET home (env key
     *  `java.home`), so a JVM run can read any JDK's module image. */
    private fun readViaJrt(image: Path): Map<String, Map<String, ByteArray>> {
        val home = image.parent?.parent ?: throw IOException("module image not under <home>/lib/modules: $image")
        val env = mapOf<String, Any>("java.home" to home.toString())
        val jrt = try {
            java.nio.file.FileSystems.newFileSystem(java.net.URI.create("jrt:/"), env)
        } catch (_: java.nio.file.FileSystemAlreadyExistsException) {
            // A jrt filesystem already opened in this process is bound to
            // whatever home IT was opened for, and there is no way to query
            // that binding. The running home is the only one we can vouch
            // for; anything else could silently read the wrong image.
            val runningHome = System.getProperty("java.home")?.let { Path.of(it).toAbsolutePath().normalize() }
            if (runningHome == null || runningHome != home.toAbsolutePath().normalize()) {
                throw IOException(
                    "a jrt filesystem is already open in this process and cannot be proven to read " +
                        "$home; the module image of a foreign home needs it closed first",
                )
            }
            java.nio.file.FileSystems.getFileSystem(java.net.URI.create("jrt:/"))
        }
        val modulesRoot = jrt.getPath("/modules")
        val out = sortedMapOf<String, SortedMap<String, ByteArray>>()
        Files.walk(modulesRoot).use { walk ->
            for (path in walk.filter { Files.isRegularFile(it) }.toList()) {
                // <module>/<path-within-module>
                val rel = modulesRoot.relativize(path).toString()
                if (!isModuleEntry(rel)) continue
                val module = rel.substringBefore('/')
                val within = rel.substringAfter('/')
                if (within.isEmpty()) continue
                out.getOrPut(module) { sortedMapOf() }[within] = Files.readAllBytes(path)
            }
        }
        return out
    }

    private fun readViaImageReader(image: Path): Map<String, SortedMap<String, ByteArray>> {
        val readerClass = Class.forName("jdk.internal.jimage.BasicImageReader")
        val reader = openImageReader(readerClass, image)
        try {
            val getEntryNames = readerClass.getMethod("getEntryNames")
            val getResource = readerClass.getMethod("getResource", String::class.java)
            val names = getEntryNames.invoke(reader) as Array<String>
            val out = sortedMapOf<String, SortedMap<String, ByteArray>>()
            for (raw in names) {
                val rel = normalizeEntryName(raw)
                if (!isModuleEntry(rel)) continue
                val module = rel.substringBefore('/')
                val within = rel.substringAfter('/')
                if (within.isEmpty()) continue
                out.getOrPut(module) { sortedMapOf() }[within] = getResource.invoke(reader, raw) as ByteArray
            }
            return out
        } finally {
            runCatching { readerClass.getMethod("close").invoke(reader) }
        }
    }

    /**
     * Stored entry names differ between JDK builds (`/<m>/...` vs
     * `/modules/<m>/...`); the jrt view is `/modules/<m>/...`. Normalized
     * form is `<module>/<path-within-module>`.
     */
    private fun normalizeEntryName(name: String): String {
        val trimmed = name.trimStart('/')
        return if (trimmed.startsWith("modules/")) trimmed.substring("modules/".length) else trimmed
    }

    private fun isModuleEntry(name: String): Boolean {
        val segments = name.split('/')
        return segments.size >= 2 && segments[0] !in NON_MODULE_SEGMENTS
    }

    // ---- reflection over the image's own jimage reader ------------------------

    private fun openImageReader(readerClass: Class<*>, image: Path): Any {
        val open = readerClass.getMethod("open", Path::class.java)
        open.isAccessible = true
        return open.invoke(null, image) ?: throw IOException("BasicImageReader.open($image) returned null")
    }

    // ---- zip writer ------------------------------------------------------------

    /**
     * Deterministic STORED zip: entries in the given order, fixed epoch
     * timestamps, no wall-clock input anywhere.
     */
    private fun writeZip(entries: Map<String, ByteArray>, target: Path) {
        val fixedTimeMillis = 315532800000L
        ZipOutputStream(Files.newOutputStream(target)).use { zip ->
            for ((name, bytes) in entries) {
                val entry = ZipEntry(name).apply {
                    time = fixedTimeMillis
                    method = ZipEntry.STORED
                    size = bytes.size.toLong()
                    compressedSize = bytes.size.toLong()
                    crc = crc32(bytes)
                }
                zip.putNextEntry(entry)
                zip.write(bytes)
                zip.closeEntry()
            }
        }
    }

    // ---- shared helpers --------------------------------------------------------

    private fun crc32(bytes: ByteArray): Long {
        val crc = java.util.zip.CRC32()
        crc.update(bytes)
        return crc.value
    }

    internal fun sha256(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
