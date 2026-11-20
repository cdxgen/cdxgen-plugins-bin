package io.cdxgen.kosi.schema

import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/**
 * File access over the analysed tree, which is untrusted input: a checkout
 * the repository's author chose, not the operator.
 *
 * Two rules keep every read inside the tree.
 *
 * Files: every reader here resolves the FINAL path component with
 * [LinkOption.NOFOLLOW_LINKS], so a symbolic link committed inside the tree
 * (`src/main/resources/application.properties` pointing at a credentials
 * file, say) is never read as the file it names.
 *
 * Directories: a path the analysis builds by resolving names under the root
 * (a source root such as `src/main/kotlin`, a Gradle or Maven module
 * directory) follows any link in its middle components, so `src` committed
 * as a link to a directory elsewhere would take the whole source walk out
 * of the tree. Such a directory is used only when [isInside] holds: its real
 * path lies under the real path of the analysis root. `Files.walk` does not
 * descend into links below its start, so a contained start keeps the whole
 * walk contained. A `--dir` that is itself a link is the operator's choice;
 * comparing real paths on both sides keeps it working.
 *
 * A hard link cannot be told apart from a regular file and is out of scope.
 * A path the analysis refuses costs a key's value (it stays unresolved) or a
 * source file's presence, never a wrong fact.
 *
 * This lives in kosi-schema because every module that reads project files
 * (kosi-project, kosi-endpoints, kosi-evidence, kosi-front) depends on it,
 * and it stays stdlib-only like the rest of this module.
 */
object SafeFiles {

    /** A regular file at exactly this path, not a link to one. */
    fun isRegularFile(path: Path): Boolean = Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)

    /**
     * Whether [path] resolves, links and all, to [root] or somewhere under
     * it. False when either does not exist or cannot be resolved.
     */
    fun isInside(root: Path, path: Path): Boolean = try {
        path.toRealPath().startsWith(root.toRealPath())
    } catch (_: Exception) {
        false
    }

    /** The file's bytes, or null when it is not a regular file at this path. */
    fun readBytes(path: Path): ByteArray? =
        if (isRegularFile(path)) try {
            Files.readAllBytes(path)
        } catch (_: Exception) {
            null
        } else {
            null
        }

    /** The file as UTF-8 text, or null when it is not a regular file at this path. */
    fun readString(path: Path): String? = readBytes(path)?.toString(Charsets.UTF_8)

    /**
     * The file's lines, or an empty list when it is not a regular file at
     * this path. Like `Files.readAllLines`, a text that ends in a newline
     * has no trailing empty element.
     */
    fun readLines(path: Path): List<String> {
        val lines = readString(path)?.lines() ?: return emptyList()
        return if (lines.isNotEmpty() && lines.last().isEmpty()) lines.dropLast(1) else lines
    }

    /**
     * An [InputStream] over the file that refuses to follow a link swapped
     * in after an [isRegularFile] check (the check and the open agree about
     * links), or null when it is not a regular file at this path.
     */
    fun newInputStream(path: Path): InputStream? =
        if (isRegularFile(path)) try {
            Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)
        } catch (_: Exception) {
            null
        } else {
            null
        }
}
