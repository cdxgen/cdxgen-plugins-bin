package io.cdxgen.kosi.schema

import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/**
 * File access over the analysed tree, which is untrusted input: a checkout
 * the repository's author chose, not the operator.
 *
 * Every reader here resolves the FINAL path component with
 * [LinkOption.NOFOLLOW_LINKS], so a symbolic link committed inside the tree
 * is never mistaken for the file it names. Before this rule, discovery
 * walked with `Files.isRegularFile` — which follows links — so a repo that
 * committed `src/main/resources/application.properties` as a link to a file
 * outside the tree made the analysis read that file, and the values it
 * found were substituted into reported routes. The same held for a linked
 * Kotlin source and a linked build script. Directories are not at issue:
 * `Files.walk` never descends into links, and a `--dir` that is itself a
 * link is the operator's own choice and keeps working.
 *
 * A hard link cannot be told apart from a regular file and is out of scope.
 * A link the analysis refuses costs a key's value (it stays honestly
 * unresolved) or a source file's presence — never a wrong fact.
 *
 * This lives in kosi-schema because every module that reads project files
 * (kosi-project, kosi-endpoints, kosi-front) depends on it and it must stay
 * stdlib-only, like the rest of this module.
 */
object SafeFiles {

    /** A regular file at exactly this path — not a link to one. */
    fun isRegularFile(path: Path): Boolean = Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)

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
     * this path. Matches `Files.readAllLines`: no trailing empty element
     * for a text that ends in a newline (the config readers treat a blank
     * line as no line, but the parity with the previous reader is free).
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
