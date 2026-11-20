package io.cdxgen.kosi.schema

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Assumptions
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The no-follow rule the analysed tree is read under: a link committed in
 * the tree is not the file it names. Without the rule, every reader that
 * asked "is this a regular file" was answered about the TARGET, and a
 * repository could point the analysis at a file outside itself.
 */
class SafeFilesTest {

    private val tmp: Path = Files.createTempDirectory("kosi-safefiles")

    @AfterTest
    fun cleanup() {
        tmp.toFile().deleteRecursively()
    }

    /** Symlinks need privileges on Windows; skip rather than fail there. */
    private fun symlink(target: Path, link: Path): Boolean =
        try {
            Files.createSymbolicLink(link, target)
            true
        } catch (_: Exception) {
            false
        } catch (_: Error) {
            false
        }

    @Test
    fun aRegularFileIsReadNormally() {
        val file = tmp.resolve("application.properties")
        Files.writeString(file, "key=value\n")
        assertTrue(SafeFiles.isRegularFile(file))
        assertEquals("key=value\n", SafeFiles.readString(file))
        assertEquals(listOf("key=value"), SafeFiles.readLines(file))
    }

    @Test
    fun aMissingFileIsNotARegularFile() {
        assertFalse(SafeFiles.isRegularFile(tmp.resolve("absent.properties")))
        assertNull(SafeFiles.readString(tmp.resolve("absent.properties")))
        assertTrue(SafeFiles.readLines(tmp.resolve("absent.properties")).isEmpty())
        assertNull(SafeFiles.newInputStream(tmp.resolve("absent.properties")))
    }

    @Test
    fun aDirectoryIsNotARegularFile() {
        Files.createDirectories(tmp.resolve("src"))
        assertFalse(SafeFiles.isRegularFile(tmp.resolve("src")))
    }

    @Test
    fun aSymlinkToAFileIsNotTreatedAsThatFile() {
        val outside = Files.createTempDirectory("kosi-safefiles-outside")
        try {
            val target = outside.resolve("credentials")
            Files.writeString(target, "secret=value\n")
            val link = tmp.resolve("application.properties")
            Assumptions.assumeTrue(symlink(target, link), "symbolic links are unavailable here")

            assertFalse(SafeFiles.isRegularFile(link), "a link must not pass as a regular file")
            assertNull(SafeFiles.readString(link), "reading through a link would leave the tree")
            assertTrue(SafeFiles.readLines(link).isEmpty())
            assertNull(SafeFiles.newInputStream(link))
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun aSymlinkToADirectoryIsNotARegularFile() {
        val outside = Files.createTempDirectory("kosi-safefiles-outside")
        try {
            val link = tmp.resolve("linked-dir")
            Assumptions.assumeTrue(symlink(outside, link), "symbolic links are unavailable here")
            assertFalse(SafeFiles.isRegularFile(link))
        } finally {
            outside.toFile().deleteRecursively()
        }
    }
}
