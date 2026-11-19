package io.cdxgen.kosi.endpoints

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Assumptions
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A repository that commits `application.properties` as a link to a file
 * outside the analysed tree used to have that file read, and the value it
 * found was substituted into Spring route templates and published in the
 * report's `apiEndpoints[].pathTemplate`. The no-follow rule leaves the
 * key honestly unresolved instead — and a value that comes from the tree
 * itself still resolves, so the fix must not cost the feature.
 */
class ConfigResolverSymlinkTest {

    private val tmp: Path = Files.createTempDirectory("kosi-config-symlink")

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

    private fun module(): Path {
        val dir = tmp.resolve("proj")
        Files.createDirectories(dir.resolve("src/main/resources"))
        return dir
    }

    @Test
    fun aLinkedPropertiesFileOutsideTheTreeIsNotRead() {
        val outside = Files.createTempDirectory("kosi-config-symlink-outside")
        try {
            val credentials = outside.resolve("credentials")
            Files.writeString(credentials, "aws_secret_access_key=SECRET-VALUE-12345\n")
            val dir = module()
            Assumptions.assumeTrue(
                symlink(credentials, dir.resolve("src/main/resources/application.properties")),
                "symbolic links are unavailable here",
            )

            val table = ConfigResolver.load(dir)
            assertNull(table["aws_secret_access_key"]?.value,
                "a value from outside the analysed tree must not enter the table")
            val (resolved, status) = ConfigResolver.resolveTemplate("/\${aws_secret_access_key}", table)
            assertNull(resolved)
            assertEquals(ConfigResolver.Status.UNRESOLVED, status,
                "the route keeps its placeholder rather than a stolen value")
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun aLinkedYamlFileOutsideTheTreeIsNotRead() {
        val outside = Files.createTempDirectory("kosi-config-symlink-outside")
        try {
            val secretYaml = outside.resolve("secret.yml")
            Files.writeString(secretYaml, "aws_secret_access_key: YML-SECRET\n")
            val dir = module()
            Assumptions.assumeTrue(
                symlink(secretYaml, dir.resolve("src/main/resources/application.yml")),
                "symbolic links are unavailable here",
            )

            val table = ConfigResolver.load(dir)
            assertNull(table["aws_secret_access_key"]?.value)
            val (_, status) = ConfigResolver.resolveTemplate("/\${aws_secret_access_key}", table)
            assertEquals(ConfigResolver.Status.UNRESOLVED, status)
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    @Test
    fun aPropertiesFileInsideTheTreeStillResolves() {
        val dir = module()
        Files.writeString(dir.resolve("src/main/resources/application.properties"), "server.port=8080\n")

        val table = ConfigResolver.load(dir)
        assertEquals("8080", table["server.port"]?.value)
        val (resolved, status) = ConfigResolver.resolveTemplate(":\${server.port}/api", table)
        assertEquals(":8080/api", resolved)
        assertEquals(ConfigResolver.Status.CONFIG, status)
    }

    @Test
    fun anUnresolvableKeyStaysUnresolvedEvenWithOtherKeysPresent() {
        val dir = module()
        Files.writeString(dir.resolve("src/main/resources/application.properties"), "server.port=8080\n")

        val table = ConfigResolver.load(dir)
        val (resolved, status) = ConfigResolver.resolveTemplate("/api/\${no.such.key}", table)
        assertNull(resolved)
        assertEquals(ConfigResolver.Status.UNRESOLVED, status)
        assertTrue(true, "the placeholder never becomes a guess")
    }
}
