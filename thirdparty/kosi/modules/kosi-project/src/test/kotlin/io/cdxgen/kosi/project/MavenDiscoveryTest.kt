package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Maven compiler settings are read from the kotlin-maven-plugin
 * <configuration> as XML. The original implementation scanned for
 * Gradle-style brace blocks, which can never match a pom — every setting came
 * back null and the gap was silent. These tests pin the XML path.
 */
class MavenDiscoveryTest {

    private val tmp: Path = Files.createTempDirectory("kosi-maven-test")

    @AfterTest
    fun cleanup() {
        tmp.toFile().deleteRecursively()
    }

    private fun pom(body: String) {
        Files.createDirectories(tmp.resolve("src/main/kotlin"))
        Files.writeString(
            tmp.resolve("pom.xml"),
            """
            <project>
              <groupId>dev.kosi</groupId>
              <artifactId>t</artifactId>
              <version>1.0</version>
              <build>
                <plugins>
                  <plugin>
                    <groupId>org.jetbrains.kotlin</groupId>
                    <artifactId>kotlin-maven-plugin</artifactId>
                    <configuration>
                      $body
                    </configuration>
                  </plugin>
                </plugins>
              </build>
            </project>
            """.trimIndent(),
        )
    }

    @Test
    fun kotlinPluginSettingsAreReadFromConfiguration() {
        pom("<languageVersion>1.9</languageVersion>\n<apiVersion>1.8</apiVersion>\n<jvmTarget>17</jvmTarget>")
        val module = MavenDiscovery.discover(tmp).modules.single()
        assertEquals("1.9", module.declaredLanguageVersion)
        assertEquals("1.8", module.declaredApiVersion)
        assertEquals("17", module.jvmTarget)
    }

    @Test
    fun absentSettingsStayNull() {
        pom("<jvmTarget>21</jvmTarget>")
        val module = MavenDiscovery.discover(tmp).modules.single()
        assertNull(module.declaredLanguageVersion)
        assertNull(module.declaredApiVersion)
        assertEquals("21", module.jvmTarget)
    }

    @Test
    fun nestedModulesAreDiscovered() {
        Files.createDirectories(tmp.resolve("app/src/main/kotlin"))
        Files.writeString(
            tmp.resolve("pom.xml"),
            """
            <project>
              <groupId>dev.kosi</groupId>
              <artifactId>root</artifactId>
              <version>1.0</version>
              <modules><module>app</module></modules>
            </project>
            """.trimIndent(),
        )
        Files.writeString(
            tmp.resolve("app/pom.xml"),
            """
            <project>
              <parent>
                <groupId>dev.kosi</groupId>
                <artifactId>root</artifactId>
                <version>1.0</version>
              </parent>
              <artifactId>app</artifactId>
            </project>
            """.trimIndent(),
        )
        val modules = MavenDiscovery.discover(tmp).modules.sortedBy { it.name }
        assertEquals(listOf("app", "root"), modules.map { it.name })
        // The child inherits coordinates from <parent> when it declares none.
        assertEquals("pkg:maven/dev.kosi/app@1.0", modules.first { it.name == "app" }.purl)
        assertTrue("app/src/main/kotlin" in modules.first { it.name == "app" }.sourceRoots)
    }
}
