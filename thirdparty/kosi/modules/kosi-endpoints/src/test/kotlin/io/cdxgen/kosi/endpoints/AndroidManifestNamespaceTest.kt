package io.cdxgen.kosi.endpoints

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Where a relative `android:name=".Foo"` gets its package.
 *
 * AGP 7 removed `package` from the manifest and put it in the module's
 * `namespace`. Measured on dagger: **25 of its 27 manifests carry no
 * `package` attribute**, so every one of their components resolved against
 * an empty package. The old code produced the string `.Foo` — a leading-dot
 * name no declaration can ever carry — and the component was then reported
 * as one whose class kosi had not read.
 *
 * Both halves are pinned: the namespace is FOUND (the fix), and a manifest
 * with neither package nor namespace yields the bare class rather than the
 * nonsense one (the defect the fix was found through).
 */
class AndroidManifestNamespaceTest {

    private val tmp: Path = Files.createTempDirectory("kosi-manifest-ns")

    @AfterTest
    fun cleanup() {
        tmp.toFile().deleteRecursively()
    }

    private val manifest = """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android">
          <application>
            <activity android:name=".ui.MainActivity" android:exported="true"/>
          </application>
        </manifest>
    """.trimIndent()

    private fun write(module: String, buildFileName: String?, buildText: String?) {
        val dir = tmp.resolve("$module/src/main")
        Files.createDirectories(dir)
        Files.writeString(dir.resolve("AndroidManifest.xml"), manifest)
        if (buildFileName != null && buildText != null) {
            Files.writeString(tmp.resolve(module).resolve(buildFileName), buildText)
        }
    }

    private fun soleClassName(): String {
        val parsed = AndroidManifestParser.parse(tmp)
        assertEquals(1, parsed.size, "expected exactly one manifest, got ${parsed.map { it.file }}")
        val components = parsed.single().components
        assertEquals(1, components.size)
        return components.single().className
    }

    @Test
    fun theKotlinDslNamespaceResolvesTheRelativeName() {
        write("app", "build.gradle.kts", "android {\n    namespace = \"com.example.app\"\n}\n")
        assertEquals("com.example.app.ui.MainActivity", soleClassName())
    }

    /** dagger writes both spellings; the Groovy one has no `=`. */
    @Test
    fun theGroovyNamespaceResolvesTheRelativeName() {
        write("app", "build.gradle", "android {\n    namespace \"com.example.app\"\n}\n")
        assertEquals("com.example.app.ui.MainActivity", soleClassName())
    }

    /**
     * The manifest's own `package` is still the first answer — it is the
     * more specific fact, and a module may carry both while they disagree.
     */
    @Test
    fun theManifestPackageStillWinsOverTheNamespace() {
        val dir = tmp.resolve("app/src/main")
        Files.createDirectories(dir)
        Files.writeString(
            dir.resolve("AndroidManifest.xml"),
            manifest.replace("<manifest ", "<manifest package=\"from.the.manifest\" "),
        )
        Files.writeString(tmp.resolve("app/build.gradle.kts"), "android { namespace = \"from.the.build\" }")
        assertEquals("from.the.manifest.ui.MainActivity", soleClassName())
    }

    /**
     * Restore-proof for the other half: with NO package anywhere, the name
     * must be the bare class. `.ui.MainActivity` was what shipped, and it
     * matches nothing by construction.
     */
    @Test
    fun withNoPackageAnywhereTheNameIsTheBareClassNeverALeadingDot() {
        write("app", null, null)
        assertEquals("ui.MainActivity", soleClassName())
    }

    /** The namespace is looked up from the nearest enclosing module, not the root. */
    @Test
    fun theNearestEnclosingBuildFileIsTheOneRead() {
        write("app", "build.gradle.kts", "android { namespace = \"com.example.app\" }")
        Files.writeString(tmp.resolve("build.gradle.kts"), "android { namespace = \"com.example.root\" }")
        assertEquals("com.example.app.ui.MainActivity", soleClassName())
    }
}
