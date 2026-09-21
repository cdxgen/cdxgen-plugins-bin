package io.cdxgen.kosi.bytecode

import java.io.File
import java.util.jar.JarFile
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Every class the IntelliJ container can construct is registered for
 * reflection in the native image.
 *
 * The container instantiates the classes named by `serviceImplementation`,
 * `implementationClass`, `implementation` and `instance` in the plugin
 * descriptors the fat jar ships — and it does so ON FIRST USE. That makes
 * tracing-agent coverage a lottery over which services a given run happens to
 * wake, and the lottery was being lost: 89 of the 133 registered classes were
 * absent from the committed metadata.
 *
 * What that cost, measured: the published darwin binary analysed every
 * bundled fixture, including the Java ones, and then exited 3 with no report
 * on dagger —
 *
 *     kosi: Either do the specified parameters not match any of the following
 *     constructors: [] or the constructors were not accessible for
 *     'class com.intellij.psi.impl.JavaClassSupersImpl'
 *
 * `JavaClassSupersImpl` is reached only when a Java class hierarchy is queried
 * across separately-parsed files, so every small fixture passed and 1,559 Java
 * files failed. The native smoke test in CI runs a pure-Kotlin fixture, which
 * is why no gate saw it.
 *
 * A FIXTURE cannot pin this. One that happens to wake one service says nothing
 * about the other 126, and the defect is the class of thing, not the instance.
 * The registrations are in the jar, so the rule is: whatever the descriptors
 * register, the metadata carries. `make psi-metadata` derives it; this test is
 * what fails when a dependency bump adds a service and nobody re-derives.
 */
class NativeServiceMetadataTest {

    private val kosiRoot: File = generateSequence(File(".").absoluteFile) { it.parentFile }
        .first { File(it, "native-metadata/kosi-psi").isDirectory }

    private val attribute = Regex(
        "(?:serviceImplementation|implementationClass|implementation|instance)\\s*=\\s*\"([A-Za-z_][\\w.$]*)\"",
    )

    @Test
    fun everyRegisteredServiceImplementationIsInTheCommittedMetadata() {
        val jar = File(kosiRoot, "modules/kosi-cli/build/dist/kosi-all.jar")
        if (!jar.isFile) {
            // The jar is a build product; the gate that matters runs after
            // `kosiFatJar`. Saying so beats a green test over no jar.
            println("NativeServiceMetadataTest: no fat jar at $jar; run :kosi-cli:kosiFatJar")
            return
        }
        val registered = sortedSetOf<String>()
        JarFile(jar).use { archive ->
            for (entry in archive.entries()) {
                val name = entry.name
                if (!name.startsWith("META-INF/") || !name.endsWith(".xml")) continue
                val xml = archive.getInputStream(entry).use { it.readBytes().toString(Charsets.UTF_8) }
                for (match in attribute.findAll(xml)) {
                    val type = match.groupValues[1]
                    if ('.' !in type) continue
                    // Only classes this jar actually carries: the descriptors
                    // also name classes from IDE modules kosi does not ship.
                    if (archive.getEntry(type.replace('.', '/') + ".class") == null) continue
                    registered.add(type)
                }
            }
        }
        assertTrue(
            registered.size > 100,
            "expected the platform descriptors to register a substantial service surface, found ${registered.size}",
        )

        val metadata = File(kosiRoot, "native-metadata/kosi-psi/reachability-metadata.json").readText()
        val missing = registered.filterNot { "\"type\": \"$it\"" in metadata }
        assertTrue(
            missing.isEmpty(),
            "${missing.size} of ${registered.size} registered service implementations are missing from the " +
                "native reachability metadata; run `make psi-metadata`. The native binary dies at RUNTIME on the " +
                "first one the platform decides to construct, which may be any repository and no fixture. " +
                "Missing: ${missing.take(10)}",
        )
    }
}
