package io.cdxgen.kosi.evidence

import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.SecuritySignal
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * The Kotlin/Native + JNI/cinterop seam as `native-interop` evidence
 * (02-ARCHITECTURE.md §8's `native-interop` signal). The seam is where a
 * managed value crosses into code the JVM never sees — an `external fun`
 * backed by a JNI library, a `System.loadLibrary` binding the two worlds, a
 * cinterop `.def` describing a C header for Kotlin/Native — and it is
 * exactly the boundary memory-safety reviewers must see even when no taint
 * flow crosses it.
 *
 * Everything here is structure, not naming heuristics: an `external`
 * MODIFIER on the lowered function, a RESOLVED call to `System.loadLibrary`
 * or `Runtime.loadLibrary`, and `.def` files under the conventional cinterop
 * source-set directories. A function merely NAMED like a native one is a
 * negative, never a finding.
 */
object NativeInterop {

    const val CODE = "native-interop"

    /** The directories cinterop `.def` files conventionally live in. */
    private val DEF_DIRS = listOf("nativeInterop/cinterop", "cinterop", "nativeinterop")

    data class Attribution(
        val byAbsoluteFilePath: Map<String, Pair<String, String>>,
        val purlByModulePath: Map<String, String>,
    )

    fun collect(root: Path, module: KirModule, attribution: Attribution): List<SecuritySignal> {
        val signals = mutableListOf<SecuritySignal>()

        // 1. `external fun` — the JNI seam declared on the function.
        for (function in module.functions) {
            if ("external" !in function.modifiers) continue
            val (filePath, modulePath) = attribution.byAbsoluteFilePath[function.file] ?: (function.file to "")
            signals.add(
                SecuritySignal(
                    code = CODE,
                    message = "`${function.canonicalName}` is external: its body lives outside the JVM " +
                        "(JNI or expect/actual native), so no analysis can see what it does with its arguments",
                    modulePath = modulePath,
                    purl = attribution.purlByModulePath[modulePath].takeUnless { it.isNullOrEmpty() } ?: function.purl,
                    filePath = filePath,
                    position = Position(filePath, function.line.coerceAtLeast(1), function.column),
                    symbol = function.canonicalName,
                ),
            )
        }

        // 2. `System.loadLibrary` / `Runtime.loadLibrary` — the binding site.
        for (function in module.functions) {
            val body = function.body ?: continue
            for (block in body.blocks) {
                for (ins in block.instructions) {
                    if (ins !is KirCall) continue
                    val fqn = ins.callee.fqn
                    if (fqn != "java.lang.System.loadLibrary" && fqn != "java.lang.System.load" &&
                        fqn != "java.lang.Runtime.loadLibrary" && fqn != "java.lang.Runtime.load"
                    ) {
                        continue
                    }
                    val (filePath, modulePath) = attribution.byAbsoluteFilePath[function.file] ?: (function.file to "")
                    signals.add(
                        SecuritySignal(
                            code = CODE,
                            message = "`${function.canonicalName}` loads a native library " +
                                "(${fqn.substringAfterLast('.')}) — native code executes inside this " +
                                "process outside every JVM guarantee",
                            modulePath = modulePath,
                            purl = attribution.purlByModulePath[modulePath].takeUnless { it.isNullOrEmpty() } ?: function.purl,
                            filePath = filePath,
                            position = Position(filePath, ins.line.coerceAtLeast(1), 1),
                            symbol = function.canonicalName,
                        ),
                    )
                }
            }
        }

        // 3. Kotlin/Native cinterop: `.def` files under conventional
        // source-set directories. The file IS the evidence; the message
        // names only its path, never its contents.
        if (Files.isDirectory(root)) {
            Files.walk(root).use { stream ->
                stream.filter { p -> Files.isRegularFile(p) && p.fileName.toString().endsWith(".def") }
                    .forEach { def ->
                        val relative = root.toAbsolutePath().normalize().relativize(def.toAbsolutePath().normalize())
                        val parents = relative.parent?.map { it.toString() }.orEmpty()
                        if (parents.any { it in DEF_DIRS }) {
                            val rel = relative.toString().replace('\\', '/')
                            signals.add(
                                SecuritySignal(
                                    code = CODE,
                                    message = "cinterop definition $rel binds Kotlin/Native to C code; " +
                                        "the C surface is outside every JVM and Kotlin/Native guarantee",
                                    modulePath = "",
                                    purl = "",
                                    filePath = rel,
                                    position = Position(rel, 1, 1),
                                    symbol = rel,
                                ),
                            )
                        }
                    }
            }
        }

        return signals.distinctBy { Triple(it.code, it.filePath, it.symbol) }
            .sortedWith(SecuritySignal.COMPARATOR)
    }

    /** Test/CLI convenience: build attribution maps the way kosi-front does. */
    fun attributionOf(byAbsoluteFilePath: Map<String, Pair<String, String>>, purlByModulePath: Map<String, String>) =
        Attribution(byAbsoluteFilePath, purlByModulePath)

    private fun rel(root: Path, path: Path): String =
        Paths.get("").toAbsolutePath().relativize(path.toAbsolutePath()).toString()
}
