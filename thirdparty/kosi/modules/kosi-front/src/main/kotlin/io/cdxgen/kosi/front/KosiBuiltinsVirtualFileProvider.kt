package io.cdxgen.kosi.front

import com.intellij.openapi.vfs.StandardFileSystems
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.vfs.VirtualFileManager
import org.jetbrains.kotlin.analysis.decompiler.psi.BuiltinsVirtualFileProviderBaseImpl
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile

/**
 * Resolves the serialized builtin declarations against the materialized
 * kotlin-stdlib jar that kosi ships, instead of deriving the jar from the
 * classloader URL. The stock [BuiltinsVirtualFileProviderBaseImpl.CliImpl
 * CLI provider] splits `jar:file:...!/path` URLs produced by the JVM
 * classloader; inside a GraalVM image the same resources surface as
 * `resource:/0!/...` URLs whose file path does not exist, so builtin
 * resolution would die with NoSuchFileException. Registered as an
 * application service by [AnalysisEnvironment] (replacing the CLI one).
 */
class KosiBuiltinsVirtualFileProvider(private val stdlibJar: Path) : BuiltinsVirtualFileProviderBaseImpl() {

    override fun findVirtualFile(url: URL): VirtualFile? =
        builtinFiles[url.path?.substringAfterLast('!') ?: return null]

    private val builtinFiles: Map<String, VirtualFile> by lazy {
        val jarFileSystem = VirtualFileManager.getInstance().getFileSystem(StandardFileSystems.JAR_PROTOCOL)
        // The jar protocol's findFileByPath takes the LOCAL part: the
        // absolute jar path and the entry, joined by "!/" (no protocol).
        val prefix: String = stdlibJar.toAbsolutePath().toString() + "!/"
        buildMap {
            ZipFile(stdlibJar.toFile()).use { zip ->
                for (entry in zip.entries()) {
                    if (!entry.name.endsWith(".kotlin_builtins")) continue
                    jarFileSystem.findFileByPath(prefix + entry.name)?.let { put("/" + entry.name, it) }
                }
            }
        }
    }
}
