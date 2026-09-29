// NIO paths are traversal sinks where they are USED: the Files operations
// and the kotlin.io.path I/O extensions. Building a Path (Paths.get, Path.of,
// resolve, kotlin's Path(..) and `/`) moves the input into the Path, so a
// normalize() between the two clears it the way the sanitizer gallery pins —
// a construction-time sink would fire before any sanitizer could. The stream
// and reader constructors that take a path string open it on the spot.
// kosi:want-not flow source=untrusted-input sink=path-traversal fn=fixtures.nio.fixedPaths mode=endpoint
// kosi:want-not flow source=untrusted-input sink=path-traversal fn=fixtures.nio.normalizedBeforeUse mode=endpoint
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesReadAllBytes mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesReadAllLines mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesReadString mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesLines mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesNewInputStream mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesNewBufferedReader mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesNewOutputStream mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesNewBufferedWriter mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesWrite mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesWriteString mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesDelete mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesDeleteIfExists mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesCreateFile mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesCreateDirectory mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesCreateDirectories mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesNewDirectoryStream mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesList mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesWalk mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesCopy mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesMove mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesCreateLink mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.filesCreateSymbolicLink mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathReadText mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathReadBytes mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathReadLines mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathWriteText mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathWriteBytes mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathAppendText mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathInputStream mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathOutputStream mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathBufferedReader mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathBufferedWriter mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathDeleteExisting mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathDeleteIfExists mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathCreateDirectories mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathCopyTo mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.pathMoveTo mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.inputStream mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.reader mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=fixtures.nio.randomAccess mode=endpoint
package fixtures.nio

import java.io.FileInputStream
import java.io.FileReader
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.io.path.Path
import kotlin.io.path.appendText
import kotlin.io.path.bufferedReader
import kotlin.io.path.bufferedWriter
import kotlin.io.path.copyTo
import kotlin.io.path.createDirectories
import kotlin.io.path.deleteExisting
import kotlin.io.path.deleteIfExists
import kotlin.io.path.div
import kotlin.io.path.inputStream
import kotlin.io.path.moveTo
import kotlin.io.path.outputStream
import kotlin.io.path.readBytes
import kotlin.io.path.readLines
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

fun filesReadAllBytes(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/uploads", name)
    return Files.readAllBytes(p)
}

fun filesReadAllLines(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path.of(name)
    return Files.readAllLines(p)
}

fun filesReadString(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv").resolve(name)
    return Files.readString(p)
}

fun filesLines(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/a").resolveSibling(name)
    return Files.lines(p)
}

fun filesNewInputStream(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv", name)
    return Files.newInputStream(p)
}

fun filesNewBufferedReader(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv") / name
    return Files.newBufferedReader(p)
}

fun filesNewOutputStream(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/uploads", name)
    return Files.newOutputStream(p)
}

fun filesNewBufferedWriter(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path.of(name)
    return Files.newBufferedWriter(p)
}

fun filesWrite(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv").resolve(name)
    return Files.write(p, byteArrayOf(1))
}

fun filesWriteString(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/a").resolveSibling(name)
    return Files.writeString(p, "d")
}

fun filesDelete(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv", name)
    return Files.delete(p)
}

fun filesDeleteIfExists(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv") / name
    return Files.deleteIfExists(p)
}

fun filesCreateFile(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/uploads", name)
    return Files.createFile(p)
}

fun filesCreateDirectory(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path.of(name)
    return Files.createDirectory(p)
}

fun filesCreateDirectories(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv").resolve(name)
    return Files.createDirectories(p)
}

fun filesNewDirectoryStream(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/a").resolveSibling(name)
    return Files.newDirectoryStream(p)
}

fun filesList(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv", name)
    return Files.list(p)
}

fun filesWalk(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv") / name
    return Files.walk(p)
}

fun filesCopy(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/uploads", name)
    return Files.copy(p, Paths.get("/tmp/copy"))
}

fun filesMove(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path.of(name)
    return Files.move(Paths.get("/tmp/move"), p)
}

fun filesCreateLink(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv").resolve(name)
    return Files.createLink(p, Paths.get("/tmp/link"))
}

fun filesCreateSymbolicLink(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/a").resolveSibling(name)
    return Files.createSymbolicLink(Paths.get("/tmp/sym"), p)
}

fun pathReadText(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv", name)
    return p.readText()
}

fun pathReadBytes(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv") / name
    return p.readBytes()
}

fun pathReadLines(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/uploads", name)
    return p.readLines()
}

fun pathWriteText(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path.of(name)
    return p.writeText("d")
}

fun pathWriteBytes(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv").resolve(name)
    return p.writeBytes(byteArrayOf(1))
}

fun pathAppendText(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/a").resolveSibling(name)
    return p.appendText("d")
}

fun pathInputStream(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv", name)
    return p.inputStream()
}

fun pathOutputStream(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv") / name
    return p.outputStream()
}

fun pathBufferedReader(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/uploads", name)
    return p.bufferedReader()
}

fun pathBufferedWriter(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path.of(name)
    return p.bufferedWriter()
}

fun pathDeleteExisting(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv").resolve(name)
    return p.deleteExisting()
}

fun pathDeleteIfExists(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/a").resolveSibling(name)
    return p.deleteIfExists()
}

fun pathCreateDirectories(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv", name)
    return p.createDirectories()
}

fun pathCopyTo(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Path("/srv") / name
    return p.copyTo(Path("/tmp/copy"))
}

fun pathMoveTo(): Any? {
    val name = readLine() ?: "x"
    val p: Path = Paths.get("/srv/uploads", name)
    return Path("/tmp/move").moveTo(p)
}

fun inputStream(): Int {
    val name = readLine() ?: "x"
    return FileInputStream(name).use { it.read() }
}

fun reader(): Int {
    val name = readLine() ?: "x"
    return FileReader(name).use { it.read() }
}

fun randomAccess(): Long {
    val name = readLine() ?: "x"
    return RandomAccessFile(name, "r").use { it.length() }
}

fun fixedPaths(): String {
    val name = readLine() ?: "x"
    println(name)
    return Path("/srv", "fixed").readText() + Files.readString(Paths.get("/srv", "a").resolve("b"))
}

fun normalizedBeforeUse(): String {
    val name = readLine() ?: "x"
    return Files.readString(Paths.get("/srv", name).normalize())
}
