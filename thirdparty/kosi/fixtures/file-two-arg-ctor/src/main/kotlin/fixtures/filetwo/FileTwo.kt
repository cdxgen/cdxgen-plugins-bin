// The two-argument file constructors: `File(parent, child)` carries the
// child in argument 1, and the upload idiom is exactly that shape.
// kosi:want flow source=untrusted-input sink=path-traversal fn=~uploadInto mode=endpoint
// kosi:want flow source=untrusted-input sink=path-traversal fn=~directPath mode=endpoint
// kosi:want-not flow source=untrusted-input sink=path-traversal fn=~cleanName mode=endpoint
// kosi:want-not diagnostic code=parse-error
package fixtures.filetwo

import java.io.File

fun uploadInto(): File {
    val name = readLine() ?: "x"
    return File("/tmp/uploads", name).apply { writeText("data") }
}

fun directPath(): File {
    val name = readLine() ?: "x"
    return File(name).apply { writeText("data") }
}

fun cleanName(): File = File("/tmp/fixed", "report.txt").apply { writeText("data") }
