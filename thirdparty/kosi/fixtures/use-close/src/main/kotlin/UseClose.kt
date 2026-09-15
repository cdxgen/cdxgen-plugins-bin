// Negative half first: close() is reached only through the try/finally the
// `use` lowering synthesizes; this file never calls it, and the plain
// readText path uses no stream at all — a lowering that closed everything
// would emit a call this file does not make.
// kosi:want-not usage name=close
// kosi:want-not usage name=~KotlinNothing
// kosi:want-not diagnostic code=lowering-failed
//
// Positive half: `use` lowers to try/finally with the close in finally.
// kosi:want declaration name=readSize kind=function
// kosi:want declaration name=readDirect kind=function
package fixtures.useclose

import java.io.File

fun readSize(path: String): Long = File(path).inputStream().use { it.available().toLong() }

fun readDirect(path: String): String = File(path).readText()
