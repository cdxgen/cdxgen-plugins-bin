// Negative half first: exact near-misses of symbols this file *does*
// contain, so none of them can pass vacuously.
//   - `newScheduledThreadPool`: the file calls `newFixedThreadPool` on the
//     same receiver, so a renderer that dropped the member name would trip;
//   - `ProcessBuilder` as an `operator`: present as a `call`;
//   - `runCommand` as a `property`: present as a `function`.
// kosi:want-not usage name=~Executors.newScheduledThreadPool
// kosi:want-not usage name=ProcessBuilder kind=operator
// kosi:want-not declaration name=runCommand kind=property
// kosi:want-not diagnostic code=parse-error
//
// Positive half.
// kosi:want usage name=ProcessBuilder
// kosi:want usage name=~.redirectErrorStream
// kosi:want usage name=~.start
// kosi:want declaration name=runCommand kind=function
//
// The flow reads untrusted input through the shipped pack source
// (kotlin.io.readLine) and concatenates it into the ProcessBuilder command
// list. Real at the resolved tier since P4; the syntax tier still has no
// flow engine (docs/KOSI.md defect 1), so the marker is scoped there — at
// the resolved slots the expectation is a live ratchet, not a known-fail.
// kosi:want flow source=untrusted-input sink=process-exec known-fail=syntax:1
package fixtures.exec

import java.io.BufferedReader
import java.io.InputStreamReader

fun runCommand(): String {
    val input = readLine() ?: return ""
    val parts = input.trim().split("\\s+".toRegex())
    val process = ProcessBuilder(*parts.toTypedArray())
        .redirectErrorStream(true)
        .start()
    return BufferedReader(InputStreamReader(process.inputStream)).readText()
}

fun cleanNeighbour(): java.util.concurrent.ExecutorService =
    java.util.concurrent.Executors.newFixedThreadPool(2)
