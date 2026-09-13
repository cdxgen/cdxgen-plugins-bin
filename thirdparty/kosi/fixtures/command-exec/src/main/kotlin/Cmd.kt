// Negative half first: exact near-misses of symbols this file *does*
// contain, so none of them can pass vacuously.
//   - `newScheduledThreadPool`: the file calls `newFixedThreadPool` on the
//     same receiver, so a renderer that dropped the member name would trip;
//   - `ProcessBuilder` as an `operator`: present as a `call`;
//   - `runCommand` as a `property`.
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
// P7: the flow is parameter-shaped again - the handler's request parameter
// is the untrusted input, seeded by --endpoint-sources in the endpoint
// slot, so the readLine() P4 patched in is gone. The expectation therefore
// lives on the endpoint slot (the others seed no endpoint sources, which is
// exactly the flag's contract).
// kosi:want endpoint framework=spring-mvc path=/run fn=~CmdRunner.runCommand mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec mode=endpoint
package fixtures.exec

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.io.BufferedReader
import java.io.InputStreamReader

@RestController
class CmdRunner {
    @GetMapping("/run")
    fun runCommand(@RequestParam command: String): String {
        val parts = command.trim().split("\\s+".toRegex())
        val process = ProcessBuilder(*parts.toTypedArray())
            .redirectErrorStream(true)
            .start()
        return BufferedReader(InputStreamReader(process.inputStream)).readText()
    }
}

fun cleanNeighbour(): java.util.concurrent.ExecutorService =
    java.util.concurrent.Executors.newFixedThreadPool(2)
