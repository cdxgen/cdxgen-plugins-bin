// A vararg parameter's written arguments occupy adjacent positions, so a
// sink or passthrough watches every position from the vararg on:
// `ProcessBuilder("sh", "-c", cmd)` carries `cmd` at 2, and a format's
// second value sits past its first.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~fixedCommand mode=endpoint
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=process-exec fn=~varargCommand mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~commandMethod mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~formattedJava mode=endpoint
// kosi:want flow source=untrusted-input sink=process-exec fn=~formattedKotlin mode=endpoint
package fixtures.pbv

fun varargCommand(): Process {
    val cmd = readLine() ?: "id"
    return ProcessBuilder("sh", "-c", cmd).start()
}

fun commandMethod(): Process {
    val cmd = readLine() ?: "id"
    val builder = ProcessBuilder()
    builder.command("sh", "-c", cmd)
    return builder.start()
}

fun formattedJava(): Process {
    val value = readLine() ?: "x"
    return Runtime.getRuntime().exec(java.lang.String.format("echo %s %s", "a", value))
}

fun formattedKotlin(): Process {
    val value = readLine() ?: "x"
    return Runtime.getRuntime().exec("echo %s %s".format("a", value))
}

fun fixedCommand(): Process {
    val cmd = readLine() ?: "id"
    println(cmd)
    return ProcessBuilder("sh", "-c", "id").start()
}
