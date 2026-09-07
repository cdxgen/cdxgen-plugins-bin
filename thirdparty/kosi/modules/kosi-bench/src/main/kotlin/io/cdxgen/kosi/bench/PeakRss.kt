package io.cdxgen.kosi.bench

import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.Path

/**
 * Peak RSS readers (golem's rss_*.go equivalent). linux reads VmHWM from
 * /proc; darwin shells to ps. Everything else reports the JVM heap+nonheap
 * used size as a documented lower bound. The value lives in bench output
 * only — never inside the deterministic analyze report.
 */
object PeakRss {

    fun bytes(): Long {
        try {
            val proc = Path.of("/proc/self/status")
            if (Files.exists(proc)) {
                for (line in Files.readAllLines(proc)) {
                    if (line.startsWith("VmHWM:")) {
                        val kb = line.substringAfter("VmHWM:").trim().substringBefore(" ").toLongOrNull()
                        if (kb != null) return kb * 1024
                    }
                }
            }
            val os = System.getProperty("os.name")?.lowercase() ?: ""
            if (os.contains("mac") || os.contains("darwin")) {
                val pid = ProcessHandle.current().pid()
                val p = ProcessBuilder("ps", "-o", "rss=", "-p", pid.toString())
                    .redirectErrorStream(true)
                    .start()
                val out = p.inputStream.bufferedReader().readText().trim()
                p.waitFor()
                val kb = out.lines().firstOrNull()?.toLongOrNull()
                if (kb != null) return kb * 1024
            }
        } catch (_: Exception) {
            // fall through to the JVM lower bound
        }
        val heap = ManagementFactory.getMemoryMXBean().heapMemoryUsage
        val nonHeap = ManagementFactory.getMemoryMXBean().nonHeapMemoryUsage
        return heap.used + nonHeap.used
    }
}
