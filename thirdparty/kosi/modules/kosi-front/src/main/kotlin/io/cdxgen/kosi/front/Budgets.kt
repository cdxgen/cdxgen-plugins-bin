package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.DiagnosticCodes
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean

/**
 * P10: the analysis budgets — `--max-analysis-seconds` and `--max-rss-mb` —
 * and the degradation discipline they enforce. The motivating failure is
 * golem's `guardAlgorithm`: a call-graph crash threw away an
 * already-computed evidence report, and a corpus-only gate could not see
 * the repo it lost. Here a budget that trips is a NAMED diagnostic plus a
 * still-valid partial report; it is never a panic and never a silent zero.
 *
 * Off by default (both options null): budgets are a degradation mode, not a
 * feature — and a tripped budget makes a run honestly non-reproducible, so
 * the default must keep the determinism contract intact.
 */
internal class Budgets private constructor(
    deadlineNanos: Long?,
    private val rssTripped: AtomicBoolean,
    private val sampler: Thread?,
) {
    private val startNanos = System.nanoTime()
    private val deadline = deadlineNanos
    private val trippedCode = java.util.concurrent.atomic.AtomicReference<String?>(null)

    /**
     * The engine calls this between analysis steps. Returns a diagnostic
     * code when the run must degrade now; the caller ships what it has.
     */
    fun shouldStop(): String? {
        val code = when {
            deadline != null && System.nanoTime() - startNanos > deadline -> DiagnosticCodes.ANALYSIS_TIME_BUDGET
            rssTripped.get() -> DiagnosticCodes.RSS_BUDGET
            else -> null
        }
        if (code != null) trippedCode.compareAndSet(null, code)
        return code
    }

    /** The first trip this run recorded, when it degraded at all. */
    fun tripCode(): String? = trippedCode.get()

    fun close() {
        sampler?.interrupt()
    }

    companion object {

        fun of(options: AnalyzeOptions): Budgets {
            val deadlineNanos = options.maxAnalysisSeconds?.takeIf { it >= 0 }?.let { it * 1_000_000_000L }
            val maxRssBytes = options.maxRssMb?.takeIf { it > 0 }?.let { it * 1024L * 1024L }
            if (maxRssBytes == null) {
                return Budgets(deadlineNanos, AtomicBoolean(false), null)
            }
            val flag = AtomicBoolean(false)
            // Synchronous first sample: an ALREADY-exceeded budget trips
            // deterministically at construction, before any thread races
            // the analysis (an absurd budget like --max-rss-mb 1 must
            // degrade the run, not sometimes miss it).
            if (currentRssBytes() > maxRssBytes) flag.set(true)
            val thread = Thread {
                while (!flag.get() && !Thread.currentThread().isInterrupted) {
                    if (currentRssBytes() > maxRssBytes) {
                        flag.set(true)
                    }
                    try {
                        Thread.sleep(100)
                    } catch (_: InterruptedException) {
                        return@Thread
                    }
                }
            }
            thread.isDaemon = true
            thread.name = "kosi-rss-budget"
            thread.start()
            return Budgets(deadlineNanos, flag, thread)
        }
    }
}

/**
 * The JVM's CURRENT resident set (not the high-water mark the bench's
 * [PeakRss] reports): a budget is about right now, and VmHWM never comes
 * back down. linux reads /proc; darwin shells to ps; everything else falls
 * to the JVM heap+nonheap used size as a documented lower bound.
 */
private fun currentRssBytes(): Long {
    try {
        val proc = Path.of("/proc/self/status")
        if (Files.exists(proc)) {
            for (line in Files.readAllLines(proc)) {
                if (line.startsWith("VmRSS:")) {
                    val kb = line.substringAfter("VmRSS:").trim().substringBefore(" ").toLongOrNull()
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
