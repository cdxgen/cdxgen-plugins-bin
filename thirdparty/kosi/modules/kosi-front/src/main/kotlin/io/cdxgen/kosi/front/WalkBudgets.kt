package io.cdxgen.kosi.front

import com.intellij.psi.PsiElement

/**
 * P29: the walk budgets that make a pathological file a NAMED diagnostic
 * instead of a dead run, and the thread the analysis runs on.
 *
 * The measured facts behind the constants (darwin-aarch64, M4 Pro, the
 * generated `s + s + ...` fixture, `java -jar kosi-all.jar`, P29 report §2):
 *
 * - On the DEFAULT thread stack, a left-deep binary chain overflows at
 *   1,250 terms and analyses at 1,200 — but the frames-per-level are not
 *   kosi's alone: every `visitBinaryExpression` descent also runs the
 *   Kotlin PSI's own `tryFlattenStringConcatenation`, so one nesting level
 *   costs roughly sixteen frames across kosi's visitor and the platform's
 *   flatten utility.
 * - `-Xss64m` analyses 5,000 terms; 2,000 die at any heap size (P28).
 *
 * [PSI_DEPTH_CAP] is therefore a POLICY bound, two orders of magnitude
 * below the big-stack failure point and far above anything human-written
 * (the deepest file in the corpus nests a few dozen levels): a file whose
 * syntax nests deeper than [PSI_DEPTH_CAP] is not walked recursively at
 * all — its declarations, usages and lowering are absent, and the report
 * carries a `psi-depth-cap` diagnostic naming the file and its measured
 * depth. A bound that trips is reported, never silent and never a crash.
 */
internal object WalkBudgets {

    /**
     * Maximum syntax nesting (PSI tree depth) the recursive walks descend
     * into. Measured headroom: at ~16 frames per level and ~100 bytes a
     * frame, a tree at this cap costs ~3 MB of stack against the 512 MB
     * analysis thread — a margin of more than 100x, verified by the
     * threshold measurement in the P29 report.
     */
    const val PSI_DEPTH_CAP = 2_000

    /**
     * The stack the analysis runs on. Stacks commit lazily: an unused
     * 512 MB reservation costs address space, not memory, and moves the
     * overflow ceiling from ~1,250 nesting levels (default stack) past
     * 100,000 (measured, P29 report §3).
     */
    const val ANALYSIS_STACK_BYTES: Long = 512L * 1024 * 1024

    /**
     * Maximum PSI depth measured ITERATIVELY (explicit stack — the measurer
     * must not be able to die of the disease it diagnoses). The result
     * bounds every recursive walk over that file: kosi's visitors, the KIR
     * lowering, and the platform's own descent (the string-concatenation
     * flattener inside the default `visitBinaryExpression`), because each
     * nesting level of any of them consumes a bounded number of frames.
     */
    fun psiMaxDepth(root: PsiElement): Int {
        var max = 0
        val stack = ArrayDeque<Pair<PsiElement, Int>>()
        stack.addLast(root to 1)
        while (stack.isNotEmpty()) {
            val (element, depth) = stack.removeLast()
            if (depth > max) max = depth
            var child = element.firstChild
            while (child != null) {
                stack.addLast(child to depth + 1)
                child = child.nextSibling
            }
        }
        return max
    }
}

/**
 * Runs [block] on a dedicated thread with [WalkBudgets.ANALYSIS_STACK_BYTES]
 * of stack, rethrowing whatever it threw on the caller's thread.
 *
 * This is the §2 fix's first half: the work is not impossible, it was just
 * done on a default-sized stack. The thread costs nothing when unused
 * (stacks commit lazily) and moves the ceiling by two orders of magnitude —
 * the same source that kills the default stack analyses on this one, and
 * everything that runs underneath the analysis (the compiler's parser, the
 * PSI walks, the KIR lowering) inherits the room without a single change.
 *
 * Output is unaffected: no report byte depends on which thread computed it,
 * which the golden gate (every fixture analysed from two locations, byte
 * compared) verifies on every run.
 */
internal fun <T> runOnAnalysisStack(block: () -> T): T {
    var result: Result<T>? = null
    val worker = Thread(
        null,
        {
            result = runCatching(block)
        },
        "kosi-analysis",
        WalkBudgets.ANALYSIS_STACK_BYTES,
    )
    worker.isDaemon = false
    worker.start()
    worker.join()
    return result!!.getOrThrow()
}
