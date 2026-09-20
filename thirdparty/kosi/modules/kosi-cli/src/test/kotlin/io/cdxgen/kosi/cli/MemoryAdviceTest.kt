package io.cdxgen.kosi.cli

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * P28 review: the message a memory-shaped death gives the operator.
 *
 * The defect this pins is not hypothetical — it is measured. dagger (1,950
 * source files) at `-Xmx8g` died with the whole of its output being
 * `kosi: io/cdxgen/kosi/flow/Summarizer$compute$4`, and the SAME run at
 * `-Xmx16g` produced a complete report. A starved JVM fails at whichever
 * class it needed next, so a `NoClassDefFoundError` naming a kosi class is a
 * heap symptom wearing the costume of a corrupt build.
 *
 * Both directions matter, and the second is the one that keeps this honest:
 * a failure that is NOT memory-shaped must get no advice at all. Advice on
 * every failure would send an operator tuning the JVM over a real defect,
 * which is worse than the silence it replaced.
 */
class MemoryAdviceTest {

    @Test
    fun aNoClassDefFoundErrorNamingAKosiClassIsDiagnosedAsTheHeap() {
        val advice = memoryAdvice(NoClassDefFoundError("io/cdxgen/kosi/flow/Summarizer\$compute\$4"))
        assertNotNull(advice, "the exact shape dagger died in at -Xmx8g went undiagnosed")
        assertTrue("-Xmx" in advice, "advice that does not name the flag cannot be acted on: $advice")
        assertTrue("memory exhaustion" in advice, "the advice must say what it thinks happened: $advice")
    }

    @Test
    fun outOfMemoryIsDiagnosedAsTheHeap() {
        val advice = memoryAdvice(OutOfMemoryError("Java heap space"))
        assertNotNull(advice)
        assertTrue("-Xmx" in advice, advice)
    }

    /**
     * A stack overflow is NOT a heap problem, and the first cut of this advice
     * said `-Xmx` for it — sending the operator to the wrong knob, confidently.
     * Measured on a generated fixture: a single expression of 2,000 `+` terms
     * (one 8 KB file) kills the run at ANY heap size, while 1,000 terms is
     * fine. So the advice must name the stack and the source shape, and must
     * NOT recommend the heap.
     */
    @Test
    fun aStackOverflowIsDiagnosedAsTheStackAndNeverTheHeap() {
        val advice = memoryAdvice(StackOverflowError())
        assertNotNull(advice)
        assertTrue("-Xss" in advice, "stack advice must name the stack flag: $advice")
        assertTrue("nested" in advice, "the operator needs to know it is the source's shape: $advice")
        // -Xmx may appear, but only to rule it OUT. What must never happen is
        // the heap being offered as the remedy, which is what the first cut
        // did. The retry line is the remedy, so that is the line checked.
        val remedy = advice.lines().single { "retry with" in it }
        assertTrue("-Xss" in remedy, "the remedy must be the stack flag: $remedy")
        assertTrue("-Xmx" !in remedy, "a stack overflow must never be remedied with the heap: $remedy")
    }

    @Test
    fun aMemoryShapedCauseIsFoundThroughTheWrapper() {
        val wrapped = RuntimeException("analysis failed", NoClassDefFoundError("kotlin/ExceptionsKt"))
        assertNotNull(
            memoryAdvice(wrapped),
            "engines wrap; advice that only reads the outermost throwable sees none of the real ones",
        )
    }

    @Test
    fun anOrdinaryFailureGetsNoAdvice() {
        assertNull(
            memoryAdvice(IllegalArgumentException("unknown classpath strategy 'gradle'")),
            "advice on a non-memory failure sends the operator tuning the JVM over a real defect",
        )
        assertNull(memoryAdvice(java.io.IOException("no such file")))
    }
}
