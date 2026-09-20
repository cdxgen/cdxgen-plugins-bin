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
    fun outOfMemoryAndStackOverflowAreDiagnosedToo() {
        assertNotNull(memoryAdvice(OutOfMemoryError("Java heap space")))
        assertNotNull(memoryAdvice(StackOverflowError()))
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
