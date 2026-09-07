package io.cdxgen.kosi.bench

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.DataflowMode

/**
 * The bench matrix (golem's manifest.go shape). Phase 0 has one backend
 * (syntax) and the two shipping dataflow modes, so every corpus case runs in
 * both `security` and `all` on every change.
 *
 * INVARIANT (06-CORPUS.md §5): the bench must use the CLI's option defaults.
 * Every slot starts from AnalyzeOptions() — the same defaults object the CLI
 * parser produces with no flags — and overrides only what its label names.
 * The equality is asserted by a test in this module and by a test in kosi-cli;
 * if either drifts, harness numbers and CLI numbers stop being comparable.
 */
data class MatrixSlot(
    val label: String,
    val dataflow: DataflowMode,
    val backend: Backend,
) {
    /** Slot options derived from the CLI defaults, overriding only `dataflow`. */
    fun options(): AnalyzeOptions = AnalyzeOptions(dataflow = dataflow, backend = backend)

    companion object {
        const val SECURITY_LABEL = "security"
        const val ALL_LABEL = "all"
    }
}

object Matrix {

    /** Both slots run the syntax backend in phase 0. */
    fun defaultMatrix(): List<MatrixSlot> = listOf(
        MatrixSlot(
            label = MatrixSlot.SECURITY_LABEL,
            dataflow = DataflowMode.SECURITY,
            backend = Backend.SYNTAX,
        ),
        MatrixSlot(
            label = MatrixSlot.ALL_LABEL,
            dataflow = DataflowMode.ALL,
            backend = Backend.SYNTAX,
        ),
    )
}
