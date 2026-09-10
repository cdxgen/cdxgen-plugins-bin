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
    val roots: List<String>? = null,
) {
    /** Slot options derived from the CLI defaults, overriding only what the label names. */
    fun options(): AnalyzeOptions = AnalyzeOptions(
        dataflow = dataflow,
        backend = backend,
        roots = roots ?: AnalyzeOptions().roots,
    )

    companion object {
        const val SECURITY_LABEL = "security"
        const val ALL_LABEL = "all"
        const val RESOLVED_LABEL = "resolved"
        const val EXPORTED_LABEL = "exported"
    }
}

object Matrix {

    /**
     * Since P1 the matrix runs every case three ways: the two syntax slots
     * (dataflow modes, as in P0) and the resolved backend, so the resolved
     * tier's expectations are ratcheted per fixture exactly like the syntax
     * tier's. P3 adds the `exported` slot: the resolved backend rooted at the
     * public API (`--roots exported`), because reachability from `main` alone
     * yields nothing on a library — golem's lesson — and the P3 edge gates
     * need a real witness denominator on every fixture. The slot options
     * still derive from [AnalyzeOptions] defaults only, overriding what the
     * label names.
     */
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
        MatrixSlot(
            label = MatrixSlot.RESOLVED_LABEL,
            dataflow = DataflowMode.SECURITY,
            backend = Backend.RESOLVED,
        ),
        MatrixSlot(
            label = MatrixSlot.EXPORTED_LABEL,
            dataflow = DataflowMode.SECURITY,
            backend = Backend.RESOLVED,
            roots = listOf(io.cdxgen.kosi.schema.RootScope.EXPORTED.id),
        ),
    )
}
