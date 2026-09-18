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
    val endpointSources: Boolean = false,
    val deps: Boolean = false,
) {
    /** Slot options derived from the CLI defaults, overriding only what the label names. */
    fun options(): AnalyzeOptions = AnalyzeOptions(
        dataflow = dataflow,
        backend = backend,
        roots = roots ?: AnalyzeOptions().roots,
        endpointSources = endpointSources,
        deps = deps,
    )

    companion object {
        const val SECURITY_LABEL = "security"
        const val RESOLVED_LABEL = "resolved"
        const val EXPORTED_LABEL = "exported"
        const val ENDPOINT_LABEL = "endpoint"
        const val DEPS_LABEL = "deps"
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
        // P23 §0 DELETED the `all` slot. It ran the SYNTAX backend, which
        // lowers no IR and therefore runs no dataflow at all, so the only
        // thing `--dataflow all` could change about its report was the echo
        // of the flag itself: measured across all 87 fixtures, the `all` and
        // `security` goldens differed in exactly one section — `options` —
        // and were byte-identical in `dataFlow`, `stats`, `crypto`,
        // `callGraph`, `services`, `apiEndpoints` and every other section
        // carrying analysis output. No fixture carried a single `mode=all`
        // annotation either, so the slot evaluated nothing. 87 golden pairs,
        // a sixth of every corpus run, every golden check and BOTH legs of
        // the two-environment proof, pinning the fact that the CLI echoes
        // its own flag (R53: a slot nobody's analysis differs on proves
        // nothing). `DataflowMode.ALL` is covered where the claim actually
        // lives: `OptionMatrixTest` asserts it is a declared alias of
        // `security`, in one line, on the RESOLVED backend where the modes
        // could differ if they ever did.
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
        // P7: endpoint-rooted taint. The resolved backend with handler
        // parameters as sources, so slices carry the endpoint they enter
        // through and the endpoint-rooted-slices gate has a real population.
        MatrixSlot(
            label = MatrixSlot.ENDPOINT_LABEL,
            dataflow = DataflowMode.SECURITY,
            backend = Backend.RESOLVED,
            endpointSources = true,
        ),
        // P9: the dependency tier. The resolved backend plus --deps: classpath
        // jars lower to the SAME KIR and summarise with origin=bytecode, so
        // the gate reads cross-dependency slices and their producer per repo.
        // Endpoint parameters seed entry-point facts (P7): at repo scale the
        // security-relevant sources ARE the handlers, and without a seed no
        // cross-dependency flow can exist to measure. Time and RSS ride the
        // same row as the `resolved` slot's, which is what makes the
        // with/without---deps delta a same-machine measurement.
        MatrixSlot(
            label = MatrixSlot.DEPS_LABEL,
            dataflow = DataflowMode.SECURITY_DEPS,
            backend = Backend.RESOLVED,
            deps = true,
            endpointSources = true,
        ),
    )
}
