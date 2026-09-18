package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnalyzeOptions
import io.cdxgen.kosi.schema.Backend
import io.cdxgen.kosi.schema.CallGraphMode
import io.cdxgen.kosi.schema.CryptoFlow
import io.cdxgen.kosi.schema.DataflowMode
import io.cdxgen.kosi.schema.KosiReport
import io.cdxgen.kosi.schema.degradations
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * P23 §0: the option pairings, walked.
 *
 * The phase rule, written against R137 and R138: **a gate covers a
 * CONFIGURATION and a TYPE, not a code path.** R137 — a `reachableSlices`
 * count that claimed every slice reachable when no reachability had been
 * computed — shipped through 522 golden pairs, a 600-row corpusQuick, a full
 * corpus and a two-environment proof, because not one of them runs
 * `--dataflow reachable`, and the defect lived in that mode's pairing with
 * `--callgraph none`. The corpus picks FIXTURES and SLOTS; nothing picked
 * option COMBINATIONS.
 *
 * This walks the accepted product of the option enums over one tiny project
 * and asserts each cell against a declared contract. Two properties make it
 * a gate rather than a sample:
 *
 *  1. it is EXHAUSTIVE over the enums — a new `DataflowMode` or
 *     `CallGraphMode` value with no declared contract fails the test, so a
 *     value cannot be both accepted and unexamined;
 *  2. the diagnostics it expects come from `AnalyzeOptions.degradations()`,
 *     the same predicate the CLI refuses from, so a run's report and the
 *     CLI's refusals cannot describe different sets.
 *
 * It costs one small project per cell and no corpus tier, which is the point:
 * the cheapest gate in the repo covers the axis the expensive ones do not.
 */
class OptionMatrixTest {

    /**
     * One source file with a taint flow AND a crypto flow, so a cell's
     * contract can distinguish the modes. A `private` function keeps the
     * flows out of the `main` roots' reach, which is what gives the
     * `reachable` cells something to intersect away.
     */
    private val sources = mapOf(
        "src/main/kotlin/App.kt" to """
            package t

            import javax.crypto.spec.SecretKeySpec

            public fun leak() {
                val raw = readLine()!!
                ProcessBuilder(raw).start()
            }

            public fun key() {
                // Material by NAME births a hardcoded-secret fact at the
                // store (the pack's literalSources rule); SecretKeySpec is a
                // crypto-asset sink, so this is a crypto flow and the one
                // above is not.
                val signingKey = "0123456789abcdef0123456789abcdef"
                SecretKeySpec(signingKey.toByteArray(), "HmacSHA256")
            }
        """.trimIndent(),
    )

    private fun project(): Path {
        val root = Files.createTempDirectory("kosi-option-matrix")
        for ((path, text) in sources) {
            val file = root.resolve(path)
            Files.createDirectories(file.parent)
            file.writeText(text)
        }
        return root
    }

    /**
     * The axes that change what a report CONTAINS. `COMPILE` is covered by
     * the exhaustiveness assertion below rather than by a run of its own: it
     * executes the resolved tier verbatim and stamps `compile-backend-gap`,
     * which `ResolvedBackendTest` already pins — running it here would be a
     * second answer to a question one test already answers (P22's rule).
     *
     * Only `NONE` and one non-`NONE` call-graph mode are run: the other five
     * choose a dispatch ALGORITHM, and the algorithm cannot change whether a
     * graph exists. `CallGraphPipelineTest` and `DispatchModeTest` cover what
     * they do change. The exhaustiveness assertion still names them.
     */
    private val backends = listOf(Backend.SYNTAX, Backend.RESOLVED)
    private val callgraphs = listOf(CallGraphMode.NONE, CallGraphMode.AUTO)
    private val dataflows = DataflowMode.entries.toList()

    private fun cells(): List<AnalyzeOptions> = buildList {
        for (backend in backends) {
            for (dataflow in dataflows) {
                for (callgraph in callgraphs) {
                    for (deps in listOf(false, true)) {
                        // The dependency tier needs a resolved classpath; on
                        // the syntax tier it cannot run at all and the cell
                        // would only re-assert the backend's own contract.
                        if (deps && backend == Backend.SYNTAX) continue
                        add(
                            AnalyzeOptions(
                                backend = backend,
                                dataflow = dataflow,
                                callgraph = callgraph,
                                deps = deps,
                            ),
                        )
                    }
                }
            }
        }
    }

    private fun label(o: AnalyzeOptions) =
        "backend=${o.backend.id} dataflow=${o.dataflow.id} callgraph=${o.callgraph.id} deps=${o.deps}"

    @Test
    fun everyAcceptedOptionPairingPublishesWhatItsContractSays() {
        val root = project()
        val reports = HashMap<String, KosiReport>()
        for (options in cells()) {
            val at = label(options)
            val report = Analyzer.analyze(root, options, commit = "test")
            reports[at] = report

            val wantsGraph = options.callgraph != CallGraphMode.NONE
            val wantsFlow = options.dataflow != DataflowMode.NONE
            val resolves = options.backend != Backend.SYNTAX

            assertEquals(
                resolves && wantsGraph,
                report.callGraph != null,
                "$at: a call graph exists exactly when a resolving tier was asked for one",
            )
            assertEquals(
                resolves && wantsFlow,
                report.dataFlow != null,
                "$at: dataFlow exists exactly when a resolving tier was asked for taint",
            )

            // The degradations are the CONTRACT, not an afterthought: every
            // pairing that cannot deliver what it names says so on the
            // report, with the code the CLI would refuse or warn with.
            val expected = options.degradations().map { it.code }.toSortedSet()
            val actual = report.diagnostics.map { it.code }.toSortedSet()
            assertTrue(
                actual.containsAll(expected),
                "$at: the report must name every degradation this pairing has. missing " +
                    "${expected - actual}; the report carries $actual",
            )

            // R137, as a contract rather than a comment: a reachable count is
            // only ever non-zero when reachability was actually computed.
            val reachable = report.stats.reachableSliceCount
            if (!(options.dataflow == DataflowMode.REACHABLE && wantsGraph && resolves)) {
                assertEquals(
                    0,
                    reachable,
                    "$at: reachability was not computed here, so the only honest count is 0 " +
                        "(0 means NOT MEASURED, never 'no reachable slices')",
                )
            }
        }

        // ---- the cross-cell contracts: what the MODES mean --------------
        fun slices(dataflow: DataflowMode) = reports
            .getValue("backend=resolved dataflow=${dataflow.id} callgraph=auto deps=false")
            .dataFlow!!.slices

        val security = slices(DataflowMode.SECURITY)
        assertTrue(security.isNotEmpty(), "the matrix project must publish slices, or every cell below is vacuous (R53)")

        // `all` is a DECLARED ALIAS of `security`: the shipped pack has no
        // category `security` leaves out, so there is nothing for `all` to
        // add. Stated here rather than left for a reader to discover — and
        // if a future mode does add something, this is the line that fails.
        assertEquals(
            security.map { it.flowKey }.sorted(),
            slices(DataflowMode.ALL).map { it.flowKey }.sorted(),
            "--dataflow all is documented as an alias of security; if that stopped being true, " +
                "the vocabulary changed and the docs and this line must change with it",
        )

        // R139: `crypto` is a FILTER, and before P23 it filtered nothing —
        // a run that asked for crypto flows was handed log-injection
        // findings under `"mode": "crypto"`.
        val crypto = slices(DataflowMode.CRYPTO)
        assertTrue(
            crypto.all { CryptoFlow.isCryptoFlow(it) },
            "every slice --dataflow crypto publishes must BE a crypto flow: ${crypto.filterNot { CryptoFlow.isCryptoFlow(it) }.map { it.ruleId }}",
        )
        assertTrue(
            crypto.size < security.size,
            "the matrix project carries both a crypto flow and a non-crypto one, so the crypto mode " +
                "must publish strictly fewer slices than security — equal counts mean the filter is " +
                "back to doing nothing (R139)",
        )
        assertTrue(
            security.any { CryptoFlow.isCryptoFlow(it) } && security.any { !CryptoFlow.isCryptoFlow(it) },
            "security publishes both kinds, which is what makes the subset above a real subset",
        )

        // A mode that NARROWS the evidence must narrow the whole document.
        // Dropping slices and leaving `nodes[]`, `edges[]` and the derived
        // counters behind publishes a contradiction — traces that are not in
        // `slices[]`, and counters still measuring the population before the
        // filter. Asserted here for the two modes that narrow (`crypto`
        // filters, `reachable` intersects), because they are the only two,
        // and `DataFlowEvidence.restrictTo` is the one place that does it.
        for (mode in listOf(DataflowMode.CRYPTO, DataflowMode.REACHABLE)) {
            val flow = reports
                .getValue("backend=resolved dataflow=${mode.id} callgraph=auto deps=false")
                .dataFlow!!
            val sliceNodeIds = flow.slices.flatMap { it.nodeIds }.toSet()
            val sliceEdgeIds = flow.slices.flatMap { it.edgeIds }.toSet()
            assertEquals(
                emptyList(),
                flow.nodes.map { it.id }.filterNot { it in sliceNodeIds },
                "${mode.id}: every published node belongs to a published slice",
            )
            assertEquals(
                emptyList(),
                flow.edges.map { it.id }.filterNot { it in sliceEdgeIds },
                "${mode.id}: every published edge belongs to a published slice",
            )
            assertEquals(
                flow.slices.size,
                flow.stats.sliceCount,
                "${mode.id}: the counters measure the slices that survived, not the ones that did not",
            )
            assertEquals(
                flow.slices.count { it.crossesDependency },
                flow.stats.crossDependencySlices,
                "${mode.id}: derived counters are recomputed after the narrowing",
            )
            assertEquals(
                0,
                flow.stats.integrityViolations,
                "${mode.id}: a narrowed document is still internally consistent",
            )
        }
    }

    /**
     * R63 for an option vocabulary: a value that no cell of the matrix
     * declares a contract for is a value nothing examines. Adding a
     * `DataflowMode` or `CallGraphMode` without deciding what it publishes
     * fails HERE, at the cost of one line, instead of shipping the way
     * `reachable` did.
     */
    @Test
    fun theMatrixIsExhaustiveOverTheOptionVocabularies() {
        assertEquals(
            DataflowMode.entries.toSet(),
            dataflows.toSet(),
            "every dataflow mode is run by the matrix",
        )
        // Backends: SYNTAX and RESOLVED are run; COMPILE runs the resolved
        // tier verbatim and is pinned by ResolvedBackendTest.
        assertEquals(
            Backend.entries.toSet(),
            (backends + Backend.COMPILE).toSet(),
            "every backend is either run by the matrix or explicitly delegated",
        )
        // Call-graph modes: NONE and AUTO are run for PRESENCE; the other
        // five choose a dispatch algorithm, which cannot change whether a
        // graph exists, and are pinned by the dispatch tests.
        val algorithmic = setOf(
            CallGraphMode.STATIC,
            CallGraphMode.CHA,
            CallGraphMode.SEALED,
            CallGraphMode.RTA,
            CallGraphMode.VTA,
        )
        assertEquals(
            CallGraphMode.entries.toSet(),
            callgraphs.toSet() + algorithmic,
            "every call-graph mode is either run by the matrix or declared algorithm-only",
        )
    }
}
