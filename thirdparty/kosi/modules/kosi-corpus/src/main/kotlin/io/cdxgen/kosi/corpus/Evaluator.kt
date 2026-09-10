package io.cdxgen.kosi.corpus

import io.cdxgen.kosi.schema.CallGraph
import io.cdxgen.kosi.schema.DataFlowEvidence
import io.cdxgen.kosi.schema.Diagnostic
import io.cdxgen.kosi.schema.FlowSlice
import io.cdxgen.kosi.schema.ImportUsage
import io.cdxgen.kosi.schema.KosiReport
import io.cdxgen.kosi.schema.LibraryUsage
import io.cdxgen.kosi.schema.ModuleRef
import io.cdxgen.kosi.schema.Position

/**
 * Matches annotations against a report and computes the corpus metrics
 * (06-CORPUS.md §4). Outcomes:
 *
 *  - PASS   positive matched / negative absent
 *  - FAIL   positive unmatched or negative violated -> blocks the build
 *  - XFAIL  known-fail and still failing -> expected, tracked, not blocking
 *  - XPASS  known-fail but now passing -> blocks the build (two-way ratchet)
 *
 * Matching semantics: a value prefixed with `~` is a substring match on the
 * report-side string; anything else is exact.
 */
object Evaluator {

    data class Outcome(
        val annotation: Annotation,
        val status: Status,
        val detail: String,
    )

    enum class Status { PASS, FAIL, XFAIL, XPASS }

    data class Evaluation(
        val outcomes: List<Outcome>,
        val knownFailuresOpen: List<Outcome>,
        val slices: List<FlowSlice>,
        val callGraph: CallGraph?,
        val dataFlow: DataFlowEvidence?,
        /**
         * The P4 flow metrics' raw counts, computed per evaluation so the
         * bench carries fractions with BOTH counts (06-CORPUS.md §4).
         * [flowPositives]/[flowPositivesMatched] are the non-known-fail flow
         * EXPECTATIONS and how many were satisfied — structural recall over
         * flows. [flowTruePositives] counts reported slices an expectation
         * actually asked for (capped per expectation by its `count=`), which
         * against the reported slice count is precision per FLOW, never per
         * category pair.
         */
        val flowPositives: Int,
        val flowPositivesMatched: Int,
        val flowTruePositives: Int,
    ) {
        val pass: List<Outcome> get() = outcomes.filter { it.status == Status.PASS }
        val fail: List<Outcome> get() = outcomes.filter { it.status == Status.FAIL }
        val xfail: List<Outcome> get() = outcomes.filter { it.status == Status.XFAIL }
        val xpass: List<Outcome> get() = outcomes.filter { it.status == Status.XPASS }

        /**
         * Structural recall over non-known-fail positive expectations. Flow
         * expectations are excluded until a flow engine produces slices: they
         * exist only as known-fails at phase 0, so this stays honest rather
         * than reporting a fake 0.0.
         */
        fun recall(backend: String): Double {
            val positives = outcomes.filter { it.annotation.want && it.annotation.knownFailFor(backend) == null }
            if (positives.isEmpty()) return 1.0
            return positives.count { it.status == Status.PASS }.toDouble() / positives.size
        }

        /** A violated negative expectation is a false positive by definition. */
        fun violatedNegatives(): List<Outcome> =
            outcomes.filter { it.annotation.isNegative && it.status == Status.FAIL }
    }

    fun evaluate(report: KosiReport, annotations: List<Annotation>, mode: String, backend: String): Evaluation {
        val outcomes = annotations
            .filter { it.mode == null || it.mode == mode }
            .map { ann -> evaluateOne(report, ann, backend) }
        val slices = report.dataFlow?.slices ?: emptyList()
        val flowOutcomes = outcomes.filter { it.annotation.kind == Annotation.Kind.FLOW }
        val flowPositives = flowOutcomes.filter { it.annotation.want && it.annotation.knownFailFor(backend) == null }
        val claimed = HashSet<Int>()
        var truePositives = 0
        for (outcome in flowPositives) {
            var need = outcome.annotation.count ?: 1
            for ((index, slice) in slices.withIndex()) {
                if (need == 0) break
                if (index in claimed) continue
                if (sliceMatches(slice, outcome.annotation)) {
                    claimed.add(index)
                    truePositives++
                    need--
                }
            }
        }
        return Evaluation(
            outcomes = outcomes,
            knownFailuresOpen = outcomes.filter { it.status == Status.XFAIL },
            slices = slices,
            callGraph = report.callGraph,
            dataFlow = report.dataFlow,
            flowPositives = flowPositives.size,
            flowPositivesMatched = flowPositives.count { it.status == Status.PASS },
            flowTruePositives = truePositives,
        )
    }

    /** The per-slice half of [flowSatisfied]: categories plus the fn= scope. */
    fun sliceMatches(slice: FlowSlice, ann: Annotation): Boolean =
        matches(ann.source, slice.sourceCategory) && matches(ann.sink, slice.sinkCategory) &&
            (ann.fn == null || matches(ann.fn, slice.sourceFunction) || matches(ann.fn, slice.sinkFunction))

    private fun evaluateOne(report: KosiReport, ann: Annotation, backend: String): Outcome {
        val satisfied = when (ann.kind) {
            Annotation.Kind.FLOW -> flowSatisfied(report, ann)
            Annotation.Kind.EDGE -> edgeSatisfied(report, ann)
            Annotation.Kind.REACHABLE -> reachableSatisfied(report, ann)
            Annotation.Kind.USAGE -> usageSatisfied(report, ann)
            Annotation.Kind.IMPORT -> importSatisfied(report, ann)
            Annotation.Kind.DECLARATION -> declarationSatisfied(report, ann)
            Annotation.Kind.MODULE -> moduleSatisfied(report, ann)
            Annotation.Kind.DIAGNOSTIC -> diagnosticSatisfied(report, ann)
        }
        // Negative expectations (want-not) never get known-fail protection:
        // a violated negative is a false positive of the engine, and hiding
        // one behind a marker would defeat the corpus (golem's invariant).
        if (ann.isNegative) {
            return if (satisfied) {
                Outcome(ann, Status.FAIL, "negative expectation violated: ${describe(ann)} was found")
            } else {
                Outcome(ann, Status.PASS, "absent, as required")
            }
        }
        val knownFail = ann.knownFailFor(backend)
        return when {
            satisfied && knownFail != null -> Outcome(ann, Status.XPASS, describe(ann))
            satisfied -> Outcome(ann, Status.PASS, "found")
            knownFail != null -> Outcome(ann, Status.XFAIL, describe(ann))
            else -> Outcome(ann, Status.FAIL, "not found: ${describe(ann)}")
        }
    }

    private fun describe(ann: Annotation): String = when (ann.kind) {
        Annotation.Kind.FLOW -> "flow ${ann.source}->${ann.sink}"
        Annotation.Kind.EDGE -> "edge ${ann.from} -> ${ann.to}"
        Annotation.Kind.REACHABLE -> "reachable ${ann.symbol}"
        Annotation.Kind.USAGE -> "usage ${ann.name}"
        Annotation.Kind.IMPORT -> "import ${ann.name}"
        Annotation.Kind.DECLARATION -> "declaration ${ann.name}"
        Annotation.Kind.MODULE -> "module ${ann.name}"
        Annotation.Kind.DIAGNOSTIC -> "diagnostic ${ann.code}"
    }

    // ---- per-kind satisfaction -------------------------------------------

    private fun flowSatisfied(report: KosiReport, ann: Annotation): Boolean {
        val slices = report.dataFlow?.slices ?: return false
        val expected = ann.count ?: 1
        return slices.count { sliceMatches(it, ann) } >= expected
    }

    private fun edgeSatisfied(report: KosiReport, ann: Annotation): Boolean {
        val edges = report.callGraph?.edges ?: return false
        val matched = edges.filter { edge ->
            val nodes = report.callGraph?.nodes ?: return false
            val source = nodes.firstOrNull { it.id == edge.sourceId }
            val target = nodes.firstOrNull { it.id == edge.targetId }
            (matches(ann.from, source?.canonicalName ?: "") || matches(ann.from, source?.name ?: "")) &&
                (matches(ann.to, target?.canonicalName ?: "") || matches(ann.to, target?.name ?: "")) &&
                (ann.callType == null || edge.callType == ann.callType)
        }
        val expected = ann.count ?: 1
        return matched.size >= expected
    }

    private fun reachableSatisfied(report: KosiReport, ann: Annotation): Boolean {
        val nodes = report.callGraph?.nodes ?: return false
        val reachability = report.callGraph?.reachability ?: return false
        val target = nodes.filter { matches(ann.symbol, it.canonicalName) || matches(ann.symbol, it.name) }
        if (target.isEmpty()) return false
        return reachability.any { entry ->
            target.any { it.id == entry.nodeId } && entry.reached
        }
    }

    private fun usageSatisfied(report: KosiReport, ann: Annotation): Boolean {
        val usages = report.usages
        val matched = usages.filter { usage ->
            matches(ann.name, usage.name) || matches(ann.name, usage.simpleName)
        }.filter { ann.usageKind == null || it.usageKind == ann.usageKind }
        val expected = ann.count ?: 1
        return matched.size >= expected
    }

    private fun importSatisfied(report: KosiReport, ann: Annotation): Boolean {
        val imports: List<ImportUsage> = report.imports
        val matched = imports.filter { imp ->
            matches(ann.name, imp.name) && (ann.star == null || imp.star == ann.star)
        }
        val expected = ann.count ?: 1
        return matched.size >= expected
    }

    private fun declarationSatisfied(report: KosiReport, ann: Annotation): Boolean {
        val matched = report.declarations.filter { decl ->
            (matches(ann.name, decl.name) || matches(ann.name, decl.canonicalName)) &&
                (ann.declKind == null || decl.kind == ann.declKind)
        }
        val expected = ann.count ?: 1
        return matched.size >= expected
    }

    private fun moduleSatisfied(report: KosiReport, ann: Annotation): Boolean {
        val modules: List<ModuleRef> = report.modules
        val matched = modules.filter { module ->
            matches(ann.name, module.name) && (ann.platform == null || module.platform == ann.platform)
        }
        val expected = ann.count ?: 1
        return matched.size >= expected
    }

    private fun diagnosticSatisfied(report: KosiReport, ann: Annotation): Boolean {
        val diagnostics: List<Diagnostic> = report.diagnostics
        val matched = diagnostics.filter { matches(ann.code, it.code) }
        return if (ann.count != null) matched.size >= ann.count else matched.isNotEmpty()
    }

    /** `~x` is a substring match; otherwise exact. */
    fun matches(expected: String?, actual: String?): Boolean {
        if (expected == null) return true
        if (actual == null) return false
        return if (expected.startsWith("~")) {
            actual.contains(expected.removePrefix("~"))
        } else {
            expected == actual
        }
    }
}
