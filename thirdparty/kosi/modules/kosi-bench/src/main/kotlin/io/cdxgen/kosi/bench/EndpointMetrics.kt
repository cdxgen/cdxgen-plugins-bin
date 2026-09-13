package io.cdxgen.kosi.bench

import io.cdxgen.kosi.corpus.Annotation
import io.cdxgen.kosi.corpus.Evaluator
import io.cdxgen.kosi.schema.CryptoAsset
import io.cdxgen.kosi.schema.FlowSlice
import io.cdxgen.kosi.schema.KosiReport

/**
 * P7/P8 report-derived metrics the gates read. Everything here is computed
 * from the REPORT (the artifact production publishes) with denominators
 * carried alongside numerators — an unbroken-down fraction is not a result.
 */
object EndpointMetrics {

    /** Endpoints whose handler symbol resolves to a call-graph node that EXISTS. */
    fun resolvedHandlers(report: KosiReport): Int? {
        val endpoints = report.apiEndpoints
        if (endpoints.isEmpty()) return null
        val graph = report.callGraph ?: return 0
        val canonicalNames = graph.nodes.map { it.canonicalName }.toSet()
        return endpoints.count { it.handlerSymbol.isNotEmpty() && it.handlerSymbol in canonicalNames }
    }

    /** Slices whose SOURCE function is an endpoint handler (endpoint-rooted). */
    fun rootedSlices(report: KosiReport): Int? {
        val endpoints = report.apiEndpoints
        if (endpoints.isEmpty()) return null
        val handlers = endpoints.map { it.handlerSymbol }.toSet()
        return report.dataFlow?.slices?.count { it.sourceFunction in handlers }
    }

    /** Per-framework endpoint EXPECTATIONS [matched, total], from the evaluation. */
    fun recallByFramework(evaluation: Evaluator.Evaluation): Map<String, List<Int>> {
        val outcomes = evaluation.outcomes.filter {
            it.annotation.kind == Annotation.Kind.ENDPOINT &&
                it.annotation.want &&
                it.annotation.framework != null
        }
        if (outcomes.isEmpty()) return emptyMap()
        return outcomes
            .groupBy { it.annotation.framework!! }
            .mapValues { (_, frameworkOutcomes) ->
                listOf(frameworkOutcomes.count { it.status == Evaluator.Status.PASS }, frameworkOutcomes.size)
            }
    }
}

/** P8 crypto metric helpers: mapping coverage keys and crypto-flow classification. */
object CryptoMetrics {

    /**
     * The mapping rows one asset exercises. A transform asset carries BOTH
     * the full-transform row and its leading algorithm row, so a fixture
     * using `AES/GCM/NoPadding` exercises `transform:AES/GCM/NoPadding` and
     * `algorithm:AES` at once; a curve asset names its `curve:` row.
     */
    fun mappingKeys(asset: CryptoAsset): List<String> {
        val keys = mutableListOf<String>()
        val segments = asset.name.split('/')
        keys.add("algorithm:${segments.first()}")
        if (segments.size > 1) keys.add("transform:${asset.name}")
        asset.curve?.let { keys.add("curve:$it") }
        return keys
    }

    /**
     * A crypto-flow slice: key/secret material (the `hardcoded-secret`
     * literal sources) reaching a crypto API (`crypto-asset`) or a TLS
     * misconfiguration (`insecure-tls`). Counted from the slices, never
     * invented.
     */
    fun isCryptoFlow(slice: FlowSlice): Boolean =
        slice.sourceCategory == "hardcoded-secret" &&
            (slice.sinkCategory == "crypto-asset" || slice.sinkCategory == "insecure-tls")

    /**
     * Per-form Cipher mode/padding extraction, from the report's assets:
     * form -> [extracted, total]. An asset counts as extracted when the
     * mapping table gave it a mode or a padding; an unresolved asset never
     * counts as extracted, which is the point.
     */
    fun modePaddingByForm(report: KosiReport): Map<String, List<Int>> {
        val ciphers = report.crypto.assets.filter { it.operation == "Cipher" }
        if (ciphers.isEmpty()) return emptyMap()
        return ciphers
            .groupBy { it.form ?: "unresolved" }
            .mapValues { (_, formAssets) ->
                listOf(
                    formAssets.count { it.mode != null || it.padding != null },
                    formAssets.size,
                )
            }
    }
}
