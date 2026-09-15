package io.cdxgen.kosi.graph

import io.cdxgen.kosi.schema.Diagnostic
import io.cdxgen.kosi.schema.DiagnosticCodes
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.RootScope
import io.cdxgen.kosi.schema.Severity

/**
 * Root selection (02-ARCHITECTURE.md §5). A root is always a WORKSPACE node:
 * `main` is the top-level `main` function, `exported` is the public API
 * (local, non-synthetic, visibility public or protected — the two
 * visibilities a library consumer can name), `handlers` is framework
 * registration (RESOLVED annotation FQNs matched in pattern notation, never
 * short-name matched), `tests` and `android` are the source-tree and
 * component-subtype conventions, `symbol:` a regex over canonical names.
 */
internal object Roots {

    /**
     * Framework registration patterns (suffix segment match on RESOLVED
     * annotation FQNs). P3 ships the annotation-driven set; DSL-routed and
     * manifest-declared handlers are P7's endpoint work and deliberately not
     * approximated here.
     */
    private val FRAMEWORK_ANNOTATIONS = listOf(
        // Spring family
        "org.springframework.web.bind.annotation.RestController",
        "org.springframework.web.bind.annotation.Controller",
        "org.springframework.web.bind.annotation.RequestMapping",
        "org.springframework.web.bind.annotation.GetMapping",
        "org.springframework.web.bind.annotation.PostMapping",
        "org.springframework.web.bind.annotation.PutMapping",
        "org.springframework.web.bind.annotation.DeleteMapping",
        "org.springframework.web.bind.annotation.PatchMapping",
        "org.springframework.messaging.handler.annotation.MessageMapping",
        "org.springframework.kafka.annotation.KafkaListener",
        "org.springframework.scheduling.annotation.Scheduled",
        "org.springframework.context.event.EventListener",
        // JAX-RS / Jakarta REST
        "jakarta.ws.rs.Path",
        "jakarta.ws.rs.GET",
        "jakarta.ws.rs.POST",
        "jakarta.ws.rs.PUT",
        "jakarta.ws.rs.DELETE",
        "javax.ws.rs.Path",
        "javax.ws.rs.GET",
        "javax.ws.rs.POST",
        // Micronaut
        "io.micronaut.http.annotation.Controller",
        "io.micronaut.http.annotation.Get",
        "io.micronaut.http.annotation.Post",
    )

    /** Android application components, matched against RESOLVED supertype FQNs. */
    private val ANDROID_COMPONENT_SUPERTYPES = listOf(
        "android.app.Activity",
        "android.app.Application",
        "android.app.Service",
        "android.content.BroadcastReceiver",
        "android.content.ContentProvider",
    )

    /** The file-path conventions that mark test sources. */
    private val TEST_PATH_MARKERS = listOf(
        "/src/test/",
        "/src/androidTest/",
        "/src/commonTest/",
        "/src/jvmTest/",
        "/src/iosTest/",
        "\\src\\test\\",
    )

    fun isFrameworkAnnotated(annotations: List<String>): Boolean =
        annotations.any { a -> FRAMEWORK_ANNOTATIONS.any { p -> Classification.suffixMatches(p, a) } }

    fun isAndroidComponent(supertypes: List<String>): Boolean =
        supertypes.any { s -> ANDROID_COMPONENT_SUPERTYPES.any { p -> Classification.suffixMatches(p, s) } }

    fun isTestSource(filePath: String): Boolean = TEST_PATH_MARKERS.any { filePath.contains(it) }

    /**
     * Selects the root node keys per requested scope. A scope that matches
     * nothing is REPORTED (`callgraph-root-not-found`) — a declared root that
     * found nothing is a fact about the run, never silence.
     */
    fun select(
        requested: List<Pair<RootScope, String?>>,
        nodes: List<GraphNodes.GNode>,
    ): Pair<Map<RootScope, Set<String>>, List<Diagnostic>> {
        val out = linkedMapOf<RootScope, MutableSet<String>>()
        val diagnostics = mutableListOf<Diagnostic>()
        for ((scope, arg) in requested) {
            val matched = sortedSetOf<String>()
            for (node in nodes) {
                val hit = when (scope) {
                    RootScope.MAIN -> node.local && node.ownerless && node.name == "main"
                    RootScope.EXPORTED -> node.local && !node.synthetic &&
                        (node.visibility == "public" || node.visibility == "protected") &&
                        // A public member of a non-public class is not API;
                        // a top-level function has no owner to check.
                        (node.ownerless ||
                            node.ownerVisibility == null ||
                            node.ownerVisibility == "unknown" ||
                            node.ownerVisibility == "public" ||
                            node.ownerVisibility == "protected")

                    RootScope.HANDLERS -> node.local &&
                        (isFrameworkAnnotated(node.annotations) || isFrameworkAnnotated(node.ownerAnnotations))

                    RootScope.TESTS -> node.local && isTestSource(node.filePath)
                    RootScope.ANDROID -> node.local && isAndroidComponent(node.supertypes)
                    // Never matched directly: `all` is the UNION of the
                    // concrete scopes, filled in below. Matching every node
                    // here would root the stdlib and every dependency, making
                    // reachability say "everything runs" — and every
                    // connectivity denominator trivially satisfiable.
                    RootScope.ALL -> false
                    RootScope.SYMBOL -> node.local && arg?.let { regexMatches(it, node.canonicalName) } == true
                }
                if (hit) matched.add(node.key)
            }
            if (scope == RootScope.ALL) {
                for (sub in listOf(RootScope.MAIN, RootScope.EXPORTED, RootScope.HANDLERS, RootScope.TESTS, RootScope.ANDROID)) {
                    matched.addAll(select(listOf(sub to null), nodes).first[sub].orEmpty())
                }
            }
            if (matched.isEmpty()) {
                diagnostics.add(
                    Diagnostic(
                        code = DiagnosticCodes.CALLGRAPH_ROOT_NOT_FOUND,
                        severity = Severity.WARNING,
                        message = "root scope ${scope.id}${arg?.let { ":$it" } ?: ""} matched no function; " +
                            "the graph's reachability starts nowhere for it",
                        position = Position(".", 1, 1),
                        count = 1,
                    ),
                )
            }
            out.getOrPut(scope) { mutableSetOf() }.addAll(matched)
        }
        return out to diagnostics
    }

    private fun regexMatches(pattern: String, canonical: String): Boolean = try {
        Regex(pattern).containsMatchIn(canonical)
    } catch (_: Exception) {
        false
    }
}
