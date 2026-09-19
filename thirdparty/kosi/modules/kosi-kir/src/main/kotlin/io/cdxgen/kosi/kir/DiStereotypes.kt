package io.cdxgen.kosi.kir

/**
 * P25 §2: the annotations that mean **the container constructs this class**.
 *
 * In a Spring, Micronaut, Dagger/Hilt or CDI application the implementation
 * behind an interface is never constructed by user code — that is the point
 * of a container — so every analysis that reasons from "what does this
 * program instantiate" was blind to exactly the classes that actually run.
 * The call graph's RTA dropped them as uninstantiated (the taint died at the
 * service boundary with no diagnostic), and the flow engine's VTA could not
 * narrow an injected receiver at all (every implementation of the interface
 * carried the finding).
 *
 * This is the one place that answers "is this class container-managed", read
 * by BOTH the graph's dispatch index and the flow engine's call index —
 * because two pieces of code answering the same question are a gate (P22),
 * and two stereotype lists would drift the first time one gained an entry.
 *
 * Matching is on RESOLVED annotation FQNs by suffix segment, the rule the
 * root selection and the endpoint detector already follow: a short-name
 * match would make any `@Service` in any package a Spring bean.
 */
object DiStereotypes {

    val ALL: List<String> = listOf(
        // Spring
        "org.springframework.stereotype.Component",
        "org.springframework.stereotype.Service",
        "org.springframework.stereotype.Repository",
        "org.springframework.stereotype.Controller",
        "org.springframework.web.bind.annotation.RestController",
        "org.springframework.context.annotation.Configuration",
        // Jakarta / CDI
        "jakarta.inject.Singleton",
        "javax.inject.Singleton",
        "jakarta.inject.Inject",
        "javax.inject.Inject",
        "jakarta.enterprise.context.ApplicationScoped",
        "jakarta.enterprise.context.RequestScoped",
        // Micronaut
        "io.micronaut.context.annotation.Bean",
        // Dagger / Hilt
        "dagger.hilt.android.lifecycle.HiltViewModel",
        "dagger.hilt.android.AndroidEntryPoint",
    )

    /** True when [annotation] (a resolved FQN) is a container stereotype. */
    fun isStereotype(annotation: String): Boolean =
        ALL.any { annotation == it || annotation.endsWith(".$it") }

    /**
     * The workspace classes a container constructs, read off the lowered
     * functions' owner annotations. A function's own annotations count too:
     * an `@Inject` constructor makes its class container-constructed even
     * when the class carries no stereotype.
     */
    fun managedClasses(functions: List<KirFunction>): Set<String> {
        val out = sortedSetOf<String>()
        for (function in functions) {
            val klass = function.enclosingClass ?: continue
            val annotations = function.ownerAnnotations + function.annotations
            if (annotations.any { isStereotype(it) }) out.add(klass)
        }
        return out
    }
}
