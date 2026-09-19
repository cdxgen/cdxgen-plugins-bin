package io.cdxgen.kosi.kir

/**
 * P25 §2: the annotations that mean **the container constructs this class**.
 *
 * In a Spring, Micronaut, Dagger/Hilt or Jakarta application the
 * implementation behind an interface is never constructed by user code — that
 * is the point of a container — so every analysis that reasons from "what
 * does this program instantiate" was blind to exactly the classes that
 * actually run. The call graph's RTA dropped them as uninstantiated (the
 * taint died at the service boundary with no diagnostic), and the flow
 * engine's VTA could not narrow an injected receiver at all (every
 * implementation of the interface carried the finding).
 *
 * This is the one place that answers "is this class container-managed", read
 * by BOTH the graph's dispatch index and the flow engine's call index —
 * because two pieces of code answering the same question are a gate (P22),
 * and two stereotype lists would drift the first time one gained an entry.
 *
 * Matching is on RESOLVED annotation FQNs by suffix segment, the rule the
 * root selection and the endpoint detector already follow: a short-name
 * match would make any `@Service` in any package a Spring bean.
 *
 * P26 §2 finishes the container: a stereotype is only the ANNOTATED half of
 * the wiring. The other half is the BINDING METHOD — `@Binds`/`@Provides`
 * (Dagger), `@Bean` (Spring), `@Produces` (CDI) — which maps an interface to
 * its implementation by SIGNATURE, and Koin's provider lambdas
 * (`single<Api> { ApiImpl() }`), which map by CONSTRUCTION inside a lambda
 * the container invokes. Both are read here, from the same function list,
 * so `bindings()` and [managedClasses] can never disagree.
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

    /**
     * P26 §2: the METHOD annotations whose signatures are BINDINGS — a
     * mapping from interface to implementation the container reads.
     *
     *  - `@Binds` (Dagger/Hilt): the single parameter IS the implementation,
     *    the return type the bound interface. No construction happens
     *    anywhere in user code, which is why the stereotype half alone could
     *    not see it.
     *  - `@Provides`/`@Bean`/`@Produces`: the return type is the interface;
     *    the implementation is what the body constructs — or, when the body
     *    constructs nothing, the parameter it returns (the `@Provides fun
     *    store(impl: JdbcStore): AuditStore = impl` shape, the usual one
     *    when the implementation's own constructor is `@Inject`-annotated).
     */
    val BINDING_ANNOTATIONS: List<String> = listOf(
        "dagger.Binds",
        "dagger.Provides",
        "org.springframework.context.annotation.Bean",
        "jakarta.enterprise.inject.Produces",
        "javax.enterprise.inject.Produces",
    )

    /**
     * P26 §2: Koin's provider DSL. `single { ApiImpl() }` inside a `module
     * { }` block is a binding written as a CONSTRUCTION inside a lambda the
     * container invokes — the interface is the call's type argument, which
     * the KIR does not carry, but the implementation is in the lambda's body
     * and that is the half dispatch needs. Matched on resolved FQNs by
     * suffix segment like everything here: an unresolved `single` is some
     * other function, and guessing would bind implementations a container
     * never saw.
     */
    val KOIN_PROVIDERS: List<String> = listOf(
        "org.koin.core.module.dsl.single",
        "org.koin.core.module.dsl.factory",
        "org.koin.core.module.dsl.scoped",
        // Koin 2.x's package for the same three functions. It is a separate
        // FQN, not a suffix of the 3.x one, so it must be listed: without it
        // a 2.x provider's implementation entered the managed set only
        // because its lambda happened to CONSTRUCT the class, which is the
        // accident `aKoinProviderDispatchIsNarrowedByTheBindingNotByLuck`
        // exists to rule out.
        "org.koin.dsl.single",
        "org.koin.dsl.factory",
        "org.koin.dsl.scoped",
        "org.koin.androidx.viewmodel.dsl.viewModel",
        "org.koin.androidx.viewmodel.dsl.sharedViewModel",
    )

    /** True when [annotation] (a resolved FQN) is a container stereotype. */
    fun isStereotype(annotation: String): Boolean =
        ALL.any { annotation == it || annotation.endsWith(".$it") }

    /** True when [annotation] (a resolved FQN) is a binding-method annotation. */
    fun isBindingAnnotation(annotation: String): Boolean =
        BINDING_ANNOTATIONS.any { annotation == it || annotation.endsWith(".$it") }

    /** True when [fqn] (a resolved callee FQN) is a Koin provider function. */
    fun isKoinProvider(fqn: String): Boolean =
        KOIN_PROVIDERS.any { fqn == it || fqn.endsWith(".$it") }

    /**
     * The workspace classes a container constructs, read off the lowered
     * functions' owner annotations. A function's own annotations count too:
     * an `@Inject` constructor makes its class container-constructed even
     * when the class carries no stereotype.
     *
     * P26 §2: the classes a BINDING names count as constructed even when no
     * construction site exists anywhere — `@Binds` never constructs; it only
     * declares that the container will — and the classes constructed inside
     * a Koin provider lambda count the same way.
     */
    fun managedClasses(functions: List<KirFunction>): Set<String> {
        val out = sortedSetOf<String>()
        for (function in functions) {
            val klass = function.enclosingClass ?: continue
            val annotations = function.ownerAnnotations + function.annotations
            if (annotations.any { isStereotype(it) }) out.add(klass)
        }
        // One scan of the bodies, not two — this runs once per CallIndex and
        // once per Dispatch over every function of the module. [bindings]
        // keeps only the sites whose type argument named the bound
        // interface; a `single { Impl() }` written without one still
        // CONSTRUCTS, so its implementations are managed either way.
        val koinSites = koinBindingSites(functions)
        out.addAll(bindings(functions, koinSites).values.flatten())
        out.addAll(koinSites.flatMap { it.second })
        return out
    }

    /**
     * P26 §2: the interface -> implementation bindings the container reads,
     * from binding-method signatures and bodies.
     *
     * The KEY is the bound interface's resolved FQN, unnormalised — an
     * interface whose only members are abstract may have NO function in the
     * caller's list (the flow engine compiles bodies only), so keying on a
     * workspace-class match would drop exactly the bindings whose interface
     * is pure. The VALUES are workspace class FQNs in the KIR's chain form
     * (the [KirFunction.enclosingClass] notation) where the implementation
     * is a workspace class; a binding whose implementation is not one is
     * dropped — the container may bind a jar type, but dispatch over
     * workspace implementations is the only question this answers.
     */
    fun bindings(
        functions: List<KirFunction>,
        koinSites: List<Pair<String?, Set<String>>> = koinBindingSites(functions),
    ): Map<String, Set<String>> {
        val workspace = functions.mapNotNull { it.enclosingClass }.toSortedSet()
        // A resolved type FQN against the workspace's chain-form classes, by
        // the suffix rule every other type match here follows.
        fun canonicalClass(typeFqn: String?): String? {
            if (typeFqn == null) return null
            return workspace.firstOrNull { klass -> typeFqn == klass || typeFqn.endsWith(".$klass") }
        }

        val out = sortedMapOf<String, MutableSet<String>>()
        for (function in functions) {
            if (!function.annotations.any { isBindingAnnotation(it) }) continue
            // @Binds: the parameter is the implementation. @Provides and
            // friends: the body's constructions are, falling back to the
            // parameter the body returns when nothing is constructed.
            val constructed = constructedWorkspaceClasses(function, workspace)
            val impls = if (constructed.isNotEmpty()) {
                constructed
            } else {
                function.params.mapNotNull { canonicalClass(it.resolvedType ?: it.type) }.toSet()
            }
            if (function.returnType != null && impls.isNotEmpty()) {
                out.getOrPut(function.returnType!!) { sortedSetOf() }.addAll(impls)
            }
        }
        // Koin's provider lambdas: the call's type argument names the bound
        // interface (`single<Api> { ApiImpl() }`), the linked lambda's
        // constructions the implementations.
        for ((bound, impls) in koinSites) {
            if (bound != null && impls.isNotEmpty()) {
                out.getOrPut(bound) { sortedSetOf() }.addAll(impls)
            }
        }
        return out
    }

    /**
     * P26 §2: Koin's provider sites — `(bound interface FQN when the call's
     * type argument names one, the classes its lambda constructs)`. The
     * lambda links to its call by the argument register; a provider whose
     * lambda constructs nothing the workspace declares yields an empty set
     * and binds nothing the engine can dispatch to.
     */
    fun koinBindingSites(functions: List<KirFunction>): List<Pair<String?, Set<String>>> {
        val workspace = functions.mapNotNull { it.enclosingClass }.toSortedSet()
        val byName = functions.groupBy { it.canonicalName }
        val out = mutableListOf<Pair<String?, Set<String>>>()
        for (function in functions) {
            val blocks = function.body?.blocks ?: continue
            for (block in blocks) {
                val lambdas = block.instructions.filterIsInstance<KirLambda>()
                if (lambdas.isEmpty()) continue
                for (call in block.instructions.filterIsInstance<KirCall>()) {
                    if (!isKoinProvider(call.callee.fqn)) continue
                    // The provider's lambda is linked to its CALL by the
                    // argument register — a block may hold unrelated lambdas
                    // (buildList beside single), and counting those would
                    // mark classes no container ever saw.
                    val providerLambdas = lambdas.filter { it.result in call.args }
                    if (providerLambdas.isEmpty()) continue
                    val bound = call.typeArguments.firstOrNull()?.takeIf { it.isNotEmpty() }
                    val impls = sortedSetOf<String>()
                    for (lambda in providerLambdas) {
                        for (lowered in byName[lambda.function].orEmpty()) {
                            impls.addAll(constructedWorkspaceClasses(lowered, workspace))
                        }
                    }
                    out.add(bound to impls.toSet())
                }
            }
        }
        return out
    }

    /** The workspace classes a function's body constructs (KirNew + constructor calls). */
    private fun constructedWorkspaceClasses(function: KirFunction, workspace: Set<String>): Set<String> {
        val out = sortedSetOf<String>()
        for (block in function.body?.blocks.orEmpty()) {
            for (ins in block.instructions) {
                when (ins) {
                    is KirNew -> workspace.firstOrNull { it == ins.type || ins.type.endsWith(".$it") }
                        ?.let(out::add)
                    is KirCall ->
                        if (ins.callee.kind == CallKind.CONSTRUCTOR) {
                            workspace.firstOrNull { it == ins.callee.fqn || ins.callee.fqn.endsWith(".$it") }
                                ?.let(out::add)
                        }
                    else -> {}
                }
            }
        }
        return out
    }
}
