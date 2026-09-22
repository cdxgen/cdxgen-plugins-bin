package io.cdxgen.kosi.front

import io.cdxgen.kosi.kir.AccessPath
import java.util.TreeSet
import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBody
import io.cdxgen.kosi.kir.KirCallee
import io.cdxgen.kosi.kir.KirBranch
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCast
import io.cdxgen.kosi.kir.KirConstant
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirElvis
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirFieldSet
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIndexGet
import io.cdxgen.kosi.kir.KirIndexSet
import io.cdxgen.kosi.kir.KirLambda
import io.cdxgen.kosi.kir.defs
import io.cdxgen.kosi.kir.mapRegisters
import io.cdxgen.kosi.kir.uses
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.kir.KirPhi
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.kir.KirStringConcat
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.kir.KirSuspendPoint
import io.cdxgen.kosi.kir.KirThrow
import io.cdxgen.kosi.kir.KirTypeCheck
import com.intellij.psi.PsiElement
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirParam
import org.jetbrains.kotlin.analysis.api.analyze
import org.jetbrains.kotlin.analysis.api.resolution.symbol
import org.jetbrains.kotlin.analysis.api.symbols.KaCallableSymbol
import org.jetbrains.kotlin.analysis.api.symbols.KaConstructorSymbol
import org.jetbrains.kotlin.analysis.api.symbols.KaFunctionSymbol
import org.jetbrains.kotlin.analysis.api.symbols.KaPropertySymbol
import org.jetbrains.kotlin.analysis.api.symbols.symbol
import org.jetbrains.kotlin.KtNodeTypes
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.load.kotlin.TypeMappingMode
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtBlockExpression
import org.jetbrains.kotlin.psi.KtBreakExpression
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtContinueExpression
import org.jetbrains.kotlin.psi.KtDoWhileExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtForExpression
import org.jetbrains.kotlin.psi.KtIfExpression
import org.jetbrains.kotlin.psi.KtIsExpression
import org.jetbrains.kotlin.psi.KtLambdaExpression
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtObjectLiteralExpression
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtPropertyAccessor
import org.jetbrains.kotlin.psi.KtReturnExpression
import org.jetbrains.kotlin.psi.KtSafeQualifiedExpression
import org.jetbrains.kotlin.psi.KtSecondaryConstructor
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.KtThisExpression
import org.jetbrains.kotlin.psi.KtTypeReference
import org.jetbrains.kotlin.psi.KtThrowExpression
import org.jetbrains.kotlin.psi.KtTreeVisitorVoid
import org.jetbrains.kotlin.psi.KtTryExpression
import org.jetbrains.kotlin.psi.KtWhenExpression
import org.jetbrains.kotlin.psi.KtWhileExpression

/**
 * PSI + one resolution pass -> [KirModule] (02-ARCHITECTURE.md §4). Lives in
 * kosi-front because lowering needs compiler types; nothing it EMITS does —
 * kosi-kir's types are compiler-free, which is the boundary the gate
 * checks.
 *
 * Every desugaring in §4 happens here, at lowering time:
 *   string templates -> StringConcat; `?.` -> branch + phi (the SafeCall
 *   opcode is reserved for safe access the lowering cannot branch through);
 *   `?:` -> phi (Elvis opcode likewise); `!!` -> checked cast plus a throw
 *   branch; delegated properties -> getValue/setValue calls; data class ->
 *   synthesized copy/componentN; destructuring -> componentN calls; `for` ->
 *   iterator/hasNext/next; operators -> named calls; scope functions ->
 *   inlined lambda body with the receiver bound plus a retained call edge;
 *   `use` -> try/finally; suspend call -> Call + SuspendPoint.
 *
 * A construct the lowering cannot perform is COUNTED by construct
 * (loweringFailures) and diagnosed (`lowering-failed`) — unsupported syntax
 * is countable, never invisible and never a crash.
 */
@OptIn(
    org.jetbrains.kotlin.analysis.api.KaExperimentalApi::class,
    org.jetbrains.kotlin.analysis.api.KaIdeApi::class,
)
object KirLowering {

    /**
     * The reserved dynamic-call name for a thrown exception's
     * binding to a catch parameter. A dynamic call routes through the
     * transfer's unknown-value default (receiver and argument taint reach
     * the result, origin `default`) and the call graph's existing
     * unresolved-call bucket — no pseudo function enters the graph. Angle
     * brackets cannot collide with a real callable name.
     */
    internal const val THROWN_EXCEPTION = "<thrown>"

    data class Result(
        val functions: List<KirFunction>,
        /** construct name -> count of functions the lowering could not perform. */
        val failures: Map<String, Int>,
        /** how many functions the lowering attempted — the denominator for the failure rate. */
        val functionCount: Int,
        /**
         * Symbol operations that threw while collecting the dispatch facts
         * (visibility, modality, overrides, supertypes). NOT a lowering
         * failure — the function still lowers — but the graph must know the
         * facts are missing, because missing facts narrow dispatch toward
         * MORE candidates, and a silent shortfall would quietly narrow it
         * toward fewer. Surfaced through `symbol-resolution-failed`.
         */
        val symbolFactFailures: Int = 0,
        /**
         * Files whose lowering was skipped whole — past the walk budget
         * (`psi-depth`), or after a `StackOverflowError` (`stack-overflow`)
         * — with the run completing for every other file. Surfaced as
         * `psi-depth-cap` / `stack-overflow-skipped` diagnostics by the
         * pipeline; never a silent gap.
         */
        val skippedFiles: List<SkippedFile> = emptyList(),
    )

    /** A file the lowering did not walk, and the reason it was not. */
    data class SkippedFile(val file: String, val reason: String, val depth: Int? = null)

    /** What the analyze-scoped resolver hands the lowering per call site. */
    data class CallInfo(
        val symbol: KaCallableSymbol,
        val descriptor: String?,
        val isSuspend: Boolean,
        val isOperator: Boolean,
        /**
         * True when this site is a Kotlin SYNTHETIC JAVA PROPERTY read —
         * `editText.text`, `intent.data`, `uri.host` — and [symbol] is the
         * Java getter it compiles to (`getText`, `getData`, `getHost`).
         * Kotlin lets you read a Java getter as a property, and the lowering
         * used to take that syntax at face value: a plain name selector
         * became a `fieldget` whose path is the LOCAL VARIABLE's name
         * (`ve.text`), carrying neither the declaring type nor the fact that
         * a method runs. Model packs match callee symbols, so every such API
         * was invisible to them — and it is the dominant source idiom in
         * Android code, where `EditText.text` is how user input enters an
         * app. Lowering it as the call it actually is on the JVM puts
         * `android.widget.TextView.getText` in front of the matcher. Only
         * synthetic JAVA properties take this route. A Kotlin property read
         * stays a field access, because the field-sensitivity work in keys
         * on those paths.
         */
        val syntheticJavaProperty: Boolean = false,
        /**
         * True for a JAVA STATIC method. `Class.forName(name)` is written
         * with a qualifier, and the lowering used to take that qualifier as
         * a RECEIVER — emitting `kind=virtual recv=<the class>` and shifting
         * every argument index by one, because index 0 means the receiver
         * when there is one. Model packs index arguments that way, so every
         * static-method model silently matched nothing: `Class.forName`,
         * `URI.create`, `Files.*`, `Base64.getDecoder`, the factory methods
         * most SDKs are built from. Constructors were unaffected, which is
         * why the shipped pack — whose every index-0 entry is a constructor
         * — never showed it.
         */
        val isStatic: Boolean = false,
        /** Resolved type arguments in declaration order (`get<Article>()`). */
        val typeArguments: List<String> = emptyList(),
        /**
         * True when the resolved symbol is a classifier's SYNTHESIZED SAM
         * constructor — `Runnable { .. }`, `Bridge { .. }` — as opposed to an
         * ordinary function that merely happens to be named after the type it
         * returns.
         *
         * Nothing downstream can re-derive this. A SAM conversion and
         * `fun Handler(block: (String) -> Unit): Handler` compile to the same
         * KIR shape — STATIC, one `kotlin.jvm.functions.FunctionN` parameter,
         * returning the callee's own name — and P33's first cut recognised the
         * conversion from that shape in `AliasAnalysis`, so a factory that
         * IGNORES its function argument had the argument's body applied at
         * every later call on the result. That is a false flow, and only
         * resolution can tell the two apart.
         */
        val isSamConstructor: Boolean = false,
        /**
         * True when this call is an implicit `invoke` of a function value that
         * resolved against an EXTENSION receiver — `b.block()` inside
         * `fun build(block: Builder.() -> Unit)`, where `block` is the
         * function and `b` is its receiver.
         *
         * False for `h.f(raw)`, where the qualifier is the object whose MEMBER
         * holds the function. The two are the same syntax, and the pure-PSI
         * name walk that used to separate them picked the wrong one whenever a
         * function-typed local shadowed a member's name — publishing a flow
         * through a lambda the program never invokes.
         */
        val invokeOnExtensionReceiver: Boolean = false,
    )

    /**
     * The dispatch facts one declaration carries into the graph: declared
     * visibility, modality/keyword modifiers, resolved canonical names of the
     * symbols it overrides, RESOLVED annotation FQNs (framework roots are
     * type-resolved, never name-matched), the JVM descriptor for overload
     * identity, and the enclosing class's supertypes, kind flags and
     * annotations. `factsAvailable = false` when the symbol could not be
     * read; consumers then treat the function as open and non-exported
     * rather than guessing.
     */
    data class Facts(
        val visibility: String,
        val modifiers: Set<String>,
        val overrides: List<String>,
        val annotations: List<String>,
        val supertypes: List<String>,
        val ownerFlags: Set<String>,
        val ownerAnnotations: List<String>,
        val ownerVisibility: String?,
        val jvmDescriptor: String?,
        val factsAvailable: Boolean,
        /**
         * Resolved annotation FQNs per VALUE parameter, in declaration
         * order. This is where framework semantics enter the KIR:
         * `@RequestParam` / `@PathVariable` / `@RequestBody` / `@QueryParam`
         * distinguish the parameters of an endpoint handler that carry
         * attacker input from the ones a container injects.
         */
        val paramAnnotations: List<List<String>> = emptyList(),
        /**
         * Resolved class-type FQNs per VALUE parameter, in declaration
         * order, aligned with [paramAnnotations]; null where the parameter's
         * type is not a resolvable class. The DI binding reader maps
         * `@Binds` parameters to implementations with these.
         */
        val paramTypes: List<String?> = emptyList(),
        /**
         * The function's own RESOLVED class-type FQN; null for Unit,
         * primitives, type parameters and anything unresolved. Unit is
         * excluded on purpose: every `fun foo()` would carry it, it is
         * already in the JVM descriptor, and the consumers of this fact
         * (binding returns, outbound interface returns) are interested in
         * exactly the non-Unit cases.
         */
        val returnTypeFq: String? = null,
    )

    private val NO_FACTS = Facts(
        visibility = "unknown",
        modifiers = emptySet(),
        overrides = emptyList(),
        annotations = emptyList(),
        supertypes = emptyList(),
        ownerFlags = emptySet(),
        ownerAnnotations = emptyList(),
        ownerVisibility = null,
        jvmDescriptor = null,
        factsAvailable = false,
    )

    /** Supertypes, kind flags and resolved annotations of one enclosing class. */
    data class OwnerFacts(
        val supertypes: List<String>,
        val flags: Set<String>,
        val annotations: List<String>,
        val visibility: String,
    )

    fun lower(env: AnalysisEnvironment, module: org.jetbrains.kotlin.analysis.api.projectStructure.KaSourceModule): Result {
        val files = env.session.modulesWithFiles.values
            .flatten()
            .filterIsInstance<org.jetbrains.kotlin.psi.KtFile>()
            .sortedBy { it.virtualFile?.path }
        val functions = mutableListOf<KirFunction>()
        val failures = LinkedHashMap<String, Int>()
        val skippedFiles = mutableListOf<SkippedFile>()
        var functionCount = 0
        var symbolFactFailures = 0
        analyze(module) {
            // resolveCall and the JVM-descriptor mapping are Analysis API
            // operations: they resolve only lexically inside this block, so
            // they are captured here and handed to the body lowering as a
            // plain function value.
            fun descriptorOf(symbol: KaCallableSymbol): String? =
                (symbol as? KaFunctionSymbol)?.let {
                    JvmSignatures.methodDescriptor(
                        it.returnType.mapToJvmType(org.jetbrains.kotlin.load.kotlin.TypeMappingMode.DEFAULT),
                        buildList {
                            it.receiverParameter?.let { r ->
                                add(r.returnType.mapToJvmType(org.jetbrains.kotlin.load.kotlin.TypeMappingMode.DEFAULT))
                            }
                            it.valueParameters.forEach { p ->
                                add(p.returnType.mapToJvmType(org.jetbrains.kotlin.load.kotlin.TypeMappingMode.DEFAULT))
                            }
                        },
                    )
                }

            /**
             * A plain `a.b` name selector, resolved. Returns non-null when
             * reading `b` RUNS A METHOD on the JVM, in which case the
             * CallInfo describes that accessor; a read of a stored field
             * returns null and stays a field access.
             *
             * Two shapes run a method:
             *
             *  - a synthetic Java property — `editText.text` for
             *    `getText()`; [CallInfo.symbol] is the Java getter.
             *  - a Kotlin property with NO BACKING FIELD — an `abstract val`
             *    or one with a custom getter. `ApplicationCall.parameters`,
             *    `ApplicationRequest.queryParameters` and
             *    `RoutingContext.body` are all of this shape, and they are
             *    how request data enters a Ktor or Vert.x handler. Lowering
             *    them as field reads put a path made of the LOCAL
             *    VARIABLE's name (`vcall.parameters`) in front of a matcher
             *    that matches callees, so every one of the pack's Ktor
             *    sources was dead: the patterns shipped, and no Ktor
             *    application could produce a single taint slice.
             *
             * A property WITH a backing field is a real field on the JVM and
             * keeps its access path, so field sensitivity over data classes
             * and workspace state is unchanged.
             */
            fun resolveProperty(psi: KtNameReferenceExpression): CallInfo? = try {
                val call: org.jetbrains.kotlin.analysis.api.resolution.KaSingleCall<*, *> =
                    psi.resolveCall() ?: return null
                when (val symbol = call.signature.symbol) {
                    is org.jetbrains.kotlin.analysis.api.symbols.KaSyntheticJavaPropertySymbol -> {
                        val getter = symbol.javaGetterSymbol
                        CallInfo(
                            symbol = getter,
                            descriptor = descriptorOf(getter),
                            isSuspend = false,
                            isOperator = false,
                            syntheticJavaProperty = true,
                        )
                    }

                    is org.jetbrains.kotlin.analysis.api.symbols.KaKotlinPropertySymbol -> {
                        // The property's OWN callableId is the name the model
                        // packs carry (`...ApplicationCall.parameters`), which
                        // is also how a Kotlin reader names it; the getter
                        // supplies the descriptor.
                        if (symbol.hasBackingField) {
                            null
                        } else {
                            CallInfo(
                                symbol = symbol,
                                descriptor = symbol.getter?.let { descriptorOf(it) },
                                isSuspend = false,
                                isOperator = false,
                                syntheticJavaProperty = true,
                            )
                        }
                    }

                    else -> null
                }
            } catch (_: Exception) {
                null
            }

            fun resolve(psi: KtCallExpression): CallInfo? = try {
                val call = psi.resolveCall() ?: return null
                val symbol = call.symbol as? KaCallableSymbol ?: return null
                val descriptor = (symbol as? KaFunctionSymbol)?.let {
                    JvmSignatures.methodDescriptor(
                        it.returnType.mapToJvmType(org.jetbrains.kotlin.load.kotlin.TypeMappingMode.DEFAULT),
                        buildList {
                            it.receiverParameter?.let { r ->
                                add(r.returnType.mapToJvmType(org.jetbrains.kotlin.load.kotlin.TypeMappingMode.DEFAULT))
                            }
                            it.valueParameters.forEach { p ->
                                add(p.returnType.mapToJvmType(org.jetbrains.kotlin.load.kotlin.TypeMappingMode.DEFAULT))
                            }
                        },
                    )
                }
                CallInfo(
                    symbol = symbol,
                    descriptor = descriptor,
                    isSuspend = (symbol as? org.jetbrains.kotlin.analysis.api.symbols.KaNamedFunctionSymbol)?.isSuspend == true,
                    isOperator = (symbol as? org.jetbrains.kotlin.analysis.api.symbols.KaNamedFunctionSymbol)?.isOperator == true,
                    isStatic = (symbol as? org.jetbrains.kotlin.analysis.api.symbols.KaNamedFunctionSymbol)?.isStatic == true,
                    typeArguments = call.typeArgumentsMapping.values.mapNotNull { type ->
                        (type as? org.jetbrains.kotlin.analysis.api.types.KaClassType)
                            ?.classId?.asSingleFqName()?.asString()
                    },
                    isSamConstructor =
                        symbol is org.jetbrains.kotlin.analysis.api.symbols.KaSamConstructorSymbol,
                    // The extension receiver of an implicit `invoke` is the
                    // function value's RECEIVER, not the object holding it.
                    // Asking the resolver is the whole point: the syntax
                    // `x.name(args)` cannot distinguish the two cases.
                    invokeOnExtensionReceiver = try {
                        (call as? org.jetbrains.kotlin.analysis.api.resolution.KaFunctionCall<*>)
                            ?.partiallyAppliedSymbol
                            ?.extensionReceiver != null
                    } catch (_: Exception) {
                        false
                    },
                )
            } catch (_: Exception) {
                null
            }

            // The dispatch facts for one declaration, computed once per run
            // through the same session (the enclosing class's facts are
            // cached — every member of one class reads them).
            val classFactsCache = HashMap<org.jetbrains.kotlin.psi.KtClassOrObject, OwnerFacts>()
            fun ownerFacts(owner: org.jetbrains.kotlin.psi.KtClassOrObject): OwnerFacts =
                classFactsCache.getOrPut(owner) {
                    val symbol = owner.symbol
                    val classSymbol = symbol as? org.jetbrains.kotlin.analysis.api.symbols.KaClassSymbol
                    val supertypes = classSymbol
                        ?.superTypes
                        ?.mapNotNull { (it as? org.jetbrains.kotlin.analysis.api.types.KaClassType)?.classId?.asSingleFqName()?.asString() }
                        ?.filter { it != "kotlin.Any" }
                        ?.distinct()
                        ?: emptyList()
                    val flags = buildSet {
                        when (classSymbol?.classKind) {
                            org.jetbrains.kotlin.analysis.api.symbols.KaClassKind.INTERFACE ->
                                add(
                                    // `fun interface` is the FUN keyword on an interface.
                                    if (owner is org.jetbrains.kotlin.psi.KtClass &&
                                        owner.isInterface() &&
                                        owner.hasModifier(org.jetbrains.kotlin.lexer.KtTokens.FUN_KEYWORD)
                                    ) {
                                        "fun-interface"
                                    } else {
                                        "interface"
                                    },
                                )

                            org.jetbrains.kotlin.analysis.api.symbols.KaClassKind.ENUM_CLASS -> add("enum")
                            org.jetbrains.kotlin.analysis.api.symbols.KaClassKind.OBJECT -> add("object")
                            org.jetbrains.kotlin.analysis.api.symbols.KaClassKind.COMPANION_OBJECT -> add("companion")
                            else -> {}
                        }
                        when (classSymbol?.modality) {
                            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.FINAL -> add("final")
                            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.OPEN -> add("open")
                            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.SEALED -> add("sealed")
                            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.ABSTRACT -> add("abstract")
                            else -> {}
                        }
                    }
                    val annotations = (symbol as? org.jetbrains.kotlin.analysis.api.annotations.KaAnnotated)
                        ?.annotations
                        ?.mapNotNull { it.classId?.asSingleFqName()?.asString() }
                        ?.distinct()
                        ?: emptyList()
                    val visibility = symbol?.let { visibilityName(it) } ?: "unknown"
                    OwnerFacts(supertypes, flags, annotations, visibility)
                }

            fun factsFor(psi: org.jetbrains.kotlin.psi.KtDeclaration): Facts = try {
                val symbol = psi.symbol
                val callable = symbol as? KaCallableSymbol
                val visibility = symbol?.let { visibilityName(it) } ?: "unknown"
                val overrides = callable
                    ?.allOverriddenSymbols
                    ?.mapNotNull { it.callableId?.asSingleFqName()?.asString() }
                    ?.toList()
                    ?.distinct()
                    ?: emptyList()
                val annotations = (symbol as? org.jetbrains.kotlin.analysis.api.annotations.KaAnnotated)
                    ?.annotations
                    ?.mapNotNull { it.classId?.asSingleFqName()?.asString() }
                    ?.distinct()
                    // An unresolved annotation keeps its PSI short name, which
                    // cannot match a framework FQN pattern — an annotation
                    // kosi could not resolve is never treated as resolved.
                    ?.ifEmpty {
                        psi.annotationEntries.mapNotNull { it.shortName?.asString() }
                    }
                    ?: psi.annotationEntries.mapNotNull { it.shortName?.asString() }
                val paramAnnotations = (psi as? KtNamedFunction)?.valueParameters?.map { parameter ->
                    val resolved = (parameter.symbol as? org.jetbrains.kotlin.analysis.api.annotations.KaAnnotated)
                        ?.annotations
                        ?.mapNotNull { it.classId?.asSingleFqName()?.asString() }
                        ?.distinct()
                        .orEmpty()
                    // Same discipline as declaration annotations: an
                    // annotation kosi could not resolve keeps its PSI short
                    // name, which cannot match a framework FQN pattern.
                    resolved.ifEmpty { parameter.annotationEntries.mapNotNull { it.shortName?.asString() } }
                }.orEmpty()
                val owner = generateSequence(psi.parent) { it.parent }
                    .firstOrNull { it is org.jetbrains.kotlin.psi.KtClassOrObject }
                    as? org.jetbrains.kotlin.psi.KtClassOrObject
                val ownerFacts = owner?.let { ownerFacts(it) }
                    ?: OwnerFacts(emptyList(), emptySet(), emptyList(), "unknown")
                val descriptor = when (callable) {
                    is org.jetbrains.kotlin.analysis.api.symbols.KaConstructorSymbol ->
                        JvmSignatures.voidMethodDescriptor(
                            callable.valueParameters.map { it.returnType.mapToJvmType(TypeMappingMode.DEFAULT) },
                        )

                    is KaFunctionSymbol -> {
                        val params = buildList {
                            callable.receiverParameter?.let { add(it.returnType.mapToJvmType(TypeMappingMode.DEFAULT)) }
                            callable.valueParameters.forEach { p ->
                                add(p.returnType.mapToJvmType(TypeMappingMode.DEFAULT))
                            }
                        }
                        JvmSignatures.methodDescriptor(
                            callable.returnType.mapToJvmType(TypeMappingMode.DEFAULT),
                            params,
                        )
                    }

                    else -> null
                }
                // Resolved class-type FQNs for the return and each value
                // parameter — the same suffix-segment-matchable notation the
                // supertypes use. A binding method's signature IS the mapping
                // the container reads, and the signature's source TEXT (what
                // KirParam.type carries) cannot answer it.
                fun classTypeFq(type: org.jetbrains.kotlin.analysis.api.types.KaType?): String? =
                    (type as? org.jetbrains.kotlin.analysis.api.types.KaClassType)
                        ?.classId?.asSingleFqName()?.asString()
                val paramTypes = (callable as? KaFunctionSymbol)
                    ?.valueParameters
                    ?.map { classTypeFq(it.returnType) }
                    .orEmpty()
                val returnTypeFq = when (callable) {
                    is KaFunctionSymbol -> classTypeFq(callable.returnType)?.takeIf { it != "kotlin.Unit" }
                    // A property initializer's "return" is the property's own
                    // type.
                    is KaPropertySymbol -> classTypeFq(callable.returnType)
                    else -> null
                }
                Facts(
                    visibility = visibility,
                    modifiers = (psiModifiers(psi) + listOfNotNull(modalityModifier(callable))).toCollection(TreeSet()),
                    overrides = overrides,
                    annotations = annotations,
                    supertypes = ownerFacts.supertypes,
                    ownerFlags = ownerFacts.flags,
                    ownerAnnotations = ownerFacts.annotations,
                    ownerVisibility = ownerFacts.visibility,
                    jvmDescriptor = descriptor,
                    factsAvailable = true,
                    paramAnnotations = paramAnnotations,
                    paramTypes = paramTypes,
                    returnTypeFq = returnTypeFq,
                )
            } catch (_: Exception) {
                symbolFactFailures++
                NO_FACTS
            }

            /**
             * The canonical name a callable reference NAMES.
             *
             * `::sink`, `obj::method` and `Type::member` are function VALUES
             * exactly as a lambda is, and built the channel that carries
             * taint through one — but the lowering wrote the reference's
             * SOURCE TEXT (`::sink`) as the function value's name, and no
             * table is keyed by source text, so every reference spelling
             * died at the invocation while `{ s -> sink(s) }` went through.
             * Resolved here, in the ambient analysis pass that already
             * answers for call expressions, because the lowering itself may
             * not call `KtReference.resolve()` (it re-enters `analyze` and
             * deadlocks a native image — the rule at `isLocalReference`).
             */
            fun resolveReference(psi: org.jetbrains.kotlin.psi.KtCallableReferenceExpression): String? = try {
                val call: org.jetbrains.kotlin.analysis.api.resolution.KaSingleCall<*, *> =
                    psi.resolveCall() ?: return@resolveReference null
                val symbol = call.signature.symbol as? KaCallableSymbol
                when (symbol) {
                    is KaConstructorSymbol ->
                        symbol.containingClassId?.asSingleFqName()?.asString()?.let { "$it.<init>" }

                    // A LOCAL function has no callableId — locals are not
                    // addressable from outside — but the lowering hoists its
                    // body to a package-qualified KIR function, so the
                    // declaration is what names it.
                    else -> symbol?.callableId?.asSingleFqName()?.asString()
                        ?: (symbol?.psi as? KtNamedFunction)?.let { canonicalNameOfDeclaration(it) }
                }
            } catch (_: Exception) {
                null
            }

            /**
             * True when this lambda's EXPECTED type is an extension function
             * type — `Builder.() -> Unit` — so its body's free `this` is a
             * receiver the caller supplies.
             *
             * Resolved here for the same reason [resolveReference] is: the
             * lowering may not re-enter `analyze`. An earlier cut inferred it
             * from the body instead ("a free `vthis` that is written to"),
             * and that inference is wrong for a NESTED lambda: an ordinary
             * lambda inside a DSL block sees the OUTER lambda's receiver as
             * free and stole a receiver parameter of its own, shifting every
             * one of its real parameters by one.
             */
            fun lambdaHasReceiver(psi: KtLambdaExpression): Boolean = try {
                val expected = psi.expectedType
                (expected as? org.jetbrains.kotlin.analysis.api.types.KaFunctionType)?.hasReceiver == true
            } catch (_: Exception) {
                false
            }

            val lambdaContext =
                LambdaContext(failures, ::resolve, ::resolveProperty, ::resolveReference, ::lambdaHasReceiver)
            for (file in files) {
                // The walk budget and the per-file boundary, exactly as
                // in ResolvedAnalyzer — the same PSI trees are walked here,
                // so the same file that would take resolution down would
                // take lowering down. A skipped file is recorded and named;
                // the run completes for every other file.
                val psiDepth = WalkBudgets.psiMaxDepth(file)
                if (psiDepth > WalkBudgets.PSI_DEPTH_CAP) {
                    skippedFiles.add(SkippedFile(file.virtualFile?.path ?: file.name, "psi-depth", psiDepth))
                    continue
                }
                try {
                for (functionLike in collectFunctionLikes(file)) {
                    functionCount++
                    lowerFunction(functionLike, failures, ::resolve, ::resolveProperty, ::factsFor, lambdaContext)?.let { functions.add(it) }
                }
                for (klass in dataClasses(file)) {
                    functions.addAll(synthesizeDataClassMembers(klass, failures))
                }
                // Every class with a primary constructor gets its
                // `<init>` lowered as the function it is — one that writes
                // the object's fields. Until now a primary constructor
                // existed in the KIR only as a CALL SITE (`kind=constructor`)
                // with no body anywhere, so `Job(tainted)` could never taint
                // `job.command`: the flow engine had no function to
                // summarise. Secondary constructors were already lowered;
                // this is the primary's turn.
                for (klass in classesWithPrimaryConstructor(file)) {
                    synthesizePrimaryConstructor(klass)?.let { functions.add(it) }
                }
                // The forwarders `by`-delegation generates. They have
                // no PSI, so nothing above this line can see them.
                for (klass in classesWithDelegation(file)) {
                    functions.addAll(synthesizeDelegationForwarders(klass, failures))
                }
                } catch (e: StackOverflowError) {
                    failures["stack-overflow"] = (failures["stack-overflow"] ?: 0) + 1
                    skippedFiles.add(SkippedFile(file.virtualFile?.path ?: file.name, "stack-overflow"))
                }
            }
            functions.addAll(lambdaContext.functions)
        }
        return Result(functions, failures, functionCount, symbolFactFailures, skippedFiles)
    }

    /**
     * The forwarders Kotlin's CLASS DELEGATION generates.
     *
     * `class RequestWithContext(private val delegate: Request, ...): Request
     * by delegate` compiles to one override per member of `Request`, each
     * body `delegate.member(...)`. Not one of them has PSI, and the lowering
     * is PSI-driven, so the whole forwarding layer was absent from the KIR:
     * `wrapped.body` resolved to an interface method with no implementation
     * anywhere, the flow engine had nothing to summarise, and the value the
     * delegate carried stopped at the wrapper.
     *
     * This is the other half of. Taught the summary to say "the
     * source came back inside the returned object's FIELD"; the 22 http4k
     * findings still did not return, because their consumers read that field
     * through exactly these missing forwarders. The channel existed and the
     * bridge did not.
     *
     * The synthesis is deliberately literal — a field read of the delegate
     * and a virtual call on it — so that nothing here is a special case
     * downstream: the summary machinery, the alias class, dispatch and the
     * frames all see an ordinary member function whose body forwards, which
     * is exactly what the JVM runs.
     *
     * Returns null members rather than guessing when the delegate is not a
     * plain name (`: Request by wrap(other)` stores an unnamed
     * `$$delegate_0` the object-identity model never wrote); those count as
     * a `delegation-opaque` lowering failure so the gap is visible instead
     * of silent.
     */
    private fun org.jetbrains.kotlin.analysis.api.KaSession.synthesizeDelegationForwarders(
        klass: org.jetbrains.kotlin.psi.KtClassOrObject,
        failures: MutableMap<String, Int>,
    ): List<KirFunction> {
        val entries = klass.superTypeListEntries
            .filterIsInstance<org.jetbrains.kotlin.psi.KtDelegatedSuperTypeEntry>()
        if (entries.isEmpty()) return emptyList()

        val pkg = (klass.containingFile as? org.jetbrains.kotlin.psi.KtFile)?.packageFqName?.asString() ?: ""
        val chain = containerChain(klass)
        // An object EXPRESSION delegating (`object: Payload by source {}`)
        // has no name; `<anonymous>` is the convention the rest of the
        // lowering already uses, and what identifies these forwarders to
        // dispatch is their `overrides` edge, not their name.
        val className = klass.name ?: "<anonymous>"
        val base = listOf(pkg, chain, className).filter { it.isNotEmpty() }.joinToString(".")
        val enclosing = listOf(chain, className).filter { it.isNotEmpty() }.joinToString(".")
        val file = klass.containingFile?.virtualFile?.path ?: "<memory>"

        // Members the class declares ITSELF always win: `override fun body()`
        // beside `by delegate` is the idiom for "forward everything except
        // this", and synthesizing over it would publish a forwarder the JVM
        // never runs.
        val declared = klass.declarations.mapNotNull { declaration ->
            when (declaration) {
                is KtNamedFunction -> declaration.name
                is org.jetbrains.kotlin.psi.KtProperty -> declaration.name
                else -> null
            }
        }.toSet()

        val out = mutableListOf<KirFunction>()
        val taken = sortedSetOf<String>()
        for (entry in entries) {
            val delegateName = (entry.delegateExpression as? KtNameReferenceExpression)
                ?.getReferencedName()
            if (delegateName == null) {
                failures.merge("delegation-opaque", 1, Int::plus)
                continue
            }
            val supertype = entry.typeReference?.type as? org.jetbrains.kotlin.analysis.api.types.KaClassType
            val symbol = supertype?.symbol as? org.jetbrains.kotlin.analysis.api.symbols.KaClassSymbol
            if (symbol == null) {
                failures.merge("delegation-unresolved-supertype", 1, Int::plus)
                continue
            }
            val supertypeFqn = supertype.classId?.asSingleFqName()?.asString() ?: continue

            for (member in symbol.memberScope.callables.sortedBy { it.callableId?.asSingleFqName()?.asString() ?: "" }) {
                val name = member.callableId?.callableName?.asString() ?: continue
                // kotlin.Any's members are on every type and forwarding them
                // says nothing about data.
                if (name in ANY_MEMBERS || name in declared || !taken.add(name)) continue
                val valueParams = (member as? KaFunctionSymbol)?.valueParameters.orEmpty()
                val params = mutableListOf(io.cdxgen.kosi.kir.KirParam("%0", "this", null, receiver = true))
                valueParams.forEachIndexed { index, parameter ->
                    params.add(
                        io.cdxgen.kosi.kir.KirParam(
                            "%${index + 1}",
                            parameter.name.asString(),
                            null,
                            receiver = false,
                            resolvedType = (parameter.returnType as? org.jetbrains.kotlin.analysis.api.types.KaClassType)
                                ?.classId?.asSingleFqName()?.asString(),
                        ),
                    )
                }
                val args = valueParams.indices.map { "%${it + 1}" }
                val delegateReg = "%d0"
                val resultReg = "%d1"
                out.add(
                    KirFunction(
                        canonicalName = "$base.$name",
                        jvmDescriptor = null,
                        purl = "",
                        file = file,
                        line = klass.line(),
                        column = klass.column(),
                        params = params,
                        returnType = (member.returnType as? org.jetbrains.kotlin.analysis.api.types.KaClassType)
                            ?.classId?.asSingleFqName()?.asString()
                            ?.takeIf { it != "kotlin.Unit" },
                        modifiers = setOf("override"),
                        visibility = "public",
                        enclosingClass = enclosing.ifEmpty { null },
                        // The dispatch edge: a call on the INTERFACE resolves
                        // here, which is the whole point of the synthesis.
                        overrides = listOf("$supertypeFqn.$name"),
                        overriddenBy = emptyList(),
                        annotations = emptyList(),
                        syntheticCause = "class-delegation",
                        body = io.cdxgen.kosi.kir.KirBody(
                            listOf(
                                io.cdxgen.kosi.kir.KirBlock(
                                    "b0",
                                    entry = true,
                                    instructions = listOf(
                                        io.cdxgen.kosi.kir.KirFieldGet(
                                            delegateReg,
                                            "%0",
                                            io.cdxgen.kosi.kir.AccessPath.field("%0", delegateName),
                                        ),
                                        io.cdxgen.kosi.kir.KirCall(
                                            result = resultReg,
                                            callee = io.cdxgen.kosi.kir.KirCallee(
                                                "$supertypeFqn.$name",
                                                null,
                                                io.cdxgen.kosi.kir.CallKind.VIRTUAL,
                                            ),
                                            receiver = delegateReg,
                                            args = args,
                                            line = klass.line(),
                                        ),
                                        io.cdxgen.kosi.kir.KirReturn(resultReg),
                                    ),
                                ),
                            ),
                        ),
                    ),
                )
            }
        }
        return out
    }

    /** Members every type has; forwarding them carries no data fact. */
    private val ANY_MEMBERS = setOf("equals", "hashCode", "toString")

    /** Classes declaring a primary constructor with at least one stored (`val`/`var`) parameter. */
    private fun classesWithPrimaryConstructor(file: org.jetbrains.kotlin.psi.KtFile): List<org.jetbrains.kotlin.psi.KtClass> {
        val out = mutableListOf<org.jetbrains.kotlin.psi.KtClass>()
        file.accept(object : KtTreeVisitorVoid() {
            override fun visitClass(klass: org.jetbrains.kotlin.psi.KtClass) {
                val primary = klass.primaryConstructor
                if (primary != null && primary.valueParameters.any { it.hasValOrVar() }) out.add(klass)
                super.visitClass(klass)
            }
        })
        return out
    }

    /**
     * The primary constructor's body: `fieldSet this.<name> = <param>` for
     * each stored parameter, in declaration order — the object-identity
     * content of a construction. The receiver parameter mirrors a member
     * function's `%0`/`this`, so the summary's `paramFieldWrites` reach the
     * caller's NEW OBJECT through the same channel every member uses.
     */
    private fun synthesizePrimaryConstructor(klass: org.jetbrains.kotlin.psi.KtClass): KirFunction? {
        val primary = klass.primaryConstructor ?: return null
        val stored = primary.valueParameters.filter { it.hasValOrVar() }
        if (stored.isEmpty()) return null
        val pkg = (klass.containingFile as? org.jetbrains.kotlin.psi.KtFile)?.packageFqName?.asString() ?: ""
        val chain = containerChain(klass)
        val className = klass.name ?: "<anonymous>"
        val base = listOf(pkg, chain, className).filter { it.isNotEmpty() }.joinToString(".")
        val file = klass.containingFile?.virtualFile?.path ?: "<memory>"
        val params = mutableListOf(io.cdxgen.kosi.kir.KirParam("%0", "this", null, receiver = true))
        val writes = mutableListOf<io.cdxgen.kosi.kir.KirIns>()
        stored.forEachIndexed { position, parameter ->
            val name = parameter.name ?: return@forEachIndexed
            params.add(io.cdxgen.kosi.kir.KirParam("%${position + 1}", name, parameter.typeReference?.text, receiver = false))
            writes.add(
                io.cdxgen.kosi.kir.KirFieldSet(
                    "%0",
                    io.cdxgen.kosi.kir.AccessPath.field("%0", name),
                    "%${position + 1}",
                ),
            )
        }
        writes.add(io.cdxgen.kosi.kir.KirReturn(null))
        return KirFunction(
            canonicalName = "$base.<init>",
            jvmDescriptor = null,
            purl = "",
            file = file,
            line = klass.line(),
            column = klass.column(),
            params = params,
            returnType = null,
            modifiers = emptySet(),
            visibility = "public",
            enclosingClass = listOf(chain, className).filter { it.isNotEmpty() }.joinToString("."),
            overrides = emptyList(),
            overriddenBy = emptyList(),
            annotations = emptyList(),
            syntheticCause = "primary-constructor",
            body = io.cdxgen.kosi.kir.KirBody(
                listOf(io.cdxgen.kosi.kir.KirBlock("b0", entry = true, instructions = writes)),
            ),
        )
    }

    private fun modalityModifier(symbol: KaCallableSymbol?): String? = when (symbol?.modality) {
        org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.FINAL -> "final"
        org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.OPEN -> "open"
        org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.ABSTRACT -> "abstract"
        org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.SEALED -> "sealed"
        else -> null
    }

    private val MODIFIER_TOKENS = linkedMapOf(
        org.jetbrains.kotlin.lexer.KtTokens.INLINE_KEYWORD to "inline",
        org.jetbrains.kotlin.lexer.KtTokens.SUSPEND_KEYWORD to "suspend",
        org.jetbrains.kotlin.lexer.KtTokens.OPERATOR_KEYWORD to "operator",
        org.jetbrains.kotlin.lexer.KtTokens.INFIX_KEYWORD to "infix",
        org.jetbrains.kotlin.lexer.KtTokens.EXPECT_KEYWORD to "expect",
        org.jetbrains.kotlin.lexer.KtTokens.ACTUAL_KEYWORD to "actual",
        org.jetbrains.kotlin.lexer.KtTokens.EXTERNAL_KEYWORD to "external",
        org.jetbrains.kotlin.lexer.KtTokens.ABSTRACT_KEYWORD to "abstract",
        org.jetbrains.kotlin.lexer.KtTokens.OPEN_KEYWORD to "open",
        org.jetbrains.kotlin.lexer.KtTokens.OVERRIDE_KEYWORD to "override",
        org.jetbrains.kotlin.lexer.KtTokens.CONST_KEYWORD to "const",
        org.jetbrains.kotlin.lexer.KtTokens.TAILREC_KEYWORD to "tailrec",
        org.jetbrains.kotlin.lexer.KtTokens.INNER_KEYWORD to "inner",
        org.jetbrains.kotlin.lexer.KtTokens.LATEINIT_KEYWORD to "lateinit",
    )

    private fun psiModifiers(element: org.jetbrains.kotlin.psi.KtModifierListOwner): List<String> =
        MODIFIER_TOKENS.mapNotNull { (token, name) -> if (element.hasModifier(token)) name else null }

    private fun visibilityName(symbol: org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol): String =
        when (symbol.visibility) {
            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolVisibility.PUBLIC -> "public"
            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolVisibility.PROTECTED -> "protected"
            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolVisibility.INTERNAL -> "internal"
            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolVisibility.PRIVATE -> "private"
            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolVisibility.PACKAGE_PROTECTED,
            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolVisibility.PACKAGE_PRIVATE,
            -> "package-private"

            org.jetbrains.kotlin.analysis.api.symbols.KaSymbolVisibility.LOCAL -> "local"
            else -> "unknown"
        }

    // ---- discovery ---------------------------------------------------------------

    private fun collectFunctionLikes(file: org.jetbrains.kotlin.psi.KtFile): List<KtDeclaration> {
        val out = mutableListOf<KtDeclaration>()
        file.accept(object : KtTreeVisitorVoid() {
            override fun visitNamedFunction(function: KtNamedFunction) {
                out.add(function)
                super.visitNamedFunction(function)
            }

            override fun visitProperty(property: KtProperty) {
                property.getter?.let { out.add(it) }
                property.setter?.let { out.add(it) }
                // An INITIALIZER is executable code — the JVM runs
                // it in the file's <clinit> (top level) or the constructor
                // (a member) — and the KIR had no function for it, so a
                // Koin module at top level (`val appModule = module {
                // single<Api> { ApiImpl() } }`, the framework's own idiom)
                // was invisible to the whole engine: no lambda, no
                // construction, no binding. Only declarations and members
                // are lowered; a LOCAL's initializer is a statement of the
                // enclosing function and lowering it again would duplicate
                // every local.
                if (property.initializer != null && property.getter == null) {
                    val parent = property.parent
                    if (parent is org.jetbrains.kotlin.psi.KtFile || parent is org.jetbrains.kotlin.psi.KtClassBody) {
                        out.add(property)
                    }
                }
                super.visitProperty(property)
            }

            override fun visitSecondaryConstructor(constructor: KtSecondaryConstructor) {
                out.add(constructor)
                super.visitSecondaryConstructor(constructor)
            }
        })
        return out
    }

    /** Classes with at least one `by`-delegated supertype. */
    private fun classesWithDelegation(
        file: org.jetbrains.kotlin.psi.KtFile,
    ): List<org.jetbrains.kotlin.psi.KtClassOrObject> {
        val out = mutableListOf<org.jetbrains.kotlin.psi.KtClassOrObject>()
        file.accept(object : KtTreeVisitorVoid() {
            override fun visitClassOrObject(classOrObject: org.jetbrains.kotlin.psi.KtClassOrObject) {
                if (classOrObject.superTypeListEntries
                        .any { it is org.jetbrains.kotlin.psi.KtDelegatedSuperTypeEntry }
                ) {
                    out.add(classOrObject)
                }
                super.visitClassOrObject(classOrObject)
            }
        })
        return out
    }

    private fun dataClasses(file: org.jetbrains.kotlin.psi.KtFile): List<org.jetbrains.kotlin.psi.KtClass> {
        val out = mutableListOf<org.jetbrains.kotlin.psi.KtClass>()
        file.accept(object : KtTreeVisitorVoid() {
            override fun visitClass(klass: org.jetbrains.kotlin.psi.KtClass) {
                if (klass.isData()) out.add(klass)
                super.visitClass(klass)
            }
        })
        return out
    }

    /**
     * Data class desugaring: `copy` and `componentN` exist in the KIR as
     * synthetic functions so downstream phases see the copies a data class
     * introduces (the field-sensitivity case) even though no source declares
     * them. Their bodies are empty by construction — the synthesis is about
     * the edges, not the code.
     */
    private fun synthesizeDataClassMembers(
        klass: org.jetbrains.kotlin.psi.KtClass,
        failures: MutableMap<String, Int>,
    ): List<KirFunction> {
        val pkg = (klass.containingFile as? org.jetbrains.kotlin.psi.KtFile)?.packageFqName?.asString() ?: ""
        val chain = containerChain(klass)
        val className = klass.name ?: "<anonymous>"
        val base = listOf(pkg, chain, className).filter { it.isNotEmpty() }.joinToString(".")
        val file = klass.containingFile?.virtualFile?.path ?: "<memory>"
        fun synthetic(name: String): KirFunction = KirFunction(
            canonicalName = "$base.$name",
            jvmDescriptor = null,
            purl = "",
            file = file,
            line = klass.line(),
            column = klass.column(),
            params = emptyList(),
            returnType = null,
            modifiers = emptySet(),
            visibility = "public",
            enclosingClass = listOf(chain, className).filter { it.isNotEmpty() }.joinToString("."),
            overrides = emptyList(),
            overriddenBy = emptyList(),
            annotations = emptyList(),
            syntheticCause = "data-class",
            body = KirBody(listOf(KirBlock("b0", entry = true, instructions = listOf(io.cdxgen.kosi.kir.KirReturn(null))))),
        )
        val functions = mutableListOf(synthetic("copy"))
        klass.primaryConstructorParameters.filter { it.hasValOrVar() }.forEachIndexed { index, _ ->
            functions.add(synthetic("component${index + 1}"))
        }
        return functions
    }

    // ---- signatures -----------------------------------------------------------------

    /**
     * Per-`lower()`-run context for the standalone-lambda extraction:
     * lambdas passed as VALUES (`runWith { .. }`, a function-valued argument)
     * lower into their own KIR functions so the summary engine can compute
     * and apply them like any other callee. The context owns the ordinal
     * (deterministic naming) and the sink the extracted functions land in.
     */
    internal class LambdaContext(
        val failures: MutableMap<String, Int>,
        val resolve: (KtCallExpression) -> CallInfo?,
        val resolveProperty: (KtNameReferenceExpression) -> CallInfo?,
        /** The canonical name a `::reference` names; null when it does not resolve. */
        val resolveReference: (org.jetbrains.kotlin.psi.KtCallableReferenceExpression) -> String? = { null },
        /** True when the lambda's EXPECTED type carries an extension receiver. */
        val lambdaHasReceiver: (KtLambdaExpression) -> Boolean = { false },
    ) {
        var ordinal = 0
        val functions = mutableListOf<KirFunction>()
    }

    private fun lowerFunction(
        psi: org.jetbrains.kotlin.psi.KtDeclaration,
        failures: MutableMap<String, Int>,
        resolve: (KtCallExpression) -> CallInfo?,
        resolveProperty: (KtNameReferenceExpression) -> CallInfo?,
        factsFor: (org.jetbrains.kotlin.psi.KtDeclaration) -> Facts,
        lambdaContext: LambdaContext,
    ): KirFunction? {
        val name = when (psi) {
            is KtNamedFunction -> psi.name ?: "<anonymous>"
            // A property INITIALIZER lowers as the function that computes
            // the initial value: the JVM runs it in <clinit> or the
            // constructor, and until now the expression was invisible to the
            // engine. Named for the PROPERTY — the accessor naming rule
            // (get/set + property) is for accessors, and this is not one.
            is KtProperty -> psi.name ?: return null
            // An accessor has no PSI name of its own; the JVM name is
            // get/setX after its PROPERTY. `<accessor>` gave every custom
            // accessor of one class the SAME canonical name — InsecureShop's
            // Prefs object lowered six colliding `Prefs.<accessor>` functions
            // (found promoting the repo into the corpus; the validator
            // named the duplicates and `kir dump` refused the module).
            is KtPropertyAccessor -> psi.name ?: accessorName(psi)
            is KtSecondaryConstructor -> "<init>"
            else -> return null
        }
        val pkg = (psi.containingFile as? org.jetbrains.kotlin.psi.KtFile)?.packageFqName?.asString() ?: ""
        val chain = containerChain(psi)
        val canonical = listOf(pkg, chain, name).filter { it.isNotEmpty() }.joinToString(".")

        val facts = factsFor(psi)
        val lower = BodyLower(failures, resolve, resolveProperty, psi, lambdaContext, enclosingCanonical = canonical)
        val bodyPsi: KtExpression? = when (psi) {
            is KtNamedFunction -> psi.bodyExpression
            is KtProperty -> psi.initializer
            is KtPropertyAccessor -> psi.bodyExpression
            is KtSecondaryConstructor -> psi.bodyExpression
            else -> null
        }
        val body: KirBody? = when {
            bodyPsi == null -> null // abstract/external/expect
            bodyPsi is KtBlockExpression -> {
                // Bind each parameter register to its named local so body
                // references (%0 vs v<name>) meet in the store.
                lower.bindParameters(signatureParams(psi))
                for (statement in bodyPsi.statements) lower.lowerStatement(statement)
                lower.returnIfOpen()
                lower.finish()
            }
            else -> {
                // Expression body: the value is the return value.
                lower.bindParameters(signatureParams(psi))
                val value = lower.lowerExpr(bodyPsi, BodyLower.Pos.STATEMENT)
                lower.returnValue(value)
                lower.finish()
            }
        }
        return KirFunction(
            canonicalName = canonical,
            jvmDescriptor = facts.jvmDescriptor,
            purl = "",
            file = psi.containingFile?.virtualFile?.path ?: "<memory>",
            line = psi.line(),
            column = psi.column(),
            params = signatureParams(psi, facts),
            returnType = facts.returnTypeFq,
            modifiers = facts.modifiers,
            visibility = facts.visibility,
            enclosingClass = chain.ifEmpty { null },
            overrides = facts.overrides,
            overriddenBy = emptyList(),
            annotations = facts.annotations,
            syntheticCause = null,
            body = body,
            supertypes = facts.supertypes,
            ownerFlags = facts.ownerFlags,
            ownerAnnotations = facts.ownerAnnotations,
            ownerVisibility = facts.ownerVisibility,
        )
    }

    private fun signatureParams(
        psi: org.jetbrains.kotlin.psi.KtDeclaration,
        facts: Facts = NO_FACTS,
    ): List<KirParam> {
        val receiverType: KtTypeReference? = when (psi) {
            is KtNamedFunction -> psi.receiverTypeReference
            is KtPropertyAccessor -> (psi.parent as? KtProperty)?.receiverTypeReference
            else -> null
        }
        val params = mutableListOf<KirParam>()
        var index = 0
        val hasDispatch = containerChain(psi).isNotEmpty() || receiverType != null
        if (hasDispatch) {
            params.add(KirParam("%${index++}", "this", null, receiver = true))
        }
        if (psi is KtNamedFunction) {
            for ((position, p) in psi.valueParameters.withIndex()) {
                params.add(
                    KirParam(
                        "%${index++}",
                        p.name,
                        p.typeReference?.text,
                        receiver = false,
                        resolvedType = facts.paramTypes.getOrNull(position),
                        annotations = facts.paramAnnotations.getOrElse(position) { emptyList() },
                    ),
                )
            }
        }
        return params
    }

    /**
     * The canonical name a declaration's lowered function carries: package,
     * enclosing class chain, then the name (`<anonymous>` for an anonymous
     * `fun`, which is exactly what the collector names it). The same three
     * parts `lowerFunction` joins — kept here so a USE of a function as a
     * value can name it the way its DECLARATION is named.
     */
    private fun canonicalNameOfDeclaration(psi: KtNamedFunction): String {
        val pkg = (psi.containingFile as? org.jetbrains.kotlin.psi.KtFile)?.packageFqName?.asString() ?: ""
        val chain = containerChain(psi)
        val name = psi.name ?: "<anonymous>"
        return listOf(pkg, chain, name).filter { it.isNotEmpty() }.joinToString(".")
    }

    private fun containerChain(psi: com.intellij.psi.PsiElement): String =
        generateSequence(psi.parent) { it.parent }
            .filterIsInstance<org.jetbrains.kotlin.psi.KtClassOrObject>()
            .toList()
            .reversed()
            .joinToString(".") { it.name ?: "<anonymous>" }

    /**
     * The JVM name of a property accessor: `getData` / `setData` after the
     * property it belongs to. The accessor PSI node carries no name of its
     * own, and a constant placeholder made every custom accessor of one
     * class COLLIDE on the same canonical name (InsecureShop's `Prefs`
     * lowered six `Prefs.<accessor>` functions).
     */
    private fun accessorName(accessor: org.jetbrains.kotlin.psi.KtPropertyAccessor): String {
        val property = accessor.property.name ?: "property"
        val prefix = if (accessor.isGetter) "get" else "set"
        return prefix + property.replaceFirstChar { it.uppercaseChar() }
    }

    private fun com.intellij.psi.PsiElement.line(): Int {
        val file = containingFile ?: return 1
        return file.text.take(textOffset).count { it == '\n' } + 1
    }

    private fun com.intellij.psi.PsiElement.column(): Int {
        val file = containingFile ?: return 1
        val prefix = file.text.take(textOffset)
        return prefix.length - prefix.lastIndexOf('\n')
    }

    // ---- the body lowering ----------------------------------------------------------

    private class BodyLower(
        private val failures: MutableMap<String, Int>,
        private val resolveCallInfo: (KtCallExpression) -> CallInfo?,
        /** Resolves a plain `a.b` selector; non-null only for synthetic Java properties. */
        private val resolvePropertyInfo: (KtNameReferenceExpression) -> CallInfo?,
        /** The lowered function's PSI: the fallback position for synthesized calls. */
        private val functionPsi: org.jetbrains.kotlin.psi.KtDeclaration,
        /** Non-null when extracted standalone lambdas land somewhere (the `lower()` run's context). */
        private val lambdaContext: LambdaContext? = null,
        /** This function's canonical name: the prefix of extracted lambda names. */
        private val enclosingCanonical: String = "",
        /** First temporary index: an extracted body starts above its enclosing body's counter. */
        tempStart: Int = 0,
    ) {

        enum class Pos { STATEMENT, NESTED }

        private var temp = tempStart
        private var counter = 1
        private val blocks = LinkedHashMap<String, MutableList<KirIns>>()
        private var currentId = "b0"

        /**
         * Every register this body has DEFINED so far (parameters, instruction
         * results, store targets). The lambda extraction reads it to decide
         * which of a lambda body's free registers are captures of the
         * enclosing scope.
         */
        private val definedRegisters = mutableSetOf<String>()

        /**
         * The `emit(x)` / `send(x)` sinks of inlined flow/channel builders,
         * innermost first. While non-empty, a receiver-less `emit`/`send`
         * call assigns its argument into the builder's value register — how
         * `flow { emit(tainted) }` puts the element's taint on the flow
         * value the downstream operator and `collect` see.
         */
        private val emitSinks = mutableListOf<String>()

        /**
         * One frame per lexically enclosing `try` with catch
         * clauses, innermost LAST. A `throw` lowered while frames are open
         * binds every frame's catch-parameter registers to the thrown value
         * (an inner throw can escape to an outer handler); a body that
         * completes with no visible `throw` seeds the parameters at the
         * dispatch edge instead, from the body's live registers.
         */
        private class TryFrame(val dispatchId: String, val catchParams: List<String>) {
            val bodyRegs = sortedSetOf<String>()
            var visibleThrow = false
        }

        private val tryFrames = ArrayDeque<TryFrame>()

        /** Registers defined by the throw expression currently lowering, or null. */
        private var throwArgRegs: MutableSet<String>? = null

        init {
            blocks["b0"] = mutableListOf()
        }

        val current: MutableList<KirIns> get() = blocks.getValue(currentId)

        fun t(): String = "t${temp++}"

        private fun newId(): String = "b${counter++}"

        private fun emit(ins: KirIns) {
            definedRegisters.addAll(ins.defs)
            // An enclosing try's dispatch seed reads the registers
            // its body left live, so every instruction emitted under an open
            // frame contributes its registers to that frame. The throw-site
            // binding also needs the registers its own thrown expression
            // defined — the exception OBJECT is a fresh KirNew (clean by the
            // transfer's rule); its construction ARGUMENTS are where thrown
            // taint lives (IllegalStateException(tainted)), and they are
            // captured here while that expression lowers.
            for (frame in tryFrames) frame.bodyRegs.addAll(ins.defs + ins.uses)
            throwArgRegs?.addAll(ins.defs)
            current.add(ins)
        }

        /** Continues in a fresh block; [promised] uses an id already branched to. */
        private fun startBlock(promised: String? = null): String {
            currentId = promised ?: newId()
            blocks.getOrPut(currentId) { mutableListOf() }
            return currentId
        }

        /** Unconditional edge, expressed as a branch on a true constant. */
        private fun goto(target: String) {
            if (terminates()) return // a terminated arm simply does not join
            val cond = t()
            emit(KirLoad(cond, KirConstant.Bool(true)))
            emit(KirBranch(cond, target, target))
        }

        private fun terminates(): Boolean =
            current.lastOrNull() is KirReturn || current.lastOrNull() is KirThrow || current.lastOrNull() is KirBranch

        fun finish(): KirBody {
            // The emitted block list can contain blocks no edge reaches —
            // an all-paths-returned `if/else` still starts its join block,
            // and a `try` whose body and handlers all returned still starts
            // its continuation. A block nothing reaches is not dead SOURCE
            // (the source never runs it either); it is emitted noise the KIR
            // validator rejects and the engines simply never analyse — but
            // noise that will mask a REAL unreachable block (a lowering bug)
            // the day one appears. Drop unreachable blocks here, and strip
            // their ids from phis so the remaining inputs name only real
            // predecessors. Ids stay as emitted (no renumbering): every
            // consumer that names a block by id stays stable.
            val ordered = blocks.map { (id, instructions) -> KirBlock(id, id == "b0", instructions) }
            val byId = ordered.associateBy { it.id }
            val indexOf = ordered.withIndex().associate { (i, b) -> b.id to i }
            val reachable = HashSet<String>()
            val work = ArrayDeque<String>()
            work.add("b0")
            while (work.isNotEmpty()) {
                val id = work.removeFirst()
                if (!reachable.add(id)) continue
                val block = byId[id] ?: continue
                var terminates = false
                for (ins in block.instructions) {
                    when (ins) {
                        is KirBranch -> {
                            work.add(ins.thenBlock)
                            work.add(ins.elseBlock)
                            terminates = true
                        }
                        is KirReturn, is KirThrow -> terminates = true
                        else -> {}
                    }
                }
                if (terminates) continue
                ordered.getOrNull((indexOf[id] ?: continue) + 1)?.let { work.add(it.id) }
            }
            if (reachable.size == ordered.size) {
                return KirBody(ordered)
            }
            val cleaned = ordered.filter { it.id in reachable }.map { block ->
                if (block.instructions.none { it is KirPhi }) block else KirBlock(
                    block.id,
                    block.entry,
                    block.instructions.map { ins ->
                        if (ins is KirPhi && ins.inputs.keys.any { it !in reachable }) {
                            ins.copy(inputs = ins.inputs.filterKeys { it in reachable })
                        } else {
                            ins
                        }
                    },
                )
            }
            return KirBody(cleaned)
        }

        /** A terminator is already in place; do not add a second return. */
        fun returnIfOpen() {
            if (!terminates()) emit(KirReturn(null))
        }

        fun returnValue(register: String) {
            emit(KirReturn(register))
        }

        /** `v<name> = %<n>` for every named parameter, at function entry. */
        fun bindParameters(params: List<KirParam>) {
            for (param in params) {
                val name = param.name ?: continue
                emit(KirStore("v$name", param.register))
            }
        }

        fun fail(construct: String) {
            failures[construct] = (failures[construct] ?: 0) + 1
        }

        // ---- statements ----

        fun lowerStatement(psi: KtExpression) {
            when (psi) {
                is KtBlockExpression -> for (s in psi.statements) lowerStatement(s)
                is KtProperty -> lowerPropertyDeclaration(psi)
                is org.jetbrains.kotlin.psi.KtDestructuringDeclaration -> lowerDestructuring(psi)
                is KtReturnExpression -> {
                    val value = psi.returnedExpression?.let { lowerExpr(it, Pos.NESTED) }
                    emit(KirReturn(value))
                }
                is KtThrowExpression -> {
                    throwArgRegs = sortedSetOf()
                    val value = psi.thrownExpression?.let { lowerExpr(it, Pos.NESTED) } ?: throwNull()
                    val argRegs = throwArgRegs?.toList() ?: emptyList()
                    throwArgRegs = null
                    // Bind the exception registers of every enclosing
                    // try to what this throw threw. The binding is a dynamic
                    // call over the thrown register AND its construction
                    // arguments: `throw RuntimeException(userInput)` puts no
                    // fact on the fresh object's register (KirNew clears it),
                    // but the exception CARRIES its arguments — the message is
                    // the argument — so a may-analysis must let argument taint
                    // reach the handler's parameter. A clean throw binds clean
                    // registers and the handler's sink stays silent.
                    if (tryFrames.isNotEmpty()) {
                        val exc = t()
                        emit(KirDynamicCall(exc, THROWN_EXCEPTION, value, argRegs, line = psi.line()))
                        // INNERMOST frame gets the CFG edge (one terminator
                        // per block): the throw reaches its handlers
                        // directly. OUTER frames get only the parameter
                        // store — their handlers are reached through the
                        // outer body's own may-edges, and the bound state
                        // travels with them; and the outer seed stays armed,
                        // because the throw is not ITS body's direct value.
                        val innermost = tryFrames.last()
                        innermost.visibleThrow = true
                        for (frame in tryFrames) {
                            for (name in frame.catchParams) emit(KirStore("v$name", exc))
                        }
                        // The throw itself becomes the exceptional edge: a
                        // KirThrow terminates its block with no successor,
                        // and inside a guarded body the throw's DESTINATION
                        // is exactly the dispatch chain. The may-edge carries
                        // the freshly bound parameters; a fresh block absorbs
                        // any (source-dead) trailing statements, and the
                        // dead-block elimination drops it when empty.
                        val cond = t()
                        emit(KirLoad(cond, KirConstant.Bool(true)))
                        emit(KirBranch(cond, innermost.dispatchId, innermost.dispatchId))
                        startBlock()
                    } else {
                        emit(KirThrow(value))
                    }
                }
                is KtBreakExpression -> {
                    val target = loopExits.lastOrNull() ?: run { fail("break"); return }
                    val cond = t()
                    emit(KirLoad(cond, KirConstant.Bool(true)))
                    emit(KirBranch(cond, target, target))
                }
                is KtContinueExpression -> {
                    val target = loopContinues.lastOrNull() ?: run { fail("continue"); return }
                    val cond = t()
                    emit(KirLoad(cond, KirConstant.Bool(true)))
                    emit(KirBranch(cond, target, target))
                }
                is KtForExpression -> lowerFor(psi)
                is KtWhileExpression -> lowerWhile(psi)
                is KtDoWhileExpression -> lowerDoWhile(psi)
                is KtIfExpression -> lowerIfStatement(psi)
                is KtWhenExpression -> lowerWhen(psi, wantValue = false)
                is KtTryExpression -> lowerTry(psi)
                else -> lowerExpr(psi, Pos.STATEMENT)
            }
        }

        private val loopExits = ArrayDeque<String>()
        private val loopContinues = ArrayDeque<String>()

        /**
         * Inlined bodies of `apply`/`run`/`with` run with the scope
         * function's receiver bound as `this`: member reads and writes inside
         * the lambda target the receiver register, not the enclosing
         * function's `this`. Stacked so nested scope functions restore the
         * outer binding when their body ends.
         */
        private val thisOverrides = ArrayDeque<String>()

        // The implicit receiver register is the ENTRY PARAMETER STORE (`v$this`
        // from bindParameters) — not a distinct "v this" register nothing
        // ever defines: with the old name, member reads and writes on the
        // implicit receiver never saw the receiver's state, and a member
        // function's own parameters never reached its fields.
        private fun currentThis(): String = thisOverrides.lastOrNull() ?: "vthis"

        private fun throwNull(): String {
            val reg = t()
            emit(KirNew(reg, "kotlin.NullPointerException", emptyList()))
            return reg
        }

        private fun lowerPropertyDeclaration(psi: KtProperty) {
            val register = "v${psi.name ?: "local$temp"}"
            when {
                psi.delegateExpression != null -> {
                    // Delegated property -> getValue call (§4).
                    val delegate = psi.delegateExpression ?: return
                    val receiver = lowerExpr(delegate, Pos.NESTED)
                    val result = t()
                    emit(
                        KirCall(
                            result,
                            KirCallee("kotlin.properties.getValue", null, CallKind.EXTENSION),
                            receiver,
                            emptyList(),
                            line = psi.line(),
                        ),
                    )
                    emit(KirStore(register, result))
                }
                psi.initializer != null -> {
                    // A property declaration is a statement: `?:` and `?.` in
                    // the initializer join through the CFG like any other.
                    val value = lowerExpr(psi.initializer!!, Pos.STATEMENT)
                    emit(KirStore(register, value))
                }
                else -> {
                    // lateinit / abstract / open-with-override: declared
                    // elsewhere; the local simply starts null here.
                    val reg = t()
                    emit(KirLoad(reg, KirConstant.Null))
                    emit(KirStore(register, reg))
                }
            }
        }

        /** `val (a, b) = pair` -> componentN calls (§4). */
        private fun lowerDestructuring(psi: org.jetbrains.kotlin.psi.KtDestructuringDeclaration) {
            val value = psi.initializer?.let { lowerExpr(it, Pos.NESTED) } ?: run { fail("destructuring"); return }
            psi.entries.forEachIndexed { index, entry ->
                val component = t()
                emit(
                    KirCall(
                        component,
                        KirCallee("kotlin.component${index + 1}", null, CallKind.EXTENSION),
                        value,
                        emptyList(),
                        line = psi.line(),
                    ),
                )
                entry.name?.let { emit(KirStore("v$it", component)) }
            }
        }

        private fun lowerFor(psi: KtForExpression) {
            // `for (x in xs) BODY` -> iterator/hasNext/next (§4).
            val iterated = psi.loopRange?.let { lowerExpr(it, Pos.NESTED) } ?: run { fail("for"); return }
            val iterator = t()
            emit(
                KirCall(
                    iterator,
                    KirCallee("kotlin.collections.iterator", null, CallKind.EXTENSION),
                    iterated,
                    emptyList(),
                    line = psi.line(),
                ),
            )
            val headerId = newId()
            val bodyId = newId()
            val exitId = newId()
            // The iterator call stays in the entry block (executed once);
            // the header block carries hasNext + the loop branch.
            startBlock(headerId)
            val hasNext = t()
            emit(
                KirCall(
                    hasNext,
                    KirCallee("kotlin.collections.hasNext", null, CallKind.EXTENSION),
                    iterator,
                    emptyList(),
                    line = psi.line(),
                ),
            )
            emit(KirBranch(hasNext, bodyId, exitId))
            startBlock(bodyId)
            val next = t()
            emit(
                KirCall(
                    next,
                    KirCallee("kotlin.collections.next", null, CallKind.EXTENSION),
                    iterator,
                    emptyList(),
                    line = psi.line(),
                ),
            )
            val loopParameter = psi.loopParameter
            val destructuring = psi.destructuringDeclaration
            if (destructuring != null) {
                // Destructuring -> componentN calls (§4).
                destructuring.entries.forEachIndexed { index, entry ->
                    val component = t()
                    emit(
                        KirCall(
                            component,
                            KirCallee("kotlin.component${index + 1}", null, CallKind.EXTENSION),
                            next,
                            emptyList(),
                            line = psi.line(),
                        ),
                    )
                    entry.name?.let { emit(KirStore("v$it", component)) }
                }
            } else if (loopParameter?.name != null) {
                emit(KirStore("v${loopParameter.name}", next))
            }
            loopExits.addLast(exitId)
            loopContinues.addLast(headerId)
            psi.body?.let { lowerStatement(it) }
            loopContinues.removeLast()
            loopExits.removeLast()
            goto(headerId)
            startBlock(exitId)
        }

        private fun lowerWhile(psi: KtWhileExpression) {
            val headerId = newId()
            goto(headerId)
            startBlock(headerId)
            val cond = psi.condition?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            val bodyId = newId()
            val exitId = newId()
            emit(KirBranch(cond, bodyId, exitId))
            startBlock(bodyId)
            loopExits.addLast(exitId)
            loopContinues.addLast(headerId)
            psi.body?.let { lowerStatement(it) }
            loopContinues.removeLast()
            loopExits.removeLast()
            goto(headerId)
            startBlock(exitId)
        }

        private fun lowerDoWhile(psi: KtDoWhileExpression) {
            val bodyId = newId()
            val condId = newId()
            val exitId = newId()
            goto(bodyId)
            startBlock(bodyId)
            loopExits.addLast(exitId)
            loopContinues.addLast(condId)
            psi.body?.let { lowerStatement(it) }
            loopContinues.removeLast()
            loopExits.removeLast()
            goto(condId)
            startBlock(condId)
            val cond = psi.condition?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            emit(KirBranch(cond, bodyId, exitId))
            startBlock(exitId)
        }

        private fun lowerIfStatement(psi: KtIfExpression) {
            lowerIf(psi, wantValue = false)
        }

        /**
         * `if` lowering: branch, arms, join; with a value the join carries a
         * phi over the arm results (`?:` uses the same shape).
         */
        private fun lowerIf(psi: KtIfExpression, wantValue: Boolean): String? {
            val cond = psi.condition?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            val thenId = newId()
            val elseId = newId()
            val joinId = newId()
            emit(KirBranch(cond, thenId, elseId))
            startBlock(thenId)
            val thenResult = psi.then?.let { lowerExpr(it, if (wantValue) Pos.NESTED else Pos.STATEMENT) }
            goto(joinId)
            startBlock(elseId)
            val elseResult = psi.`else`?.let { lowerExpr(it, if (wantValue) Pos.NESTED else Pos.STATEMENT) }
            goto(joinId)
            startBlock(joinId)
            if (wantValue) {
                val phi = t()
                emit(
                    KirPhi(
                        phi,
                        buildMap {
                            put(thenId, thenResult ?: "null-reg")
                            put(elseId, elseResult ?: "null-reg")
                        },
                    ),
                )
                return phi
            }
            return null
        }

        private fun lowerWhen(psi: KtWhenExpression, wantValue: Boolean): String? {
            // Condition blocks chain: entry i's checks live in the block the
            // previous entry's branch jumped to for "no match"; a match goes
            // to that entry's body, which rejoins at the end.
            val subject = psi.subjectExpression?.let { lowerExpr(it, Pos.NESTED) }
            val joinId = newId()
            val arms = mutableListOf<Pair<String, String>>() // body block -> result register
            val bodyIds = psi.entries.map { newId() }
            psi.entries.forEachIndexed { index, entry ->
                val bodyId = bodyIds[index]
                val nextId = if (index == psi.entries.lastIndex) joinId else newId()
                val cond = if (entry.isElse) {
                    val cond = t()
                    emit(KirLoad(cond, KirConstant.Bool(true)))
                    cond
                } else {
                    entry.conditions.fold(null as String?) { acc, condition ->
                        val matched = when (condition) {
                            is org.jetbrains.kotlin.psi.KtWhenConditionWithExpression -> {
                                val expected = condition.expression?.let { lowerExpr(it, Pos.NESTED) } ?: run {
                                    val reg = t()
                                    emit(KirLoad(reg, KirConstant.Null))
                                    reg
                                }
                                if (subject != null) {
                                    val call = t()
                                    emit(
                                        KirCall(
                                            call,
                                            KirCallee("kotlin.equals", null, CallKind.STATIC),
                                            null,
                                            listOf(subject, expected),
                                            line = psi.line(),
                                        ),
                                    )
                                    call
                                } else {
                                    expected
                                }
                            }
                            is org.jetbrains.kotlin.psi.KtWhenConditionIsPattern -> {
                                val check = t()
                                emit(
                                    KirTypeCheck(
                                        check,
                                        subject ?: "null-reg",
                                        condition.typeReference?.text ?: "unknown",
                                    ),
                                )
                                check
                            }
                            is org.jetbrains.kotlin.psi.KtWhenConditionInRange -> {
                                val range = condition.rangeExpression?.let { lowerExpr(it, Pos.NESTED) }
                                val call = t()
                                emit(
                                    KirCall(
                                        call,
                                        KirCallee("kotlin.collections.contains", null, CallKind.EXTENSION),
                                        range,
                                        listOfNotNull(subject),
                                        line = psi.line(),
                                    ),
                                )
                                call
                            }
                            else -> {
                                fail("when-condition")
                                null
                            }
                        }
                        acc ?: matched
                    } ?: run {
                        val cond = t()
                        emit(KirLoad(cond, KirConstant.Bool(true)))
                        cond
                    }
                }
                emit(KirBranch(cond, bodyId, nextId))
                startBlock(bodyId)
                val result = entry.expression?.let { lowerExpr(it, Pos.NESTED) } ?: "null-reg"
                arms.add(bodyId to result)
                goto(joinId)
                startBlock(nextId)
            }
            // The join phi is the when's value; statement-form whens just
            // fall through.
            if (wantValue) {
                val phi = t()
                emit(KirPhi(phi, arms.ifEmpty { listOf(joinId to "null-reg") }.toMap()))
                return phi
            }
            return null
        }

        private fun lowerTry(psi: KtTryExpression) {
            // try body, one catch path per clause, finally last — the shape
            // `use` lowering produces directly and source try lowers into.
            //
            // the CFG has no exceptional-edge instruction, so catch
            // handlers lowered as standalone blocks had NO incoming edge at
            // all — structurally unreachable, never analysed, and taint
            // through them silently dropped (InsecureShop's
            // `catch (e) { throw RuntimeException(e) }` and
            // `catch (e: Exception) { return null }` were dead code to the
            // engine). The fix is an explicit may-edge into a DISPATCH CHAIN
            // over the handlers: any call in the try body may throw, and
            // which handler runs depends on the exception's type, which the
            // KIR cannot express — so every handler is reachable from the
            // chain and no handler flows into another (running h1 to
            // completion does not run h2). Two may-edges feed the chain:
            // from the try body's ENTRY (a throw at the first call carries
            // the pre-body state; the only edge possible when the body ends
            // terminated) and from the body's open END (a throw at the last
            // call; over-approximates mid-body throws — conservative for a
            // may-analysis). The transfer treats a branch's two arms as
            // may-successors without evaluating the condition, so a
            // true-condition branch is exactly this may-edge.
            val finallyId = newId()
            val catches = psi.catchClauses
            if (catches.isEmpty()) {
                psi.tryBlock?.let { lowerStatement(it) }
                goto(finallyId)
            } else {
                val dispatchId = newId()
                val bodyId = newId()
                // ENTRY fork: continue into the body, or (may-)throw now.
                val entryCond = t()
                emit(KirLoad(entryCond, KirConstant.Bool(true)))
                emit(KirBranch(entryCond, bodyId, dispatchId))
                startBlock(bodyId)
                // The handler's own PARAMETER is a value a handler is
                // written to read, and until now it existed nowhere in the KIR —
                // `catch (e: Exception)` read `e` as a FIELD on `this`. The
                // parameter is bound on the dispatch chain's edge in two shapes:
                // at a VISIBLE `throw` site the thrown register (and its
                // construction arguments) flows into every enclosing handler's
                // parameter register (see the KtThrowExpression arm); where NO
                // throw is visible the body may still throw implicitly (a
                // platform call failing), and the exception object is modelled as
                // an UNKNOWN value that inherits whatever taint the body left
                // live on the dispatch edge — tainted-if-the-body-was, the same
                // sound-leaning default an unresolved call gets, and clean when
                // the body was clean (a handler for a clean body must not
                // report). A visible CLEAN throw suppresses the seed: the thrown
                // value is then known, and blanket body-taint would report flows
                // the guarded code cannot produce.
                val frame = TryFrame(dispatchId, catches.mapNotNull { it.catchParameter?.name }.distinct())
                tryFrames.addLast(frame)
                psi.tryBlock?.let { lowerStatement(it) }
                tryFrames.removeLast()
                // END fork, only when the body's last block is still open.
                if (!terminates()) {
                    val endCond = t()
                    emit(KirLoad(endCond, KirConstant.Bool(true)))
                    emit(KirBranch(endCond, finallyId, dispatchId))
                }
                // The dispatch chain: one block per handler step, each
                // branching to its handler and to the next step. The seed
                // (no visible throw) is emitted at the head of the chain,
                // where both may-edges join, so it reads the union of the
                // try-entry and try-end states.
                startBlock(dispatchId)
                if (!frame.visibleThrow) {
                    for (name in frame.catchParams) {
                        val exc = t()
                        emit(
                            KirDynamicCall(
                                exc,
                                THROWN_EXCEPTION,
                                null,
                                frame.bodyRegs.filter { it != "v$name" }.sorted(),
                            ),
                        )
                        emit(KirStore("v$name", exc))
                    }
                }
                var step = dispatchId
                for ((index, catch) in catches.withIndex()) {
                    val handlerId = newId()
                    startBlock(step)
                    val cond = t()
                    if (index == catches.lastIndex) {
                        emit(KirLoad(cond, KirConstant.Bool(true)))
                        emit(KirBranch(cond, handlerId, handlerId))
                    } else {
                        val nextStep = newId()
                        emit(KirLoad(cond, KirConstant.Bool(true)))
                        emit(KirBranch(cond, handlerId, nextStep))
                        step = nextStep
                    }
                    startBlock(handlerId)
                    catch.catchBody?.let { lowerStatement(it) }
                    goto(finallyId)
                }
            }
            startBlock(finallyId)
            psi.finallyBlock?.finalExpression?.let { lowerStatement(it) }
        }

        // ---- expressions ----

        fun lowerExpr(psi: KtExpression, pos: Pos): String = when (psi) {
            is KtConstantExpression -> constant(psi)
            is KtStringTemplateExpression -> stringTemplate(psi)
            is org.jetbrains.kotlin.psi.KtParenthesizedExpression -> psi.expression?.let { lowerExpr(it, pos) } ?: run { fail("paren"); unknown(psi) }
            is KtBlockExpression -> blockValue(psi)
            is KtIfExpression -> lowerIf(psi, wantValue = true) ?: unknown(psi)
            is KtWhenExpression -> lowerWhen(psi, wantValue = true) ?: unknown(psi)
            is KtBinaryExpression -> binary(psi, pos)
            is org.jetbrains.kotlin.psi.KtBinaryExpressionWithTypeRHS -> typeCast(psi)
            is org.jetbrains.kotlin.psi.KtPostfixExpression -> postfix(psi)
            is org.jetbrains.kotlin.psi.KtPrefixExpression -> prefix(psi)
            is KtDotQualifiedExpression -> dotChain(psi)
            is KtSafeQualifiedExpression -> safeCall(psi)
            is KtCallExpression -> call(psi)
            is KtThisExpression -> thisReg()
            is org.jetbrains.kotlin.psi.KtSuperExpression -> "v super"
            is KtLambdaExpression -> lambda(psi)
            is org.jetbrains.kotlin.psi.KtAnnotatedExpression -> psi.baseExpression?.let { lowerExpr(it, pos) } ?: unknown(psi)
            is org.jetbrains.kotlin.psi.KtClassLiteralExpression -> {
                // `Foo::class` carries evidence, not computation: a named
                // constant keeps the reference visible without pretending to
                // model class objects.
                val reg = t()
                emit(KirLoad(reg, KirConstant.Str("kclass ${psi.receiverExpression?.text ?: psi.text}")))
                reg
            }
            is org.jetbrains.kotlin.psi.KtCallableReferenceExpression -> {
                // The RESOLVED target, not the source text. A reference is
                // a function value whose target is known at its allocation
                // site — which is exactly what the invoke-bind channel
                // needs to carry taint through it — and naming it `::sink`
                // made that channel unreachable for every reference
                // spelling in the language. The text survives as the
                // fallback so an unresolvable reference is still visible as
                // a function value rather than vanishing.
                val reg = t()
                emit(KirLambda(reg, lambdaContext?.resolveReference?.invoke(psi) ?: psi.text, emptyList()))
                reg
            }
            is KtNamedFunction -> {
                // A local or anonymous function at value position: its body
                // lowers as its own KIR function (collectFunctionLikes
                // visits it), and the use site must name it the way that
                // function is NAMED — package-qualified, container chain and
                // all. The bare `sink` / `<local-fun>` written here before
                // matched no function in any table, so an anonymous `fun`
                // and a `::reference` were function values pointing at
                // nothing (the sweep).
                val reg = t()
                emit(KirLambda(reg, canonicalNameOfDeclaration(psi), emptyList()))
                reg
            }
            is KtProperty -> {
                // A property at value position (last statement of an inlined
                // lambda): lower the declaration, the value is the local.
                lowerPropertyDeclaration(psi)
                "v${psi.name ?: "local$temp"}"
            }
            is KtObjectLiteralExpression -> {
                // Anonymous object: its members lower as their own functions
                // (the visitor reaches them); the site names the object.
                val reg = t()
                val supertypes = psi.objectDeclaration?.superTypeListEntries
                    ?.joinToString(",") { it.text ?: "" } ?: ""
                emit(KirLoad(reg, KirConstant.Str("object <$supertypes>")))
                reg
            }
            is KtIsExpression -> {
                val value = lowerExpr(psi.leftHandSide, Pos.NESTED)
                val check = t()
                emit(KirTypeCheck(check, value, psi.typeReference?.text ?: "unknown"))
                check
            }
            is KtNameReferenceExpression -> reference(psi)
            is org.jetbrains.kotlin.psi.KtArrayAccessExpression -> arrayAccess(psi)
            is KtReturnExpression, is KtThrowExpression, is KtBreakExpression, is KtContinueExpression -> {
                // A control-flow statement at a value position (an inlined
                // lambda arm): the function's control flow leaves, the
                // position yields no value.
                lowerStatement(psi)
                "null-reg"
            }
            is KtForExpression, is KtWhileExpression, is KtDoWhileExpression, is KtTryExpression -> {
                // Loop/try at value position (inlined lambda arm).
                lowerStatement(psi)
                "null-reg"
            }
            is org.jetbrains.kotlin.psi.KtLabeledExpression -> {
                // The label decorates a loop/block; the KIR's explicit edges
                // already carry what the label named.
                psi.baseExpression?.let { lowerStatement(it) }
                "null-reg"
            }
            is org.jetbrains.kotlin.psi.KtClass -> {
                // A local class: members lower as their own functions; the
                // site names the class.
                val reg = t()
                emit(KirLoad(reg, KirConstant.Str("local class ${psi.name ?: "<anonymous>"}")))
                reg
            }
            else -> {
                fail("expression:${psi.javaClass.simpleName}")
                unknown(psi)
            }
        }

        /** A block at value position: its statements, then the last value. */
        private fun blockValue(psi: KtBlockExpression): String {
            val statements = psi.statements
            if (statements.isEmpty()) return unknown(psi)
            for (statement in statements.dropLast(1)) lowerStatement(statement)
            return lowerExpr(statements.last(), Pos.NESTED)
        }

        /** `as` / `as?` -> Cast (§4's cast family). The operation reference's
         *  text is `as` or `as?` on every PSI build. */
        private fun typeCast(psi: org.jetbrains.kotlin.psi.KtBinaryExpressionWithTypeRHS): String {
            val value = lowerExpr(psi.left, Pos.NESTED)
            val reg = t()
            val safe = psi.operationReference.text == "as?"
            emit(KirCast(reg, value, psi.right?.text ?: "unknown", checked = !safe))
            return reg
        }

        /** Unary `-`/`+`/`!`/`++`/`--` -> named calls. */
        private fun prefix(psi: org.jetbrains.kotlin.psi.KtPrefixExpression): String {
            val base = psi.baseExpression?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            val name = when (psi.operationToken) {
                KtTokens.PLUS -> "unaryPlus"
                KtTokens.MINUS -> "unaryMinus"
                KtTokens.EXCL -> "not"
                KtTokens.PLUSPLUS -> "inc"
                KtTokens.MINUSMINUS -> "dec"
                else -> {
                    fail("prefix:${psi.operationToken}")
                    return base
                }
            }
            val reg = t()
            emit(KirCall(reg, KirCallee("kotlin.$name", null, CallKind.OPERATOR), base, emptyList(), line = psi.line()))
            return reg
        }

        /**
         * A Kotlin integer literal's VALUE: decimal, hex and binary, with
         * the underscores and the `L`/`u`/`U` suffixes Kotlin allows. A
         * literal that does not parse stays its source text (a Str), which
         * is what every integer literal used to be — losing the digits to a
         * silent 0 would be worse than the untyped form it replaces.
         */
        private fun parseInteger(text: String): KirConstant {
            val cleaned = text.replace("_", "").removeSuffix("L").removeSuffix("u").removeSuffix("U")
            val value = when {
                cleaned.startsWith("0x") || cleaned.startsWith("0X") -> cleaned.drop(2).toLongOrNull(16)
                cleaned.startsWith("0b") || cleaned.startsWith("0B") -> cleaned.drop(2).toLongOrNull(2)
                else -> cleaned.toLongOrNull()
            }
            return value?.let { KirConstant.IntConst(it) } ?: KirConstant.Str(text)
        }

        private fun constant(psi: KtConstantExpression): String {
            val reg = t()
            // A KtConstantExpression's element type is its NODE type
            // (KtNodeTypes.INTEGER_CONSTANT, ..., NULL) — never the lexer
            // TOKEN (KtTokens.INTEGER_LITERAL, ...). Matching tokens here
            // meant every arm missed and every literal lowered through the
            // `else`: `5`, `true` and `null` all became KirConstant.Str of
            // their source TEXT, so the typed constants were unreachable and
            // a null literal was indistinguishable from the string "null"
            // (a later review). The distinction is not cosmetic: the contract
            // DSL's `security = null` is the ABSENCE of a requirement, and
            // it read as a value.
            val constant = when (psi.node.elementType) {
                KtNodeTypes.INTEGER_CONSTANT -> parseInteger(psi.text)
                KtNodeTypes.FLOAT_CONSTANT ->
                    KirConstant.FloatConst(psi.text.removeSuffix("f").removeSuffix("F").toDoubleOrNull() ?: 0.0)
                KtNodeTypes.BOOLEAN_CONSTANT -> KirConstant.Bool(psi.text == "true")
                KtNodeTypes.NULL -> KirConstant.Null
                else -> KirConstant.Str(psi.text)
            }
            emit(KirLoad(reg, constant))
            return reg
        }

        private fun stringTemplate(psi: KtStringTemplateExpression): String {
            // String template -> StringConcat (§4); all-literal templates stay a Load.
            val parts = psi.entries.mapNotNull { entry ->
                when (entry) {
                    is org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry -> entry.text.takeIf { it.isNotEmpty() }
                    is org.jetbrains.kotlin.psi.KtSimpleNameStringTemplateEntry ->
                        entry.expression?.let { lowerExpr(it, Pos.NESTED) }
                    is org.jetbrains.kotlin.psi.KtBlockStringTemplateEntry ->
                        entry.expression?.let { lowerExpr(it, Pos.NESTED) }
                    else -> null
                }
            }
            val reg = t()
            val allConstant = psi.entries.all { it is org.jetbrains.kotlin.psi.KtLiteralStringTemplateEntry }
            if (allConstant) {
                emit(KirLoad(reg, KirConstant.Str(psi.text)))
            } else {
                emit(KirStringConcat(reg, parts))
            }
            return reg
        }

        private fun reference(psi: KtNameReferenceExpression): String {
            val name = psi.getReferencedName()
            if (isLocalReference(psi)) {
                return "v$name"
            }
            // Not a local. A BARE-NAME read can still RUN A METHOD on the JVM
            // — the sibling: `call` inside a Ktor route lambda is an
            // implicit-receiver property whose getter runs, and lowering it
            // as `fieldget vthis vthis.call` hides the callee from every
            // pack exactly the way `a.b` did previously. The same rule as
            // dotChain: resolve the reference, and lower as a call only when
            // the property demonstrably has NO backing field. A property with
            // a backing field keeps its access path, so field
            // sensitivity is untouched.
            val propertyInfo = resolvePropertyInfo(psi)
            if (propertyInfo != null) {
                val fqn = propertyInfo.symbol.callableId?.asSingleFqName()?.asString()
                if (fqn != null) {
                    // A member property's getter dispatches virtually. A
                    // TOP-LEVEL EXTENSION property's getter is static on the
                    // JVM but still READS its receiver — `val
                    // ApplicationRequest.uri` is exactly that shape — so it
                    // takes the implicit receiver even though its kind is
                    // static. Only a receiverless top-level property gets
                    // neither, or taint arriving on the receiver would stop
                    // at every extension accessor.
                    val member = propertyInfo.symbol.callableId?.className != null
                    val extension = propertyInfo.symbol.receiverParameter != null
                    val reg = t()
                    emit(
                        KirCall(
                            reg,
                            KirCallee(fqn, propertyInfo.descriptor, if (member) CallKind.VIRTUAL else CallKind.STATIC),
                            if (member || extension) currentThis() else null,
                            emptyList(),
                            line = psi.line(),
                        ),
                    )
                    return reg
                }
            }
            // A stored field read, carried by the access path over the
            // CURRENT `this` (a scope function's receiver when inside an
            // inlined apply/run/with).
            val thisReg = currentThis()
            val reg = t()
            emit(
                KirFieldGet(
                    reg,
                    thisReg,
                    AccessPath.of(thisReg, listOf(AccessPath.Element.Field(name))),
                ),
            )
            return reg
        }

        /**
         * Pure-PSI scope check: the name is declared as this function's
         * parameter or as a local property/destructuring entry in an
         * enclosing block. NO `KtReference.resolve()` here — K1's reference
         * resolution re-enters the analysis machinery under its own
         * `analyze`, which deadlocks in a native image (observed: every
         * `kir dump` hung; the JVM tolerated the re-entry). The lowering's
         * only resolution is the ambient `resolveCall` pass, which
         * ResolvedAnalyzer had already proven image-safe.
         */
        private fun isLocalReference(psi: KtNameReferenceExpression): Boolean {
            val name = psi.getReferencedName()
            // Kotlin's implicit lambda parameter: the scope-function lowering
            // binds it as a plain local (`v it` <- receiver), so a read of it
            // must be a local read, not a member access on `this`.
            if (name == "it") return true
            var cursor: com.intellij.psi.PsiElement? = psi.parent
            while (cursor != null) {
                when (cursor) {
                    is KtNamedFunction -> {
                        if (cursor.valueParameters.any { it.name == name }) return true
                    }

                    // A NAMED lambda parameter (`collect { value -> .. }`):
                    // the lowering binds it as a plain local exactly like the
                    // implicit `it`, so a read of it must be a local read.
                    is KtLambdaExpression -> {
                        if (cursor.valueParameters.any { it.name == name }) return true
                    }

                    is org.jetbrains.kotlin.psi.KtForExpression -> {
                        // A `for` loop parameter is bound to the next() result
                        // by the lowering (`v<name>` <- iterator.next()); a
                        // read of it must stay a local read.
                        if (cursor.loopParameter?.name == name) return true
                        if (cursor.destructuringDeclaration?.entries?.any { it.name == name } == true) return true
                    }

                    // A catch parameter is bound at the dispatch edge
                    // (`v<name>` <- the thrown value, or the unknown-exception
                    // seed); a read of it inside the handler is a local read,
                    // not a field on `this`.
                    is org.jetbrains.kotlin.psi.KtCatchClause -> {
                        if (cursor.catchParameter?.name == name) return true
                    }

                    is KtBlockExpression, is org.jetbrains.kotlin.psi.KtClassBody -> {
                        for (child in cursor.children) {
                            when (child) {
                                is KtProperty -> if (child.isLocal && child.name == name) return true
                                is org.jetbrains.kotlin.psi.KtDestructuringDeclaration ->
                                    if (child.entries.any { it.name == name }) return true
                                else -> {}
                            }
                        }
                    }

                    else -> {}
                }
                cursor = cursor.parent
            }
            return false
        }

        private fun thisReg(): String = currentThis()

        private fun arrayAccess(psi: org.jetbrains.kotlin.psi.KtArrayAccessExpression): String {
            val receiver = psi.arrayExpression?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            val index = psi.indexExpressions.firstOrNull()?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            val reg = t()
            emit(KirIndexGet(reg, receiver, index))
            return reg
        }

        private fun unknown(psi: KtExpression): String {
            val reg = t()
            emit(KirLoad(reg, KirConstant.Null))
            return reg
        }

        private fun binary(psi: KtBinaryExpression, pos: Pos): String {
            val token = psi.operationToken
            return when (token) {
                KtTokens.EQ -> assign(psi)
                KtTokens.PLUSEQ, KtTokens.MINUSEQ, KtTokens.MULTEQ, KtTokens.DIVEQ, KtTokens.PERCEQ ->
                    compoundAssign(psi)
                KtTokens.ELVIS -> elvis(psi, pos)
                KtTokens.EXCLEXCL -> notNull(psi)
                else -> namedOperator(psi)
            }
        }

        private fun assign(psi: KtBinaryExpression): String {
            val value = psi.right?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            when (val target = psi.left) {
                is KtNameReferenceExpression -> {
                    if (!isLocalReference(target)) {
                        // A member field of the enclosing receiver.
                        val receiver = target.receiverExpressionSafe()
                        emit(
                            KirFieldSet(
                                receiver,
                                AccessPath.of(receiver, listOf(AccessPath.Element.Field(target.getReferencedName()))),
                                value,
                            ),
                        )
                    } else {
                        emit(KirStore("v${target.getReferencedName()}", value))
                    }
                }
                is KtDotQualifiedExpression -> {
                    val name = (target.selectorExpression as? KtNameReferenceExpression)?.getReferencedName()
                    if (name == null) {
                        fail("assignment-target")
                    } else {
                        // The whole qualifier chain, so the key this write
                        // lands on is the key the matching read looks at.
                        val (base, path) = fieldAccess(target.receiverExpression, name)
                        emit(KirFieldSet(base, path, value))
                    }
                }
                is org.jetbrains.kotlin.psi.KtArrayAccessExpression -> {
                    val receiver = target.arrayExpression?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
                    val index = target.indexExpressions.firstOrNull()?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
                    emit(KirIndexSet(receiver, index, value))
                }
                is KtSafeQualifiedExpression -> {
                    val receiver = lowerExpr(target.receiverExpression, Pos.NESTED)
                    val name = (target.selectorExpression as? KtNameReferenceExpression)?.getReferencedName()
                    if (name == null) {
                        fail("assignment-target:safe:${target.text.take(60)}")
                    } else {
                        emit(
                            KirFieldSet(
                                receiver,
                                AccessPath.of(receiver, listOf(AccessPath.Element.Field(name))),
                                value,
                            ),
                        )
                    }
                }
                else -> fail("assignment-target:${target?.javaClass?.simpleName}:${target?.text?.take(60)}")
            }
            return value
        }

        /**
         * `x += y` desugars to `x = x.plus(y)` for every assignment target
         * shape: read, named call, write back.
         */
        private fun compoundAssign(psi: KtBinaryExpression): String {
            val value = psi.right?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            val simpleToken = when (psi.operationToken) {
                KtTokens.PLUSEQ -> KtTokens.PLUS
                KtTokens.MINUSEQ -> KtTokens.MINUS
                KtTokens.MULTEQ -> KtTokens.MUL
                KtTokens.DIVEQ -> KtTokens.DIV
                else -> KtTokens.PERC
            }
            val opName = operatorName(simpleToken) ?: run {
                fail("operator:${psi.operationToken}")
                return value
            }
            fun call(left: String): String {
                val reg = t()
                emit(KirCall(reg, KirCallee("kotlin.$opName", null, CallKind.OPERATOR), left, listOf(value), line = psi.line()))
                return reg
            }
            when (val target = psi.left) {
                is KtNameReferenceExpression -> {
                    if (!isLocalReference(target)) {
                        val receiver = target.receiverExpressionSafe()
                        val path = AccessPath.of(receiver, listOf(AccessPath.Element.Field(target.getReferencedName())))
                        val read = t()
                        emit(KirFieldGet(read, receiver, path))
                        val combined = call(read)
                        emit(KirFieldSet(receiver, path, combined))
                    } else {
                        val name = "v${target.getReferencedName()}"
                        val read = t()
                        emit(KirFieldGet(read, name, AccessPath.of(name, emptyList())))
                        val combined = call(read)
                        emit(KirStore(name, combined))
                    }
                }
                is KtDotQualifiedExpression -> {
                    val name = (target.selectorExpression as? KtNameReferenceExpression)?.getReferencedName()
                    if (name == null) {
                        fail("assignment-target:${target.selectorExpression?.javaClass?.simpleName}")
                    } else {
                        val (base, path) = fieldAccess(target.receiverExpression, name)
                        val read = t()
                        emit(KirFieldGet(read, base, path))
                        emit(KirFieldSet(base, path, call(read)))
                    }
                }
                is org.jetbrains.kotlin.psi.KtArrayAccessExpression -> {
                    val receiver = target.arrayExpression?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
                    val index = target.indexExpressions.firstOrNull()?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
                    val read = t()
                    emit(KirIndexGet(read, receiver, index))
                    emit(KirIndexSet(receiver, index, call(read)))
                }
                else -> {
                    fail("assignment-target:${target?.javaClass?.simpleName}:${target?.text?.take(60)}")
                }
            }
            return value
        }

        private fun KtNameReferenceExpression.receiverExpressionSafe(): String {
            val parentDot = parent as? KtDotQualifiedExpression
            return if (parentDot != null) lowerExpr(parentDot.receiverExpression, Pos.NESTED) else currentThis()
        }

        /** `?:` -> phi at statement/return positions (§4); Elvis opcode nested. */
        private fun elvis(psi: KtBinaryExpression, pos: Pos): String {
            val left = psi.left?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            // A fallback that itself leaves the function (`x ?: return`) must
            // lower INSIDE the null arm's block — a terminator can never land
            // in the middle of the current one. Plain expressions at nested
            // positions keep the Elvis opcode (the §4 shape pinned).
            val fallbackLeaves = psi.right.let { it is KtReturnExpression || it is KtThrowExpression }
            if (pos == Pos.NESTED && !fallbackLeaves) {
                val fallback = psi.right?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
                val reg = t()
                emit(KirElvis(reg, left, fallback))
                return reg
            }
            val isNull = t()
            emit(KirCall(isNull, KirCallee("kotlin.isNull", null, CallKind.STATIC), null, listOf(left), line = psi.line()))
            val nullId = newId()
            val valueId = newId()
            val joinId = newId()
            emit(KirBranch(isNull, nullId, valueId))
            startBlock(nullId)
            val fallback = psi.right?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            goto(joinId)
            startBlock(valueId)
            goto(joinId)
            startBlock(joinId)
            val phi = t()
            emit(KirPhi(phi, mapOf(nullId to fallback, valueId to left)))
            return phi
        }

        /** `!!` -> checked cast plus a throw branch on the null path (§4). */
        private fun notNull(psi: KtBinaryExpression): String {
            val left = psi.left?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            return notNullOf(left, psi.line())
        }

        /** `x!!` (checked cast) and `x++`/`x--` (inc/dec). The post-form's
         *  old-value semantics are not modelled: the KIR exposes the inc/dec
         *  call, which is the evidence a flow engine needs. */
        private fun postfix(psi: org.jetbrains.kotlin.psi.KtPostfixExpression): String {
            val left = psi.baseExpression?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            when (psi.operationToken) {
                KtTokens.EXCLEXCL -> return notNullOf(left, psi.line())
                KtTokens.PLUSPLUS, KtTokens.MINUSMINUS -> {
                    val name = if (psi.operationToken == KtTokens.PLUSPLUS) "inc" else "dec"
                    val reg = t()
                    emit(KirCall(reg, KirCallee("kotlin.$name", null, CallKind.OPERATOR), left, emptyList(), line = psi.line()))
                    return reg
                }
            }
            fail("postfix:${psi.operationToken}")
            return left
        }

        private fun notNullOf(left: String, line: Int): String {
            val isNull = t()
            emit(KirCall(isNull, KirCallee("kotlin.isNull", null, CallKind.STATIC), null, listOf(left), line = line))
            val throwId = newId()
            val okId = newId()
            emit(KirBranch(isNull, throwId, okId))
            startBlock(throwId)
            val npe = t()
            emit(KirNew(npe, "kotlin.KotlinNullPointerException", emptyList()))
            emit(KirThrow(npe))
            startBlock(okId)
            val reg = t()
            emit(KirCast(reg, left, "T", checked = true))
            return reg
        }

        /** Operators -> named calls (§4); `&&`/`||` lower with real branches. */
        private fun namedOperator(psi: KtBinaryExpression): String {
            val token = psi.operationToken
            if (token == KtTokens.ANDAND || token == KtTokens.OROR) return shortCircuit(psi, token)
            val left = psi.left?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            val right = psi.right?.let { lowerExpr(it, Pos.NESTED) }
            val name = when {
                token == KtTokens.IN_KEYWORD || token == KtTokens.NOT_IN -> "contains"
                token == KtTokens.IDENTIFIER ->
                    // An infix function call (`x until y`, `a to b`): the
                    // operation reference IS the callee name.
                    psi.operationReference.text.takeIf { IDENTIFIER.matches(it) } ?: run {
                        fail("operator:${psi.operationToken}")
                        return left
                    }
                else -> operatorName(token) ?: run {
                    fail("operator:${psi.operationToken}")
                    return left
                }
            }
            if (token == KtTokens.IN_KEYWORD || token == KtTokens.NOT_IN) {
                // `x in xs` is xs.contains(x): the range is the receiver.
                val reg = t()
                emit(
                    KirCall(reg, KirCallee("kotlin.collections.contains", null, CallKind.OPERATOR), right, listOf(left), line = psi.line()),
                )
                return reg
            }
            val reg = t()
            emit(
                KirCall(
                    reg,
                    KirCallee("kotlin.$name", null, CallKind.OPERATOR),
                    left,
                    listOfNotNull(right),
                ),
            )
            return reg
        }

        private val IDENTIFIER = Regex("""[A-Za-z_][A-Za-z0-9_]*""")

        /** `&&`/`||` with short-circuit shape: branch, right arm, join phi. */
        private fun shortCircuit(psi: KtBinaryExpression, token: com.intellij.psi.tree.IElementType): String {
            val left = psi.left?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            val rhsId = newId()
            val skipId = newId()
            val joinId = newId()
            if (token == KtTokens.ANDAND) {
                emit(KirBranch(left, rhsId, skipId))
            } else {
                // `a || b`: skip the right arm when a is true.
                emit(KirBranch(left, skipId, rhsId))
            }
            startBlock(rhsId)
            val right = psi.right?.let { lowerExpr(it, Pos.NESTED) } ?: unknown(psi)
            goto(joinId)
            startBlock(skipId)
            goto(joinId)
            startBlock(joinId)
            val phi = t()
            emit(KirPhi(phi, mapOf(rhsId to right, skipId to left)))
            return phi
        }

        private fun operatorName(token: com.intellij.psi.tree.IElementType): String? = when (token) {
            KtTokens.PLUS -> "plus"
            KtTokens.MINUS -> "minus"
            KtTokens.MUL -> "times"
            KtTokens.DIV -> "div"
            KtTokens.PERC -> "rem"
            KtTokens.PLUSEQ -> "plusAssign"
            KtTokens.MINUSEQ -> "minusAssign"
            KtTokens.MULTEQ -> "timesAssign"
            KtTokens.DIVEQ -> "divAssign"
            KtTokens.PERCEQ -> "remAssign"
            // Comparisons are compareTo under the hood — the same name the
            // syntax tier publishes for them (one naming, two tiers).
            KtTokens.EQEQ -> "equals"
            KtTokens.EXCLEQ -> "equals"
            KtTokens.EQEQEQ -> "equals"
            KtTokens.EXCLEQEQEQ -> "equals"
            KtTokens.LT, KtTokens.GT, KtTokens.LTEQ, KtTokens.GTEQ -> "compareTo"
            KtTokens.RANGE, KtTokens.RANGE_UNTIL -> "rangeTo"
            else -> null
        }

        /**
         * Flattens a syntactic `a.b.c` qualifier chain into ONE base register
         * and a multi-element field path.
         *
         * `AccessPath` has carried `elements: List<Element>` with a depth cap
         * of 5, and both dataflow engines join those elements into
         * the key they read and write — but the lowering only ever emitted
         * paths of length ONE. `o.inner.a = tainted` became `t4 = fieldget vo
         * vo.inner; fieldset t4 t4.a`, and the read `o.inner.a` became a
         * fieldget off a DIFFERENT temp, so the write and the read never met:
         * every nested field flow was lost, intraprocedurally and across
         * summaries alike. Composing here fixes both engines at once,
         * and `AccessPath.of` still collapses past the cap.
         *
         * The walk stops at anything that is not a plain name selector — a
         * call, an index, a safe call — so `f().inner.a` still lowers its
         * receiver as an expression and composes only the part that is a
         * syntactic field chain.
         */
        private fun fieldChain(psi: KtExpression): Pair<String, List<AccessPath.Element>> {
            val names = ArrayDeque<String>()
            var current: KtExpression = psi
            while (current is KtDotQualifiedExpression) {
                val selector = current.selectorExpression as? KtNameReferenceExpression ?: break
                names.addFirst(selector.getReferencedName())
                current = current.receiverExpression
            }
            return lowerExpr(current, Pos.NESTED) to names.map { AccessPath.Element.Field(it) }
        }

        /** The base register and full path for reading or writing `<receiver>.<name>`. */
        private fun fieldAccess(receiverPsi: KtExpression, name: String): Pair<String, AccessPath> {
            val (base, prefix) = fieldChain(receiverPsi)
            return base to AccessPath.of(base, prefix + AccessPath.Element.Field(name))
        }

        private fun dotChain(psi: KtDotQualifiedExpression): String {
            val selector = psi.selectorExpression
            // A plain name selector is USUALLY a field read: compose the
            // whole qualifier chain into one path instead of one temp per
            // hop. The exception is a synthetic Java property — `e.text`
            // for `e.getText()` — which is a method call on the JVM and
            // must lower as one, or no model pack can see it (see
            // CallInfo.syntheticJavaProperty).
            if (selector is KtNameReferenceExpression) {
                val propertyInfo = resolvePropertyInfo(selector)
                if (propertyInfo != null) {
                    val receiverReg = lowerExpr(psi.receiverExpression, Pos.NESTED)
                    val fqn = propertyInfo.symbol.callableId?.asSingleFqName()?.asString()
                    if (fqn != null) {
                        val reg = t()
                        emit(
                            KirCall(
                                reg,
                                KirCallee(fqn, propertyInfo.descriptor, CallKind.VIRTUAL),
                                receiverReg,
                                emptyList(),
                                line = psi.line(),
                            ),
                        )
                        return reg
                    }
                }
                val (base, path) = fieldAccess(psi.receiverExpression, selector.getReferencedName())
                val reg = t()
                emit(KirFieldGet(reg, base, path))
                return reg
            }
            if (selector is KtCallExpression) {
                qualifiedFunctionValueCall(psi, selector)?.let { return it }
            }
            val receiver = lowerExpr(psi.receiverExpression, Pos.NESTED)
            return when (selector) {
                is KtCallExpression -> {
                    // `x.let { .. }` and friends: qualified scope functions
                    // inline their lambda with the receiver bound (§4), like
                    // the receiver-less `with(x) { .. }` form.
                    val name = (selector.calleeExpression as? KtNameReferenceExpression)?.getReferencedName()
                    if (name in SCOPE_FUNCTIONS && selector.hasLambdaArgument()) {
                        inlineScopeFunction(selector, name!!, receiver)
                    } else if (name != null && selector.hasLambdaArgument()) {
                        // `flow { .. }.map { .. }.collect { .. }`: the flow
                        // operators inline their lambda with the flow value
                        // bound.
                        inlineCoroutineBuilder(selector, name, receiver) ?: callWithReceiver(selector, receiver)
                    } else {
                        callWithReceiver(selector, receiver)
                    }
                }
                else -> {
                    fail("selector:${selector?.javaClass?.simpleName ?: "null"}")
                    receiver
                }
            }
        }

        /**
         * `?.` -> branch + phi (§4): null arm loads null, value arm lowers the
         * selector, the join merges. Short and long forms both branch — this
         * IS the desugaring, at any expression position.
         */
        private fun safeCall(psi: KtSafeQualifiedExpression): String {
            val receiver = lowerExpr(psi.receiverExpression, Pos.NESTED)
            val isNull = t()
            emit(KirCall(isNull, KirCallee("kotlin.isNull", null, CallKind.STATIC), null, listOf(receiver), line = psi.line()))
            val nullId = newId()
            val valueId = newId()
            val joinId = newId()
            emit(KirBranch(isNull, nullId, valueId))
            startBlock(valueId)
            val valueResult = when (val selector = psi.selectorExpression) {
                is KtCallExpression -> {
                    val name = (selector.calleeExpression as? KtNameReferenceExpression)?.getReferencedName()
                    if (name in SCOPE_FUNCTIONS && selector.hasLambdaArgument()) {
                        // `x?.let { .. }`: the inlining runs on the non-null
                        // arm, where the receiver register is the value.
                        inlineScopeFunction(selector, name!!, receiver)
                    } else if (name != null && selector.hasLambdaArgument()) {
                        inlineCoroutineBuilder(selector, name, receiver) ?: callWithReceiver(selector, receiver)
                    } else {
                        callWithReceiver(selector, receiver)
                    }
                }
                is KtNameReferenceExpression -> {
                    val reg = t()
                    emit(
                        KirFieldGet(
                            reg,
                            receiver,
                            AccessPath.of(receiver, listOf(AccessPath.Element.Field(selector.getReferencedName()))),
                        ),
                    )
                    reg
                }
                else -> {
                    fail("safe-selector:${selector?.javaClass?.simpleName ?: "null"}")
                    receiver
                }
            }
            goto(joinId)
            startBlock(nullId)
            val nullReg = t()
            emit(KirLoad(nullReg, KirConstant.Null))
            goto(joinId)
            startBlock(joinId)
            val phi = t()
            emit(KirPhi(phi, mapOf(valueId to valueResult, nullId to nullReg)))
            return phi
        }

        private fun call(psi: KtCallExpression): String {
            val name = (psi.calleeExpression as? KtNameReferenceExpression)?.getReferencedName()
                ?: run {
                    // The callee is an EXPRESSION, not a name — `fs[0](raw)`,
                    // `(pick())(raw)`. When it resolves to `FunctionN.invoke`
                    // that expression IS the function value, and it has to
                    // reach the invoke as the receiver: without it the call
                    // lowered with no receiver at all, so nothing downstream
                    // could say which function ran.
                    val callee = psi.calleeExpression
                    val receiver = if (callee != null && isFunctionTypeInvoke(psi)) {
                        lowerExpr(callee, Pos.NESTED)
                    } else {
                        null
                    }
                    return callWithReceiver(psi, receiver)
                }
            // A receiver-less scope-function call (`with(x) { }`, `run { }`)
            // or a plain call that happens to carry a lambda.
            if (name in SCOPE_FUNCTIONS && psi.hasLambdaArgument()) {
                val receiver: String = if (name == "with" || name == "run") {
                    psi.valueArguments.firstNotNullOfOrNull { arg ->
                        (arg.getArgumentExpression() as? KtExpression)
                            ?.takeIf { it !is KtLambdaExpression }
                            ?.let { lowerExpr(it, Pos.NESTED) }
                    } ?: "vthis"
                } else {
                    "vthis"
                }
                return inlineScopeFunction(psi, name, receiver)
            }
            // Coroutine builders and flow operators: their trailing lambda is
            // analysed in the caller's context.
            if (psi.hasLambdaArgument()) {
                inlineCoroutineBuilder(psi, name, receiver = null)?.let { return it }
            }
            // A function-valued local invoked by name (`block(x)`): the
            // invoked VALUE is the dispatch receiver of the invoke call. The
            // lowering keeps it on the receiver so the graph's edge and the
            // summary engine's invoked-parameter facts both see which local
            // was invoked — without it, an invocation site loses the one
            // fact higher-order analysis needs.
            // Resolution first — it knows whether what runs is a function
            // VALUE. [isFunctionValueLocal] stays as the fallback for a site
            // that did not resolve, where a name walk is all there is.
            val calleeRef = psi.calleeExpression as? KtNameReferenceExpression
            if (calleeRef != null) {
                // Either witness suffices, and they cover different gaps:
                // resolution knows an invoke through a typed value, the name
                // walk still catches a local whose invoke resolution reports
                // as the REFERENT (`val f = ::exec; f(x)` resolves to `exec`,
                // not to `Function1.invoke`). Unlike the qualified case there
                // is no qualifier to mistake the local for, so the walk
                // cannot pick a wrong receiver here.
                val info = resolveCallInfo(psi)
                val isValueInvoke = (info != null && isFunctionTypeInvoke(info)) || isFunctionValueLocal(calleeRef)
                if (isValueInvoke) return callWithReceiver(psi, lowerExpr(calleeRef, Pos.NESTED))
            }
            return callWithReceiver(psi, receiver = null)
        }

        private fun callWithReceiver(
            psi: KtCallExpression,
            receiver: String?,
            /**
             * Registers bound BEFORE the written arguments. Only an extension
             * lambda's receiver uses this: `b.block()` passes `b` in the
             * position the lambda body's implicit `this` occupies.
             */
            leadingArgs: List<String> = emptyList(),
        ): String {
            val argRegs = leadingArgs + psi.valueArguments.mapNotNull { arg ->
                arg.getArgumentExpression()?.let { lowerExpr(it, Pos.NESTED) }
            }
            val info = resolveCallInfo(psi)
            val symbol = info?.symbol
            val simpleName = (psi.calleeExpression as? KtNameReferenceExpression)?.getReferencedName() ?: "<unknown>"
            if (symbol == null) {
                val reg = t()
                emit(KirDynamicCall(reg, simpleName, receiver, argRegs, line = psi.line()))
                hookEmitSink(receiver, simpleName, argRegs)
                return reg
            }
            // A Java static method written with its class qualifier is NOT
            // a receiver call: drop the qualifier register so argument
            // indexes line up with the pack's convention (index 0 is the
            // first argument when there is no receiver).
            val receiver = if (info.isStatic) null else receiver
            val kind: CallKind
            val fqn: String
            when (symbol) {
                is KaConstructorSymbol -> {
                    kind = CallKind.CONSTRUCTOR
                    fqn = symbol.containingClassId?.asSingleFqName()?.asString() ?: "<constructor>"
                }
                is KaPropertySymbol -> {
                    kind = if (receiver != null) CallKind.VIRTUAL else CallKind.STATIC
                    fqn = symbol.callableId?.asSingleFqName()?.asString() ?: "<property>"
                }
                else -> {
                    kind = when {
                        info.isOperator -> CallKind.OPERATOR
                        receiver != null -> CallKind.VIRTUAL
                        else -> CallKind.STATIC
                    }
                    fqn = symbol.callableId?.asSingleFqName()?.asString() ?: "<function>"
                }
            }
            val reg = t()
            emit(
                KirCall(
                    reg,
                    KirCallee(fqn, info.descriptor, kind, samConstructor = info.isSamConstructor),
                    receiver,
                    argRegs,
                    line = psi.line(),
                    typeArguments = info.typeArguments,
                ),
            )
            if (info.isSuspend) emit(KirSuspendPoint(reg))
            hookEmitSink(receiver, simpleName, argRegs)
            return reg
        }

        /**
         * Inside an inlined `flow { }` / `channelFlow { }` body, a
         * receiver-less `emit(x)` / `send(x)` is the body handing a value to
         * the flow: the argument's taint lands on the builder's value
         * register, which is what the operators and `collect` downstream
         * read. Receiver-ful calls (`stateFlow.emit(x)`) are real member
         * calls on other objects and keep their own semantics. The move is an
         * ASSIGN, so multiple emits leave the LAST element's facts — a
         * named approximation, documented in docs/KOSI.md.
         */
        private fun hookEmitSink(receiver: String?, simpleName: String, argRegs: List<String>) {
            val sink = emitSinks.lastOrNull() ?: return
            if (receiver != null) return
            if (simpleName != "emit" && simpleName != "send") return
            val arg = argRegs.firstOrNull() ?: return
            emit(io.cdxgen.kosi.kir.KirAssign(sink, arg))
        }

        /**
         * Scope functions (let/run/apply/also/with/use) and `use`: inline the
         * lambda body with the receiver bound and retain the call edge for
         * evidence (§4). Two bindings, matching Kotlin's semantics:
         *   - `let`/`also`/`use` bind the receiver to the lambda's parameter
         *     (`it` unless named) as a plain local;
         *   - `apply`/`run`/`with` bind the receiver as `this` for the body,
         *     so member reads and writes inside the lambda target it.
         * `apply`/`also` return the receiver; the others return the body's
         * value. `use` shapes the inlined body as try/finally with the close
         * call in the finally arm.
         */
        private fun inlineScopeFunction(psi: KtCallExpression, name: String, receiver: String): String {
            val lambdaPsi = psi.valueArguments
                .mapNotNull { it.getArgumentExpression() as? KtLambdaExpression }
                .firstOrNull() ?: return callWithReceiver(psi, receiver)
            // The retained evidence edge.
            val edge = t()
            emit(
                KirCall(
                    edge,
                    KirCallee("kotlin.$name", null, CallKind.EXTENSION),
                    receiver,
                    emptyList(),
                    line = psi.line(),
                ),
            )
            val bindsParameter = name == "let" || name == "also" || name == "use"
            val paramReg = "v${lambdaPsi.valueParameters.firstOrNull()?.name ?: "it"}"
            if (bindsParameter) emit(KirStore(paramReg, receiver))
            val rebindsThis = name == "apply" || name == "run" || name == "with"
            if (rebindsThis) thisOverrides.addLast(receiver)
            val isUse = name == "use"
            val bodyResult = if (isUse) {
                // use -> try/finally (§4): body in the try arm, close in the
                // finally arm.
                val tryId = newId()
                val finallyId = newId()
                goto(tryId)
                startBlock(tryId)
                val result = lowerLambdaBody(lambdaPsi)
                goto(finallyId)
                startBlock(finallyId)
                emit(
                    KirCall(
                        t(),
                        KirCallee("java.io.Closeable.close", null, CallKind.EXTENSION),
                        receiver,
                        emptyList(),
                        line = psi.line(),
                    ),
                )
                result
            } else {
                lowerLambdaBody(lambdaPsi)
            }
            if (rebindsThis) thisOverrides.removeLast()
            // apply/also hand the receiver back; let/run/with/use the value.
            return if (name == "apply" || name == "also") receiver else bodyResult
        }

        /**
         * Coroutine builders and flow operators: the trailing lambda body is
         * lowered INTO the caller's context under the binding the builder
         * names, with the RESOLVED call retained as the evidence edge —
         * the same shape the scope functions use. Returns the expression's
         * value register, or null when this call is not a builder the
         * lowering inlines (the caller falls through to the plain call path).
         */
        private fun inlineCoroutineBuilder(psi: KtCallExpression, name: String, receiver: String?): String? {
            val info = resolveCallInfo(psi)
            val fqn = (info?.symbol as? org.jetbrains.kotlin.analysis.api.symbols.KaCallableSymbol)
                ?.callableId?.asSingleFqName()?.asString()
            val binding = coroutineBuilderBinding(name, fqn) ?: return null
            val lambdaPsi = psi.valueArguments
                .mapNotNull { it.getArgumentExpression() as? KtLambdaExpression }
                .firstOrNull() ?: return null
            // Only the NON-lambda arguments are argument values (a context, a
            // dispatcher, Compose keys); the lambda is the body being inlined.
            val argRegs = psi.valueArguments.mapNotNull { arg ->
                (arg.getArgumentExpression() as? KtLambdaExpression)?.let { return@mapNotNull null }
                arg.getArgumentExpression()?.let { lowerExpr(it, Pos.NESTED) }
            }
            // The retained evidence edge: the real callee where resolution
            // succeeded, the plain name where it did not.
            val edge = t()
            val symbol = info?.symbol
            if (symbol == null) {
                emit(KirDynamicCall(edge, name, receiver, argRegs, line = psi.line()))
            } else {
                val calleeFqn = (symbol as? org.jetbrains.kotlin.analysis.api.symbols.KaCallableSymbol)
                    ?.callableId?.asSingleFqName()?.asString() ?: "<function>"
                val kind = if (receiver != null) CallKind.VIRTUAL else CallKind.STATIC
                emit(KirCall(edge, KirCallee(calleeFqn, info!!.descriptor, kind), receiver, argRegs, line = psi.line()))
                if (info.isSuspend) emit(KirSuspendPoint(edge))
            }

            when (binding) {
                "value-builder" -> {
                    // The builder's value register IS the flow value: every
                    // receiver-less emit/send in the body assigns into it.
                    val valueReg = t()
                    emitSinks.addLast(valueReg)
                    lowerLambdaBody(lambdaPsi)
                    emitSinks.removeLast()
                    return valueReg
                }

                "element-operator" -> {
                    if (receiver != null) {
                        val paramReg = "v${lambdaPsi.valueParameters.firstOrNull()?.name ?: "it"}"
                        emit(io.cdxgen.kosi.kir.KirStore(paramReg, receiver))
                    }
                    return lowerLambdaBody(lambdaPsi)
                }

                "async" -> {
                    // async's value is the body's value: `async { t }.await()`
                    // then moves the body value to the await result through
                    // the Deferred.await pack passthrough.
                    return lowerLambdaBody(lambdaPsi)
                }

                else -> return lowerLambdaBody(lambdaPsi) // "plain"
            }
        }

        /**
         * True when this call site resolves to `kotlin.FunctionN.invoke` —
         * that is, when what runs is a function VALUE rather than a declared
         * function. Resolution answers this; the syntax does not, because
         * `f(x)`, `h.f(x)`, `fs[0](x)` and `b.block()` are all spelled like
         * ordinary calls and only one of them was being lowered as an invoke.
         */
        private fun isFunctionTypeInvoke(psi: KtCallExpression): Boolean =
            isFunctionTypeInvoke(resolveCallInfo(psi) ?: return false)

        private fun isFunctionTypeInvoke(info: CallInfo): Boolean {
            val fqn = info.symbol.callableId?.asSingleFqName()?.asString() ?: return false
            return FUNCTION_INVOKE.matches(fqn)
        }

        /**
         * `qualifier.name(args)` where the call resolves to an invoke of a
         * function VALUE. Two different shapes wear that syntax, and telling
         * them apart is the whole job:
         *
         *  - **the value is the qualifier's member** — `h.f(raw)` for
         *    `class FunctionHolder(val f: (String) -> Unit)`. The function
         *    value is `h.f`, so the invoke's receiver must be a READ of that
         *    field. Lowering it with `h` on the receiver (what happened
         *    before) hands the invoke the holder instead of the function, and
         *    the callee becomes unnameable.
         *  - **the value is in scope and the qualifier is its RECEIVER** —
         *    `b.block()` inside `fun build(block: Builder.() -> Unit)`. Here
         *    the function value is `block` and `b` is the extension receiver,
         *    so the invoke takes `block` as its receiver and `b` as its first
         *    argument, which is the position [lowerLambdaBody] gives the
         *    body's implicit `this`.
         *
         * RESOLUTION is the discriminator, not the syntax and not a name walk:
         * an implicit `invoke` that resolved against an EXTENSION receiver is
         * the second shape, anything else the first. An earlier cut asked
         * [isFunctionValueLocal] — a pure-PSI walk that matches by NAME — and
         * it second-guessed the resolver: with a function-typed local `f` in
         * scope, `h.f(raw)` bound the LOCAL's body to the holder and published
         * a process-exec flow through a lambda the program never invokes.
         * `onClick`, `handler` and `callback` are exactly the names that
         * collide this way in real UI code.
         */
        private fun qualifiedFunctionValueCall(psi: KtDotQualifiedExpression, selector: KtCallExpression): String? {
            val calleeRef = selector.calleeExpression as? KtNameReferenceExpression ?: return null
            val info = resolveCallInfo(selector) ?: return null
            if (!isFunctionTypeInvoke(info)) return null
            if (info.invokeOnExtensionReceiver) {
                val function = lowerExpr(calleeRef, Pos.NESTED)
                val extensionReceiver = lowerExpr(psi.receiverExpression, Pos.NESTED)
                return callWithReceiver(selector, function, leadingArgs = listOf(extensionReceiver))
            }
            val (base, path) = fieldAccess(psi.receiverExpression, calleeRef.getReferencedName())
            val value = t()
            emit(KirFieldGet(value, base, path))
            return callWithReceiver(selector, value)
        }

        /**
         * True when [psi] names a function-valued LOCAL: a parameter or local
         * property whose declared type is a function type, or whose
         * initializer is a lambda. Invoking one by name (`block(x)`) is an
         * invoke on that VALUE, and the lowering must keep the value on the
         * call's receiver. A local FUNCTION is not function-valued — its call
         * is a plain call to the KIR function the visitor already lowered.
         * Pure-PSI like [isLocalReference]: no reference re-resolution.
         */
        private fun isFunctionValueLocal(psi: KtNameReferenceExpression): Boolean {
            val name = psi.getReferencedName()
            var cursor: com.intellij.psi.PsiElement? = psi.parent
            while (cursor != null) {
                when (cursor) {
                    is KtNamedFunction -> {
                        val param = cursor.valueParameters.firstOrNull { it.name == name }
                        if (param != null) {
                            return param.typeReference?.text?.contains("->") == true
                        }
                    }

                    is KtBlockExpression, is org.jetbrains.kotlin.psi.KtClassBody -> {
                        for (child in cursor.children) {
                            if (child is KtProperty && child.isLocal && child.name == name) {
                                // Every expression that PRODUCES a function
                                // value, not only the lambda spelling: a
                                // `::reference` and an anonymous `fun` are
                                // function values too, and treating them as
                                // ordinary locals dropped the receiver from
                                // their invocation — which is the one fact
                                // higher-order analysis needs.
                                when (child.initializer) {
                                    is KtLambdaExpression,
                                    is org.jetbrains.kotlin.psi.KtCallableReferenceExpression,
                                    -> return true

                                    is KtNamedFunction ->
                                        return (child.initializer as KtNamedFunction).name == null

                                    else -> {}
                                }
                                return child.typeReference?.text?.contains("->") == true
                            }
                        }
                    }

                    else -> {}
                }
                cursor = cursor.parent
            }
            return false
        }

        private fun lowerLambdaBody(lambdaPsi: KtLambdaExpression): String {
            val statements = lambdaPsi.bodyExpression?.statements ?: return unknown(lambdaPsi)
            var result = unknown(lambdaPsi)
            statements.forEachIndexed { index, statement ->
                if (index == statements.lastIndex) {
                    // The last statement carries the lambda's value WHEN it is
                    // a value expression; a return/throw arm yields no value.
                    result = when (statement) {
                        is KtReturnExpression, is KtThrowExpression, is KtBlockExpression -> {
                            lowerStatement(statement)
                            "null-reg"
                        }
                        is KtProperty -> {
                            lowerStatement(statement)
                            "v${statement.name ?: "local$temp"}"
                        }
                        else -> lowerExpr(statement, Pos.NESTED)
                    }
                } else {
                    lowerStatement(statement)
                }
            }
            return result
        }
        private fun lambda(psi: KtLambdaExpression): String {
            // A standalone lambda value (an argument to a higher-order call,
            // a function-valued local) is EXTRACTED into its own KIR function
            // so the summary engine can compute a summary for the body and
            // apply it where the lambda is passed or invoked (the higher-
            // order item; the `lambda-inlined` deviation named this as the
            // missing lowering). The KirLambda instruction keeps the
            // canonical name of the extracted body plus the CAPTURES: the
            // enclosing registers the body reads, in the order the extracted
            // function's capture parameters expect them.
            val reg = t()
            val extracted = lambdaContext?.let { extractLambda(psi, it) }
            emit(
                KirLambda(
                    reg,
                    extracted?.first ?: "<lambda>",
                    extracted?.second ?: emptyList(),
                ),
            )
            return reg
        }

        /**
         * Lowers [psi]'s body into a fresh [BodyLower], discovers the free
         * registers it reads from this scope, renames them into capture
         * parameters (`%c<i>`), and registers the extracted function.
         *
         * Naming rules that make the rewrite unambiguous without a register
         * namespace prefix: the extracted body's temporaries start ABOVE this
         * body's counter (they can never collide with a capture name), and
         * captures are renamed at USE positions only, so a body-local that
         * shares a name with an enclosing local stays a body-local (Kotlin's
         * shadowing). The rewrite renames a capture read even when the body
         * later defines the same v-name — the pre-definition read is the
         * capture, which is the semantics that matters for taint.
         */
        /**
         * Does this lambda body read the implicit `it` that belongs to THIS
         * lambda? An inner lambda that declares no parameter of its own owns
         * the `it` inside it, so the scan stops there; an inner lambda that
         * declares one shadows nothing, and an `it` under it is still ours.
         * Missing a reference costs a parameter that carries no taint;
         * inventing one would mis-address every later argument, so the doubt
         * is resolved toward not inventing.
         */
        private fun referencesImplicitIt(body: KtExpression): Boolean {
            var found = false
            body.accept(object : KtTreeVisitorVoid() {
                override fun visitLambdaExpression(expression: KtLambdaExpression) {
                    if (expression.valueParameters.isNotEmpty()) super.visitLambdaExpression(expression)
                }

                override fun visitSimpleNameExpression(expression: org.jetbrains.kotlin.psi.KtSimpleNameExpression) {
                    if (expression.getReferencedName() == "it") found = true
                    super.visitSimpleNameExpression(expression)
                }
            })
            return found
        }

        private fun extractLambda(psi: KtLambdaExpression, context: LambdaContext): Pair<String, List<String>>? {
            val bodyPsi = psi.bodyExpression ?: return null
            val ordinal = context.ordinal++
            val canonical = "$enclosingCanonical\$lambda$ordinal"
            val bodyLower = BodyLower(
                context.failures,
                context.resolve,
                context.resolveProperty,
                functionPsi,
                lambdaContext = context,
                enclosingCanonical = canonical,
                tempStart = temp,
            )
            val valueParams = if (psi.valueParameters.isEmpty() && referencesImplicitIt(bodyPsi)) {
                // Kotlin's implicit lambda parameter is a REAL parameter with
                // no PSI: `{ exec(it) }` declares nothing, so the extraction
                // gave the body no value parameter and the read of `it`
                // became a register nothing defines. Every interprocedural
                // channel that speaks parameter indices — the invoke-binds
                // above all — then had nothing to bind, and the taint died at
                // the invocation. The review's probe found this: `viaLambda {
                // s -> exec(s) }` publishes the flow and `viaLambda {
                // exec(it) }`, the far commoner spelling, does not. Declared
                // here so the two spellings are one capability.
                listOf(KirParam("%p0", "it", null, receiver = false))
            } else {
                psi.valueParameters.mapIndexed { index, param ->
                    KirParam("%p$index", param.name, param.typeReference?.text, receiver = false)
                }
            }
            bodyLower.bindParameters(valueParams)
            val statements = bodyPsi.statements
            for ((index, statement) in statements.withIndex()) {
                if (index < statements.lastIndex) {
                    bodyLower.lowerStatement(statement)
                    continue
                }
                // The last statement carries the lambda's value WHEN it is a
                // value expression; a return/throw arm yields no value.
                when (statement) {
                    is KtReturnExpression, is KtThrowExpression -> bodyLower.lowerStatement(statement)
                    is KtProperty -> {
                        bodyLower.lowerStatement(statement)
                        bodyLower.returnValue("v${statement.name ?: "local"}")
                    }

                    else -> bodyLower.returnValue(bodyLower.lowerExpr(statement, Pos.NESTED))
                }
            }
            bodyLower.returnIfOpen()
            val body = bodyLower.finish()
            val instructions = body.blocks.flatMap { it.instructions }
            val bodyDefs = instructions.flatMap { it.defs }.toHashSet() + valueParams.map { it.register }
            val captureRegs = instructions
                .flatMap { it.uses }
                .filter { it !in bodyDefs }
                .filter { it in definedRegisters }
                .distinct()
            val captureParams = captureRegs.mapIndexed { index, reg -> KirParam("%c$index", "capture$reg", null, receiver = false) }
            // An EXTENSION lambda's implicit `this`. `build { cmd = raw }` for
            // `block: Builder.() -> Unit` lowers its body to
            // `fieldset vthis vthis.cmd = ...`, and `vthis` is free: not
            // defined in the body and not a register of the enclosing scope,
            // because the enclosing function has no `this` of its own. That
            // is precisely the signature of an implicit receiver, so the body
            // takes it as a parameter and the invoke site binds it. Without
            // it the write landed on a register nobody owned, and a DSL
            // block — the idiom Gradle and Android code is made of — moved
            // nothing to its caller.
            //
            // RESOLUTION decides, not the body. An earlier cut asked whether
            // the body writes through a free `vthis`, and that is wrong twice
            // over: a class-qualified call (`Runtime.getRuntime()`) lowers its
            // qualifier as a `fieldget` on `vthis`, and — worse — an ORDINARY
            // lambda nested inside a DSL block sees the OUTER lambda's
            // receiver as free, so it stole an `%r0` of its own and shifted
            // every one of its real parameters by one. The expected type is
            // the only thing that knows, and it also covers the READ-ONLY
            // extension lambda the body test could never see.
            val implicitReceiver = context.lambdaHasReceiver(psi) &&
                "vthis" !in bodyDefs &&
                instructions.any { "vthis" in it.uses }
            val receiverParams = if (implicitReceiver) {
                listOf(KirParam("%r0", "this", null, receiver = false))
            } else {
                emptyList()
            }
            val rename = captureRegs.withIndex().associate { (index, reg) -> reg to "%c$index" } +
                if (implicitReceiver) mapOf("vthis" to "%r0") else emptyMap()
            val rewritten = body.blocks.map { block ->
                block.copy(instructions = block.instructions.map { ins -> ins.mapRegisters({ rename[it] ?: it }, defsToo = false) })
            }
            context.functions.add(
                KirFunction(
                    canonicalName = canonical,
                    jvmDescriptor = null,
                    purl = "",
                    file = psi.containingFile?.virtualFile?.path
                        ?: functionPsi.containingFile?.virtualFile?.path ?: "<memory>",
                    line = psi.line(),
                    column = psi.column(),
                    params = captureParams + receiverParams + valueParams,
                    returnType = null,
                    modifiers = emptySet(),
                    visibility = "private",
                    enclosingClass = null,
                    overrides = emptyList(),
                    overriddenBy = emptyList(),
                    annotations = emptyList(),
                    syntheticCause = null,
                    body = KirBody(rewritten),
                    supertypes = emptyList(),
                    ownerFlags = emptySet(),
                    ownerAnnotations = emptyList(),
                    ownerVisibility = null,
                ),
            )
            return canonical to captureRegs
        }
    }

    /** `kotlin.Function0.invoke` .. `kotlin.FunctionN.invoke`: an invoke of a function VALUE. */
    private val FUNCTION_INVOKE = Regex("""kotlin\.Function\d+\.invoke""")

    private val SCOPE_FUNCTIONS = setOf("let", "run", "apply", "also", "with", "use")

    /**
     * Coroutine builders whose trailing lambda produces the builder's own
     * value: `flow { emit(x) }` — the body's `emit` (and `channelFlow`'s
     * `send`) calls assign their argument into the builder's value register,
     * which is what the downstream operators and `collect` read.
     */
    private val FLOW_VALUE_BUILDERS = setOf("flow", "channelFlow")

    /**
     * Flow operators whose trailing lambda receives the flow's element: the
     * flow value (the receiver) is bound to the lambda's parameter, so
     * `collect { sink(it) }` reads the flow value and `map { it }` passes it
     * through; the operator's value is the body's value, so a sanitizing
     * `map` body sanitizes everything downstream of it.
     */
    private val FLOW_ELEMENT_OPERATORS = setOf(
        "map", "mapNotNull", "transform", "filter", "filterNot", "onEach",
        "collect", "collectLatest", "forEach", "single", "first", "last",
    )

    /**
     * Suspending builders whose body is analysed plainly in the caller's
     * context: `launch`, `withContext`, `runBlocking`, `LaunchedEffect`
     * capture their closure and run it; `async` additionally values as its
     * body's value, which is what makes `async { t }.await()` a
     * receiver-to-result passthrough on the body value (`Deferred.await` is
     * a pack entry).
     */
    private val SUSPEND_BUILDERS = setOf("launch", "async", "withContext", "runBlocking", "LaunchedEffect")

    /** The flow/channel packages an inlining-eligible callee must resolve into. */
    private const val FLOW_PACKAGE = "kotlinx.coroutines.flow."
    private const val COROUTINES_PACKAGE = "kotlinx.coroutines."

    /**
     * Which binding a builder call gets. When resolution FAILED the call's
     * FQN is unknown and the NAME decides: an unresolved `collect { }` is
     * modelled the same way as the resolved one, because skipping the body
     * (the earlier behaviour) loses the very flows this change exists for. A
     * RESOLVED callee outside the coroutines packages never inlines —
     * `xs.map { }` over a collection keeps its pack passthrough, and the
     * lambda parameter keeps collection element semantics.
     */
    private fun coroutineBuilderBinding(name: String, fqn: String?): String? = when {
        name in FLOW_VALUE_BUILDERS && (fqn == null || fqn.startsWith(FLOW_PACKAGE)) -> "value-builder"
        name in FLOW_ELEMENT_OPERATORS && (fqn == null || fqn.startsWith(FLOW_PACKAGE)) -> "element-operator"
        name == "async" && (fqn == null || fqn.startsWith(COROUTINES_PACKAGE)) -> "async"
        name in SUSPEND_BUILDERS && (fqn == null || fqn.startsWith(COROUTINES_PACKAGE) || fqn == "androidx.compose.runtime.LaunchedEffect") -> "plain"
        else -> null
    }

    private fun KtCallExpression.hasLambdaArgument(): Boolean =
        valueArguments.any { it.getArgumentExpression() is KtLambdaExpression }
}

private typealias KtDeclaration = org.jetbrains.kotlin.psi.KtDeclaration
