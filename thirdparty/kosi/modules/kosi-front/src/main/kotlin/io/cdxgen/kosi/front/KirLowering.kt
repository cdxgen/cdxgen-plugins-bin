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
import io.cdxgen.kosi.kir.KirSafeCall
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
 * kosi-kir's types are compiler-free, which is the boundary the P2 gate
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
    )

    /** What the analyze-scoped resolver hands the lowering per call site. */
    data class CallInfo(
        val symbol: KaCallableSymbol,
        val descriptor: String?,
        val isSuspend: Boolean,
        val isOperator: Boolean,
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
        var functionCount = 0
        var symbolFactFailures = 0
        analyze(module) {
            // resolveCall and the JVM-descriptor mapping are Analysis API
            // operations: they resolve only lexically inside this block, so
            // they are captured here and handed to the body lowering as a
            // plain function value.
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
                )
            } catch (_: Exception) {
                symbolFactFailures++
                NO_FACTS
            }

            val lambdaContext = LambdaContext(failures, ::resolve)
            for (file in files) {
                for (functionLike in collectFunctionLikes(file)) {
                    functionCount++
                    lowerFunction(functionLike, failures, ::resolve, ::factsFor, lambdaContext)?.let { functions.add(it) }
                }
                for (klass in dataClasses(file)) {
                    functions.addAll(synthesizeDataClassMembers(klass, failures))
                }
            }
            functions.addAll(lambdaContext.functions)
        }
        return Result(functions, failures, functionCount, symbolFactFailures)
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
                super.visitProperty(property)
            }

            override fun visitSecondaryConstructor(constructor: KtSecondaryConstructor) {
                out.add(constructor)
                super.visitSecondaryConstructor(constructor)
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
     * Per-`lower()`-run context for the standalone-lambda extraction (P5):
     * lambdas passed as VALUES (`runWith { .. }`, a function-valued argument)
     * lower into their own KIR functions so the summary engine can compute
     * and apply them like any other callee. The context owns the ordinal
     * (deterministic naming) and the sink the extracted functions land in.
     */
    internal class LambdaContext(
        val failures: MutableMap<String, Int>,
        val resolve: (KtCallExpression) -> CallInfo?,
    ) {
        var ordinal = 0
        val functions = mutableListOf<KirFunction>()
    }

    private fun lowerFunction(
        psi: org.jetbrains.kotlin.psi.KtDeclaration,
        failures: MutableMap<String, Int>,
        resolve: (KtCallExpression) -> CallInfo?,
        factsFor: (org.jetbrains.kotlin.psi.KtDeclaration) -> Facts,
        lambdaContext: LambdaContext,
    ): KirFunction? {
        val name = when (psi) {
            is KtNamedFunction -> psi.name ?: "<anonymous>"
            is KtPropertyAccessor -> psi.name ?: "<accessor>"
            is KtSecondaryConstructor -> "<init>"
            else -> return null
        }
        val pkg = (psi.containingFile as? org.jetbrains.kotlin.psi.KtFile)?.packageFqName?.asString() ?: ""
        val chain = containerChain(psi)
        val canonical = listOf(pkg, chain, name).filter { it.isNotEmpty() }.joinToString(".")

        val facts = factsFor(psi)
        val lower = BodyLower(failures, resolve, psi, lambdaContext, enclosingCanonical = canonical)
        val bodyPsi: KtExpression? = when (psi) {
            is KtNamedFunction -> psi.bodyExpression
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
            params = signatureParams(psi),
            returnType = null,
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

    private fun signatureParams(psi: org.jetbrains.kotlin.psi.KtDeclaration): List<KirParam> {
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
            for (p in psi.valueParameters) {
                params.add(KirParam("%${index++}", p.name, p.typeReference?.text, receiver = false))
            }
        }
        return params
    }

    private fun containerChain(psi: com.intellij.psi.PsiElement): String =
        generateSequence(psi.parent) { it.parent }
            .filterIsInstance<org.jetbrains.kotlin.psi.KtClassOrObject>()
            .toList()
            .reversed()
            .joinToString(".") { it.name ?: "<anonymous>" }

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
         * value the downstream operator and `collect` see (P6).
         */
        private val emitSinks = mutableListOf<String>()

        init {
            blocks["b0"] = mutableListOf()
        }

        val current: MutableList<KirIns> get() = blocks.getValue(currentId)

        fun t(): String = "t${temp++}"

        private fun newId(): String = "b${counter++}"

        private fun emit(ins: KirIns) {
            definedRegisters.addAll(ins.defs)
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

        fun finish(): KirBody = KirBody(
            blocks.map { (id, instructions) -> KirBlock(id, id == "b0", instructions) },
        )

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
                    val value = psi.thrownExpression?.let { lowerExpr(it, Pos.NESTED) } ?: throwNull()
                    emit(KirThrow(value))
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
            val finallyId = newId()
            psi.tryBlock?.let { lowerStatement(it) }
            goto(finallyId)
            for (catch in psi.catchClauses) {
                startBlock(newId())
                catch.catchBody?.let { lowerStatement(it) }
                goto(finallyId)
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
                val reg = t()
                emit(KirLambda(reg, psi.text, emptyList()))
                reg
            }
            is KtNamedFunction -> {
                // A local function: its body lowers as its own KIR function
                // (collectFunctionLikes visits it); the use site names it.
                val reg = t()
                emit(KirLambda(reg, psi.name ?: "<local-fun>", emptyList()))
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

        private fun constant(psi: KtConstantExpression): String {
            val reg = t()
            val constant = when (psi.elementType) {
                KtTokens.INTEGER_LITERAL -> KirConstant.IntConst(psi.text.removeSuffix("L").toLongOrNull() ?: 0)
                KtTokens.FLOAT_LITERAL ->
                    KirConstant.FloatConst(psi.text.removeSuffix("f").removeSuffix("F").toDoubleOrNull() ?: 0.0)
                KtTokens.TRUE_KEYWORD, KtTokens.FALSE_KEYWORD ->
                    KirConstant.Bool(psi.text == "true")
                KtTokens.NULL_KEYWORD -> KirConstant.Null
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
            return if (isLocalReference(psi)) {
                "v$name"
            } else {
                // Not a local: a member (or top-level) property read, carried
                // by the access path over the CURRENT `this` (a scope
                // function's receiver when inside an inlined apply/run/with).
                val thisReg = currentThis()
                val reg = t()
                emit(
                    KirFieldGet(
                        reg,
                        thisReg,
                        AccessPath.of(thisReg, listOf(AccessPath.Element.Field(name))),
                    ),
                )
                reg
            }
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
                        // lands on is the key the matching read looks at (R63).
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
            // positions keep the Elvis opcode (the §4 shape P2 pinned).
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
         * of 5 since P2, and both dataflow engines join those elements into
         * the key they read and write — but the lowering only ever emitted
         * paths of length ONE. `o.inner.a = tainted` became `t4 = fieldget vo
         * vo.inner; fieldset t4 t4.a`, and the read `o.inner.a` became a
         * fieldget off a DIFFERENT temp, so the write and the read never met:
         * every nested field flow was lost, intraprocedurally and across
         * summaries alike (R63). Composing here fixes both engines at once,
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
            // A plain name selector is a field read: compose the whole
            // qualifier chain into one path instead of one temp per hop.
            if (selector is KtNameReferenceExpression) {
                val (base, path) = fieldAccess(psi.receiverExpression, selector.getReferencedName())
                val reg = t()
                emit(KirFieldGet(reg, base, path))
                return reg
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
                        // bound (P6).
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
                ?: return callWithReceiver(psi, receiver = null)
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
            // analysed in the caller's context (P6).
            if (psi.hasLambdaArgument()) {
                inlineCoroutineBuilder(psi, name, receiver = null)?.let { return it }
            }
            // A function-valued local invoked by name (`block(x)`): the
            // invoked VALUE is the dispatch receiver of the invoke call. The
            // lowering keeps it on the receiver so the graph's edge and the
            // summary engine's invoked-parameter facts both see which local
            // was invoked — without it, an invocation site loses the one
            // fact higher-order analysis needs.
            val calleeRef = psi.calleeExpression as? KtNameReferenceExpression
            if (calleeRef != null && isFunctionValueLocal(calleeRef)) {
                return callWithReceiver(psi, lowerExpr(calleeRef, Pos.NESTED))
            }
            return callWithReceiver(psi, receiver = null)
        }

        private fun callWithReceiver(psi: KtCallExpression, receiver: String?): String {
            val argRegs = psi.valueArguments.mapNotNull { arg ->
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
            emit(KirCall(reg, KirCallee(fqn, info.descriptor, kind), receiver, argRegs, line = psi.line()))
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
         * names (P6), with the RESOLVED call retained as the evidence edge —
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
                                if (child.initializer is KtLambdaExpression) return true
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
            // apply it where the lambda is passed or invoked (P5's
            // higher-order item; the P3 `lambda-inlined` deviation named this
            // as the missing lowering). The KirLambda instruction keeps the
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
        private fun extractLambda(psi: KtLambdaExpression, context: LambdaContext): Pair<String, List<String>>? {
            val bodyPsi = psi.bodyExpression ?: return null
            val ordinal = context.ordinal++
            val canonical = "$enclosingCanonical\$lambda$ordinal"
            val bodyLower = BodyLower(
                context.failures,
                context.resolve,
                functionPsi,
                lambdaContext = context,
                enclosingCanonical = canonical,
                tempStart = temp,
            )
            val valueParams = psi.valueParameters.mapIndexed { index, param ->
                KirParam("%p$index", param.name, param.typeReference?.text, receiver = false)
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
            val rename = captureRegs.withIndex().associate { (index, reg) -> reg to "%c$index" }
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
                    params = captureParams + valueParams,
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

    private val SCOPE_FUNCTIONS = setOf("let", "run", "apply", "also", "with", "use")

    /**
     * Coroutine builders whose trailing lambda produces the builder's own
     * value: `flow { emit(x) }` — the body's `emit` (and `channelFlow`'s
     * `send`) calls assign their argument into the builder's value register,
     * which is what the downstream operators and `collect` read (P6).
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
     * (the pre-P6 behaviour) loses the very flows this phase exists for. A
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
