package io.cdxgen.kosi.front

import com.intellij.psi.PsiClass
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiJavaFile
import com.intellij.psi.PsiModifierListOwner
import io.cdxgen.kosi.schema.AnnotationEvidence
import io.cdxgen.kosi.schema.Diagnostic
import io.cdxgen.kosi.schema.DiagnosticCodes
import io.cdxgen.kosi.schema.ImportUsage
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.Severity
import org.jetbrains.kotlin.analysis.api.KaSession
import org.jetbrains.kotlin.analysis.api.analyze
import org.jetbrains.kotlin.analysis.api.components.KaDiagnosticCheckerFilter
import org.jetbrains.kotlin.analysis.api.components.allOverriddenSymbols
import org.jetbrains.kotlin.analysis.api.projectStructure.KaSourceModule
import org.jetbrains.kotlin.analysis.api.resolution.KaFunctionCall
import org.jetbrains.kotlin.analysis.api.resolution.symbols
import org.jetbrains.kotlin.analysis.api.symbols.KaCallableSymbol
import org.jetbrains.kotlin.analysis.api.symbols.KaClassSymbol
import org.jetbrains.kotlin.analysis.api.symbols.KaConstructorSymbol
import org.jetbrains.kotlin.analysis.api.symbols.KaFunctionSymbol
import org.jetbrains.kotlin.analysis.api.symbols.KaPropertySymbol
import org.jetbrains.kotlin.analysis.api.symbols.symbol
import org.jetbrains.kotlin.analysis.api.types.KaClassType
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.load.kotlin.TypeMappingMode
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtDeclaration
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtModifierListOwner
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtObjectDeclaration
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtTreeVisitorVoid
import org.jetbrains.kotlin.psi.KtTypeAlias

/**
 * The resolved tier: symbol-resolved declarations, imports and usages over the
 * standalone session's merged workspace module. Facts the syntax tier reads
 * from PSI text stay text-shaped here (names, signatures, modifiers), so the
 * tiers differ only in what resolution ADDS: `jvmOwner`/`jvmDescriptor`,
 * `supertypes`, `overrides`, Java-source declarations, resolved-call counting
 * and resolution diagnostics.
 *
 * Structural rule: the 2.4 Analysis API resolves its operations only inside
 * the `analyze` block it gives a session to, so every symbol fact below is
 * computed in straight-line loops inside that block, keyed by symbol, and the
 * (pure-PSI) emission reads the maps. No `Ka*` value leaves this object.
 */
@OptIn(
    org.jetbrains.kotlin.analysis.api.KaExperimentalApi::class,
    org.jetbrains.kotlin.analysis.api.KaIdeApi::class,
    org.jetbrains.kotlin.analysis.api.KaContextParameterApi::class,
    org.jetbrains.kotlin.analysis.api.KaNonPublicApi::class,
)
object ResolvedAnalyzer {

    class ResolvedDeclaration(
        val name: String,
        val qualifiedName: String,
        val canonicalName: String,
        val kind: String,
        val signature: String?,
        val returnType: String?,
        val extensionReceiverType: String?,
        val visibility: String,
        val modifiers: List<String>,
        val annotations: List<AnnotationEvidence>,
        val overrides: List<String>,
        val supertypes: List<String>,
        val jvmOwner: String?,
        val jvmDescriptor: String?,
        val position: Position,
    )

    data class ResolvedFileFacts(
        val relativePath: String,
        val modulePath: String,
        val packageName: String,
        val imports: List<ImportUsage>,
        val declarations: List<ResolvedDeclaration>,
        val usages: List<SyntaxAnalyzer.RawUsage>,
        val diagnostics: List<Diagnostic>,
        val callsTotal: Int,
        val callsResolved: Int,
        val resolutionErrorCodes: Map<String, Int>,
    )

    fun run(
        env: AnalysisEnvironment,
        module: KaSourceModule,
        fileRelPathByAbsolute: Map<String, Pair<String, String>>,
    ): List<ResolvedFileFacts> {
        val files = mutableListOf<Triple<KtFile?, PsiElement, Pair<String, String>>>()
        for ((_, psiFiles) in env.session.modulesWithFiles) {
            for (psi in psiFiles) {
                val abs = psi.virtualFile?.path ?: continue
                val rel = fileRelPathByAbsolute[abs] ?: continue
                when (psi) {
                    is KtFile -> files.add(Triple(psi, psi, rel))
                    is PsiJavaFile -> files.add(Triple(null, psi, rel))
                }
            }
        }
        files.sortBy { it.third.first }

        val out = mutableListOf<ResolvedFileFacts>()
        // The Analysis API resolves its operations only lexically inside the
        // `analyze` block it hands a session to, so the whole per-file pass
        // lives in this one scope: loops only, no helper functions calling
        // session operations.
        analyze(module) {
        fileLoop@ for ((ktFile, psi, rel) in files) {
        val relativePath = rel.first
        val modulePath = rel.second
        val lines = SyntaxAnalyzer.LineIndex(psi.text)
        val declarations = mutableListOf<ResolvedDeclaration>()
        val usages = mutableListOf<SyntaxAnalyzer.RawUsage>()
        val diagnostics = mutableListOf<Diagnostic>()
        var callsTotal = 0
        var callsResolved = 0
        val unresolvedSample = mutableListOf<String>()
        val errorCodes = LinkedHashMap<String, Int>()

        if (ktFile != null) {
            // Usages keep the syntax tier's text shapes (model matching).
            val syntax = SyntaxAnalyzer(env, relativePath, modulePath, collectDeclarations = false)
            val syntaxResult = syntax.analyze(ktFile)
            usages.addAll(syntaxResult.usages)
            diagnostics.addAll(syntaxResult.diagnostics)

            val imports = ktFile.importDirectives.mapNotNull { directive ->
                val fqName = directive.importedFqName?.asString() ?: return@mapNotNull null
                ImportUsage(
                    name = SyntaxAnalyzer.normalizeName(fqName),
                    alias = directive.aliasName,
                    star = directive.isAllUnder,
                    purl = null,
                    filePath = relativePath,
                    position = positionAt(lines, relativePath, directive.textOffset),
                )
            }

            val walked = mutableListOf<KtDeclaration>()
            val callExpressions = mutableListOf<KtCallExpression>()
            ktFile.accept(object : KtTreeVisitorVoid() {
                override fun visitDeclaration(declaration: KtDeclaration) {
                    walked.add(declaration)
                    super.visitDeclaration(declaration)
                }

                override fun visitCallExpression(expression: KtCallExpression) {
                    callExpressions.add(expression)
                    super.visitCallExpression(expression)
                }
            })

            // Pass 1: resolve every walked declaration to its symbol.
            data class Sym(
                val declaration: KtDeclaration,
                val symbol: org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol?,
            )
            val resolved = walked.map { declaration ->
                val symbol = try {
                    declaration.symbol
                } catch (_: Exception) {
                    null
                }
                Sym(declaration, symbol)
            }

            // Pass 2: compute every symbol-derived fact up front, keyed by
            // symbol, so emission is pure data assembly.
            val visibilityOf = HashMap<org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol, String>()
            val overridesOf = HashMap<org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol, List<String>>()
            val supertypesOf = HashMap<org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol, List<String>>()
            val annotationsOf = HashMap<org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol, List<AnnotationEvidence>>()
            val modifiersOf = HashMap<org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol, List<String>>()
            val jvmOf = HashMap<org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol, Pair<String?, String?>>()
            for ((_, symbol) in resolved) {
                if (symbol == null || visibilityOf.containsKey(symbol)) continue
                visibilityOf[symbol] = visibilityName(symbol)
                overridesOf[symbol] = try {
                    if (symbol is org.jetbrains.kotlin.analysis.api.symbols.KaCallableSymbol) {
                        symbol.allOverriddenSymbols
                            .mapNotNull { it.callableId?.asSingleFqName()?.asString() }
                            .toList()
                            .distinct()
                    } else {
                        emptyList()
                    }
                } catch (_: Exception) {
                    emptyList()
                }
                supertypesOf[symbol] = try {
                    if (symbol is KaClassSymbol) {
                        symbol.superTypes.mapNotNull { (it as? KaClassType)?.classId?.asSingleFqName()?.asString() }
                            .filter { it != "kotlin.Any" }
                            .distinct()
                    } else {
                        emptyList()
                    }
                } catch (_: Exception) {
                    emptyList()
                }
                annotationsOf[symbol] = try {
                    (symbol as? org.jetbrains.kotlin.analysis.api.annotations.KaAnnotated)
                        ?.annotations
                        ?.map { AnnotationEvidence(
                            name = it.classId?.shortClassName?.asString()
                                ?: it.classId?.asSingleFqName()?.asString()
                                ?: "<annotation>",
                            value = it.arguments.asSequence()
                                .mapNotNull { arg -> arg.expression }
                                .mapNotNull { v -> (v as? org.jetbrains.kotlin.analysis.api.annotations.KaAnnotationValue.ConstantValue)?.value?.toString() }
                                .firstOrNull(),
                            position = positionAt(lines, relativePath, 0),
                        ) }
                        ?: emptyList()
                } catch (_: Exception) {
                    emptyList()
                }
                modifiersOf[symbol] = when (symbol) {
                    is org.jetbrains.kotlin.analysis.api.symbols.KaCallableSymbol ->
                        if (symbol.modality == org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.ABSTRACT) {
                            listOf("abstract")
                        } else {
                            emptyList()
                        }

                    is KaClassSymbol -> buildList {
                        if (symbol.modality == org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.ABSTRACT) add("abstract")
                        if (symbol.modality == org.jetbrains.kotlin.analysis.api.symbols.KaSymbolModality.SEALED) add("sealed")
                    }

                    else -> emptyList()
                }
                jvmOf[symbol] = try {
                    val callable = symbol as? KaCallableSymbol
                    if (callable == null) {
                        null to null
                    } else {
                        val owner = callable.containingJvmClassName?.replace('.', '/')
                        val descriptor = when (callable) {
                            is KaConstructorSymbol ->
                                JvmSignatures.voidMethodDescriptor(
                                    callable.valueParameters.map { it.returnType.mapToJvmType(TypeMappingMode.DEFAULT) },
                                )

                            is KaPropertySymbol -> null // no single JVM member; accessors carry it

                            is KaFunctionSymbol -> {
                                val params = buildList {
                                    callable.receiverParameter?.let { add(it.returnType.mapToJvmType(TypeMappingMode.DEFAULT)) }
                                    callable.valueParameters.forEach { add(it.returnType.mapToJvmType(TypeMappingMode.DEFAULT)) }
                                }
                                JvmSignatures.methodDescriptor(
                                    callable.returnType.mapToJvmType(TypeMappingMode.DEFAULT),
                                    params,
                                )
                            }

                            else -> null
                        }
                        owner to descriptor
                    }
                } catch (_: Exception) {
                    null to null
                }
            }

            // Pass 3: emission, pure PSI + computed facts.
            for ((declaration, symbol) in resolved) {
                val shape = declarationShapes(declaration) ?: continue
                val name = declaration.name ?: "<anonymous>"
                val pkg = ktFile.packageFqName.asString()
                val canonical = SyntaxAnalyzer.joinCanonical(pkg, containerChain(declaration), name)
                declarations.add(
                    ResolvedDeclaration(
                        name = name,
                        qualifiedName = "$modulePath:$canonical",
                        canonicalName = canonical,
                        kind = shape.kind,
                        signature = shape.signature,
                        returnType = shape.returnType,
                        extensionReceiverType = shape.extensionReceiver,
                        visibility = symbol?.let { visibilityOf[it] } ?: psiVisibility(declaration) ?: "public",
                        modifiers = psiModifiers(declaration) + (symbol?.let { modifiersOf[it] } ?: emptyList()),
                        annotations = symbol?.let { annotationsOf[it] } ?: emptyList(),
                        overrides = symbol?.let { overridesOf[it] } ?: emptyList(),
                        supertypes = symbol?.let { supertypesOf[it] } ?: emptyList(),
                        jvmOwner = symbol?.let { jvmOf[it]?.first },
                        jvmDescriptor = symbol?.let { jvmOf[it]?.second },
                        position = positionAt(lines, relativePath, declaration.textOffset),
                    ),
                )
            }

            // Resolved-call counting: resolveCall yields the single-or-multi
            // call container; a container with symbols is a resolved call.
            for (expression in callExpressions) {
                callsTotal++
                val call = try {
                    expression.resolveCall()
                } catch (_: Exception) {
                    null
                }
                val resolved = try {
                    call?.symbols?.isNotEmpty() == true
                } catch (_: Exception) {
                    false
                }
                if (resolved) {
                    callsResolved++
                } else if (System.getenv("KOSI_TRACE") != null && unresolvedSample.size < 25) {
                    unresolvedSample.add(relativePath + ": " + expression.text.take(80))
                }
            }
            for (u in unresolvedSample) System.err.println("UNRESOLVED: " + u)

            // Resolution diagnostics, summarised: per-error floods would dwarf
            // the evidence on real projects; the count is the signal.
            val fileDiagnostics = try {
                ktFile.collectDiagnostics(KaDiagnosticCheckerFilter.ONLY_COMMON_CHECKERS)
            } catch (_: Exception) {
                emptyList()
            }
            for (d in fileDiagnostics) {
                val code = d.factoryName ?: continue
                errorCodes[code] = (errorCodes[code] ?: 0) + 1
            }
            if (errorCodes.isNotEmpty()) {
                val summary = errorCodes.entries.sortedWith(
                    compareByDescending<Map.Entry<String, Int>> { it.value }.thenBy { it.key },
                ).joinToString(", ") { "${it.key}=${it.value}" }
                diagnostics.add(
                    Diagnostic(
                        code = DiagnosticCodes.RESOLUTION_ERRORS,
                        severity = Severity.WARNING,
                        message = "frontend resolution reported ${fileDiagnostics.size} diagnostic(s) in " +
                            "$relativePath: $summary",
                        position = Position(relativePath, 1, 1),
                        count = fileDiagnostics.size,
                    ),
                )
            }

            out.add(
                ResolvedFileFacts(
                    relativePath = relativePath,
                    modulePath = modulePath,
                    packageName = ktFile.packageFqName.asString(),
                    imports = imports,
                    declarations = declarations,
                    usages = usages,
                    diagnostics = diagnostics,
                    callsTotal = callsTotal,
                    callsResolved = callsResolved,
                    resolutionErrorCodes = errorCodes,
                ),
            )
            continue@fileLoop
        }

        // Java source: same evidence through the same symbols, same pattern —
        // resolve up front in the loop, emit from the maps.
        val javaFile = psi as PsiJavaFile
        val javaClasses = mutableListOf<PsiClass>()
        collectJavaClasses(javaFile, javaClasses)
        val classSymbols = javaClasses.associateWith { psiClass ->
            try {
                psiClass.namedClassSymbol
            } catch (_: Exception) {
                null
            }
        }
        val javaMembers = javaClasses.flatMap { psiClass ->
            psiClass.methods.map { member -> member as com.intellij.psi.PsiMember } +
                psiClass.fields.map { member -> member as com.intellij.psi.PsiMember }
        }
        val memberSymbols = HashMap<com.intellij.psi.PsiMember, org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol?>()
        for (member in javaMembers) {
            memberSymbols[member] = try {
                member.callableSymbol
            } catch (_: Exception) {
                null
            }
        }
        val jvmByMember = HashMap<org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol, Pair<String?, String?>>()
        val visibilityByMember = HashMap<org.jetbrains.kotlin.analysis.api.symbols.KaDeclarationSymbol, String>()
        for ((_, symbol) in memberSymbols) {
            if (symbol == null || jvmByMember.containsKey(symbol)) continue
            visibilityByMember[symbol] = visibilityName(symbol)
            jvmByMember[symbol] = try {
                val callable = symbol as? KaCallableSymbol
                if (callable == null) {
                    null to null
                } else {
                    val owner = callable.containingJvmClassName?.replace('.', '/')
                    val descriptor = when (callable) {
                        is KaConstructorSymbol ->
                            JvmSignatures.voidMethodDescriptor(
                                callable.valueParameters.map { it.returnType.mapToJvmType(TypeMappingMode.DEFAULT) },
                            )

                        is KaPropertySymbol -> null

                        is KaFunctionSymbol -> {
                            val params = buildList {
                                callable.receiverParameter?.let { add(it.returnType.mapToJvmType(TypeMappingMode.DEFAULT)) }
                                callable.valueParameters.forEach { add(it.returnType.mapToJvmType(TypeMappingMode.DEFAULT)) }
                            }
                            JvmSignatures.methodDescriptor(
                                callable.returnType.mapToJvmType(TypeMappingMode.DEFAULT),
                                params,
                            )
                        }

                        else -> null
                    }
                    owner to descriptor
                }
            } catch (_: Exception) {
                null to null
            }
        }
        for (psiClass in javaClasses) {
            val name = psiClass.name ?: "<anonymous>"
            val canonical = javaCanonicalName(psiClass)
            val symbol = classSymbols[psiClass]
            declarations.add(
                ResolvedDeclaration(
                    name = name,
                    qualifiedName = "$modulePath:$canonical",
                    canonicalName = canonical,
                    kind = when {
                        psiClass.isAnnotationType -> "annotation"
                        psiClass.isEnum -> "enum"
                        psiClass.isInterface -> "interface"
                        else -> "class"
                    },
                    signature = null,
                    returnType = null,
                    extensionReceiverType = null,
                    visibility = symbol?.let { visibilityByMember[it] } ?: javaVisibility(psiClass),
                    modifiers = javaModifiers(psiClass),
                    annotations = emptyList(),
                    overrides = emptyList(),
                    supertypes = try {
                        symbol?.let { s ->
                            (s as? KaClassSymbol)?.superTypes
                                ?.mapNotNull { (it as? KaClassType)?.classId?.asSingleFqName()?.asString() }
                                ?.filter { it != "kotlin.Any" }
                                ?.distinct()
                        } ?: emptyList()
                    } catch (_: Exception) {
                        emptyList()
                    },
                    jvmOwner = symbol?.let { jvmByMember[it]?.first },
                    jvmDescriptor = symbol?.let { jvmByMember[it]?.second },
                    position = positionAt(lines, relativePath, psiClass.textOffset),
                ),
            )

            for (method in psiClass.methods) {
                val methodSymbol = memberSymbols[method]
                val callable = methodSymbol as? KaCallableSymbol
                val params = method.parameterList.parameters.joinToString(", ") { p ->
                    "${p.name ?: "_"}: ${p.type.canonicalText.normalized()}"
                }
                declarations.add(
                    ResolvedDeclaration(
                        name = method.name,
                        qualifiedName = "$modulePath:${canonical}.${method.name}",
                        canonicalName = "${canonical}.${method.name}",
                        kind = if (method.isConstructor) "constructor" else "method",
                        signature = "fun ${method.name}($params)" +
                            method.returnType?.let { ": ${it.canonicalText.normalized()}" }.orEmpty(),
                        returnType = method.returnType?.canonicalText?.normalized(),
                        extensionReceiverType = null,
                        visibility = methodSymbol?.let { visibilityByMember[it] } ?: javaVisibility(method),
                        modifiers = javaModifiers(method),
                        annotations = emptyList(),
                        overrides = try {
                            if (callable != null) {
                                callable.allOverriddenSymbols
                                    .mapNotNull { it.callableId?.asSingleFqName()?.asString() }
                                    .toList().distinct()
                            } else {
                                emptyList()
                            }
                        } catch (_: Exception) {
                            emptyList()
                        },
                        supertypes = emptyList(),
                        jvmOwner = methodSymbol?.let { jvmByMember[it]?.first },
                        jvmDescriptor = methodSymbol?.let { jvmByMember[it]?.second },
                        position = positionAt(lines, relativePath, method.textOffset),
                    ),
                )
            }
            for (field in psiClass.fields) {
                val fieldSymbol = memberSymbols[field]
                val callable = fieldSymbol as? KaCallableSymbol
                declarations.add(
                    ResolvedDeclaration(
                        name = field.name,
                        qualifiedName = "$modulePath:${canonical}.${field.name}",
                        canonicalName = "${canonical}.${field.name}",
                        kind = "property",
                        signature = "val ${field.name}: ${field.type.canonicalText.normalized()}",
                        returnType = field.type.canonicalText.normalized(),
                        extensionReceiverType = null,
                        visibility = fieldSymbol?.let { visibilityByMember[it] } ?: javaVisibility(field),
                        modifiers = javaModifiers(field),
                        annotations = emptyList(),
                        overrides = emptyList(),
                        supertypes = emptyList(),
                        jvmOwner = fieldSymbol?.let { jvmByMember[it]?.first },
                        jvmDescriptor = fieldSymbol?.let { jvmByMember[it]?.second },
                        position = positionAt(lines, relativePath, field.textOffset),
                    ),
                )
            }
        }
        out.add(
            ResolvedFileFacts(
                relativePath = relativePath,
                modulePath = modulePath,
                packageName = javaFile.packageName,
                imports = emptyList(),
                declarations = declarations,
                usages = usages,
                diagnostics = diagnostics,
                callsTotal = 0,
                callsResolved = 0,
                resolutionErrorCodes = emptyMap(),
            ),
        )
        }
        }
        return out
    }

    private fun collectJavaClasses(file: PsiJavaFile, out: MutableList<PsiClass>) {
        for (psiClass in file.classes) {
            out.add(psiClass)
            for (inner in psiClass.innerClasses) {
                out.add(inner)
            }
        }
    }

    private fun positionAt(lines: SyntaxAnalyzer.LineIndex, filename: String, offset: Int): Position =
        lines.positionAt(offset).copy(filename = filename)

    /** Kind/signature from PSI text, matching the syntax tier's forms. */
    private fun declarationShapes(declaration: KtDeclaration): Shape? = when (declaration) {
        is KtClass -> Shape(
            kind = when {
                declaration.hasModifier(KtTokens.ENUM_KEYWORD) -> "enum"
                declaration.hasModifier(KtTokens.ANNOTATION_KEYWORD) -> "annotation"
                declaration.hasModifier(KtTokens.DATA_KEYWORD) -> "data-class"
                declaration.hasModifier(KtTokens.SEALED_KEYWORD) -> "sealed-class"
                declaration.isInterface() -> "interface"
                else -> "class"
            },
        )

        is KtObjectDeclaration -> Shape(
            kind = if (declaration.isCompanion()) "companion" else "object",
        )

        is KtNamedFunction -> {
            val name = declaration.name ?: "<anonymous>"
            val params = declaration.valueParameters.map { param ->
                "${param.name ?: "_"}: ${param.typeReference?.text?.normalized() ?: "?"}"
            }
            val returnType = declaration.typeReference?.text?.normalized()
            val signature = buildString {
                append("fun ")
                declaration.receiverTypeReference?.let { append(it.text.normalized()).append('.') }
                append(name)
                append('(').append(params.joinToString(", ")).append(')')
                returnType?.let { append(": ").append(it) }
            }
            Shape(
                kind = when {
                    declaration.receiverTypeReference != null -> "extension-function"
                    declaration.isTopLevel -> "function"
                    else -> "method"
                },
                signature = signature,
                returnType = returnType,
                extensionReceiver = declaration.receiverTypeReference?.text?.normalized(),
            )
        }

        is KtProperty -> {
            val typeText = declaration.typeReference?.text?.normalized()
            val signature = buildString {
                append(if (declaration.isVar) "var " else "val ")
                declaration.receiverTypeReference?.let { append(it.text.normalized()).append('.') }
                append(declaration.name ?: "<anonymous>")
                typeText?.let { append(": ").append(it) }
            }
            Shape(
                kind = "property",
                signature = signature,
                returnType = typeText,
                extensionReceiver = declaration.receiverTypeReference?.text?.normalized(),
            )
        }

        is KtTypeAlias -> {
            val name = declaration.name ?: "<anonymous>"
            val target = declaration.getTypeReference()?.text?.normalized() ?: "?"
            Shape(
                kind = "typealias",
                signature = "typealias $name = $target",
                returnType = target,
            )
        }

        // Constructors, accessors and init blocks are JVM evidence on their
        // owner, not separate declarations at the resolved tier.
        else -> null
    }

    data class Shape(
        val kind: String,
        val signature: String? = null,
        val returnType: String? = null,
        val extensionReceiver: String? = null,
    )

    // ---- helpers called inside the analyze scope ------------------------------

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

    private fun javaCanonicalName(psiClass: PsiClass): String {
        val outer = psiClass.containingClass
        return if (outer != null) {
            "${javaCanonicalName(outer)}$${psiClass.name}"
        } else {
            psiClass.qualifiedName ?: psiClass.name ?: "<anonymous>"
        }
    }

    // ---- pure PSI helpers (shape parity with the syntax tier) ------------------

    private fun psiVisibility(element: KtModifierListOwner): String? = when {
        element.hasModifier(KtTokens.PRIVATE_KEYWORD) -> "private"
        element.hasModifier(KtTokens.INTERNAL_KEYWORD) -> "internal"
        element.hasModifier(KtTokens.PROTECTED_KEYWORD) -> "protected"
        element.hasModifier(KtTokens.PUBLIC_KEYWORD) -> "public"
        else -> null
    }

    private fun javaVisibility(member: PsiModifierListOwner): String = when {
        member.hasModifierProperty("private") -> "private"
        member.hasModifierProperty("protected") -> "protected"
        member.hasModifierProperty("public") -> "public"
        else -> "package-private"
    }

    private fun psiModifiers(element: KtModifierListOwner): List<String> {
        val out = mutableListOf<String>()
        for ((token, name) in MODIFIER_NAMES) {
            if (element.hasModifier(token)) out.add(name)
        }
        return out
    }

    private fun javaModifiers(member: PsiModifierListOwner): List<String> {
        val out = mutableListOf<String>()
        for (modifier in listOf("abstract", "final", "static")) {
            if (member.hasModifierProperty(modifier)) out.add(modifier)
        }
        return out
    }

    private fun containerChain(element: PsiElement): List<String> {
        val chain = mutableListOf<String>()
        var current: PsiElement? = element.parent
        while (current != null) {
            if (current is KtClassOrObject) {
                current.name?.let { chain.add(0, it) }
            }
            current = current.parent
        }
        return chain
    }

    private val MODIFIER_NAMES = linkedMapOf(
        KtTokens.INLINE_KEYWORD to "inline",
        KtTokens.SUSPEND_KEYWORD to "suspend",
        KtTokens.OPERATOR_KEYWORD to "operator",
        KtTokens.INFIX_KEYWORD to "infix",
        KtTokens.EXPECT_KEYWORD to "expect",
        KtTokens.ACTUAL_KEYWORD to "actual",
        KtTokens.EXTERNAL_KEYWORD to "external",
        KtTokens.ABSTRACT_KEYWORD to "abstract",
        KtTokens.OPEN_KEYWORD to "open",
        KtTokens.OVERRIDE_KEYWORD to "override",
        KtTokens.CONST_KEYWORD to "const",
        KtTokens.TAILREC_KEYWORD to "tailrec",
        KtTokens.SEALED_KEYWORD to "sealed",
        KtTokens.DATA_KEYWORD to "data",
        KtTokens.VALUE_KEYWORD to "value",
        KtTokens.INNER_KEYWORD to "inner",
        KtTokens.LATEINIT_KEYWORD to "lateinit",
        KtTokens.COMPANION_KEYWORD to "companion",
    )

    private fun String.normalized(): String = SyntaxAnalyzer.normalizeName(this)


}
