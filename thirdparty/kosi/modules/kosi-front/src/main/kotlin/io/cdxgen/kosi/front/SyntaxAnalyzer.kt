package io.cdxgen.kosi.front

import io.cdxgen.kosi.schema.AnnotationEvidence
import io.cdxgen.kosi.schema.Diagnostic
import io.cdxgen.kosi.schema.ImportUsage
import io.cdxgen.kosi.schema.Position
import io.cdxgen.kosi.schema.Severity
import org.jetbrains.kotlin.com.intellij.psi.PsiElement
import org.jetbrains.kotlin.com.intellij.psi.PsiErrorElement
import org.jetbrains.kotlin.psi.KtTreeVisitorVoid
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtAnnotated
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtCallableReferenceExpression
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtClassInitializer
import org.jetbrains.kotlin.psi.KtClassOrObject
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtImportDirective
import org.jetbrains.kotlin.psi.KtModifierListOwner
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtObjectDeclaration
import org.jetbrains.kotlin.psi.KtPrimaryConstructor
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtPropertyAccessor
import org.jetbrains.kotlin.psi.KtSecondaryConstructor
import org.jetbrains.kotlin.psi.KtSuperTypeCallEntry
import org.jetbrains.kotlin.psi.KtTypeAlias
import org.jetbrains.kotlin.psi.KtValueArgument

/**
 * PSI-only extraction for the syntax tier: imports, declarations and
 * usages-by-name, with parse errors surfaced as diagnostics. No resolution is
 * performed and none is pretended (the report carries
 * `syntax-backend-no-resolution`).
 */
class SyntaxAnalyzer(
    private val env: PsiEnvironment,
    private val filePath: String,
    private val modulePath: String,
) {

    data class FileResult(
        val packageName: String,
        val imports: List<ImportUsage>,
        val declarations: List<RawDeclaration>,
        val usages: List<RawUsage>,
        val diagnostics: List<Diagnostic>,
    )

    data class RawDeclaration(
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
        val position: Position,
    )

    data class RawUsage(
        val name: String,
        val usageKind: String,
        val position: Position,
    )

    fun analyze(text: String): FileResult {
        val file = env.parseFile(text)
        val lines = LineIndex(text)
        val diagnostics = mutableListOf<Diagnostic>()
        for (error in collectParseErrors(file)) {
            diagnostics.add(
                Diagnostic(
                    code = "parse-error",
                    severity = Severity.ERROR,
                    message = error.errorDescription ?: "syntax error",
                    position = lines.positionAt(error.textOffset).copy(filename = filePath),
                ),
            )
        }
        val imports = file.importDirectives.mapNotNull { directive -> importUsage(directive, lines) }
        val declarations = mutableListOf<RawDeclaration>()
        val usages = mutableListOf<RawUsage>()
        val pkg = file.packageFqName.asString()
        file.accept(DeclarationVisitor(lines, pkg, declarations, usages))
        // Stamp the filename on every position now that we know it.
        declarations.replaceAll { it.copy(position = it.position.copy(filename = filePath)) }
        usages.replaceAll { it.copy(position = it.position.copy(filename = filePath)) }
        return FileResult(pkg, imports, declarations, usages, diagnostics)
    }

    private fun collectParseErrors(file: KtFile): List<PsiErrorElement> = env.collectParseErrors(file)

    private fun importUsage(directive: KtImportDirective, lines: LineIndex): ImportUsage? {
        val offset = directive.textOffset
        val fqName = directive.importedFqName?.asString() ?: return null
        return ImportUsage(
            name = normalizeName(fqName),
            alias = directive.aliasName,
            star = directive.isAllUnder,
            purl = null,
            filePath = filePath,
            position = lines.positionAt(offset).copy(filename = filePath),
        )
    }

    private inner class DeclarationVisitor(
        private val lines: LineIndex,
        private val pkg: String,
        private val declarations: MutableList<RawDeclaration>,
        private val usages: MutableList<RawUsage>,
    ) : KtTreeVisitorVoid() {

        private fun pos(element: PsiElement): Position =
            lines.positionAt(element.textOffset).copy(filename = filePath)

        private fun emit(
            element: PsiElement,
            name: String,
            containers: List<String>,
            kind: String,
            signature: String? = null,
            returnType: String? = null,
            extensionReceiverType: String? = null,
            visibility: String = "public",
            modifiers: List<String> = emptyList(),
            annotations: List<AnnotationEvidence> = emptyList(),
        ) {
            val fqName = joinCanonical(pkg, containers, name)
            declarations.add(
                RawDeclaration(
                    name = name,
                    qualifiedName = "$modulePath:$fqName",
                    canonicalName = fqName,
                    kind = kind,
                    signature = signature,
                    returnType = returnType,
                    extensionReceiverType = extensionReceiverType,
                    visibility = visibility,
                    modifiers = modifiers,
                    annotations = annotations,
                    position = pos(element),
                ),
            )
        }

        override fun visitClass(klass: KtClass) {
            val kind = when {
                klass.hasModifier(KtTokens.ENUM_KEYWORD) -> "enum"
                klass.hasModifier(KtTokens.ANNOTATION_KEYWORD) -> "annotation"
                klass.hasModifier(KtTokens.DATA_KEYWORD) -> "data-class"
                klass.hasModifier(KtTokens.SEALED_KEYWORD) -> "sealed-class"
                klass.isInterface() -> "interface"
                else -> "class"
            }
            val name = klass.name ?: "<anonymous>"
            emit(
                klass, name, containerChainOf(klass), kind,
                visibility = visibilityOf(klass) ?: "public",
                modifiers = modifiersOf(klass),
                annotations = annotationsOf(klass),
            )
            super.visitClass(klass)
        }

        override fun visitObjectDeclaration(declaration: KtObjectDeclaration) {
            val name = declaration.name ?: "<anonymous>"
            emit(
                declaration, name, containerChainOf(declaration),
                if (declaration.isCompanion()) "companion" else "object",
                visibility = visibilityOf(declaration) ?: "public",
                modifiers = modifiersOf(declaration),
                annotations = annotationsOf(declaration),
            )
            super.visitObjectDeclaration(declaration)
        }

        override fun visitNamedFunction(function: KtNamedFunction) {
            val name = function.name ?: "<anonymous>"
            val containers = containerChainOf(function)
            val kind = when {
                function.receiverTypeReference != null -> "extension-function"
                function.isTopLevel -> "function"
                else -> "method"
            }
            val params = function.valueParameters.map { param ->
                "${param.name ?: "_"}: ${param.typeReference?.text?.normalized() ?: "?"}"
            }
            val returnType = function.typeReference?.text?.normalized()
            val signature = buildString {
                append("fun ")
                function.receiverTypeReference?.let { append(it.text.normalized()).append('.') }
                append(name)
                append('(').append(params.joinToString(", ")).append(')')
                returnType?.let { append(": ").append(it) }
            }
            emit(
                function, name, containers, kind,
                signature = signature,
                returnType = returnType,
                extensionReceiverType = function.receiverTypeReference?.text?.normalized(),
                visibility = visibilityOf(function) ?: "public",
                modifiers = modifiersOf(function),
                annotations = annotationsOf(function),
            )
            super.visitNamedFunction(function)
        }

        override fun visitProperty(property: KtProperty) {
            val name = property.name ?: "<anonymous>"
            val typeText = property.typeReference?.text?.normalized()
            val signature = buildString {
                append(if (property.isVar) "var " else "val ")
                property.receiverTypeReference?.let { append(it.text.normalized()).append('.') }
                append(name)
                typeText?.let { append(": ").append(it) }
            }
            emit(
                property, name, containerChainOf(property), "property",
                signature = signature,
                returnType = typeText,
                extensionReceiverType = property.receiverTypeReference?.text?.normalized(),
                visibility = visibilityOf(property) ?: "public",
                modifiers = modifiersOf(property),
                annotations = annotationsOf(property),
            )
            super.visitProperty(property)
        }

        override fun visitPropertyAccessor(accessor: KtPropertyAccessor) {
            val property = accessor.property
            val name = property?.name ?: "<anonymous>"
            val fqName = joinCanonical(pkg, containerChainOf(accessor), name) +
                if (accessor.isGetter) ".get" else ".set"
            declarations.add(
                RawDeclaration(
                    name = name,
                    qualifiedName = "$modulePath:$fqName",
                    canonicalName = fqName,
                    kind = if (accessor.isGetter) "getter" else "setter",
                    signature = null,
                    returnType = null,
                    extensionReceiverType = property?.receiverTypeReference?.text?.normalized(),
                    visibility = visibilityOf(accessor)
                        ?: property?.let { visibilityOf(it) }
                        ?: "public",
                    modifiers = emptyList(),
                    annotations = annotationsOf(accessor),
                    position = pos(accessor),
                ),
            )
            super.visitPropertyAccessor(accessor)
        }

        override fun visitPrimaryConstructor(constructor: KtPrimaryConstructor) {
            val container = constructor.getContainingClassOrObject()
            val containerName = container?.name ?: "<anonymous>"
            emit(
                constructor, containerName, containerChainOf(constructor), "constructor",
                signature = constructor.valueParameterList?.text?.normalized()
                    ?.let { "$containerName$it" },
                visibility = visibilityOf(constructor) ?: "public",
                annotations = annotationsOf(constructor),
            )
            super.visitPrimaryConstructor(constructor)
        }

        override fun visitSecondaryConstructor(constructor: KtSecondaryConstructor) {
            val container = constructor.getContainingClassOrObject()
            val containerName = container?.name ?: "<anonymous>"
            emit(
                constructor, containerName, containerChainOf(constructor), "constructor",
                signature = constructor.valueParameterList?.text?.normalized()
                    ?.let { "$containerName$it" },
                visibility = visibilityOf(constructor) ?: "public",
                annotations = annotationsOf(constructor),
            )
            super.visitSecondaryConstructor(constructor)
        }

        override fun visitClassInitializer(initializer: KtClassInitializer) {
            val container = initializer.parent as? KtClassOrObject
            val containerName = container?.name ?: "<anonymous>"
            val fqName = joinCanonical(pkg, containerChainOf(initializer), containerName) + ".<init-block>"
            declarations.add(
                RawDeclaration(
                    name = containerName,
                    qualifiedName = "$modulePath:$fqName",
                    canonicalName = fqName,
                    kind = "init",
                    signature = null,
                    returnType = null,
                    extensionReceiverType = null,
                    visibility = "public",
                    modifiers = emptyList(),
                    annotations = emptyList(),
                    position = pos(initializer),
                ),
            )
            super.visitClassInitializer(initializer)
        }

        override fun visitTypeAlias(typeAlias: KtTypeAlias) {
            val name = typeAlias.name ?: "<anonymous>"
            val target = typeAlias.getTypeReference()?.text?.normalized() ?: "?"
            emit(
                typeAlias, name, containerChainOf(typeAlias), "typealias",
                signature = "typealias $name = $target",
                returnType = target,
                visibility = visibilityOf(typeAlias) ?: "public",
                annotations = annotationsOf(typeAlias),
            )
            super.visitTypeAlias(typeAlias)
        }

        // ---- usages --------------------------------------------------------

        override fun visitCallExpression(expression: KtCallExpression) {
            val callee = expression.calleeExpression
            if (callee != null) {
                // `stmt.executeQuery(...)` parses as a qualified expression with
                // the call as its selector; the usage name carries the receiver
                // chain so model patterns can match on the dotted form.
                val parent = expression.parent
                val name = if (parent is org.jetbrains.kotlin.psi.KtQualifiedExpression &&
                    parent.selectorExpression == expression
                ) {
                    qualifiedNameWithoutArgs(parent)
                } else {
                    normalizeName(callee.text)
                }
                usages.add(RawUsage(name, "call", pos(callee)))
            }
            super.visitCallExpression(expression)
        }

        override fun visitBinaryExpression(expression: org.jetbrains.kotlin.psi.KtBinaryExpression) {
            emitOperator(expression.operationReference)
            super.visitBinaryExpression(expression)
        }

        override fun visitUnaryExpression(expression: org.jetbrains.kotlin.psi.KtUnaryExpression) {
            emitOperator(expression.operationReference)
            super.visitUnaryExpression(expression)
        }

        /**
         * Emits an operator usage only when the operator denotes a *callable*
         * (`+` -> `plus`, an infix function by its own name). `=`, `&&`, `!!`,
         * `as` and friends resolve to no function, so naming them as usages
         * would put unmatchable names in `usages[]`; [operatorFunctionName]
         * returning null means "not a call".
         */
        private fun emitOperator(ref: org.jetbrains.kotlin.psi.KtSimpleNameExpression) {
            val name = operatorFunctionName(ref.text) ?: return
            usages.add(RawUsage(name, "operator", pos(ref)))
        }

        override fun visitCallableReferenceExpression(expression: KtCallableReferenceExpression) {
            val name = expression.callableReference.getReferencedName()
            val receiver = expression.receiverExpression?.text?.normalized()
            usages.add(
                RawUsage(
                    name = receiver?.let { "$it::$name" } ?: name,
                    usageKind = "reference",
                    position = pos(expression),
                ),
            )
            super.visitCallableReferenceExpression(expression)
        }

        override fun visitSuperTypeCallEntry(call: KtSuperTypeCallEntry) {
            usages.add(
                RawUsage(
                    normalizeName(call.calleeExpression.text),
                    "call",
                    pos(call.calleeExpression),
                ),
            )
            super.visitSuperTypeCallEntry(call)
        }

        // ---- shared helpers -------------------------------------------------

        private fun containerChainOf(element: PsiElement): List<String> {
            val chain = mutableListOf<String>()
            var current: PsiElement? = element.parent
            while (current != null) {
                when (val node = current) {
                    is KtClassOrObject -> node.name?.let { chain.add(0, it) }
                    else -> {}
                }
                current = current.parent
            }
            return chain
        }

        private fun annotationsOf(element: KtAnnotated): List<AnnotationEvidence> =
            element.annotationEntries.map { entry ->
                AnnotationEvidence(
                    name = entry.shortName?.asString() ?: entry.text.normalized(),
                    value = entry.valueArgumentList?.arguments?.firstOrNull()
                        ?.argumentStringTemplateExpression()?.text?.normalized()?.removeSurrounding("\""),
                    position = pos(entry),
                )
            }

        private fun visibilityOf(element: KtModifierListOwner): String? = when {
            element.hasModifier(KtTokens.PRIVATE_KEYWORD) -> "private"
            element.hasModifier(KtTokens.INTERNAL_KEYWORD) -> "internal"
            element.hasModifier(KtTokens.PROTECTED_KEYWORD) -> "protected"
            element.hasModifier(KtTokens.PUBLIC_KEYWORD) -> "public"
            else -> null
        }

        private fun modifiersOf(element: KtModifierListOwner): List<String> =
            MODIFIER_NAMES.filter { (token, _) -> element.hasModifier(token) }.values.toList()

        private fun KtValueArgument.argumentStringTemplateExpression(): PsiElement? =
            getArgumentExpression()
    }

    companion object {
        /**
         * Renders a qualified expression as a dotted name with argument lists
         * elided (`a.b(x).c()` -> `a.b.c`), so usage names are comparable to
         * model-pack patterns regardless of call arguments.
         */
        fun qualifiedNameWithoutArgs(expression: org.jetbrains.kotlin.com.intellij.psi.PsiElement): String =
            renderQualified(expression)

        private fun renderQualified(element: org.jetbrains.kotlin.com.intellij.psi.PsiElement): String =
            when (element) {
                is org.jetbrains.kotlin.psi.KtQualifiedExpression ->
                    renderQualified(element.receiverExpression) + "." +
                        renderQualified(element.selectorExpression ?: element)
                is org.jetbrains.kotlin.psi.KtCallExpression ->
                    element.calleeExpression?.let { renderQualified(it) } ?: element.text.normalized()
                is org.jetbrains.kotlin.psi.KtNameReferenceExpression -> normalizeName(element.text)
                else -> normalizeName(element.text)
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

        /**
         * Maps operator spellings to the Kotlin operator function names
         * (02-ARCHITECTURE.md §4, "operators -> named calls"). The operation
         * token is rendered by PSI as its debug text (PLUS, MUL, IDENTIFIER,
         * ...); mapping here keeps usages matching the model-pack notation.
         */
        fun operatorFunctionName(text: String): String? = when (text) {
            "+" -> "plus"
            "-" -> "minus"
            "*" -> "times"
            "/" -> "div"
            "%" -> "rem"
            "+=" -> "plusAssign"
            "-=" -> "minusAssign"
            "*=" -> "timesAssign"
            "/=" -> "divAssign"
            "%=" -> "remAssign"
            "in" -> "contains"
            "!in" -> "contains"
            ".." -> "rangeTo"
            "..<" -> "rangeUntil"
            "<", ">", "<=", ">=" -> "compareTo"
            "==", "!=", "===", "!==" -> "equals"
            "++" -> "inc"
            "--" -> "dec"
            // Infix functions arrive as their own names, which are
            // identifiers; every remaining symbolic operator (`=`, `&&`,
            // `||`, `!!`, `?:`, `as`, ...) resolves to no function and is
            // deliberately not a usage. Keywords are identifiers too, so the
            // ones that are operators rather than calls are named here.
            else -> text.takeIf { IDENTIFIER.matches(it) && it !in NON_CALL_KEYWORD_OPERATORS }
        }

        private val IDENTIFIER = Regex("""[A-Za-z_][A-Za-z0-9_]*""")

        /** Keyword operators that are not function calls. */
        private val NON_CALL_KEYWORD_OPERATORS = setOf("as", "is", "in")

        fun normalizeName(raw: String): String =
            raw.replace(Regex("\\s+"), "")
                .replace("?.", ".")
                .replace("`", "")

        private fun String.normalized(): String = normalizeName(this)

        fun joinCanonical(pkg: String, containers: List<String>, name: String): String =
            (listOf(pkg).filter { it.isNotBlank() } + containers + name)
                .filter { it.isNotBlank() }
                .joinToString(".")

        fun positionAt(text: String, offset: Int): Position = LineIndex(text).positionAt(offset)
    }

    /**
     * Offset -> (line, column) over one file. The line starts are indexed once
     * and binary-searched per lookup; scanning the prefix per element made
     * position stamping quadratic in file length.
     */
    class LineIndex(text: String) {
        private val length = text.length
        private val lineStarts: IntArray = buildList {
            add(0)
            for (i in text.indices) if (text[i] == '\n') add(i + 1)
        }.toIntArray()

        fun positionAt(offset: Int): Position {
            val safeOffset = offset.coerceIn(0, length)
            val found = lineStarts.binarySearch(safeOffset)
            // binarySearch returns -(insertionPoint) - 1 when absent; the line
            // is the one whose start is the greatest <= safeOffset.
            val index = if (found >= 0) found else -found - 2
            val lineStart = lineStarts[index]
            return Position(filename = "", line = index + 1, column = safeOffset - lineStart + 1)
        }
    }
}
