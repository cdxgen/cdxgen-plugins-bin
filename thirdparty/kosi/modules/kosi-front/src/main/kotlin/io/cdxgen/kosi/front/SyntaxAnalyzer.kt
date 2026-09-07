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
        val receiverType: String?,
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
        val diagnostics = mutableListOf<Diagnostic>()
        for (error in collectParseErrors(file)) {
            diagnostics.add(
                Diagnostic(
                    code = "parse-error",
                    severity = Severity.ERROR,
                    message = error.errorDescription ?: "syntax error",
                    position = positionAt(text, error.textOffset).copy(filename = filePath),
                ),
            )
        }
        val imports = file.importDirectives.mapNotNull { directive -> importUsage(directive, text) }
        val declarations = mutableListOf<RawDeclaration>()
        val usages = mutableListOf<RawUsage>()
        val pkg = file.packageFqName.asString()
        file.accept(DeclarationVisitor(text, pkg, declarations, usages))
        // Stamp the filename on every position now that we know it.
        declarations.replaceAll { it.copy(position = it.position.copy(filename = filePath)) }
        usages.replaceAll { it.copy(position = it.position.copy(filename = filePath)) }
        return FileResult(pkg, imports, declarations, usages, diagnostics)
    }

    private fun collectParseErrors(file: KtFile): List<PsiErrorElement> = env.collectParseErrors(file)

    private fun importUsage(directive: KtImportDirective, text: String): ImportUsage? {
        val offset = directive.textOffset
        val fqName = directive.importedFqName?.asString() ?: return null
        return ImportUsage(
            name = normalizeName(fqName),
            alias = directive.aliasName,
            star = directive.isAllUnder,
            purl = null,
            filePath = filePath,
            position = positionAt(text, offset).copy(filename = filePath),
        )
    }

    private inner class DeclarationVisitor(
        private val text: String,
        private val pkg: String,
        private val declarations: MutableList<RawDeclaration>,
        private val usages: MutableList<RawUsage>,
    ) : KtTreeVisitorVoid() {

        private fun pos(element: PsiElement): Position =
            positionAt(text, element.textOffset).copy(filename = filePath)

        private fun emit(
            element: PsiElement,
            name: String,
            containers: List<String>,
            kind: String,
            signature: String? = null,
            receiverType: String? = null,
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
                    receiverType = receiverType,
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
                receiverType = returnType,
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
                receiverType = typeText,
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
                    receiverType = null,
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
                    receiverType = null,
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
                receiverType = target,
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
            val ref = expression.operationReference
            usages.add(
                RawUsage(
                    name = operatorFunctionName(ref.text) ?: normalizeName(ref.text),
                    usageKind = "operator",
                    position = pos(ref),
                ),
            )
            super.visitBinaryExpression(expression)
        }

        override fun visitUnaryExpression(expression: org.jetbrains.kotlin.psi.KtUnaryExpression) {
            val ref = expression.operationReference
            usages.add(
                RawUsage(
                    name = operatorFunctionName(ref.text) ?: normalizeName(ref.text),
                    usageKind = "operator",
                    position = pos(ref),
                ),
            )
            super.visitUnaryExpression(expression)
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
            "*=" -> "mulAssign"
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
            else -> if (text.isNotBlank() && text != "!!" && text != "!" && text != "?" &&
                text != "?:" && text != "[]" && text != "as" && text != "as?"
            ) {
                // Infix functions come through as their own names; non-function
                // operators are excluded so usage evidence stays nameable.
                text
            } else {
                null
            }
        }

        fun normalizeName(raw: String): String =
            raw.replace(Regex("\\s+"), "")
                .replace("?.", ".")
                .replace("`", "")

        private fun String.normalized(): String = normalizeName(this)

        fun joinCanonical(pkg: String, containers: List<String>, name: String): String =
            (listOf(pkg).filter { it.isNotBlank() } + containers + name)
                .filter { it.isNotBlank() }
                .joinToString(".")

        fun positionAt(text: String, offset: Int): Position {
            val safeOffset = offset.coerceIn(0, text.length)
            var line = 1
            var lineStart = 0
            for (i in 0 until safeOffset) {
                if (text[i] == '\n') {
                    line++
                    lineStart = i + 1
                }
            }
            return Position(filename = "", line = line, column = safeOffset - lineStart + 1)
        }
    }
}
