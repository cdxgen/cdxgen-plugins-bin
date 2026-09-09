package io.cdxgen.kosi.kir

/**
 * Deterministic text dump of a [KirModule] (`kir dump`). The format is the
 * round-trip contract: `KirReader.read(KirWriter.write(m))` rebuilds an
 * equal module, so dump -> read -> dump is byte-identical — that equality is
 * what makes dumps diffable and goldenable.
 *
 * Layout: one declaration per line, two-space indented, registers unquoted
 * (they cannot contain whitespace by construction), free-form names quoted
 * with JSON escaping. Modules print functions in canonical-name order, and
 * writers never consult a map iteration order that the reader could not
 * reproduce.
 */
object KirWriter {

    fun write(module: KirModule): String = buildString {
        appendLine(KirModule.FORMAT)
        for (function in module.functions.sortedBy { it.canonicalName }) {
            writeFunction(this, function)
        }
    }

    private fun writeFunction(out: StringBuilder, f: KirFunction) {
        out.appendLine("function ${q(f.canonicalName)}")
        out.appendLine("  jvm ${qn(f.jvmDescriptor)}")
        out.appendLine("  purl ${q(f.purl)}")
        out.appendLine("  at ${q(f.file)} ${f.line} ${f.column}")
        out.appendLine("  enclosing ${qn(f.enclosingClass)}")
        out.appendLine("  visibility ${q(f.visibility)}")
        out.appendLine("  modifiers ${f.modifiers.sorted().joinToString(" ") { q(it) }}")
        out.appendLine("  annotations ${f.annotations.sorted().joinToString(" ") { q(it) }}")
        out.appendLine("  overrides ${f.overrides.sorted().joinToString(" ") { q(it) }}")
        out.appendLine("  overriddenBy ${f.overriddenBy.sorted().joinToString(" ") { q(it) }}")
        out.appendLine("  synthetic ${qn(f.syntheticCause)}")
        out.appendLine("  returns ${qn(f.returnType)}")
        for (p in f.params) {
            out.appendLine(
                "  param ${p.register} name=${qn(p.name)} type=${qn(p.type)} receiver=${p.receiver}",
            )
        }
        val body = f.body ?: return
        for ((index, block) in body.blocks.withIndex()) {
            out.appendLine("  block ${block.id}${if (index == 0) " entry" else ""}")
            for (ins in block.instructions) {
                out.appendLine("    ${writeIns(ins)}")
            }
        }
    }

    private fun writeIns(ins: KirIns): String = when (ins) {
        is KirAssign -> "${ins.result} = assign ${ins.source}"
        is KirLoad -> "${ins.result} = load ${writeConst(ins.constant)}"
        is KirStore -> "store ${ins.target} = ${ins.value}"
        is KirFieldGet -> "${ins.result} = fieldget ${ins.receiver} ${writePath(ins.path)}"
        is KirFieldSet -> "fieldset ${ins.receiver} ${writePath(ins.path)} = ${ins.value}"
        is KirIndexGet -> "${ins.result} = indexget ${ins.receiver} ${ins.index}"
        is KirIndexSet -> "indexset ${ins.receiver} ${ins.index} = ${ins.value}"
        is KirCall -> lhs(ins.result) + "call " + writeCall(ins.callee, ins.receiver, ins.args)
        is KirDynamicCall ->
            lhs(ins.result) + "dynamic " + q(ins.name) + writeRecvArgs(ins.receiver, ins.args)
        is KirNew -> "${ins.result} = new ${qn(ins.type)}${writeArgs(ins.args)}"
        is KirPhi ->
            "${ins.result} = phi [" + ins.inputs.entries.sortedBy { it.key }.joinToString(" ") { "${it.key}=${it.value}" } + "]"
        is KirBranch -> "branch ${ins.condition} then=${ins.thenBlock} else=${ins.elseBlock}"
        is KirReturn -> ins.value?.let { "return $it" } ?: "return"
        is KirThrow -> "throw ${ins.exception}"
        is KirSuspendPoint -> "suspend ${ins.result}"
        is KirStringConcat -> "${ins.result} = concat ${writeArgs(ins.parts)}"
        is KirLambda -> "${ins.result} = lambda ${q(ins.function)}${writeArgs(ins.captures)}"
        is KirElvis -> "${ins.result} = elvis ${ins.value} fallback=${ins.fallback}"
        is KirSafeCall -> "${ins.result} = safecall ${ins.receiver} ${writePath(ins.path)}"
        is KirCast ->
            "${ins.result} = cast ${ins.value} as ${qn(ins.type)}${if (ins.checked) " checked" else ""}"
        is KirTypeCheck -> "${ins.result} = typeof ${ins.value} is ${qn(ins.type)}"
    }

    private fun lhs(result: String?): String = result?.let { "$it = " } ?: ""

    private fun writeCall(callee: KirCallee, receiver: String?, args: List<String>): String =
        "${q(callee.fqn)} kind=${callee.kind.name.lowercase()} desc=${qn(callee.descriptor)}" +
            writeRecvArgs(receiver, args)

    private fun writeRecvArgs(receiver: String?, args: List<String>): String =
        (receiver?.let { " recv=$it" } ?: "") + writeArgs(args)

    private fun writeArgs(args: List<String>): String =
        if (args.isEmpty()) "" else " args=(" + args.joinToString(",") + ")"

    private fun writePath(path: AccessPath): String =
        path.base + path.elements.joinToString("") { element ->
            when (element) {
                is AccessPath.Element.Field -> ".${element.name}"
                is AccessPath.Element.Index -> "[]"
                is AccessPath.Element.Star -> ".*"
            }
        }

    private fun writeConst(constant: KirConstant): String = when (constant) {
        is KirConstant.Str -> q(constant.value)
        is KirConstant.IntConst -> "int ${constant.value}"
        is KirConstant.FloatConst -> "float ${constant.value}"
        is KirConstant.Bool -> "bool ${constant.value}"
        is KirConstant.Null -> "null"
    }

    /** Nullable fields print the literal `null`; q("") prints the empty quotes. */
    fun qn(text: String?): String = text?.let { q(it) } ?: "null"

    /** JSON-style quoting for any free-form name. */
    fun q(text: String?): String {
        if (text != null && text.isNotEmpty() && !text.any { it.isWhitespace() || it == '"' || it == '#' }) {
            return text
        }
        val escaped = text.orEmpty()
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        return "\"$escaped\""
    }
}
