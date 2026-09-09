package io.cdxgen.kosi.kir

/**
 * Reads back what [KirWriter] wrote. The pair is the `kir dump` round-trip:
 * dump, re-read, dump again must be byte-identical, so the reader accepts
 * exactly the writer's grammar — no bare-name leniency the writer never
 * exercises, no default values the writer never omits.
 */
object KirReader {

    class KirFormatException(message: String, line: Int) : RuntimeException("line $line: $message")

    fun read(text: String): KirModule {
        val cursor = Cursor(text.lines())
        cursor.expect(KirModule.FORMAT)
        val functions = mutableListOf<KirFunction>()
        while (!cursor.atEnd()) {
            functions.add(readFunction(cursor))
        }
        return KirModule(functions)
    }

    private fun readFunction(cursor: Cursor): KirFunction {
        val canonicalName = cursor.expect("function ").removePrefix("function ").let { unq(it) }
        var jvmDescriptor: String? = null
        var purl = ""
        var file = ""
        var line = 0
        var column = 0
        var enclosing: String? = null
        var visibility = ""
        var modifiers = emptySet<String>()
        var annotations = emptyList<String>()
        var overrides = emptyList<String>()
        var overriddenBy = emptyList<String>()
        var synthetic: String? = null
        var returnType: String? = null
        val params = mutableListOf<KirParam>()
        var blocks = mutableListOf<KirBlock>()
        var current: MutableList<KirIns>? = null

        loop@ while (!cursor.atEnd()) {
            val text = cursor.peek()
            when {
                text.startsWith("function ") -> break@loop
                text.startsWith("  jvm ") -> jvmDescriptor = unqn(text.removePrefix("  jvm "))
                text.startsWith("  purl ") -> purl = unq(text.removePrefix("  purl "))
                text.startsWith("  at ") -> {
                    val rest = text.removePrefix("  at ")
                    val (fileToken, after) = quotedToken(rest)
                    file = unq(fileToken)
                    line = after.substringBefore(' ').toInt()
                    column = after.substringAfter(' ').toInt()
                }
                text.startsWith("  enclosing ") -> enclosing = unqn(text.removePrefix("  enclosing "))
                text.startsWith("  visibility ") -> visibility = unq(text.removePrefix("  visibility "))
                text.startsWith("  modifiers ") -> modifiers = splitList(text.removePrefix("  modifiers ")).toSet()
                text.startsWith("  annotations ") -> annotations = splitList(text.removePrefix("  annotations "))
                text.startsWith("  overrides ") -> overrides = splitList(text.removePrefix("  overrides "))
                text.startsWith("  overriddenBy ") -> overriddenBy = splitList(text.removePrefix("  overriddenBy "))
                text.startsWith("  synthetic ") -> synthetic = unqn(text.removePrefix("  synthetic "))
                text.startsWith("  returns ") -> returnType = unqn(text.removePrefix("  returns "))
                text.startsWith("  param ") -> {
                    val rest = text.removePrefix("  param ")
                    params.add(
                        KirParam(
                            register = rest.substringBefore(' '),
                            name = unqn(quotedToken(rest.substringAfter(" name=")).first),
                            type = unqn(quotedToken(rest.substringAfter(" type=")).first),
                            receiver = rest.substringAfter(" receiver=") == "true",
                        ),
                    )
                }
                text.startsWith("  block ") -> {
                    val header = text.removePrefix("  block ")
                    current = mutableListOf()
                    blocks.add(KirBlock(header.substringBefore(' '), header.endsWith(" entry"), current))
                }
                text.startsWith("    ") -> {
                    val ins = readIns(text.trim())
                        ?: throw KirFormatException("cannot parse instruction '${text.take(60)}'", cursor.lineNo)
                    val sink = current
                        ?: throw KirFormatException("instruction before any block", cursor.lineNo)
                    sink.add(ins)
                }
                else -> throw KirFormatException("unexpected line '${text.take(40)}'", cursor.lineNo)
            }
            cursor.advance()
        }
        return KirFunction(
            canonicalName = canonicalName,
            jvmDescriptor = jvmDescriptor,
            purl = purl,
            file = file,
            line = line,
            column = column,
            params = params,
            returnType = returnType,
            modifiers = modifiers,
            visibility = visibility,
            enclosingClass = enclosing,
            overrides = overrides,
            overriddenBy = overriddenBy,
            annotations = annotations,
            syntheticCause = synthetic,
            body = if (blocks.isEmpty()) null else KirBody(blocks),
        )
    }

    /**
     * Keyword-first parse: either the line is `reg = op ...` (the first
     * token is a register) or it starts with an opcode that carries no
     * result prefix (`fieldset %0 %0.count = t1` puts spaces in the LHS).
     */
    private fun readIns(text: String): KirIns? {
        val firstToken = text.substringBefore(' ')
        if (firstToken !in NO_RESULT_OPS && firstToken != "dynamic" && isRegister(firstToken) && text.contains(" = ")) {
            val opRest = text.substringAfter(" = ")
            val op = opRest.substringBefore(' ')
            val rest = opRest.substringAfter(' ', missingDelimiterValue = "")
            return parseWithResult(op, firstToken, rest)
        }
        if (firstToken in NO_RESULT_OPS) {
            return parseNoResult(firstToken, text.substringAfter(' ', missingDelimiterValue = ""))
        }
        // `dynamic` is the one opcode that may appear without a result.
        if (firstToken == "dynamic") {
            val rest = text.substringAfter(' ', missingDelimiterValue = "")
            val name = unq(rest.substringBefore(" recv=").substringBefore(" args="))
            val recv = if (" recv=" in rest) rest.substringAfter(" recv=").substringBefore(" args=") else null
            val args = if (" args=" in rest) {
                rest.substringAfter(" args=(").removeSuffix(")").split(',').filter { it.isNotEmpty() }
            } else {
                emptyList()
            }
            return KirDynamicCall(null, name, recv, args)
        }
        return null
    }

    private val NO_RESULT_OPS = setOf("store", "fieldset", "indexset", "branch", "return", "throw", "suspend")

    private fun isRegister(token: String): Boolean =
        token.startsWith("%") || (token.startsWith("t") && token.drop(1).all { it.isDigit() } && token.length > 1) ||
            token.startsWith("v")

    private fun parseNoResult(head: String, rest: String): KirIns? = when (head) {
        "store" -> {
            val target = rest.substringBefore(" = ")
            KirStore(target, rest.substringAfter(" = "))
        }
        "fieldset" -> {
            val receiver = rest.substringBefore(' ')
            val after = rest.substringAfter(' ')
            KirFieldSet(receiver, readPath(after.substringBefore(" = ")), after.substringAfter(" = "))
        }
        "indexset" -> {
            val pair = rest.substringBefore(" = ").split(' ')
            KirIndexSet(pair[0], pair[1], rest.substringAfter(" = "))
        }
        "branch" -> KirBranch(
            rest.substringBefore(' '),
            rest.substringAfter("then=").substringBefore(' '),
            rest.substringAfter("else="),
        )
        "return" -> KirReturn(rest.takeIf { it.isNotEmpty() })
        "throw" -> KirThrow(rest)
        "suspend" -> KirSuspendPoint(rest)
        else -> null
    }

    private fun parseWithResult(head: String, reg: String, rest: String): KirIns? = when (head) {
        "assign" -> KirAssign(reg, rest)
        "load" -> KirLoad(reg, readConst(rest))
        "fieldget" -> KirFieldGet(reg, rest.substringBefore(' '), readPath(rest.substringAfter(' ')))
        "indexget" -> {
            val parts = rest.split(' ')
            KirIndexGet(reg, parts[0], parts[1])
        }
        "call" -> {
            val fqn = unq(rest.substringBefore(" kind="))
            val kind = rest.substringAfter(" kind=").substringBefore(" desc=").let { kindByName(it) }
            val desc = unqn(rest.substringAfter(" desc=").substringBefore(" recv=").substringBefore(" args="))
            val recv = if (" recv=" in rest) rest.substringAfter(" recv=").substringBefore(" args=") else null
            val args = if (" args=" in rest) {
                rest.substringAfter(" args=(").removeSuffix(")").split(',').filter { it.isNotEmpty() }
            } else {
                emptyList()
            }
            KirCall(reg, KirCallee(fqn, desc, kind), recv, args)
        }
        "dynamic" -> {
            val name = unq(rest.substringBefore(" recv=").substringBefore(" args="))
            val recv = if (" recv=" in rest) rest.substringAfter(" recv=").substringBefore(" args=") else null
            val args = if (" args=" in rest) {
                rest.substringAfter(" args=(").removeSuffix(")").split(',').filter { it.isNotEmpty() }
            } else {
                emptyList()
            }
            KirDynamicCall(reg, name, recv, args)
        }
        "new" -> {
            val type = unq(rest.substringBefore(" args="))
            val args = if (" args=" in rest) {
                rest.substringAfter(" args=(").removeSuffix(")").split(',').filter { it.isNotEmpty() }
            } else {
                emptyList()
            }
            KirNew(reg, type, args)
        }
        "phi" -> {
            val inputs = rest.removePrefix("[").removeSuffix("]")
                .split(' ').filter { it.isNotEmpty() }.associate {
                    it.substringBefore('=') to it.substringAfter('=')
                }
            KirPhi(reg, inputs)
        }
        "concat" -> KirStringConcat(
            reg,
            rest.substringAfter("args=(").removeSuffix(")").split(',').filter { it.isNotEmpty() },
        )
        "lambda" -> {
            val fn = unq(rest.substringBefore(" args="))
            val captures = if (" args=" in rest) {
                rest.substringAfter(" args=(").removeSuffix(")").split(',').filter { it.isNotEmpty() }
            } else {
                emptyList()
            }
            KirLambda(reg, fn, captures)
        }
        "elvis" -> KirElvis(reg, rest.substringBefore(" fallback="), rest.substringAfter(" fallback="))
        "safecall" -> KirSafeCall(reg, rest.substringBefore(' '), readPath(rest.substringAfter(' ')))
        "cast" -> {
            val value = rest.substringBefore(" as ")
            val afterAs = rest.substringAfter(" as ")
            KirCast(reg, value, unq(afterAs.substringBefore(" checked")), checked = afterAs.endsWith(" checked"))
        }
        "typeof" -> KirTypeCheck(reg, rest.substringBefore(" is "), unq(rest.substringAfter(" is ")))
        else -> null
    }

    private fun kindByName(name: String): CallKind =
        CallKind.entries.firstOrNull { it.name.lowercase() == name }
            ?: throw KirFormatException("unknown call kind '$name'", 0)

    private fun readConst(text: String): KirConstant = when {
        text == "null" -> KirConstant.Null
        text.startsWith("int ") -> KirConstant.IntConst(text.removePrefix("int ").toLong())
        text.startsWith("float ") -> KirConstant.FloatConst(text.removePrefix("float ").toDouble())
        text.startsWith("bool ") -> KirConstant.Bool(text.removePrefix("bool ") == "true")
        else -> KirConstant.Str(unq(text))
    }

    /** `base.a.b[]` -> AccessPath(base, [Field(a), Field(b), Index]) */
    private fun readPath(text: String): AccessPath {
        val base = text.substringBefore('.')
        val elements = mutableListOf<AccessPath.Element>()
        var rest = text.removePrefix(base)
        while (rest.isNotEmpty()) {
            when {
                rest.startsWith(".*") -> {
                    elements.add(AccessPath.Element.Star)
                    rest = rest.removePrefix(".*")
                }
                rest.startsWith("[]") -> {
                    elements.add(AccessPath.Element.Index)
                    rest = rest.removePrefix("[]")
                }
                rest.startsWith(".") -> {
                    var field = rest.removePrefix(".")
                    var end = field.length
                    for ((offset, c) in field.withIndex()) {
                        if (c == '.' || c == '*' || c == '[') {
                            end = offset
                            break
                        }
                    }
                    field = field.substring(0, end)
                    elements.add(AccessPath.Element.Field(field))
                    rest = rest.removePrefix(".").removePrefix(field)
                }
                else -> throw KirFormatException("bad access path '$text'", 0)
            }
        }
        return AccessPath(base, elements)
    }

    private fun splitList(text: String): List<String> {
        val out = mutableListOf<String>()
        var i = 0
        while (i < text.length) {
            if (text[i] == '"') {
                var j = i + 1
                while (j < text.length && (text[j] != '"' || text[j - 1] == '\\')) j++
                out.add(unq(text.substring(i, j + 1)))
                i = j + 2
            } else {
                var j = i
                while (j < text.length && text[j] != ' ') j++
                out.add(unq(text.substring(i, j)))
                i = j + 1
            }
        }
        return out.filter { it.isNotEmpty() }
    }

    /** The writer's `null` literal for nullable fields. */
    private fun unqn(text: String): String? = if (text == "null") null else unq(text)

    /** First token of [text]; a JSON-quoted token may span spaces. Returns token + remainder. */
    private fun quotedToken(text: String): Pair<String, String> {
        if (!text.startsWith('"')) {
            return text.substringBefore(' ') to text.substringAfter(' ', missingDelimiterValue = "")
        }
        var i = 1
        while (i < text.length) {
            if (text[i] == '"' && text[i - 1] != '\\') break
            i++
        }
        return text.substring(0, i + 1) to text.substring(i + 2, text.length)
    }

    fun unq(text: String): String {
        if (!text.startsWith('"')) return text
        val body = text.removePrefix("\"").removeSuffix("\"")
        return body
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    }

    private class Cursor(lines: List<String>) {
        private val numbered = lines.mapIndexed { index, line -> index + 1 to line }.filter { it.second.isNotBlank() }
        private var pos = 0

        val lineNo: Int get() = numbered.getOrNull(pos)?.first ?: 0

        fun atEnd(): Boolean = pos >= numbered.size

        fun peek(): String {
            if (atEnd()) throw KirFormatException("unexpected end of input", lineNo)
            return numbered[pos].second
        }

        fun advance() {
            pos++
        }

        fun expect(prefix: String): String {
            val text = peek()
            if (!text.startsWith(prefix)) {
                throw KirFormatException("expected '$prefix', got '${text.take(40)}'", lineNo)
            }
            advance()
            return text
        }
    }
}
