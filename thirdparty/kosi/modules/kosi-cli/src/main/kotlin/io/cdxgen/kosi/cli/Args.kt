package io.cdxgen.kosi.cli

/**
 * Hand-rolled argument parsing (~200 lines, no CLI library). Supports both
 * `--flag value` and `--flag=value`, `--no-` prefixes for boolean flags, and
 * repeatable flags.
 *
 * Exit codes (documented in README.md):
 *  - 0  success
 *  - 1  the command ran but its expectations failed (bench regressions,
 *       golden mismatch, ratchet violations)
 *  - 2  usage error (unknown flag, missing value, bad subcommand)
 *  - 3  runtime error (unreadable corpus, internal failure)
 */
object ExitCodes {
    const val OK = 0
    const val EXPECTATIONS_FAILED = 1
    const val USAGE = 2
    const val RUNTIME = 3
}

class UsageException(message: String) : RuntimeException(message)

class ParsedArgs private constructor() {

    /** Every occurrence of a value flag, in command-line order. */
    private val values = linkedMapOf<String, MutableList<String>>()
    private val flags = linkedMapOf<String, Boolean>()
    val positionals = mutableListOf<String>()

    /** The last occurrence of a value flag, so a later flag overrides an earlier one. */
    fun value(name: String, default: String? = null): String? = values[name]?.lastOrNull() ?: default

    /** Every occurrence, for repeatable flags such as `--roots` and `--opt-in`. */
    fun values(name: String): List<String> = values[name]?.toList() ?: emptyList()

    fun bool(name: String, default: Boolean = false): Boolean = flags[name] ?: default

    fun requireValue(name: String): String =
        value(name) ?: throw UsageException("missing required --$name")

    companion object {
        /**
         * Parses `args` accepting only the flags in [known] — an unknown flag
         * is a usage error, not a silently dropped option (a report that
         * echoes `options` must echo what actually ran). Names in [booleans]
         * take no value; every other known name requires one and may repeat.
         */
        fun parse(args: List<String>, known: Set<String>, booleans: Set<String>): ParsedArgs {
            require(booleans.all { it in known }) { "boolean flags must also be declared known" }
            val parsed = ParsedArgs()
            var i = 0
            while (i < args.size) {
                val arg = args[i]
                when {
                    arg == "--" -> {
                        args.drop(i + 1).forEach { parsed.positionals.add(it) }
                        return parsed
                    }
                    arg.startsWith("--") -> {
                        val body = arg.removePrefix("--")
                        val (rawName, inlineValue) = body.split("=", limit = 2).let {
                            it[0] to it.getOrElse(1) { null }
                        }
                        val negated = rawName.startsWith("no-") && rawName.removePrefix("no-") in booleans
                        val name = if (negated) rawName.removePrefix("no-") else rawName
                        if (name !in known) {
                            throw UsageException(
                                "unknown flag --$rawName (known: ${known.sorted().joinToString(", ")})",
                            )
                        }
                        when {
                            negated -> {
                                if (inlineValue != null) {
                                    throw UsageException("--$rawName does not take a value")
                                }
                                parsed.flags[name] = false
                            }
                            name in booleans -> {
                                if (inlineValue != null) {
                                    parsed.flags[name] = inlineValue.toBooleanStrictOrNull()
                                        ?: throw UsageException("--$name must be true or false, got '$inlineValue'")
                                } else {
                                    parsed.flags[name] = true
                                }
                            }
                            else -> {
                                val value = inlineValue ?: args.getOrNull(i + 1)?.also { i++ }
                                    ?: throw UsageException("--$name requires a value")
                                parsed.values.getOrPut(name) { mutableListOf() }.add(value)
                                parsed.flags[name] = true
                            }
                        }
                    }
                    arg.startsWith("-") && arg.length > 1 ->
                        throw UsageException("single-dash flags are not supported: $arg")
                    else -> parsed.positionals.add(arg)
                }
                i++
            }
            return parsed
        }
    }
}
