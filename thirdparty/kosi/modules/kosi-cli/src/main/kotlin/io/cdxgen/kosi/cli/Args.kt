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

    private val values = linkedMapOf<String, String>()
    private val flags = linkedMapOf<String, Boolean>()
    val positionals = mutableListOf<String>()

    fun value(name: String, default: String? = null): String? = values[name] ?: default

    fun values(name: String): List<String> =
        values.entries.filter { it.key.startsWith("$name.") }.map { it.value }

    fun bool(name: String, default: Boolean = false): Boolean = flags[name] ?: default

    fun requireValue(name: String): String =
        values[name] ?: throw UsageException("missing required --$name")

    companion object {
        fun parse(args: List<String>): ParsedArgs {
            val parsed = ParsedArgs()
            var i = 0
            var valueCounts = mutableMapOf<String, Int>()
            while (i < args.size) {
                val arg = args[i]
                when {
                    arg == "--" -> {
                        args.drop(i + 1).forEach { parsed.positionals.add(it) }
                        return parsed
                    }
                    arg.startsWith("--") -> {
                        val body = arg.removePrefix("--")
                        val (name, inlineValue) = body.split("=", limit = 2).let {
                            it[0] to it.getOrElse(1) { null }
                        }
                        if (name.startsWith("no-")) {
                            parsed.flags[name.removePrefix("no-")] = false
                        } else if (inlineValue != null) {
                            store(parsed, valueCounts, name, inlineValue)
                            parsed.flags[name] = true
                        } else if (BOOLEAN_FLAGS.contains(name)) {
                            parsed.flags[name] = true
                        } else {
                            val next = args.getOrNull(i + 1)
                                ?: throw UsageException("--$name requires a value")
                            store(parsed, valueCounts, name, next)
                            parsed.flags[name] = true
                            i++
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

        private fun store(parsed: ParsedArgs, counts: MutableMap<String, Int>, name: String, value: String) {
            val n = counts.getOrDefault(name, 0)
            counts[name] = n + 1
            val key = if (n == 0) name else "$name.$n"
            parsed.values[key] = value
        }

        private val BOOLEAN_FLAGS = setOf(
            "pretty", "help", "version", "write-baseline", "compare", "fail-unless-promotable",
            "update-goldens", "verbose", "progressive", "skip-missing-repos",
        )
    }
}
