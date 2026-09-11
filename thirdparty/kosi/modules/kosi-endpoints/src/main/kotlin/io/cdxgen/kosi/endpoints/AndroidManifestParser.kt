package io.cdxgen.kosi.endpoints

import java.nio.file.Files
import java.nio.file.Path

/**
 * AndroidManifest.xml component extraction (P7). A tolerant scanner for the
 * manifest's machine-generated shape — `activity`/`service`/`receiver`/
 * `provider` elements with their attributes and `intent-filter` children —
 * not a general XML parser. What it publishes per component:
 *
 *  - the class name, resolved against the manifest `package` attribute when
 *    the manifest uses the relative `.ui.MainActivity` form;
 *  - `exported`: the manifest's own value, or — when absent, the pre-API-31
 *    default — true exactly when an intent filter exists;
 *  - permissions and deep links (VIEW actions with a data scheme/host).
 */
object AndroidManifestParser {

    data class ManifestComponent(
        val kind: String,
        val className: String,
        val exported: Boolean?,
        val permissions: List<String>,
        val actions: List<String>,
        val deepLinkHosts: List<String>,
    )

    data class Manifest(
        val file: String,
        val components: List<ManifestComponent>,
    )

    private val COMPONENT_TAGS = setOf("activity", "activity-alias", "service", "receiver", "provider")

    fun parse(root: Path): List<Manifest> {
        if (!Files.isDirectory(root)) return emptyList()
        val manifests = Files.walk(root).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter { it.fileName.toString() == "AndroidManifest.xml" }
                .filter { !it.toString().contains("/build/") }
                .sorted()
                .toList()
        }
        return manifests.mapNotNull { path ->
            val text = try {
                Files.readString(path)
            } catch (_: Exception) {
                return@mapNotNull null
            }
            parseText(text, path.toString())
        }
    }

    internal fun parseText(text: String, file: String): Manifest? {
        // Comments first: a commented-out component is not a component.
        val withoutComments = text.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
        val packageAttr = Regex("""<manifest[^>]*\bpackage\s*=\s*"([^"]+)"""").find(withoutComments)?.groupValues?.get(1).orEmpty()
        val components = mutableListOf<ManifestComponent>()
        // Component elements with optional intent-filter children; scanning
        // element opens in document order and tracking the enclosing element
        // keeps the state machine one pass.
        var current: ComponentBuilder? = null
        var applicationPackage = packageAttr
        Regex("""<(/?)([\w.-]+)([^>]*?)(/?)>""").findAll(withoutComments).forEach { match ->
            val (closing, rawTag, rawAttrs, selfClose) = match.destructured
            val tag = rawTag.substringAfterLast(':')
            val attrs = parseAttrs(rawAttrs)
            when {
                closing == "/" -> {
                    if ((tag == "activity" || tag == "service" || tag == "receiver" || tag == "provider" || tag == "activity-alias") &&
                        current?.kind == tag
                    ) {
                        components.add(current.build())
                        current = null
                    }
                }

                tag == "application" && current == null -> {
                    applicationPackage = attrs["package"] ?: applicationPackage
                }

                tag in COMPONENT_TAGS && current == null && selfClose.isEmpty() -> {
                    current = ComponentBuilder(tag, resolveClass(attrs["name"], applicationPackage))
                    current?.explicitExported = attrs["exported"]
                    if (tag == "provider") current?.addPermission(attrs["permission"])
                    if (tag == "activity-alias") current?.setTarget(attrs["targetActivity"])
                }

                tag in COMPONENT_TAGS && selfClose == "/" && current == null -> {
                    val builder = ComponentBuilder(tag, resolveClass(attrs["name"], applicationPackage))
                    builder.explicitExported = attrs["exported"]
                    if (tag == "provider") builder.addPermission(attrs["permission"])
                    components.add(builder.build())
                }

                tag == "intent-filter" && current != null -> current?.beginIntentFilter()

                tag == "action" && current != null -> current?.addAction(attrs["name"])

                tag == "data" && current != null -> {
                    current?.addScheme(attrs["scheme"])
                    current?.addHost(attrs["host"])
                }

                tag == "permission" && current == null -> {}
            }
        }
        current?.let { components.add(it.build()) }
        return if (components.isEmpty()) null else Manifest(file, components)
    }

    private fun resolveClass(name: String?, pkg: String): String = when {
        name == null -> ""
        name.startsWith(".") -> pkg + name
        name.contains('.') -> name
        pkg.isNotEmpty() -> "$pkg.$name"
        else -> name
    }

    private fun parseAttrs(raw: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        Regex("""([\w:.-]+)\s*=\s*"([^"]*)"""").findAll(raw).forEach { match ->
            out[match.groupValues[1].substringAfterLast(':')] = match.groupValues[2]
        }
        return out
    }

    private class ComponentBuilder(val kind: String, val className: String) {
        var explicitExported: String? = null
        var targetActivity: String? = null
        val permissions = mutableListOf<String>()
        val actions = mutableListOf<String>()
        val schemes = mutableListOf<String>()
        val hosts = mutableListOf<String>()
        var filterCount = 0
        var inFilter = false

        fun addPermission(value: String?) {
            if (!value.isNullOrBlank()) permissions.add(value)
        }

        fun setTarget(value: String?) {
            targetActivity = value
        }

        fun beginIntentFilter() {
            filterCount++
            inFilter = true
        }

        fun addAction(value: String?) {
            if (inFilter && !value.isNullOrBlank()) actions.add(value)
        }

        fun addScheme(value: String?) {
            if (inFilter && !value.isNullOrBlank()) schemes.add(value)
        }

        fun addHost(value: String?) {
            if (inFilter && !value.isNullOrBlank()) hosts.add(value)
        }

        fun build(): ManifestComponent {
            val exported = when (explicitExported) {
                "true" -> true
                "false" -> false
                // The pre-API-31 default: components with an intent filter
                // are exported, components without are not.
                else -> if (filterCount > 0) true else false
            }
            val deepLinks = if (actions.any { it.endsWith("android.intent.action.VIEW") } && schemes.isNotEmpty()) {
                hosts.ifEmpty { listOf("*") }
            } else {
                emptyList()
            }
            return ManifestComponent(
                kind = kind,
                className = targetActivity ?: className,
                exported = exported,
                permissions = permissions,
                actions = actions,
                deepLinkHosts = deepLinks,
            )
        }
    }
}
