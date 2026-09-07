package io.cdxgen.kosi.project

import java.nio.file.Files
import java.nio.file.Path

/**
 * Minimal XML element over the text of a pom.xml — enough structure for
 * module discovery without pulling an XML library (the dependency allowlist
 * is closed). Handles nesting and text content; skips comments and
 * declarations. Self-closing tags and mismatched closers are tolerated.
 */
class XmlElement(
    val name: String,
    var text: String = "",
    val children: MutableList<XmlElement> = mutableListOf(),
) {
    fun child(name: String): XmlElement? = children.firstOrNull { it.name == name }

    fun childrenNamed(name: String): List<XmlElement> = children.filter { it.name == name }

    fun textOr(name: String, fallback: String? = null): String? =
        child(name)?.text?.takeIf { it.isNotBlank() } ?: fallback

    /** Depth-first search for the first element with [name] (e.g. build/plugins). */
    fun findRecursive(name: String): XmlElement? {
        childrenNamed(name).firstOrNull()?.let { return it }
        for (c in children) {
            c.findRecursive(name)?.let { return it }
        }
        return null
    }

    companion object {
        private val TAG = Regex("""<(/?)([A-Za-z0-9_.:-]+)([^>]*?)(/?)>""")

        fun parse(text: String): XmlElement {
            val dotAll = setOf(RegexOption.DOT_MATCHES_ALL)
            val stripped = text
                .replace(Regex("""<!--.*?-->""", dotAll), "")
                .replace(Regex("""<\?.*?\?>""", dotAll), "")
                .replace(Regex("""<!\[CDATA\[(.*?)\]\]>""", dotAll)) { it.groupValues[1] }
            val fakeRoot = XmlElement("#document")
            val stack = ArrayDeque<XmlElement>()
            stack.addLast(fakeRoot)
            var lastMatchEnd = 0
            for (match in TAG.findAll(stripped)) {
                val (closing, tagName, _, selfClosing) = match.destructured
                val textContent = stripped.substring(lastMatchEnd, match.range.first).trim()
                if (textContent.isNotEmpty() && stack.size > 1) {
                    val owner = stack.last()
                    owner.text = if (owner.text.isEmpty()) textContent else owner.text
                }
                if (closing.isEmpty()) {
                    val element = XmlElement(tagName, "")
                    stack.last().children.add(element)
                    if (selfClosing != "/") stack.addLast(element)
                } else {
                    val idx = stack.indexOfLast { it.name == tagName }
                    if (idx >= 0) {
                        while (stack.size > idx) stack.removeLast()
                    }
                }
                lastMatchEnd = match.range.last + 1
            }
            return fakeRoot.children.firstOrNull() ?: XmlElement("empty")
        }
    }
}

/**
 * Parses Maven projects: the module list from <modules>, coordinates from
 * project/parent, and Kotlin compiler settings from plugin configuration.
 */
object MavenDiscovery {

    fun discover(root: Path): DiscoveryResult {
        val modules = mutableListOf<DiscoveredModule>()
        val poms = mutableListOf(root.resolve("pom.xml"))
        // Collect nested module poms breadth-first.
        var index = 0
        while (index < poms.size) {
            val pom = poms[index++]
            val text = if (Files.isRegularFile(pom)) Files.readString(pom) else continue
            val xml = XmlElement.parse(text)
            val modulesSection = xml.child("modules") ?: continue
            for (m in modulesSection.childrenNamed("module")) {
                val dir = root.resolve(m.text.trim())
                val nested = dir.resolve("pom.xml")
                if (Files.isRegularFile(nested)) poms.add(nested)
            }
        }
        for (pom in poms) {
            val text = Files.readString(pom)
            val xml = XmlElement.parse(text)
            val parent = xml.child("parent")
            val groupId = xml.textOr("groupId") ?: parent?.textOr("groupId")
            val artifactId = xml.textOr("artifactId") ?: continue
            val version = xml.textOr("version") ?: parent?.textOr("version")
            val dir = pom.parent ?: root
            val modulePath = if (dir == root) "." else root.relativize(dir).toString().replace('\\', '/')
            // sourceRoots are relative to the ANALYSIS root (that is what
            // SourceCollector resolves them against), so a nested module's
            // roots carry the module directory prefix.
            val roots = mutableListOf<String>()
            for (candidate in listOf("src/main/kotlin", "src/main/java")) {
                if (TextScan.isDirectory(dir, candidate)) {
                    roots.add(if (modulePath == ".") candidate else "$modulePath/$candidate")
                }
            }
            if (roots.isEmpty()) roots.add(modulePath)
            val props = xml.child("properties")
            modules.add(
                DiscoveredModule(
                    name = artifactId,
                    modulePath = modulePath,
                    platform = DiscoveredModule.PLATFORM_JVM,
                    workspaceMember = modulePath,
                    sourceRoots = roots,
                    declaredLanguageVersion = kotlinPluginSetting(text, "languageVersion"),
                    declaredApiVersion = kotlinPluginSetting(text, "apiVersion"),
                    jvmTarget = kotlinPluginSetting(text, "jvmTarget")
                        ?: props?.textOr("maven.compiler.target"),
                    purl = GradleDiscovery.purl(groupId, artifactId, version),
                ),
            )
        }
        return DiscoveryResult(modules, buildSystem = "maven")
    }

    /**
     * Reads <languageVersion>/<apiVersion>/<jvmTarget> from the
     * kotlin-maven-plugin's <configuration> block. XML is parsed as XML (the
     * brace-block scanner in TextScan is for Gradle scripts and can never
     * match a pom), and a setting that is absent stays null — never guessed.
     */
    private fun kotlinPluginSetting(pomText: String, setting: String): String? {
        val pom = XmlElement.parse(pomText)
        val configuration = pom.findRecursive("plugins")
            ?.childrenNamed("plugin")
            ?.firstOrNull { plugin ->
                plugin.childrenNamed("artifactId").any { it.text.trim() == "kotlin-maven-plugin" }
            }
            ?.child("configuration")
            ?: return null
        val raw = configuration?.childrenNamed(setting)
            ?.firstOrNull { it.text.isNotBlank() }
            ?.text?.trim()
            ?: return null
        return TextScan.versionValue(raw) ?: raw.removeSurrounding("\"").ifBlank { null }
    }
}
