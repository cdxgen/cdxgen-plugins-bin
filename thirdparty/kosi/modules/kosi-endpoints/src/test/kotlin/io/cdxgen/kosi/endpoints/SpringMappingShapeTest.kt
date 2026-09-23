package io.cdxgen.kosi.endpoints

import io.cdxgen.kosi.models.EndpointModels
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * atom-tools#92: against the real spring-web jar every mapping path arrives
 * as an ARRAY constant, and a detector that read only a first scalar
 * constant published `pathTemplate ""` for every Spring handler. Every
 * fixture's stub declared `value: String`, so no fixture could see it.
 */
class SpringMappingShapeTest {

    private val repoRoot: Path = run {
        var current: Path? = Path.of("").toAbsolutePath()
        while (current != null) {
            if (Files.isRegularFile(current.resolve("corpus.toml"))) return@run current
            current = current.parent
        }
        error("corpus.toml not found upward from the working directory")
    }

    private val spring = EndpointModels.loadBuiltin().frameworks.single { it.id == "spring-mvc" }
    private val requestMapping = spring.mappingAnnotations.single { it.pattern.endsWith(".RequestMapping") }
    private val getMapping = spring.mappingAnnotations.single { it.pattern.endsWith(".GetMapping") }

    private fun ann(value: String? = null, vararg named: Pair<String, List<String>>) =
        EndpointDetector.DeclAnnotation("x", value, 1, named.toMap())

    @Test
    fun `every fixture stub declares Spring's mapping paths as arrays, as spring-web does`() {
        val scalar = Regex("""annotation class (Get|Post|Put|Delete|Patch|Request)Mapping\((?![^)]*vararg val value)""")
        val offenders = Files.walk(repoRoot.resolve("fixtures")).use { stream ->
            stream.filter { it.toString().endsWith("org/springframework/web/bind/annotation/Annotations.kt") }
                .filter { scalar.containsMatchIn(Files.readString(it)) }
                .map { repoRoot.relativize(it).toString() }
                .toList()
        }
        assertEquals(emptyList(), offenders, "a scalar `value` stub cannot exercise the real array shape")
    }

    @Test
    fun `every fixture servlet stub declares value and urlPatterns as arrays, as servlet-api does`() {
        val scalar = Regex("""annotation class Web(Servlet|Filter)\((?![^)]*vararg val value)""")
        val offenders = Files.walk(repoRoot.resolve("fixtures")).use { stream ->
            stream.filter { it.toString().contains("/servlet/annotation/") && it.toString().endsWith(".kt") }
                .filter { scalar.containsMatchIn(Files.readString(it)) }
                .map { repoRoot.relativize(it).toString() }
                .toList()
        }
        assertEquals(emptyList(), offenders, "a scalar `value` stub cannot exercise the real array shape")
    }

    @Test
    fun `the path is read from value or path, one entry per array element`() {
        assertEquals(listOf("/a"), EndpointDetector.pathsOf(ann(null, "value" to listOf("/a")), spring.pathArguments))
        assertEquals(listOf("/p"), EndpointDetector.pathsOf(ann(null, "path" to listOf("/p")), spring.pathArguments))
        assertEquals(
            listOf("/x", "/y"),
            EndpointDetector.pathsOf(ann(null, "path" to listOf("/x", "/y")), spring.pathArguments),
        )
    }

    @Test
    fun `a non-path constant is never a path`() {
        // @GetMapping(produces = ["application/json"]) maps the class path.
        val produces = ann("application/json", "produces" to listOf("application/json"))
        assertEquals(listOf(""), EndpointDetector.pathsOf(produces, spring.pathArguments))
    }

    @Test
    fun `the scalar value is kept only when nothing folded to a constant`() {
        assertEquals(listOf("/t/\$id"), EndpointDetector.pathsOf(ann("/t/\$id"), spring.pathArguments))
    }

    @Test
    fun `RequestMapping takes its methods from the method argument, in either spelling`() {
        assertEquals(listOf("POST"), EndpointDetector.methodsOf(ann(null, "method" to listOf("POST")), requestMapping))
        assertEquals(
            listOf("PUT", "PATCH"),
            EndpointDetector.methodsOf(ann(null, "method" to listOf("RequestMethod.PUT", "RequestMethod.PATCH")), requestMapping),
        )
        // No method argument: RequestMapping serves every method, reported as none named.
        assertTrue(EndpointDetector.methodsOf(ann(null, "value" to listOf("/v")), requestMapping).isEmpty())
    }

    @Test
    fun `a method argument never overrides a mapping whose method is its name`() {
        assertEquals(listOf("GET"), EndpointDetector.methodsOf(ann(null, "method" to listOf("POST")), getMapping))
    }

    @Test
    fun `a value that is not an HTTP method is dropped, not guessed`() {
        assertTrue(EndpointDetector.methodsOf(ann(null, "method" to listOf("RequestMethod.BREW")), requestMapping).isEmpty())
    }

    @Test
    fun `annotations are scoped to the declaring file across same-named modules`() {
        val alpha = EndpointDetector.DeclAnnotation("x", "/alpha", 1, file = "app-alpha/src/main/kotlin/web/Api.kt")
        val beta = EndpointDetector.DeclAnnotation("x", "/beta", 1, file = "app-beta/src/main/kotlin/web/Api.kt")
        assertEquals(
            listOf(beta),
            EndpointDetector.declaredIn(listOf(alpha, beta), "/abs/root/app-beta/src/main/kotlin/web/Api.kt"),
        )
        // A sibling that merely shares the file NAME is another file.
        assertEquals(emptyList(), EndpointDetector.declaredIn(listOf(alpha), "/abs/root/other-alpha/src/main/kotlin/web/Api.kt"))
    }
}
