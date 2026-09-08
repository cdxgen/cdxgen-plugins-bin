package io.cdxgen.kosi.front

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SyntaxAnalyzerTest {

    private fun analyze(text: String): SyntaxAnalyzer.FileResult =
        AnalysisEnvironment.createForSyntax().use { env ->
            SyntaxAnalyzer(env, "src/Test.kt", ".").analyze(text)
        }

    @Test
    fun parsesDeclarationsImportsAndUsages() {
        val result = analyze(
            """
            package com.example

            import java.sql.Statement

            class Repo(private val stmt: Statement) {
                fun query(id: String): String {
                    return stmt.executeQuery("SELECT 1").toString()
                }
            }
            """.trimIndent(),
        )
        assertEquals("com.example", result.packageName)
        assertEquals(listOf("java.sql.Statement"), result.imports.map { it.name })
        val kinds = result.declarations.map { it.kind }.sorted()
        assertTrue("class" in kinds, "class declaration expected: $kinds")
        assertTrue("method" in kinds, "method declaration expected: $kinds")
        assertTrue("constructor" in kinds, "primary constructor expected: $kinds")
        val repo = result.declarations.first { it.kind == "class" }
        assertEquals("com.example.Repo", repo.canonicalName)
        assertEquals("public", repo.visibility)
        val usages = result.usages.map { it.name }
        assertTrue("stmt.executeQuery" in usages, "dotted call usage expected: $usages")
        assertTrue(
            usages.any { it.endsWith(".toString") },
            "qualified call chain expected: $usages",
        )
    }

    @Test
    fun parseErrorsAreDiagnosticsNotCrashes() {
        val result = analyze(
            """
            class Broken {
                fun f( {
                }
            }
            """.trimIndent(),
        )
        assertTrue(result.diagnostics.any { it.code == "parse-error" }, "parse-error expected")
        assertEquals("Broken", result.declarations.first().name)
    }

    @Test
    fun extensionFunctionsAndKinds() {
        val result = analyze(
            """
            package p

            sealed class Shape
            data class Point(val x: Int, val y: Int)
            enum class Color { RED }
            interface Api { fun go() }
            object Singleton
            typealias Handler = (Int) -> Unit

            fun Shape.name(): String = "s"

            suspend inline fun work(crossinline block: () -> Unit) {
                block()
            }
            """.trimIndent(),
        )
        val byKind = result.declarations.groupBy({ it.kind }, { it.name })
        assertEquals(setOf("Shape"), byKind["sealed-class"]!!.toSet())
        assertEquals(setOf("Point"), byKind["data-class"]!!.toSet())
        assertEquals(setOf("Color"), byKind["enum"]!!.toSet())
        assertEquals(setOf("Api"), byKind["interface"]!!.toSet())
        assertEquals(setOf("Singleton"), byKind["object"]!!.toSet())
        assertEquals(setOf("Handler"), byKind["typealias"]!!.toSet())
        assertEquals(setOf("name"), byKind["extension-function"]!!.toSet())
        val work = result.declarations.first { it.name == "work" }
        assertEquals(setOf("suspend", "inline"), work.modifiers.toSet())
    }

    @Test
    fun operatorsMapToFunctionNames() {
        val result = analyze(
            """
            package p
            fun demo(a: Int, b: List<Int>): Int {
                var c = a + 1
                c += 2
                if (b contains a) { }
                return c
            }
            """.trimIndent(),
        )
        val ops = result.usages.filter { it.usageKind == "operator" }.map { it.name }
        assertTrue("plus" in ops, "plus expected: $ops")
        assertTrue("plusAssign" in ops, "plusAssign expected: $ops")
        assertTrue("contains" in ops, "contains expected: $ops")
    }

    @Test
    fun versionBandReadFromBundledCompiler() {
        val band = CompilerInfo.versionBand()
        assertTrue(band.allAccepted.contains(band.latestStable))
        assertTrue(band.first <= band.latestStable)
        // 1.x language versions are unsupported on a 2.x compiler (K1 removal).
        assertTrue(band.first.startsWith("2."), "first supported should be 2.x: ${band.first}")
        val clamped = CompilerInfo.clampLanguageVersion("1.9")
        assertTrue(clamped.clamped)
        assertEquals(band.first, clamped.effective)
    }
}
