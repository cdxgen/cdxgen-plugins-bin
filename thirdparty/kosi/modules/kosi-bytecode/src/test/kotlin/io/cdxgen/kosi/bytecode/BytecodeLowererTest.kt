package io.cdxgen.kosi.bytecode

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BytecodeLowererTest {

    // The test JVM's working directory is not stable across environments:
    // walk up until the repository root (the one holding fixtures/) is found.
    private val fixtureDir: java.nio.file.Path by lazy {
        var dir = java.nio.file.Path.of("").toAbsolutePath()
        repeat(6) {
            if (dir.resolve("fixtures").resolve("dep-taint-through-lib").toFile().exists()) {
                return@lazy dir.resolve("fixtures").resolve("dep-taint-through-lib")
            }
            dir = dir.parent ?: return@lazy dir
        }
        dir.resolve("fixtures").resolve("dep-taint-through-lib")
    }

    @Test
    fun lowersTimberWithClosure() {
        val jar = java.nio.file.Path.of("/var/folders/rg/1z98wnk91g7b0h0s530h6vz80000gn/T/kosi-aar/2387639140/classes.jar")
        if (!java.nio.file.Files.isRegularFile(jar)) return
        val result = BytecodeLowerer.lower(
            jars = listOf(BytecodeLowerer.JarSpec(jar, "pkg:maven/com.jakewharton.timber/timber@5.0.1")),
            wantedCallables = setOf("timber.log.Timber.d", "timber.log.Timber.w"),
            maxClasses = 100,
        )
        val names = result.module.functions.map { it.canonicalName }
        println("TIMBER FUNCS: " + names.filter { it.startsWith("timber") }.sorted())
        println("TIMBER classes=${result.classCount} unlowered=${result.unlowered}")
        println("TIMBER bodyless=${result.bodylessRecords}")
    }

    @Test
    fun lowersTheHelperJarIntoKir() {
        val jar = fixtureDir.resolve("libs").resolve("dep-helper.jar")
        val result = BytecodeLowerer.lower(
            jars = listOf(BytecodeLowerer.JarSpec(jar, "pkg:maven/dev.kosi/dep-helper@1.0")),
            wantedCallables = setOf(
                "dev.kosi.helper.Db.runQuery",
                "dev.kosi.helper.Db.runUpdate",
                "dev.kosi.helper.Db.hashOf",
                "dev.kosi.helper.Console.readSetting",
                "dev.kosi.helper.Provider.provide",
            ),
            maxClasses = 100,
        )
        val names = result.module.functions.map { it.canonicalName }
        println("FUNCTIONS: $names")
        println("aliases: ${result.aliases}")
        println("classes=${result.classCount} fns=${result.functionCount} bodyless=${result.bodylessRecords}")
        println("unlowered=${result.unlowered}")
        assertTrue("dev.kosi.helper.Db.runQuery" in names)
        assertTrue("dev.kosi.helper.Console.readSetting" in names)
        // Provider.provide is abstract: present, with NO body, never summarised.
        val provide = result.module.functions.first { it.canonicalName == "dev.kosi.helper.Provider.provide" }
        assertEquals(null, provide.body)
        val readSetting = result.module.functions.first { it.canonicalName == "dev.kosi.helper.Console.readSetting" }
        assertNotNull(readSetting.body)
        // The in-jar source call must render in the pack's callable-id form.
        val calleeFqns = readSetting.body!!.blocks.flatMap { b -> b.instructions }.mapNotNull { ins ->
            (ins as? io.cdxgen.kosi.kir.KirCall)?.callee?.fqn
        }
        println("readSetting calls: $calleeFqns")
        assertTrue("kotlin.io.readLine" in calleeFqns)
    }

    /**
     * The wanted phase is unbounded, so a wanted set LARGER than the
     * budget once filled `selected` past `maxClasses` and the closure loop's
     * first guard broke before anything was lowered — the tier shipped zero
     * functions behind a cap diagnostic (anki-android: 571 classes, 0
     * compiled functions). The budget bounds the LOWERED set: exactly
     * `maxClasses` classes lower, in the same deterministic order, and the
     * cut is named.
     */
    @Test
    fun aWantedSetLargerThanTheBudgetStillLowersTheBudget() {
        val jar = fixtureDir.resolve("libs").resolve("dep-helper.jar")
        val wanted = setOf(
            "dev.kosi.helper.Db.runQuery",
            "dev.kosi.helper.Db.runUpdate",
            "dev.kosi.helper.Db.hashOf",
            "dev.kosi.helper.Console.readSetting",
            "dev.kosi.helper.Provider.provide",
            "dev.kosi.helper.AuditLog.record",
        )
        val result = BytecodeLowerer.lower(
            jars = listOf(BytecodeLowerer.JarSpec(jar, "pkg:maven/dev.kosi/dep-helper@1.0")),
            wantedCallables = wanted,
            maxClasses = 2,
        )
        assertEquals(2, result.classCount, "the budget caps the LOWERED set, not the selection")
        assertTrue(result.classLimitHit, "a wanted set over the budget is a named cap hit")
        assertTrue(result.classesNotLowered.isNotEmpty(), "the cut is a named row, never a silent absence")
        val loweredNames = result.module.functions.map { it.canonicalName }
        assertTrue(loweredNames.isNotEmpty(), "a cap under the wanted set must not zero the tier")
        // Deterministic order: the first classes in sorted order lower; the
        // rest are named. The helper's sorted order is AuditLog, Console, Db,
        // Provider — so Db is CUT here, and that cut is exactly what the
        // diagnostic must name.
        assertEquals(
            listOf("dev/kosi/helper/Db", "dev/kosi/helper/Provider"),
            result.classesNotLowered,
        )
        assertEquals(
            setOf("dev.kosi.helper.AuditLog", "dev.kosi.helper.Console"),
            result.module.functions.mapNotNull { it.enclosingClass }.toSet(),
            "only the classes the budget admitted are in the module",
        )
    }
}
