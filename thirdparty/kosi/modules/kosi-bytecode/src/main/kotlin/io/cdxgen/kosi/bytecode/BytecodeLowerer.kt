package io.cdxgen.kosi.bytecode

import io.cdxgen.kosi.kir.AccessPath
import io.cdxgen.kosi.kir.CallKind
import io.cdxgen.kosi.kir.KirAssign
import io.cdxgen.kosi.kir.KirBlock
import io.cdxgen.kosi.kir.KirBody
import io.cdxgen.kosi.kir.KirBranch
import io.cdxgen.kosi.kir.KirCall
import io.cdxgen.kosi.kir.KirCallee
import io.cdxgen.kosi.kir.KirConstant
import io.cdxgen.kosi.kir.KirDynamicCall
import io.cdxgen.kosi.kir.KirFieldGet
import io.cdxgen.kosi.kir.KirFieldSet
import io.cdxgen.kosi.kir.KirFunction
import io.cdxgen.kosi.kir.KirIndexGet
import io.cdxgen.kosi.kir.KirIndexSet
import io.cdxgen.kosi.kir.KirIns
import io.cdxgen.kosi.kir.KirLoad
import io.cdxgen.kosi.kir.KirModule
import io.cdxgen.kosi.kir.KirNew
import io.cdxgen.kosi.kir.KirParam
import io.cdxgen.kosi.kir.KirReturn
import io.cdxgen.kosi.kir.KirStore
import io.cdxgen.kosi.kir.KirStringConcat
import io.cdxgen.kosi.kir.KirThrow
import io.cdxgen.kosi.kir.KirTypeCheck
import org.jetbrains.org.objectweb.asm.Opcodes
import org.jetbrains.org.objectweb.asm.Type
import org.jetbrains.org.objectweb.asm.tree.AbstractInsnNode
import org.jetbrains.org.objectweb.asm.tree.ClassNode
import org.jetbrains.org.objectweb.asm.tree.FieldInsnNode
import org.jetbrains.org.objectweb.asm.tree.FrameNode
import org.jetbrains.org.objectweb.asm.tree.IincInsnNode
import org.jetbrains.org.objectweb.asm.tree.InsnNode
import org.jetbrains.org.objectweb.asm.tree.IntInsnNode
import org.jetbrains.org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.jetbrains.org.objectweb.asm.tree.JumpInsnNode
import org.jetbrains.org.objectweb.asm.tree.LabelNode
import org.jetbrains.org.objectweb.asm.tree.LdcInsnNode
import org.jetbrains.org.objectweb.asm.tree.LineNumberNode
import org.jetbrains.org.objectweb.asm.tree.LookupSwitchInsnNode
import org.jetbrains.org.objectweb.asm.tree.MethodInsnNode
import org.jetbrains.org.objectweb.asm.tree.MethodNode
import org.jetbrains.org.objectweb.asm.tree.MultiANewArrayInsnNode
import org.jetbrains.org.objectweb.asm.tree.TableSwitchInsnNode
import org.jetbrains.org.objectweb.asm.tree.TypeInsnNode
import org.jetbrains.org.objectweb.asm.tree.VarInsnNode
import java.util.jar.JarFile

/**
 * P9: lowers dependency jars into the SAME KIR the source front end
 * produces. One IR, one summariser — the engine in kosi-flow never learns
 * that a function came from a class file; this module is responsible for
 * producing KIR whose canonical names, jvmDescriptors, access paths and
 * CFG contract match exactly what [io.cdxgen.kosi.kir] documents.
 *
 * Selection: from the workspace call sites' callee fqns, the classes they
 * name are located across the resolved classpath jars, plus a bounded
 * same-jar closure of the classes those classes CALL — a summary is only
 * useful if the callees it needs inside the jar are lowered too. Everything
 * is bounded by `maxClasses` with a counted, diagnostic-backed cap.
 *
 * The body-less rule (the phase's most important sentence): a record with
 * no body — abstract, interface, native, synthetic bridge, or a method the
 * lowering aborts on — is emitted with `body = null` and is therefore
 * IGNORED ENTIRELY by the engine (kosi-flow only compiles and summarises
 * functions with bodies). An empty body is indistinguishable from a no-op;
 * summarising one as "no flow" would invent a sanitiser. Every excluded
 * record is counted here and the counts surface in the report.
 */
object BytecodeLowerer {

    data class JarSpec(val jar: java.nio.file.Path, val purl: String)

    class Result(
        val module: KirModule,
        /** Classes actually lowered (the tier's published denominator). */
        val classCount: Int,
        /** Methods lowered WITH bodies — the population summaries were computed over. */
        val functionCount: Int,
        /** Body-less records: abstract/interface/native/stripped — ignored, never concluded about. */
        val bodylessRecords: Int,
        /** `<init>` bodies (constructors have no summary to apply — targets() excludes them). */
        val constructorsSkipped: Int,
        /** `<clinit>` bodies. */
        val clinitSkipped: Int,
        /** Synthetic methods (bridges, `access$`, lambda bodies) with no workspace-visible callable id. */
        val syntheticSkipped: Int,
        /** Itemised lowering misses: construct -> count. Merged into stats.loweringFailures. */
        val unlowered: Map<String, Int>,
        /** Classes the workspace calls that no classpath jar contains. */
        val classesNotFound: List<String>,
        /** True when the class budget capped the lowered set. */
        val classLimitHit: Boolean,
        /**
         * Classes the workspace calls (or the closure reached) that the
         * budget CUT after lowering stopped: named here so a cap truncation
         * is a counted row, never a silent zero. R70: when the wanted set
         * alone exceeded the budget, the old check stopped the loop before
         * ANY class was lowered and the whole tier shipped empty behind a
         * cap diagnostic.
         */
        val classesNotLowered: List<String>,
        /** Purls of the jars that actually contributed classes. */
        val purlsUsed: Set<String>,
        /** Demangled aliases: alias canonical name -> primary canonical names, tried in order. */
        val aliases: Map<String, List<String>>,
    )

    private class LoweringAbort(val construct: String) : Exception()

    fun lower(jars: List<JarSpec>, wantedCallables: Set<String>, maxClasses: Int): Result {
        val unlowered = sortedMapOf<String, Int>()
        val orderedJars = jars.sortedWith(compareBy({ it.purl }, { it.jar.toString() }))
        val classIndex = HashMap<String, JarSpec>() // internal name -> jar
        for (spec in orderedJars) {
            try {
                JarFile(spec.jar.toFile()).use { file ->
                    for (entry in file.entries()) {
                        if (entry.isDirectory) continue
                        if (entry.name.endsWith(".class") && !entry.name.contains("module-info") &&
                            !entry.name.contains("package-info")
                        ) {
                            classIndex.putIfAbsent(entry.name.removeSuffix(".class"), spec)
                        }
                    }
                }
            } catch (_: Exception) {
                unlowered.merge("jar-unreadable", 1, Int::plus)
            }
        }

        // ---- selection: workspace callables -> classes, then a bounded call closure.
        val selected = sortedSetOf<String>()
        val classesNotFound = sortedSetOf<String>()
        for (callable in wantedCallables) {
            var found = false
            var prefix = callable
            // A CONSTRUCTOR callee's fqn IS the class name (dotted, with
            // Kotlin/AJava nested classes rendered `Outer.Inner`); a method
            // callee's names its owner after the last dot. Try the full name
            // and every `$`-nested re-splitting before stripping segments.
            while (prefix.contains('.')) {
                val internal = prefix.replace('.', '/')
                if (classIndex.containsKey(internal)) {
                    selected.add(internal)
                    found = true
                    break
                }
                var variant = prefix
                while (variant.contains('.')) {
                    variant = variant.substringBeforeLast('.') + "$" + variant.substringAfterLast('.')
                    val nested = variant.replace('.', '/')
                    if (classIndex.containsKey(nested)) {
                        selected.add(nested)
                        found = true
                        break
                    }
                }
                if (found) break
                prefix = prefix.substringBeforeLast('.')
                // A Kotlin file facade named `X.kt` compiles to `<pkg>.<X>Kt`:
                // when the plain class name is absent, add the package's
                // Kt-suffixed classes (a facade with a custom @JvmName is a
                // named limitation — it is found only through the call
                // closure). Bounded per callable; this must never balloon
                // into lowering whole packages.
                val pkg = prefix.substringBeforeLast('.', "").replace('.', '/')
                if (pkg.isNotEmpty()) {
                    var facades = 0
                    val pkgPrefix = "$pkg/"
                    for (candidate in classIndex.keys) {
                        if (facades >= 8) break
                        if (!candidate.startsWith(pkgPrefix)) continue
                        val simple = candidate.substringAfterLast('/')
                        if (simple.endsWith("Kt") && !simple.contains('$')) {
                            selected.add(candidate)
                            found = true
                            facades++
                        }
                    }
                    if (found) break
                }
            }
            if (!found) classesNotFound.add(callable)
        }

        val loweredBodies = HashMap<String, ClassWork>() // internal name -> work
        val purlsUsed = sortedSetOf<String>()
        var classLimitHit = false
        var rounds = 0
        val frontier = selected.toMutableList()
        // R70: the budget bounds the LOWERED set, not the selected set. The
        // wanted phase above is unbounded by design (index lookups only);
        // when it alone filled `selected` past maxClasses, the old
        // `selected.size >= maxClasses` guard broke the loop before the
        // first class was lowered and the whole tier shipped empty — 571
        // classes "lowered", zero functions compiled, on anki-android.
        while (frontier.isNotEmpty() && rounds < 4) {
            rounds++
            val nextFrontier = sortedSetOf<String>()
            for (internal in frontier) {
                if (loweredBodies.size >= maxClasses) {
                    classLimitHit = true
                    break
                }
                if (loweredBodies.containsKey(internal)) continue
                val spec = classIndex[internal] ?: continue
                selected.add(internal)
                purlsUsed.add(spec.purl)
                val work = lowerClass(internal, spec, classIndex, unlowered)
                loweredBodies[internal] = work
                // The call closure: owners this class calls that live in the
                // SAME jar (cross-jar closure is unbounded on a fat classpath)
                // join the next round, budget permitting. Owners are recorded
                // dotted; the index is keyed by internal (slash) name.
                for (owner in work.calledClasses) {
                    val internalOwner = owner.replace('.', '/')
                    val ownerJar = classIndex[internalOwner]
                    if (ownerJar?.jar == spec.jar && internalOwner !in loweredBodies && !selected.contains(internalOwner)) {
                        nextFrontier.add(internalOwner)
                    }
                }
            }
            frontier.clear()
            frontier.addAll(nextFrontier.filter { !loweredBodies.containsKey(it) && loweredBodies.size < maxClasses })
        }
        // Every selected class the budget cut, in the same deterministic
        // order the loop would have lowered them: the truncation's named row.
        val classesNotLowered = selected.filter { !loweredBodies.containsKey(it) }

        // ---- assemble the module ------------------------------------------------
        val functions = mutableListOf<KirFunction>()
        var functionCount = 0
        var bodyless = 0
        var constructorsSkipped = 0
        var clinitSkipped = 0
        var syntheticSkipped = 0
        val aliases = HashMap<String, MutableSet<String>>()
        for (internal in selected) {
            val work = loweredBodies[internal] ?: continue
            for (method in work.functions) {
                if (method.body != null) functionCount++
                if (method.body == null && method.syntheticCause == null) bodyless++
                functions.add(method)
            }
            for ((alias, primary) in work.aliases) {
                aliases.getOrPut(alias) { sortedSetOf() }.add(primary)
            }
            constructorsSkipped += work.constructorsSkipped
            clinitSkipped += work.clinitSkipped
            syntheticSkipped += work.syntheticSkipped
        }
        val overrides = resolveOverrides(loweredBodies)
        val module = KirModule(functions.map { fn ->
                overrides[fn.canonicalName + "\u0000" + (fn.jvmDescriptor ?: "")] ?: fn
            }.sortedWith(
                compareBy({ it.canonicalName }, { it.jvmDescriptor ?: "" }, { it.file }, { it.line }),
            ))
        return Result(
            module = module,
            classCount = loweredBodies.size,
            functionCount = functionCount,
            bodylessRecords = bodyless,
            constructorsSkipped = constructorsSkipped,
            clinitSkipped = clinitSkipped,
            syntheticSkipped = syntheticSkipped,
            unlowered = unlowered,
            classesNotFound = classesNotFound.toList(),
            classLimitHit = classLimitHit,
            classesNotLowered = classesNotLowered,
            purlsUsed = purlsUsed,
            aliases = aliases.mapValues { (_, primaries) -> primaries.toList().sorted() },
        )
    }

    // ---- one class -------------------------------------------------------------

    private class ClassWork(
        val functions: List<KirFunction>,
        /** alias canonical -> primary canonical (the demangler's output). */
        val aliases: Map<String, String>,
        val calledClasses: Set<String>,
        val constructorsSkipped: Int,
        val clinitSkipped: Int,
        val syntheticSkipped: Int,
        /** Dotted class name of this work. */
        val className: String,
        /** Dotted supertype names (superclass first, then interfaces). */
        val supertypeNames: List<String>,
        /** JVM `name(desc)` -> primary canonical for every emitted method. */
        val signatureToPrimary: Map<String, String>,
        /** primary canonical -> JVM `name(desc)` for every emitted method with a body. */
        val primaryToSignature: Map<String, String>,
    )

    private fun lowerClass(
        internal: String,
        spec: JarSpec,
        classIndex: Map<String, JarSpec>,
        unlowered: MutableMap<String, Int>,
    ): ClassWork {
        val node = ClassNode()
        try {
            JarFile(spec.jar.toFile()).use { file ->
                file.getInputStream(file.getJarEntry("$internal.class")).use { input ->
                    org.jetbrains.org.objectweb.asm.ClassReader(input.readBytes()).accept(node, 0)
                }
            }
        } catch (t: Exception) {
            unlowered.merge("class-unreadable", 1, Int::plus)
            return ClassWork(emptyList(), emptyMap(), emptySet(), 0, 0, 0, "", emptyList(), emptyMap(), emptyMap())
        }

        val classFqn = internal.replace('/', '.')
        val metadata = metadataOf(node)
        val demangler = metadata?.let { KotlinDemangler.read(it.d1, it.d2, it.kind) }
        if (metadata != null && demangler == null) unlowered.merge("metadata-unreadable", 1, Int::plus)

        val isFacade = demangler?.isFileFacade == true
        // The package a file facade's callables live in: the class name minus
        // its `Kt` suffix, then minus the class part (`com.foo.UtilsKt` ->
        // `com.foo`). Facade functions' canonical names drop the class part
        // entirely — the workspace renderer names top-level callables `pkg.name`.
        val facadePrefix = if (isFacade && classFqn.endsWith("Kt")) {
            classFqn.removeSuffix("Kt").substringBeforeLast('.', "")
        } else {
            null
        }
        val companionOuter = if (demangler?.isCompanion == true && classFqn.contains('$')) {
            classFqn.substringBeforeLast('$')
        } else {
            null
        }

        val ownerFlags = sortedSetOf<String>()
        if ((node.access and Opcodes.ACC_INTERFACE) != 0) ownerFlags.add("interface")
        if ((node.access and Opcodes.ACC_ABSTRACT) != 0) ownerFlags.add("abstract")
        if ((node.access and Opcodes.ACC_FINAL) != 0) ownerFlags.add("final")
        if ((node.access and Opcodes.ACC_ENUM) != 0) ownerFlags.add("enum")
        val supertypes = buildList {
            node.superName?.let { add(it.replace('/', '.')) }
            node.interfaces.map { add(it.replace('/', '.')) }
        }.filter { it != "java.lang.Object" }

        val classVisibility = when {
            (node.access and Opcodes.ACC_PUBLIC) != 0 || (node.access and Opcodes.ACC_PROTECTED) != 0 -> "public"
            else -> "internal"
        }

        val functions = mutableListOf<KirFunction>()
        val aliases = HashMap<String, String>()
        val calledClasses = sortedSetOf<String>()
        val signatureToPrimary = HashMap<String, String>()
        val primaryToSignature = HashMap<String, String>()
        var constructorsSkipped = 0
        var clinitSkipped = 0
        var syntheticSkipped = 0

        @Suppress("UNCHECKED_CAST")
        for (m in node.methods as List<MethodNode>) {
            val jvmName = m.name
            val desc = m.desc
            when {
                jvmName == "<init>" -> { constructorsSkipped++; continue }
                jvmName == "<clinit>" -> { clinitSkipped++; continue }
                (m.access and Opcodes.ACC_SYNTHETIC) != 0 -> { syntheticSkipped++; continue }
            }
            val sourceName = demangler?.jvmMethodToSource?.get(jvmName + desc) ?: jvmName
            val primaryClassPart = if (facadePrefix != null && demangler != null) null else classFqn
            val primaryName = if (primaryClassPart != null) "$classFqn.$sourceName" else "$facadePrefix.$sourceName"
            val suspend = demangler?.suspendMethods?.contains(jvmName + desc) == true

            val bodylessRecord = (m.access and Opcodes.ACC_ABSTRACT) != 0 || (m.access and Opcodes.ACC_NATIVE) != 0
            val params = paramsOf(m)
            val visibility = when {
                (m.access and Opcodes.ACC_PUBLIC) != 0 -> "public"
                (m.access and Opcodes.ACC_PROTECTED) != 0 -> "protected"
                (m.access and Opcodes.ACC_PRIVATE) != 0 -> "private"
                else -> "internal"
            }
            val modifiers = sortedSetOf<String>()
            if ((m.access and Opcodes.ACC_FINAL) != 0) modifiers.add("final")
            if ((m.access and Opcodes.ACC_ABSTRACT) != 0) modifiers.add("abstract")
            if (suspend) modifiers.add("suspend")
            val returnType = Type.getReturnType(desc).let { if (it == Type.VOID_TYPE) null else it.className }
            val jarRef = "${spec.jar.fileName}!$internal.class"
            val body = if (bodylessRecord) {
                null
            } else {
                try {
                    MethodLowerer(
                        method = m,
                        params = params,
                        classFqn = classFqn,
                        calledClasses = calledClasses,
                    ).lower()
                } catch (abort: LoweringAbort) {
                    unlowered.merge(abort.construct, 1, Int::plus)
                    unlowered.merge("method-aborted", 1, Int::plus)
                    null
                }
            }
            val jvmKey = jvmName + desc
            signatureToPrimary[jvmKey] = primaryName
            if (!bodylessRecord && body != null) primaryToSignature[primaryName] = jvmKey
            functions.add(
                KirFunction(
                    canonicalName = primaryName,
                    jvmDescriptor = desc,
                    purl = spec.purl,
                    file = jarRef,
                    line = firstLine(m),
                    column = 1,
                    params = params.list,
                    returnType = returnType,
                    modifiers = modifiers,
                    visibility = visibility,
                    enclosingClass = primaryClassPart,
                    overrides = emptyList(),
                    overriddenBy = emptyList(),
                    annotations = emptyList(),
                    syntheticCause = if (bodylessRecord) null else if (body == null) "bytecode-aborted" else null,
                    body = body,
                    supertypes = supertypes,
                    ownerFlags = ownerFlags,
                    ownerAnnotations = emptyList(),
                    ownerVisibility = classVisibility,
                ),
            )
            // Aliases: the JVM-named form (facades), the outer form
            // (companions), and the property callable id (accessors/fields).
            if (facadePrefix != null && primaryName != "$classFqn.$sourceName") {
                aliases["$classFqn.$sourceName"] = primaryName
            }
            if (companionOuter != null && demangler != null) {
                aliases["$companionOuter.$sourceName"] = "$classFqn.$sourceName"
            }
            // Nested classes: the workspace renderer names members through
            // the DOTTED inner form (`Timber.Forest.d`, the Kotlin callable
            // id), while the class file holds `Timber$Forest.d`.
            if (classFqn.contains('$')) {
                aliases["${classFqn.replace('$', '.')}.$sourceName"] = "$classFqn.$sourceName"
            }
            demangler?.accessorToProperty?.get(jvmName + desc)?.let { property ->
                val readAccessor = jvmName.startsWith("get") || jvmName.startsWith("is")
                if (readAccessor) {
                    aliases["$classFqn.$property"] = primaryName
                }
            }
        }
        return ClassWork(
            functions, aliases, calledClasses, constructorsSkipped, clinitSkipped, syntheticSkipped,
            className = classFqn,
            supertypeNames = supertypes,
            signatureToPrimary = signatureToPrimary,
            primaryToSignature = primaryToSignature,
        )
    }

    /**
     * Fills `overrides` WITHIN the lowered set: a method whose JVM name and
     * descriptor match a method of a selected supertype overrides it. This
     * is what dependency-internal dispatch needs — a jar body calling an
     * abstract supertype method (Timber's Tree.log -> DebugTree.log) must
     * resolve to the concrete summary, or the chain to a pack sink inside
     * the jar breaks at exactly that hop. Matching is BFS over supertypes
     * and stops at the first hit per method; supertypes outside the lowered
     * set resolve to nothing and are counted nowhere (a named miss).
     */
    private fun resolveOverrides(loweredBodies: Map<String, ClassWork>): Map<String, KirFunction> {
        // Keyed by canonical + descriptor: overload siblings of one primary
        // name share the canonical but carry distinct JVM descriptors.
        val byClass = HashMap<String, ClassWork>()
        for ((internal, work) in loweredBodies) byClass[internal.replace('/', '.')] = work
        val out = HashMap<String, KirFunction>()
        for ((_, work) in loweredBodies) {
            for (fn in work.functions) {
                if (fn.body == null) continue
                val sig = work.primaryToSignature[fn.canonicalName] ?: continue
                val overridden = sortedSetOf<String>()
                val seen = HashSet<String>()
                val queue = ArrayDeque(work.supertypeNames)
                while (queue.isNotEmpty()) {
                    val superName = queue.removeFirst()
                    if (!seen.add(superName)) continue
                    val superWork = byClass[superName]
                    if (superWork == null) continue
                    val superPrimary = superWork.signatureToPrimary[sig]
                    if (superPrimary != null && superPrimary != fn.canonicalName) {
                        overridden.add(superPrimary)
                        continue // matched here: this line's search stops
                    }
                    superWork.supertypeNames.forEach { if (it !in seen) queue.addLast(it) }
                }
                if (overridden.isNotEmpty()) {
                    out[fn.canonicalName + "\u0000" + (fn.jvmDescriptor ?: "")] =
                        fn.copy(overrides = overridden.toList())
                }
            }
        }
        return out
    }

    private class Metadata(val d1: List<String>, val d2: List<String>, val kind: Int?)

    private fun metadataOf(node: ClassNode): Metadata? {
        val annotations = node.visibleAnnotations ?: return null
        for (annotation in annotations) {
            if (annotation.desc != "Lkotlin/Metadata;") continue
            val values = annotation.values ?: continue
            var d1: List<String>? = null
            var d2: List<String>? = null
            var kind: Int? = null
            var i = 0
            while (i + 1 < values.size) {
                when (values[i]) {
                    "d1" -> (values[i + 1] as? List<*>)?.let { list -> d1 = list.filterIsInstance<String>() }
                    "d2" -> (values[i + 1] as? List<*>)?.let { list -> d2 = list.filterIsInstance<String>() }
                    "k" -> (values[i + 1] as? Int)?.let { kind = it }
                }
                i += 2
            }
            if (d1 != null && d2 != null) return Metadata(d1!!, d2!!, kind)
        }
        return null
    }

    private fun firstLine(m: MethodNode): Int {
        for (ins in m.instructions) {
            if (ins is LineNumberNode) return ins.line
        }
        return 0
    }

    private fun paramsOf(m: MethodNode): Params {
        val isStatic = (m.access and Opcodes.ACC_STATIC) != 0
        val argTypes = Type.getArgumentTypes(m.desc)
        val list = mutableListOf<KirParam>()
        val slotToRegister = HashMap<Int, String>()
        var slot = 0
        if (!isStatic) {
            val register = "%0"
            list.add(KirParam(register, "this", null, receiver = true))
            slotToRegister[slot] = register
            slot += 1
        }
        argTypes.forEachIndexed { index, type ->
            val register = "%${list.size}"
            val name = m.localVariables?.firstOrNull { lv ->
                lv.index == slot && lv.name != "this" && !lv.name.startsWith("$")
            }?.name
            list.add(KirParam(register, name, type.className, receiver = false))
            slotToRegister[slot] = register
            slot += if (type == Type.LONG_TYPE || type == Type.DOUBLE_TYPE) 2 else 1
        }
        return Params(list, slotToRegister)
    }

    private class Params(val list: List<KirParam>, val slotToRegister: Map<Int, String>)

    // ---- one method body: the JVM operand stack -> KIR registers ----------------

    private class Entry(val reg: String, val cat2: Boolean)

    private class BlockBuilder(val id: String, val entry: Boolean) {
        val ins = mutableListOf<KirIns>()
    }

    /**
     * Lowers one method body into a [KirBody], or aborts with
     * [LoweringAbort] when it meets an instruction it cannot translate — the
     * method is then treated as BODY-LESS (ignored entirely, counted under
     * `bytecode-unlowered`), never summarised from a half-body.
     */
    private class MethodLowerer(
        val method: MethodNode,
        val params: Params,
        val classFqn: String,
        val calledClasses: MutableSet<String>,
    ) {
        private val stack = ArrayDeque<Entry>()
        private var temps = 0
        private var phantoms = 0
        private var falls = 0
        private var switches = 0
        private val blocks = LinkedHashMap<String, BlockBuilder>()
        private var current: BlockBuilder? = null
        private var terminated = false
        private var line = 0

        /**
         * The operand stack is simulated LINEARLY, which a CFG with joins
         * breaks: at a branch target reached from a different predecessor,
         * the linear walk's stack is not the target's real entry state. Two
         * rounds fix this: round 1 (dry) records the stack state AT every
         * branch, per target block; round 2 emits, RESTORING each target's
         * recorded state at its block entry. A target with no recorded
         * state keeps the linear stack; popping an empty stack synthesises
         * a fresh PHANTOM register (untainted — conservative for a
         * may-analysis, never a wrong flow). Both rounds walk in the same
         * order with the same counters, so register and block ids are
         * identical to a single-pass lowering.
         */
        private var dryRun = true
        private val entryStacks = HashMap<String, List<Entry>>()

        private fun fresh(): String = "%s${temps++}"

        private fun block(id: String, entry: Boolean = false): BlockBuilder =
            blocks.getOrPut(id) { BlockBuilder(id, entry) }

        private fun emit(ins: KirIns) {
            if (dryRun) return
            val b = current ?: error("no current block")
            b.ins.add(ins)
        }

        private fun push(reg: String, cat2: Boolean = false) = stack.addLast(Entry(reg, cat2))

        private fun push(entry: Entry) = stack.addLast(entry)

        private fun pop(): Entry =
            if (stack.isEmpty()) Entry("%ph${phantoms++}", false) else stack.removeLast()

        private fun popArgs(desc: String): List<String> {
            val types = Type.getArgumentTypes(desc)
            val regs = arrayOfNulls<String>(types.size)
            for (i in types.indices.reversed()) {
                regs[i] = pop().reg
            }
            return regs.map { it!! }
        }

        private fun recordEntry(id: String) {
            if (id !in entryStacks) entryStacks[id] = stack.toList()
        }

        private fun restore(snapshot: List<Entry>) {
            stack.clear()
            snapshot.forEach { stack.addLast(it) }
        }

        // Block ids are assigned in walk order — label identity hashes would
        // be stable only within one JVM, and the KIR must be identical
        // across runs and machines.
        private lateinit var labelIds: Map<LabelNode, String>

        private fun targetOf(label: LabelNode): String = labelIds.getValue(label)

        fun lower(): KirBody {
            // Pass 0: which labels are branch targets, and their stable ids
            // in first-appearance order.
            val ids = LinkedHashMap<LabelNode, String>()
            for (ins in method.instructions) {
                when (ins) {
                    is JumpInsnNode -> ids.putIfAbsent(ins.label, "b${ids.size}")
                    is TableSwitchInsnNode -> {
                        ids.putIfAbsent(ins.dflt, "b${ids.size}")
                        ins.labels.forEach { ids.putIfAbsent(it, "b${ids.size}") }
                    }

                    is LookupSwitchInsnNode -> {
                        ids.putIfAbsent(ins.dflt, "b${ids.size}")
                        ins.labels.forEach { ids.putIfAbsent(it, "b${ids.size}") }
                    }

                    else -> {}
                }
            }
            labelIds = ids
            // Round 1: dry walk, recording every branch target's entry stack.
            walk()
            // Round 2: the emitting walk, restoring recorded states.
            resetForEmit()
            dryRun = false
            walk()
            if (blocks.isEmpty()) throw LoweringAbort("empty-body")
            // Every branch target must exist as a materialised block: labels
            // in unreachable code (after a return, say) are never visited by
            // the walk but are still referenced. They materialise as
            // terminated empty blocks so no consumer ever looks up a block
            // the body does not carry.
            for (b in blocks.values.toList()) {
                for (ins in b.ins) {
                    if (ins is KirBranch) {
                        for (target in listOf(ins.thenBlock, ins.elseBlock)) {
                            blocks.getOrPut(target) {
                                BlockBuilder(target, entry = false).also { phantom ->
                                    phantom.ins.add(KirReturn(null))
                                }
                            }
                        }
                    }
                }
            }
            return KirBody(blocks.values.map { b -> KirBlock(b.id, b.entry, b.ins.toList()) })
        }

        private fun resetForEmit() {
            stack.clear()
            temps = 0
            phantoms = 0
            falls = 0
            switches = 0
            blocks.clear()
            current = null
            terminated = false
            line = 0
        }

        private fun walk() {
            current = block("entry", entry = true)
            terminated = false
            for (ins in method.instructions) {
                when (ins) {
                    is LabelNode -> {
                        val id = labelIds[ins]
                        if (id != null) {
                            // The label's block appends right after the
                            // current one, so an unterminated (fall-through)
                            // predecessor stays connected per the CFG
                            // contract; a terminated one just ends here.
                            current = block(id)
                            terminated = false
                            // A branch-recorded entry state is the block's
                            // truth; the fall-through linear state only
                            // applies when no branch ever targeted it.
                            entryStacks[id]?.let { restore(it) }
                        }
                    }

                    is FrameNode -> {}
                    is LineNumberNode -> line = ins.line

                    is VarInsnNode -> visitVar(ins)
                    is InsnNode -> visitSimple(ins)
                    is IntInsnNode -> when (ins.opcode) {
                        Opcodes.SIPUSH, Opcodes.BIPUSH -> {
                            val r = fresh()
                            emit(KirLoad(r, KirConstant.IntConst(ins.operand.toLong())))
                            push(r)
                        }

                        Opcodes.NEWARRAY -> {
                            val r = fresh()
                            emit(KirNew(r, "array", emptyList()))
                            push(r)
                        }

                        else -> throw LoweringAbort("int-insn-${ins.opcode}")
                    }

                    is LdcInsnNode -> {
                        val r = fresh()
                        val constant: KirConstant = when (val cst = ins.cst) {
                            is String -> KirConstant.Str(cst)
                            is Integer -> KirConstant.IntConst(cst.toLong())
                            is java.lang.Long -> KirConstant.IntConst(cst.toLong())
                            is java.lang.Float -> KirConstant.FloatConst(cst.toDouble())
                            is java.lang.Double -> KirConstant.FloatConst(cst.toDouble())
                            is Type -> KirConstant.Str(cst.className)
                            else -> KirConstant.Str(cst.toString())
                        }
                        val cat2 = ins.cst is java.lang.Long || ins.cst is java.lang.Double
                        emit(KirLoad(r, constant))
                        push(r, cat2)
                    }

                    is TypeInsnNode -> when (ins.opcode) {
                        Opcodes.NEW -> {
                            val r = fresh()
                            val type = Type.getObjectType(ins.desc).className
                            // The register is DEFINED by the <init> lowering
                            // (a KirNew) when it arrives; until then the
                            // pending table only remembers the type.
                            push(r)
                            pendingNews[r] = type
                        }

                        Opcodes.CHECKCAST -> {} // the value passes through unchanged
                        Opcodes.ANEWARRAY -> {
                            val r = fresh()
                            emit(KirNew(r, Type.getObjectType(ins.desc).className + "[]", emptyList()))
                            push(r)
                        }

                        Opcodes.INSTANCEOF -> {
                            val value = pop()
                            val r = fresh()
                            emit(KirTypeCheck(r, value.reg, Type.getObjectType(ins.desc).className))
                            push(r)
                        }

                        else -> throw LoweringAbort("type-insn-${ins.opcode}")
                    }

                    is FieldInsnNode -> visitField(ins)
                    is MethodInsnNode -> visitInvoke(ins)
                    is InvokeDynamicInsnNode -> visitIndy(ins)
                    is IincInsnNode -> {
                        val local = localReg(ins.`var`)
                        val inc = fresh()
                        emit(KirLoad(inc, KirConstant.IntConst(ins.incr.toLong())))
                        emit(KirCall(local, KirCallee("kotlin.plus", null, CallKind.OPERATOR), null, listOf(local, inc), line = line))
                    }

                    is JumpInsnNode -> visitJump(ins)
                    is TableSwitchInsnNode -> visitSwitch(ins.labels, ins.dflt)
                    is LookupSwitchInsnNode -> visitSwitch(ins.labels, ins.dflt)
                    is MultiANewArrayInsnNode -> {
                        repeat(ins.dims) { pop() }
                        val r = fresh()
                        emit(KirNew(r, ins.desc.replace('/', '.'), emptyList()))
                        push(r)
                    }

                    else -> throw LoweringAbort("insn-${ins.opcode}")
                }
            }
        }

        private val pendingNews = HashMap<String, String>()

        private fun localReg(slot: Int): String =
            params.slotToRegister[slot] ?: "%L$slot"

        private fun visitVar(ins: VarInsnNode) {
            when (ins.opcode) {
                Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD, Opcodes.DLOAD, Opcodes.ALOAD -> {
                    val cat2 = ins.opcode == Opcodes.LLOAD || ins.opcode == Opcodes.DLOAD
                    push(localReg(ins.`var`), cat2)
                }

                Opcodes.ISTORE, Opcodes.LSTORE, Opcodes.FSTORE, Opcodes.DSTORE, Opcodes.ASTORE -> {
                    val value = pop()
                    emit(KirAssign(localReg(ins.`var`), value.reg))
                }

                Opcodes.RET -> throw LoweringAbort("ret")
                else -> throw LoweringAbort("var-insn-${ins.opcode}")
            }
        }

        private fun visitSimple(ins: InsnNode) {
            when (ins.opcode) {
                Opcodes.NOP -> {}
                Opcodes.ACONST_NULL -> {
                    val r = fresh()
                    emit(KirLoad(r, KirConstant.Null))
                    push(r)
                }

                Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2,
                Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
                -> {
                    val value = ins.opcode - Opcodes.ICONST_0
                    val r = fresh()
                    emit(KirLoad(r, KirConstant.IntConst(value.toLong())))
                    push(r)
                }

                Opcodes.LCONST_0, Opcodes.LCONST_1 -> {
                    val r = fresh()
                    emit(KirLoad(r, KirConstant.IntConst((ins.opcode - Opcodes.LCONST_0).toLong())))
                    push(r, cat2 = true)
                }

                Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2 -> {
                    val r = fresh()
                    emit(KirLoad(r, KirConstant.FloatConst((ins.opcode - Opcodes.FCONST_0).toDouble())))
                    push(r)
                }

                Opcodes.DCONST_0, Opcodes.DCONST_1 -> {
                    val r = fresh()
                    emit(KirLoad(r, KirConstant.FloatConst((ins.opcode - Opcodes.DCONST_0).toDouble())))
                    push(r, cat2 = true)
                }

                Opcodes.IALOAD, Opcodes.LALOAD, Opcodes.FALOAD, Opcodes.DALOAD, Opcodes.AALOAD,
                Opcodes.BALOAD, Opcodes.CALOAD, Opcodes.SALOAD,
                -> {
                    val index = pop()
                    val array = pop()
                    val r = fresh()
                    emit(KirIndexGet(r, array.reg, index.reg))
                    push(r)
                }

                Opcodes.IASTORE, Opcodes.LASTORE, Opcodes.FASTORE, Opcodes.DASTORE, Opcodes.AASTORE,
                Opcodes.BASTORE, Opcodes.CASTORE, Opcodes.SASTORE,
                -> {
                    val value = pop()
                    val index = pop()
                    val array = pop()
                    emit(KirIndexSet(array.reg, index.reg, value.reg))
                }

                Opcodes.ARRAYLENGTH -> {
                    val array = pop()
                    val r = fresh()
                    emit(KirFieldGet(r, array.reg, AccessPath(array.reg, listOf(AccessPath.Element.Field("length")))))
                    push(r)
                }

                Opcodes.ATHROW -> {
                    val value = pop()
                    emit(KirThrow(value.reg))
                    terminated = true
                }

                in INT_RETURN_OPS -> {
                    val e = pop()
                    emit(KirReturn(e.reg))
                    terminated = true
                }

                Opcodes.RETURN -> {
                    emit(KirReturn(null))
                    terminated = true
                }

                Opcodes.DUP -> {
                    val e = pop()
                    push(e)
                    push(e)
                }

                Opcodes.DUP_X1 -> {
                    val v1 = pop()
                    val v2 = pop()
                    push(v1)
                    push(v2)
                    push(v1)
                }

                Opcodes.DUP_X2 -> {
                    val v1 = pop()
                    val v2 = pop()
                    val v3 = pop()
                    push(v1)
                    push(v3)
                    push(v2)
                    push(v1)
                }

                Opcodes.DUP2 -> {
                    val v1 = pop()
                    if (v1.cat2) {
                        push(v1)
                        push(v1)
                    } else {
                        val v2 = pop()
                        push(v2)
                        push(v1)
                        push(v2)
                        push(v1)
                    }
                }

                Opcodes.DUP2_X1 -> {
                    val v1 = pop()
                    val v2 = pop()
                    if (v1.cat2) {
                        push(v1)
                        push(v2)
                        push(v1)
                    } else {
                        val v3 = pop()
                        push(v2)
                        push(v1)
                        push(v3)
                        push(v2)
                        push(v1)
                    }
                }

                Opcodes.DUP2_X2 -> {
                    val v1 = pop()
                    val v2 = pop()
                    val v3 = pop()
                    val v4 = pop()
                    push(v2)
                    push(v1)
                    push(v4)
                    push(v3)
                    push(v2)
                    push(v1)
                }

                Opcodes.SWAP -> {
                    val v1 = pop()
                    val v2 = pop()
                    push(v1)
                    push(v2)
                }

                Opcodes.POP -> pop()
                Opcodes.POP2 -> {
                    val v1 = pop()
                    if (!v1.cat2) pop()
                }

                Opcodes.IADD, Opcodes.LADD, Opcodes.FADD, Opcodes.DADD,
                Opcodes.ISUB, Opcodes.LSUB, Opcodes.FSUB, Opcodes.DSUB,
                Opcodes.IMUL, Opcodes.LMUL, Opcodes.FMUL, Opcodes.DMUL,
                Opcodes.IDIV, Opcodes.LDIV, Opcodes.FDIV, Opcodes.DDIV,
                Opcodes.IREM, Opcodes.LREM, Opcodes.FREM, Opcodes.DREM,
                Opcodes.IAND, Opcodes.LAND, Opcodes.IOR, Opcodes.LOR,
                Opcodes.IXOR, Opcodes.LXOR, Opcodes.ISHL, Opcodes.LSHL,
                Opcodes.ISHR, Opcodes.LSHR, Opcodes.IUSHR, Opcodes.LUSHR,
                -> {
                    val name = arithName(ins.opcode)
                    val b = pop()
                    val a = pop()
                    val r = fresh()
                    val cat2 = ins.opcode in CAT2_RESULT
                    emit(KirCall(r, KirCallee("kotlin.$name", null, CallKind.OPERATOR), null, listOf(a.reg, b.reg), line = line))
                    push(r, cat2)
                }

                Opcodes.INEG, Opcodes.LNEG, Opcodes.FNEG, Opcodes.DNEG -> {
                    val a = pop()
                    val r = fresh()
                    emit(KirCall(r, KirCallee("kotlin.unaryMinus", null, CallKind.OPERATOR), a.reg, emptyList(), line = line))
                    push(r, a.cat2)
                }

                Opcodes.LCMP, Opcodes.FCMPL, Opcodes.FCMPG, Opcodes.DCMPL, Opcodes.DCMPG -> {
                    val b = pop()
                    val a = pop()
                    val r = fresh()
                    emit(KirCall(r, KirCallee("kotlin.compareTo", null, CallKind.OPERATOR), null, listOf(a.reg, b.reg), line = line))
                    push(r)
                }

                // Numeric conversions preserve the value's taint identity: the
                // same register flows through, no instruction needed.
                Opcodes.I2L, Opcodes.I2F, Opcodes.I2D, Opcodes.L2I, Opcodes.L2F, Opcodes.L2D,
                Opcodes.F2I, Opcodes.F2L, Opcodes.F2D, Opcodes.D2I, Opcodes.D2L, Opcodes.D2F,
                Opcodes.I2B, Opcodes.I2C, Opcodes.I2S,
                -> {
                    val a = pop()
                    push(a.reg, a.cat2)
                }

                Opcodes.MONITORENTER, Opcodes.MONITOREXIT -> {
                    // A monitor is transparent to taint: the value crosses
                    // unchanged. Counted, so the treatment is visible.
                    pop()
                    monitorsIgnored += 1
                }

                else -> throw LoweringAbort("simple-${ins.opcode}")
            }
        }

        var monitorsIgnored = 0
            private set

        private fun arithName(opcode: Int): String = when (opcode) {
            Opcodes.IADD, Opcodes.LADD, Opcodes.FADD, Opcodes.DADD -> "plus"
            Opcodes.ISUB, Opcodes.LSUB, Opcodes.FSUB, Opcodes.DSUB -> "minus"
            Opcodes.IMUL, Opcodes.LMUL, Opcodes.FMUL, Opcodes.DMUL -> "times"
            Opcodes.IDIV, Opcodes.LDIV, Opcodes.FDIV, Opcodes.DDIV -> "div"
            Opcodes.IREM, Opcodes.LREM, Opcodes.FREM, Opcodes.DREM -> "rem"
            Opcodes.IAND, Opcodes.LAND -> "and"
            Opcodes.IOR, Opcodes.LOR -> "or"
            Opcodes.IXOR, Opcodes.LXOR -> "xor"
            Opcodes.ISHL, Opcodes.LSHL -> "shl"
            Opcodes.ISHR, Opcodes.LSHR -> "shr"
            Opcodes.IUSHR, Opcodes.LUSHR -> "ushr"
            else -> "plus"
        }

        private val CAT2_RESULT = setOf(
            Opcodes.LADD, Opcodes.DADD, Opcodes.LSUB, Opcodes.DSUB,
            Opcodes.LMUL, Opcodes.DMUL, Opcodes.LDIV, Opcodes.DDIV,
            Opcodes.LREM, Opcodes.DREM, Opcodes.LAND, Opcodes.LOR,
            Opcodes.LXOR, Opcodes.LSHL, Opcodes.LSHR, Opcodes.LUSHR,
        )

        private val INT_RETURN_OPS = setOf(
            Opcodes.IRETURN, Opcodes.LRETURN, Opcodes.FRETURN, Opcodes.DRETURN, Opcodes.ARETURN,
        )

        private val EQUALITY_OPS = setOf(
            Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE,
        )

        private fun visitField(ins: FieldInsnNode) {
            val owner = Type.getObjectType(ins.owner).className
            when (ins.opcode) {
                Opcodes.GETFIELD -> {
                    val recv = pop()
                    val r = fresh()
                    emit(KirFieldGet(r, recv.reg, AccessPath(recv.reg, listOf(AccessPath.Element.Field(ins.name)))))
                    push(r)
                }

                Opcodes.PUTFIELD -> {
                    val value = pop()
                    val recv = pop()
                    emit(KirFieldSet(recv.reg, AccessPath(recv.reg, listOf(AccessPath.Element.Field(ins.name))), value.reg))
                }

                Opcodes.GETSTATIC -> {
                    val r = fresh()
                    emit(KirLoad(r, KirConstant.Str("$owner.${ins.name}")))
                    push(r)
                }

                Opcodes.PUTSTATIC -> {
                    val value = pop()
                    emit(KirStore("%S:$owner.${ins.name}", value.reg))
                }

                else -> throw LoweringAbort("field-${ins.opcode}")
            }
        }

        private fun visitInvoke(ins: MethodInsnNode) {
            var owner = Type.getObjectType(ins.owner).className
            calledClasses.add(ins.owner.replace('/', '.'))
            // A static call into a Kotlin file facade carries the JVM facade
            // name (`kotlin.io.ConsoleKt.readLine`), while every caller-side
            // renderer — and therefore every pack pattern — uses the source
            // callable id (`kotlin.io.readLine`). Render `*Kt` static owners
            // the source way so pack entries match inside jar bodies exactly
            // as they match in workspace bodies. (@JvmName facades are a
            // named limitation; `*Kt` is the compiler default.)
            if (ins.opcode == Opcodes.INVOKESTATIC && owner.endsWith("Kt")) {
                // The facade class's SIMPLE name (e.g. `ConsoleKt`) is the
                // file's name, not a class in the callable id: the source
                // callable id is package + function name alone.
                val pkg = owner.substringBeforeLast('.', "")
                if (pkg.isNotEmpty()) owner = pkg
            }
            when (ins.opcode) {
                Opcodes.INVOKESTATIC -> {
                    val args = popArgs(ins.desc)
                    val ret = Type.getReturnType(ins.desc)
                    val result = if (ret == Type.VOID_TYPE) null else fresh()
                    result?.let { push(it, ret == Type.LONG_TYPE || ret == Type.DOUBLE_TYPE) }
                    emit(KirCall(result, KirCallee("$owner.${ins.name}", ins.desc, CallKind.STATIC), null, args, line = line))
                }

                Opcodes.INVOKESPECIAL -> {
                    val args = popArgs(ins.desc)
                    val recv = pop()
                    if (ins.name == "<init>") {
                        val type = pendingNews.remove(recv.reg)
                        if (type != null) {
                            emit(KirNew(recv.reg, type, args, line = line))
                        } else {
                            // A super constructor call: keep the evidence edge.
                            emit(KirCall(null, KirCallee("$owner.${ins.name}", ins.desc, CallKind.CONSTRUCTOR), recv.reg, args, line = line))
                        }
                    } else {
                        val ret = Type.getReturnType(ins.desc)
                        val result = if (ret == Type.VOID_TYPE) null else fresh()
                        result?.let { push(it, ret == Type.LONG_TYPE || ret == Type.DOUBLE_TYPE) }
                        emit(KirCall(result, KirCallee("$owner.${ins.name}", ins.desc, CallKind.VIRTUAL), recv.reg, args, line = line))
                    }
                }

                Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE -> {
                    val args = popArgs(ins.desc)
                    val recv = pop()
                    val ret = Type.getReturnType(ins.desc)
                    val result = if (ret == Type.VOID_TYPE) null else fresh()
                    result?.let { push(it, ret == Type.LONG_TYPE || ret == Type.DOUBLE_TYPE) }
                    emit(KirCall(result, KirCallee("$owner.${ins.name}", ins.desc, CallKind.VIRTUAL), recv.reg, args, line = line))
                }

                else -> throw LoweringAbort("invoke-${ins.opcode}")
            }
        }

        private fun visitIndy(ins: InvokeDynamicInsnNode) {
            if (ins.name == "makeConcatWithConstants" || ins.name == "makeConcat") {
                val parts = popArgs(ins.desc)
                val r = fresh()
                emit(KirStringConcat(r, parts))
                push(r)
                return
            }
            // LambdaMetafactory and friends: the functional value is unknown
            // here, so it lowers to a dynamic call — the labelled unknown
            // default covers it, counted, never silent.
            val args = popArgs(ins.desc)
            val ret = Type.getReturnType(ins.desc)
            val result = if (ret == Type.VOID_TYPE) null else fresh()
            result?.let { push(it, ret == Type.LONG_TYPE || ret == Type.DOUBLE_TYPE) }
            emit(KirDynamicCall(result, ins.name, null, args, line = line))
        }

        private fun visitJump(ins: JumpInsnNode) {
            if (ins.opcode == Opcodes.GOTO) {
                val t = fresh()
                emit(KirLoad(t, KirConstant.Bool(true)))
                val target = targetOf(ins.label)
                recordEntry(target)
                emit(KirBranch(t, target, target))
                terminated = true
                return
            }
            if (ins.opcode == Opcodes.JSR) throw LoweringAbort("jsr")
            val cond = when (ins.opcode) {
                Opcodes.IFNULL, Opcodes.IFNONNULL, Opcodes.IFEQ, Opcodes.IFNE,
                Opcodes.IFLT, Opcodes.IFGE, Opcodes.IFGT, Opcodes.IFLE,
                -> pop().reg

                else -> {
                    val b = pop()
                    val a = pop()
                    val r = fresh()
                    val calleeName = if (ins.opcode in EQUALITY_OPS) "equals" else "compareTo"
                    emit(KirCall(r, KirCallee("kotlin.$calleeName", null, CallKind.OPERATOR), null, listOf(a.reg, b.reg), line = line))
                    r
                }
            }
            val thenId = targetOf(ins.label)
            val elseId = "fall${falls++}"
            recordEntry(thenId)
            emit(KirBranch(cond, thenId, elseId))
            terminated = true
            current = block(elseId)
            terminated = false
        }

        private fun visitSwitch(labels: List<LabelNode>, dflt: LabelNode) {
            val cond = pop().reg
            // A switch lowers to a chain of two-way branches: the first lives
            // here with the real condition, and each subsequent case gets a
            // small block whose (constant-true) branch points at its case,
            // ELSE-chaining to the next. Polarity is irrelevant to a
            // may-analysis; the targets are what carry the CFG.
            val ordered = labels + dflt
            val chainIds = (1 until ordered.size).map { "sw${switches++}" }
            val firstElse = chainIds.firstOrNull() ?: targetOf(ordered[0])
            recordEntry(targetOf(ordered[0]))
            emit(KirBranch(cond, targetOf(ordered[0]), firstElse))
            for ((idx, chainId) in chainIds.withIndex()) {
                val b = block(chainId)
                val t = fresh()
                b.ins.add(KirLoad(t, KirConstant.Bool(true)))
                b.ins.add(KirBranch(t, targetOf(ordered[idx + 1]), chainIds.getOrNull(idx + 1) ?: targetOf(dflt)))
            }
            terminated = true
            current = block("fall${falls++}")
            terminated = false
        }
    }
}
