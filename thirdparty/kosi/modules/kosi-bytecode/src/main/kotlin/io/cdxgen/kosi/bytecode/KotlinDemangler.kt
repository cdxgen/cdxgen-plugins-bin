package io.cdxgen.kosi.bytecode

import org.jetbrains.kotlin.metadata.ProtoBuf
import org.jetbrains.kotlin.metadata.deserialization.Flags
import org.jetbrains.kotlin.metadata.deserialization.TypeTable
import org.jetbrains.kotlin.metadata.jvm.deserialization.JvmProtoBufUtil

/**
 * Reads a class file's `@kotlin.Metadata` annotation and maps JVM method
 * signatures back to their SOURCE names — the demangling half of.
 *
 * Why this exists: the workspace KIR names callees by Kotlin callable id
 * (`com.foo.bar` for a top-level function, `com.foo.Bar.name` for a
 * property read), while the class file holds JVM names (`com/foo/UtilsKt.bar`
 * — possibly hash-mangled for overloads with defaults, `com/foo/Bar.getName`
 * for a property accessor). A dependency summary is only reachable from a
 * workspace call site when the tier's canonical names match the renderer's,
 * so a mangled or accessor method that demangling misses is a summary no
 * caller can ever apply — a capability the report then silently lacks.
 *
 * The metadata protobuf reader comes from kotlin-compiler-common-for-ide,
 * which is already a shipped runtime dependency; nothing new rides the
 * allowlist (02-ARCHITECTURE.md §1). A class whose metadata cannot be read
 * (version skew, truncated annotation) yields `null`: the methods keep their
 * JVM names and the miss is counted by the caller, never invented around.
 */
internal object KotlinDemangler {

    class Info(
        /**
         * JVM `name(desc)` -> the declaration's SOURCE name. Covers functions
         * (including hash-mangled overloads) and property accessors (whose
         * source name is the accessor's, not the property's — the property
         * aliases live in [propertyAliases]).
         */
        val jvmMethodToSource: Map<String, String>,
        /** `get/is/setX` accessor JVM `name(desc)` -> the property's source name. */
        val accessorToProperty: Map<String, String>,
        /** Function flags the renderer needs (currently `suspend`). */
        val suspendMethods: Set<String>,
        /** The metadata `k` kind: 2 marks a file facade (top-level functions). */
        val isFileFacade: Boolean,
        /** True when the proto says the class is a companion object. */
        val isCompanion: Boolean,
        /** The class's own FQ name as the metadata records it, when readable. */
        val classFqName: String?,
    )

    fun read(d1: List<String>, d2: List<String>, kind: Int?): Info? = try {
        val (nameResolver, classProto) = JvmProtoBufUtil.readClassDataFrom(
            d1.toTypedArray(),
            d2.toTypedArray(),
        )
        val typeTable = TypeTable(classProto.typeTable)
        val methods = HashMap<String, String>()
        val accessors = HashMap<String, String>()
        val suspend = sortedSetOf<String>()
        for (f in classProto.functionList) {
            val sourceName = nameResolver.getString(f.name)
            val signature = JvmProtoBufUtil.getJvmMethodSignature(f, nameResolver, typeTable) ?: continue
            methods[signature.name + signature.desc] = sourceName
            if (Flags.IS_SUSPEND.get(f.flags)) suspend.add(signature.name + signature.desc)
            val propertyName = accessorProperty(sourceName)
            if (propertyName != null) accessors[signature.name + signature.desc] = propertyName
        }
        // Property accessors ALSO answer for the property's own callable id;
        // fields go the same way when the class carries them (a workspace
        // read of a public Java field lowers to the field, not a getter).
        for (p in classProto.propertyList) {
            val propertyName = nameResolver.getString(p.name)
            val fieldSignature = JvmProtoBufUtil.getJvmFieldSignature(p, nameResolver, typeTable, false) ?: continue
            accessors[fieldSignature.name + fieldSignature.desc] = propertyName
        }
        Info(
            jvmMethodToSource = methods,
            accessorToProperty = accessors,
            suspendMethods = suspend,
            isFileFacade = kind == 2,
            isCompanion = Flags.CLASS_KIND.get(classProto.flags) == ProtoBuf.Class.Kind.COMPANION_OBJECT,
            classFqName = nameResolver.getString(classProto.fqName),
        )    } catch (_: Throwable) {
        // Unreadable metadata is a NAMED miss (counted by the caller as
        // `metadata-unreadable`), never a guessed name.
        null
    }

    /** `getX`/`isX`/`setX` -> `x`; anything else null. */
    private fun accessorProperty(methodName: String): String? {
        val prefix = when {
            methodName.startsWith("get") -> "get"
            methodName.startsWith("is") -> "is"
            methodName.startsWith("set") -> "set"
            else -> return null
        }
        if (methodName.length == prefix.length) return null
        val property = methodName.substring(prefix.length).decapitalizeAscii()
        return property.ifEmpty { null }
    }

    private fun String.decapitalizeAscii(): String =
        if (isEmpty() || this[0] !in 'A'..'Z') this else this[0].lowercaseChar() + substring(1)
}
