package io.cdxgen.kosi.front

import org.jetbrains.org.objectweb.asm.Type

/**
 * Assembles JVM descriptor strings from already-mapped parameter/return
 * [Type]s. The Analysis API mapping itself (`mapToJvmType`, the machinery
 * the compiler back end uses) is called by [ResolvedAnalyzer] inside its
 * session scope; this object only owns the descriptor algebra, so a report's
 * `jvmDescriptor` agrees with what kotlinc would emit for the same
 * declaration. `null` means "not computable", never "guessed".
 */
object JvmSignatures {

    /** `(Ljava/lang/String;)Ljava/lang/String;`-shaped, erased. */
    fun methodDescriptor(returnType: Type, params: List<Type>): String =
        Type.getMethodDescriptor(returnType, *params.toTypedArray())

    fun voidMethodDescriptor(params: List<Type>): String =
        Type.getMethodDescriptor(Type.VOID_TYPE, *params.toTypedArray())
}
