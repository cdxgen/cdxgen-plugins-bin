// Koin 2.x's provider spellings at their real package — the same capability
// under its older name (P25's rule: one capability, every spelling).
package org.koin.dsl

import org.koin.core.definition.Definition
import org.koin.core.module.Module

inline fun <reified T : Any> Module.single(noinline definition: Definition<T>): Module = this

inline fun <reified T : Any> Module.factory(noinline definition: Definition<T>): Module = this
