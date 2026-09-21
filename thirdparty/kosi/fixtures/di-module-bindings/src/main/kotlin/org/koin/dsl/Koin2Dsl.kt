// Koin 2.x's spellings at their real package — the same capability under its
// older name (the rule: one capability, every spelling). Real Koin 2.x
// applications `import org.koin.dsl.*` and this is what `module` and
// `single` resolve to.
package org.koin.dsl

import org.koin.core.definition.Definition
import org.koin.core.module.Module

fun module(moduleDeclaration: Module.() -> Unit): Module = Module()

fun <T : Any> Module.single(definition: Definition<T>): Module = this

fun <T : Any> Module.factory(definition: Definition<T>): Module = this
