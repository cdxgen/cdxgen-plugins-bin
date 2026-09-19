// Koin 3.x's provider DSL at its real package: `single` and `factory` are
// extensions on Module whose lambda constructs what the container manages.
package org.koin.core.module.dsl

import org.koin.core.definition.Definition
import org.koin.core.module.Module

inline fun <reified T : Any> Module.single(createdAtStart: Boolean = false, noinline definition: Definition<T>): Module = this

inline fun <reified T : Any> Module.factory(noinline definition: Definition<T>): Module = this
