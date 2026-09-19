package org.koin.core.module

class Module

// Koin 3.x's `module { }`: the block's receiver is the Module the providers
// register against.
fun module(createdAtStart: Boolean = false, moduleDeclaration: Module.() -> Unit): Module =
    Module().apply(moduleDeclaration)
