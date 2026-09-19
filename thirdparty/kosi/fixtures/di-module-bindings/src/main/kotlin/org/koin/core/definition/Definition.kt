// Koin 3.x's definition shape, at its real package: a function from the
// scope to the provided instance.
package org.koin.core.definition

public typealias Definition<T> = (org.koin.core.scope.Scope) -> T
