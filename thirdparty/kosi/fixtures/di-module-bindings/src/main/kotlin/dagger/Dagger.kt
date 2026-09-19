// Dagger's module annotations at their real package (dagger.Binds /
// dagger.Provides / dagger.Module), declared in source so the fixture's
// annotations RESOLVE — kosi matches resolved FQNs, never short names.
package dagger

@Target(AnnotationTarget.CLASS)
annotation class Module

@Target(AnnotationTarget.FUNCTION)
annotation class Binds

@Target(AnnotationTarget.FUNCTION)
annotation class Provides
