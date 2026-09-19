// The two Spring stereotypes this fixture needs, declared in source at their
// real package. The framework fixtures do this deliberately (see
// implicit-routes' classpath.txt): kosi matches RESOLVED annotation FQNs and
// never short names, so an annotation the fixture cannot resolve is an
// annotation the engine must ignore — which is the contract, and which means
// a fixture has to make the type real to exercise the matcher at all.
package org.springframework.stereotype

@Target(AnnotationTarget.CLASS)
annotation class Component

@Target(AnnotationTarget.CLASS)
annotation class Service
