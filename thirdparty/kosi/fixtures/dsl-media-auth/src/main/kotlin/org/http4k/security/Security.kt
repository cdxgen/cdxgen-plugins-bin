// Minimal http4k security-provider surface (core/security/core/src/main/
// kotlin/org/http4k/security/ at 6.59.0.0): each class IS a Security whose
// filter the router applies per request. Constructor argument types are
// reduced to what the fixture needs; the FQNs are the modelled surface.
package org.http4k.security

open class Security

class BasicAuthSecurity(val realm: String, val credentials: String) : Security()

class ApiKeySecurity(val name: String, val validateKey: (String) -> Boolean) : Security()
