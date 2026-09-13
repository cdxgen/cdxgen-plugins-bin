package io.jsonwebtoken

enum class SignatureAlgorithm { NONE, HS256 }

class JwtBuilder {
    fun signWith(algorithm: SignatureAlgorithm): JwtBuilder = this
    fun compact(): String = ""
}

object Jwts {
    fun builder(): JwtBuilder = JwtBuilder()
}
