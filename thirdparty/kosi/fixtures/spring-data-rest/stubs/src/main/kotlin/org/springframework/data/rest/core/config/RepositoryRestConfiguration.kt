// getBasePath() returns URI while setBasePath takes String, so Kotlin
// synthesizes no `basePath` property: the call is the only code spelling.
package org.springframework.data.rest.core.config

open class RepositoryRestConfiguration {
    fun setBasePath(basePath: String): RepositoryRestConfiguration = this
    fun getBasePath(): java.net.URI = java.net.URI("")
}
