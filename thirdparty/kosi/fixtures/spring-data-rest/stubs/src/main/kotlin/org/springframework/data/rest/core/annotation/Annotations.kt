// spring-data-rest-core 3.6.4: `path` and `exported` are SCALARS here.
package org.springframework.data.rest.core.annotation

annotation class RepositoryRestResource(
    val exported: Boolean = true,
    val path: String = "",
    val collectionResourceRel: String = "",
)

annotation class RestResource(val exported: Boolean = true, val path: String = "", val rel: String = "")
