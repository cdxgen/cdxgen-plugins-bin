// spring-data-rest-webmvc 3.6.4, by shape: both are meta-annotated
// @Component and NOT @Controller, and RepositoryRestController carries
// BasePathAwareController (javap -v).
package org.springframework.data.rest.webmvc

annotation class BasePathAwareController(vararg val value: String = [])

@BasePathAwareController
annotation class RepositoryRestController(vararg val value: String = [])
