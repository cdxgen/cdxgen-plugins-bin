// The base path set in CODE: Spring applies RepositoryRestConfigurer after
// the properties, so the folded setBasePath argument is the served base.
// An empty repository interface (no members, so no KIR function) is still
// a resource, under its @RepositoryRestResource path.
//
// kosi:want endpoint framework=spring-mvc path=/v2/reports method=GET pathunresolved=none mode=resolved
// kosi:want endpoint framework=spring-mvc path=/v2/people method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/v2/people/{id} method=DELETE mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/v2/persons
// kosi:want-not endpoint framework=spring-mvc path=/reports
// kosi:want-not endpoint framework=spring-mvc path=/v2/secrets
package fixtures.datarest

import org.springframework.data.repository.CrudRepository
import org.springframework.data.rest.core.annotation.RepositoryRestResource
import org.springframework.data.rest.core.config.RepositoryRestConfiguration
import org.springframework.data.rest.webmvc.BasePathAwareController
import org.springframework.data.rest.webmvc.config.RepositoryRestConfigurer
import org.springframework.web.bind.annotation.GetMapping

private const val API_VERSION = "/v2"

class RestConfig : RepositoryRestConfigurer {
    override fun configureRepositoryRestConfiguration(config: RepositoryRestConfiguration) {
        config.setBasePath(API_VERSION)
    }
}

@BasePathAwareController
class Reports {
    @GetMapping("/reports")
    fun reports(): String = "r"
}

class Person(val id: Long = 0)

@RepositoryRestResource(path = "people")
interface PersonRepository : CrudRepository<Person, Long>

class Secret(val id: Long = 0)

@RepositoryRestResource(exported = false)
interface SecretRepository : CrudRepository<Secret, Long>
