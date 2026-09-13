// Negative half: a homonym @Get declared in the DTO's own package must not
// resolve into an endpoint.
// kosi:want-not endpoint framework=micronaut path=~/dto-plans mode=resolved
package fixtures.micronaut

import fixtures.micronaut.dto.Get

class DtoApi {
    @Get("/dto-plans")
    fun dtoPlans(): List<String> = listOf("dto")
}
