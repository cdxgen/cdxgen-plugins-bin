// Positive half: Micronaut's controller marker + method mappings.
// kosi:want endpoint framework=micronaut path=/plans fn=~PlanApi.plans method=GET mode=resolved
// kosi:want endpoint framework=micronaut path=/plans fn=~PlanApi.createPlan method=POST mode=resolved
// kosi:want-not endpoint framework=micronaut fn=~PlanCalculator mode=resolved
// kosi:want-not endpoint framework=micronaut path=~/pricing mode=resolved
package fixtures.micronaut

import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Post

@Controller("/plans")
class PlanApi {
    @Get
    fun plans(): List<String> = listOf("free")

    @Post
    fun createPlan(name: String): String = name
}

// A plain class with a mapping-SHAPED method name: the marker gate refuses
// it (no controller annotation on the class), and the commented mapping
// stays commented.
// @Get("/pricing")
class PlanCalculator {
    fun getPricing(): String = "calculation only"
}
