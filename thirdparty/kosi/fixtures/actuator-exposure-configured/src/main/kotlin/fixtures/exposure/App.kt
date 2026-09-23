// Exposure as configured: include names health, env, loggers and heapdump,
// exclude wins over include for heapdump; path-mapping renames health to
// healthz; springdoc serves its spec at springdoc.api-docs.path and the
// swagger UI is disabled.
// kosi:want endpoint framework=spring-actuator path=/actuator/healthz method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/env method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/env/{toMatch} method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/loggers/{name} method=POST mode=resolved
// kosi:want endpoint framework=springdoc path=/openapi mode=resolved
// kosi:want endpoint framework=springdoc path=/openapi.yaml mode=resolved
// kosi:want-not endpoint framework=spring-actuator path=/actuator/heapdump
// kosi:want-not endpoint framework=spring-actuator path=/actuator/health
// kosi:want-not endpoint framework=spring-actuator path=/actuator/loggers method=POST
// kosi:want-not endpoint framework=springdoc path=/v3/api-docs
// kosi:want-not endpoint framework=springdoc path=/swagger-ui.html
// kosi:want-not endpoint framework=springdoc path=/swagger-ui/index.html
package fixtures.exposure

class App
