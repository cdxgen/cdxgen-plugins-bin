// Actuator with exposure.include=* : every modelled endpoint is served under
// /actuator, except those exposure.exclude names (exclude wins).
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
// kosi:want endpoint framework=spring-actuator path=/actuator/health method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/health/{path} method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/info method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/beans method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/caches method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/caches method=DELETE mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/conditions method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/configprops method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/loggers method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/loggers/{name} method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/loggers/{name} method=POST mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/metrics method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/metrics/{requiredMetricName} method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/threaddump method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/heapdump method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/mappings method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/scheduledtasks method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/prometheus method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/startup method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/startup method=POST mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator/shutdown method=POST mode=resolved
//
// Negative half: the excluded id is not served, and nothing leaks to the root.
// kosi:want-not endpoint framework=spring-actuator path=/actuator/env
// kosi:want-not endpoint framework=spring-actuator path=/actuator/env/{toMatch}
// kosi:want-not endpoint framework=spring-actuator path=/heapdump
package fixtures.actuatorall

class App
