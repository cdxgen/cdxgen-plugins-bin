// With the starter and NO exposure config, Spring Boot exposes "only the
// /health endpoint" over HTTP (docs.spring.io actuator/endpoints). /env,
// /heapdump and the rest were published on every such app.
// kosi:want endpoint framework=spring-actuator path=/actuator/health method=GET mode=resolved
// kosi:want endpoint framework=spring-actuator path=/actuator method=GET mode=resolved
// kosi:want endpoint framework=springdoc path=/v3/api-docs mode=resolved
// kosi:want endpoint framework=springdoc path=/v3/api-docs.yaml mode=resolved
// kosi:want endpoint framework=springdoc path=/swagger-ui.html mode=resolved
// kosi:want-not endpoint framework=spring-actuator path=/actuator/env
// kosi:want-not endpoint framework=spring-actuator path=/actuator/heapdump
// kosi:want-not endpoint framework=spring-actuator path=/actuator/threaddump
// kosi:want-not endpoint framework=spring-actuator path=/actuator/info
package fixtures.exposure

class App
