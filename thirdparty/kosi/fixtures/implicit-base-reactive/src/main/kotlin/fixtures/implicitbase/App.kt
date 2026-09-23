// Dependency-implied trees (Actuator, springdoc) are served by the same
// DispatcherServlet / WebFlux handler as the app's own routes, so the
// deployment base path applies to them: spring.webflux.base-path=/rx.
// kosi:want endpoint framework=spring-actuator path=/rx/actuator/health mode=resolved
// kosi:want endpoint framework=springdoc path=/rx/v3/api-docs mode=resolved
// kosi:want-not endpoint framework=spring-actuator path=/actuator/health
// kosi:want-not endpoint framework=springdoc path=/v3/api-docs
package fixtures.implicitbase

class App
