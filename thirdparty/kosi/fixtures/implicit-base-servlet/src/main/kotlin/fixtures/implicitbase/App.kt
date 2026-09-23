// Dependency-implied trees (Actuator, springdoc) are served by the same
// DispatcherServlet / WebFlux handler as the app's own routes, so the
// deployment base path applies to them: server.servlet.context-path=/ctx + spring.mvc.servlet.path=/app.
// kosi:want endpoint framework=spring-actuator path=/ctx/app/actuator/health mode=resolved
// kosi:want endpoint framework=springdoc path=/ctx/app/v3/api-docs mode=resolved
// kosi:want-not endpoint framework=spring-actuator path=/actuator/health
// kosi:want-not endpoint framework=springdoc path=/v3/api-docs
package fixtures.implicitbase

class App
