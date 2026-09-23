// Deployment base paths, one module per key: each framework reads ITS keys,
// keys within a group are alternatives, groups compose (Spring:
// context-path + spring.mvc.servlet.path; Quarkus: root-path + (rest.path |
// @ApplicationPath) with the property winning). Before, one repo-wide
// first-match list applied a Micronaut context path to gRPC and Azure routes
// and never composed the DispatcherServlet path.
//
// kosi:want endpoint framework=spring-mvc path=/ctx/dispatch/b method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/rx/c method=GET mode=resolved
// kosi:want endpoint framework=graphql path=/gql method=POST mode=resolved
// kosi:want endpoint framework=graphql path=/g2 method=POST mode=resolved
// kosi:want endpoint framework=graphql path=/c/s/graphql method=POST mode=resolved
// kosi:want endpoint framework=graphql path=/r/graphql method=POST mode=resolved
// kosi:want endpoint framework=micronaut path=/mn/m/x method=GET mode=resolved
// kosi:want endpoint framework=quarkus path=/root/q/x method=GET mode=resolved
// kosi:want endpoint framework=quarkus path=/rest/q/x method=GET mode=resolved
// kosi:want endpoint framework=quarkus path=/rr/q/x method=GET mode=resolved
// kosi:want endpoint framework=quarkus path=/re/q/x method=GET mode=resolved
// kosi:want endpoint framework=quarkus path=/root/prop/q/x method=GET mode=resolved
// kosi:want endpoint framework=servlet path=/sv/s method=GET mode=resolved
//
// Negative half: a Micronaut @Get outside a @Controller is no route;
// @ApplicationPath loses to quarkus.rest.path; no GraphQL module serves the
// bare default when it configures a path.
// kosi:want-not endpoint framework=micronaut path=/mn/nope
// kosi:want-not endpoint framework=micronaut path=/nope
// kosi:want-not endpoint framework=quarkus path=/root/annotation/q/x
// kosi:want-not endpoint framework=quarkus path=/root/prop/annotation/q/x
// kosi:want-not endpoint framework=graphql path=/graphql
package fixtures.deploy

class Marker
