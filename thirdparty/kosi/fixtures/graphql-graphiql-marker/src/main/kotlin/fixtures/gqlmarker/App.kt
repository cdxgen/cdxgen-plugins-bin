// The GraphQL starter on the classpath and GraphiQL switched on, with no
// handler in source: the route exists because of the dependency and config
// (graphql-surfaces is the handler-evidenced case).
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=graphql path=/ide method=GET mode=resolved
// kosi:want-not endpoint framework=graphql path=/graphiql
// kosi:want-not endpoint framework=graphql path=/graphql/schema
package fixtures.gqlmarker

class App
