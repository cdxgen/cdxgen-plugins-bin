// spring-graphql's controller annotations.
package org.springframework.graphql.data.method.annotation

annotation class QueryMapping(val name: String = "")

annotation class MutationMapping(val name: String = "")

annotation class SubscriptionMapping(val name: String = "")

annotation class SchemaMapping(val typeName: String = "", val field: String = "")

annotation class Argument(val name: String = "")
