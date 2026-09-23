// spring-graphql 1.x by shape.
package org.springframework.graphql.data.method.annotation

annotation class QueryMapping(val value: String = "")
annotation class SubscriptionMapping(val value: String = "")
annotation class BatchMapping(val value: String = "", val field: String = "")
annotation class Argument(val value: String = "")
