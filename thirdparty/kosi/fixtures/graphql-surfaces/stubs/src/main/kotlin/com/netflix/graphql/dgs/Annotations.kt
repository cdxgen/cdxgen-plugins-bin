// graphql-dgs 8.x by shape (netflix.github.io/dgs).
package com.netflix.graphql.dgs

annotation class DgsComponent
annotation class DgsQuery(val field: String = "")
annotation class DgsMutation(val field: String = "")
annotation class DgsSubscription(val field: String = "")
annotation class DgsData(val parentType: String, val field: String = "")
annotation class InputArgument(val value: String = "")
