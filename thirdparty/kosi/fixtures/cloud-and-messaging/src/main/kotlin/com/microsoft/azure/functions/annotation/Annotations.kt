// Azure Functions Java annotations (azure-functions-java-library 3.3.0, the
// extract's pin): @FunctionName names the function, @HttpTrigger marks the
// HTTP entry parameter.
package com.microsoft.azure.functions.annotation

annotation class FunctionName(val value: String)

annotation class HttpTrigger(
    val name: String = "",
    val route: String = "",
    val methods: Array<com.microsoft.azure.functions.HttpMethod> = [],
)

annotation class QueueTrigger(val name: String = "", val queueName: String = "")

annotation class BindingName(val value: String)
