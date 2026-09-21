// the frameworks the pack modelled but no fixture exercised — the
// liveness sweep's whole-population finding. Each handler here makes its
// framework's rows LIVE (removing the pack entry changes this fixture's
// report), which is the only proof a modelled capability exists.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// One live want per modelled row-group: the endpoint EXISTS with its
// handler, which is exactly what the liveness sweep needs (removing the
// pack entry changes this fixture's report).
// kosi:want endpoint framework=aws-lambda fn=~LambdaHandler.handleRequest mode=resolved
// kosi:want endpoint framework=aws-lambda fn=~StreamLambdaHandler.handleRequest mode=resolved
//
// (docs: the Context argument is the runtime's, not the event's):
// under handlerInput=all the event parameter still seeds, and the declared
// context type does not. Both directions pinned.
// kosi:want flow source=untrusted-input sink=process-exec fn=~LambdaHandler.handleRequest mode=endpoint
// kosi:want-not flow source=~ sink=~ fn=~ContextOnlyHandler.handleRequest mode=endpoint
// kosi:want endpoint framework=azure-functions path=hello mode=resolved
// kosi:want endpoint framework=azure-functions path=queued mode=resolved
// kosi:want endpoint framework=graphql fn=~GraphApi.book mode=resolved
// kosi:want endpoint framework=graphql fn=~GraphApi.addBook mode=resolved
// kosi:want endpoint framework=graphql fn=~GraphApi.updates mode=resolved
// kosi:want endpoint framework=graphql fn=~GraphApi.author mode=resolved
// kosi:want endpoint framework=spring-messaging path=/echo mode=resolved
// kosi:want endpoint framework=spring-messaging path=/init mode=resolved
// kosi:want endpoint framework=spring-messaging path=/room/{room} mode=resolved
// kosi:want endpoint framework=spring-messaging fn=~Listeners.onKafka mode=resolved
// kosi:want endpoint framework=spring-messaging fn=~Listeners.onRabbit mode=resolved
// kosi:want endpoint framework=spring-messaging fn=~Listeners.onJms mode=resolved
// kosi:want endpoint framework=spring-messaging fn=~Listeners.onSqs mode=resolved
// kosi:want endpoint framework=spring-messaging fn=~Listeners.tick mode=resolved
package fixtures.cloudmsg

import com.amazonaws.services.lambda.runtime.Context
import com.amazonaws.services.lambda.runtime.RequestHandler
import com.amazonaws.services.lambda.runtime.RequestStreamHandler
import com.microsoft.azure.functions.annotation.BindingName
import com.microsoft.azure.functions.annotation.FunctionName
import com.microsoft.azure.functions.annotation.HttpTrigger
import com.microsoft.azure.functions.annotation.QueueTrigger
import io.awspring.cloud.sqs.annotation.SqsListener
import org.springframework.amqp.rabbit.annotation.RabbitListener
import org.springframework.graphql.data.method.annotation.Argument
import org.springframework.graphql.data.method.annotation.MutationMapping
import org.springframework.graphql.data.method.annotation.QueryMapping
import org.springframework.graphql.data.method.annotation.SchemaMapping
import org.springframework.graphql.data.method.annotation.SubscriptionMapping
import org.springframework.jms.annotation.JmsListener
import org.springframework.kafka.annotation.KafkaListener
import org.springframework.messaging.handler.annotation.DestinationVariable
import org.springframework.messaging.handler.annotation.Header
import org.springframework.messaging.handler.annotation.MessageMapping
import org.springframework.messaging.handler.annotation.Payload
import org.springframework.messaging.simp.annotation.SubscribeMapping
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Controller

// ---- AWS Lambda: the supertype shape --------------------------------------

class LambdaHandler : RequestHandler<String, String> {
    override fun handleRequest(input: String, context: Context): String {
        // The EVENT is the payload (`all`), the Context beside it is
        // the framework's own — the flow pins the first, the want-not below
        // pins the second.
        Runtime.getRuntime().exec(input)
        return input
    }
}

class StreamLambdaHandler : RequestStreamHandler {
    override fun handleRequest(input: java.io.InputStream, output: java.io.OutputStream, context: Context) {
    }
}

/**
 * Only the Context reaches a sink — nothing may flow from it. The
 * FIELD read is the pin: under the defect the context seeds FIELD-BEARING
 * and `context.functionName` derives taint, so the want-not fails.
 */
class ContextOnlyHandler : RequestHandler<String, String> {
    override fun handleRequest(input: String, context: Context): String =
        Runtime.getRuntime().exec(context.functionName).toString()
}

// ---- Azure Functions: the annotation shape --------------------------------

class Functions {
    @FunctionName("hello")
    fun hello(@HttpTrigger(name = "req") req: String): String = req

    @FunctionName("queued")
    fun queued(@QueueTrigger(name = "msg") msg: String, @BindingName("id") id: String): String = msg
}

// ---- spring-graphql: the controller shape ---------------------------------

@Controller
class GraphApi {
    @QueryMapping
    fun book(@Argument id: String): String = id

    @MutationMapping
    fun addBook(@Argument title: String): String = title

    @SubscriptionMapping
    fun updates(): String = ""

    @SchemaMapping(typeName = "Book", field = "author")
    fun author(): String = ""
}

// ---- spring-messaging: the listener shapes --------------------------------

class Listeners {
    @MessageMapping("/echo")
    fun echo(@Payload body: String, @Header("X-Trace") trace: String): String = body

    @SubscribeMapping("/init")
    fun init(): String = ""

    @MessageMapping("/room/{room}")
    fun room(@DestinationVariable room: String): String = room

    @KafkaListener(topics = ["orders"])
    fun onKafka(@Payload payload: String): String = payload

    @RabbitListener(queues = ["work"])
    fun onRabbit(@Payload payload: String): String = payload

    @JmsListener(destination = "jobs")
    fun onJms(@Payload payload: String): String = payload

    @SqsListener(queueNames = ["emails"])
    fun onSqs(@Payload payload: String): String = payload

    @Scheduled(cron = "0 * * * * *")
    fun tick(): String = ""
}
