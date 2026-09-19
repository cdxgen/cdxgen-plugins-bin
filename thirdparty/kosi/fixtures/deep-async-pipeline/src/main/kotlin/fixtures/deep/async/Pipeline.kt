// The value crosses a suspend call, a Flow operator chain and a Channel,
// then reaches the sink four frames later. The negative half is the same
// pipeline with a sanitizer in one operator.
//
// Negative half first: UUID.fromString inside the flow operator clears the
// untrusted-input category before the sink.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~pipelineSanitized
// kosi:want-not diagnostic code=parse-error
//
// Positive half.
// kosi:want flow source=untrusted-input sink=process-exec fn=~pipelineSink frames=6
package fixtures.deep.async

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.util.UUID

class Loader {
    suspend fun fetch(raw: String): String = withContext(Dispatchers.Default) { raw }
}

class Transformer(private val loader: Loader) {
    fun stream(raw: String): Flow<String> = flow {
        emit(loader.fetch(raw))
    }.map { value -> "job:" + value }

    fun streamSanitized(raw: String): Flow<String> = flow {
        emit(loader.fetch(raw))
    }.map { value -> UUID.fromString(value.trim()).toString() }
}

class Sink(private val transformer: Transformer) {
    suspend fun drain(raw: String): String {
        val channel = Channel<String>(4)
        transformer.stream(raw).collect { value -> channel.send(value) }
        return channel.receive()
    }

    suspend fun drainSanitized(raw: String): String {
        val channel = Channel<String>(4)
        transformer.streamSanitized(raw).collect { value -> channel.send(value) }
        return channel.receive()
    }
}

suspend fun pipelineSink(sink: Sink) {
    val carried = sink.drain(readLine() ?: "")
    Runtime.getRuntime().exec(carried)
}

suspend fun pipelineSanitized(sink: Sink) {
    val carried = sink.drainSanitized(readLine() ?: "")
    Runtime.getRuntime().exec(carried)
}
