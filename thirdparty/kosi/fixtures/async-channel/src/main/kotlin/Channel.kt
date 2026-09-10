// A send/receive pair moves the value through the channel's element state.
// Negative half: the channel only ever carries clean values.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~channelClean known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~channelSink known-fail=syntax:1
package fixtures.async.channel

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel

fun channelSink() {
    runBlocking {
        val channel = Channel<String>(4)
        channel.send(readLine() ?: "")
        ProcessBuilder(channel.receive())
    }
}

fun channelClean() {
    runBlocking {
        val channel = Channel<String>(4)
        channel.send("safe")
        ProcessBuilder(channel.receive())
    }
}
