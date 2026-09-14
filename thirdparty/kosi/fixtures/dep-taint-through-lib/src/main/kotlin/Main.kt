// P9 fixture: cross-dependency taint. The DEPENDENCY is libs/dep-helper.jar
// (committed; its source and build live in helper-src/). Every annotation
// names which SIDE of the boundary it proves:
//
//  - dep-sink-flow: the SOURCE is workspace readLine(), the SINK sits INSIDE
//    the jar (Db.runQuery's body calls Statement.executeQuery). Only the
//    --deps tier can see it: on the deps slot the jar's summary carries
//    paramToSink with origin=bytecode and the slice crossesDependency.
//  - dep-source-flow: the SOURCE is INSIDE the jar (Console.readSetting
//    calls readLine()); the jar's sourceReturns carries it back to the
//    workspace, which sinks it in ProcessBuilder.
//  - bodyless-flow: Provider.provide is ABSTRACT (no body). It must never
//    be summarised as "no flow": the flow through it exists on every
//    backend (unknown-propagation without the tier, labelled propagation
//    with it — but it EXISTS either way, which is the point).
//  - clean-helper: Db.hashOf sinks nothing, with or without the tier —
//    the near-miss negative a collapsing implementation would fail.
//
// kosi:want-not diagnostic code=parse-error
//
// kosi:want-not flow source=untrusted-input sink=~ fn=~cleanHelper
// kosi:want flow source=untrusted-input sink=sql-query fn=~depSinkFlow mode=deps
// kosi:want flow source=untrusted-input sink=sql-query fn=~runUpdateFlow mode=deps
// kosi:want flow source=untrusted-input sink=process-exec fn=~depSourceFlow mode=deps
// kosi:want flow source=untrusted-input sink=process-exec fn=~bodylessFlow mode=resolved
// kosi:want flow source=untrusted-input sink=process-exec fn=~bodylessFlow mode=deps
package dev.kosi.app

import dev.kosi.helper.Console
import dev.kosi.helper.Db
import dev.kosi.helper.Provider
import java.sql.DriverManager

fun depSinkFlow(db: Db) {
    val query = readLine() ?: "1=1"
    db.runQuery(query)
}

fun runUpdateFlow(db: Db) {
    db.runUpdate(readLine() ?: "")
}

fun depSourceFlow() {
    val db = Db(DriverManager.getConnection("jdbc:h2:mem:test"))
    val setting = Console.readSetting()
    if (setting != null) {
        ProcessBuilder(setting)
    }
    db.hashCode()
}

fun bodylessFlow(provider: Provider) {
    val key = readLine() ?: ""
    ProcessBuilder(provider.provide(key))
}

fun cleanHelper(db: Db) {
    db.hashOf(readLine() ?: "")
}


