// The entry point: reachability runs from `main`, so every flow below is
// reachableFromRoots with a root witness when --dataflow reachable runs.
package com.example.audit

fun main() {
    val audit = AuditService()
    audit.initLogging()
    val users = UserRepository.connect()
    audit.audit("startup")
    users.findUser()
    users.countUsers()
    users.tokenFor("kosi")
    audit.heartbeat()
}
