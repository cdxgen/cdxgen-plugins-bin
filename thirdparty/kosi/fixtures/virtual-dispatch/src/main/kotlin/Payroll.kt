// Negative half first: an open hierarchy must keep its full candidate set —
// a plausibly over-narrow dispatcher (sealed logic applied to an interface,
// or a single-target guess) would drop the second implementation, and the
// label would say sealed-bounded where the hierarchy is open.
// kosi:want-not edge from=~Payroll.pay to=~Hourly.net calltype=sealed-bounded mode=exported
// kosi:want-not edge from=~pay to=~AuditTrail.run calltype=receiver-typed mode=exported
// kosi:want-not edge from=~runAudit to=java.lang.Runnable.run mode=exported
// kosi:want-not diagnostic code=parse-error
//
// Positive half: interface dispatch keeps every workspace implementation,
// and a call through a LIBRARY interface (java.lang.Runnable) dispatches to
// the workspace implementation instead of stranding at the library leaf.
// kosi:want edge from=~Payroll.pay to=~Salaried.net calltype=interface-cha mode=exported
// kosi:want edge from=~Payroll.pay to=~Hourly.net calltype=interface-cha mode=exported
// kosi:want edge from=~runAudit to=~AuditTrail.run calltype=interface-cha mode=exported
// kosi:want reachable symbol=~Payroll.pay mode=exported
package fixtures.payroll

interface Payslip {
    fun net(): Long
}

class Salaried(val amount: Long) : Payslip {
    override fun net(): Long = amount
}

class Hourly(val hours: Int, val rate: Long) : Payslip {
    override fun net(): Long = hours * rate
}

class Payroll {
    fun pay(p: Payslip): Long = p.net()
}

class AuditTrail(private val tag: String) : Runnable {
    override fun run() {
        println("audit:$tag")
    }
}

fun defaultAudit(): Runnable = AuditTrail("payroll")

fun runAudit(audit: Runnable) {
    audit.run()
}
