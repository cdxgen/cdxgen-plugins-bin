// Negative half first: narrowing must be auditable in the EDGE LABELS, not
// just the target set — a plausibly over-broad dispatcher would label the
// sealed sites with the open-hierarchy type or strand them as one static
// edge to the abstract declaration, and both are wanted-NOT here.
// kosi:want-not edge from=~Checkout.total to=~Walkup.price calltype=interface-cha mode=exported
// kosi:want-not edge from=~Checkout.total to=~Advance.price calltype=sealed-exact mode=exported
// kosi:want-not edge from=~Checkout.total to=~Ticket.price calltype=static mode=exported
// kosi:want-not diagnostic code=parse-error
//
// Positive half: dispatch on a sealed hierarchy narrows to the closed target
// set (sealed-bounded), and a receiver whose exact type is known narrows to
// sealed-exact (02-ARCHITECTURE.md §5, sealed).
// kosi:want edge from=~Checkout.total to=~Walkup.price calltype=sealed-bounded mode=exported
// kosi:want edge from=~Checkout.total to=~Advance.price calltype=sealed-bounded mode=exported
// kosi:want edge from=~dispatchExact to=~Advance.price calltype=static mode=exported
// kosi:want edge from=~advanceTotal to=~Advance.price calltype=sealed-exact mode=exported
// kosi:want reachable symbol=~Checkout.total mode=exported
package fixtures.tickets

sealed class Ticket {
    abstract fun price(): Int
    object Walkup : Ticket() {
        override fun price() = 20
    }

    data class Advance(val daysEarly: Int) : Ticket() {
        override fun price() = 15 - daysEarly.coerceAtMost(10)
    }
}

class Checkout {
    fun total(ticket: Ticket, qty: Int): Int = ticket.price() * qty
}

// Resolution on the EXACT type lands on the final override directly: static.
fun dispatchExact(): Int = Ticket.Advance(3).price() * 2

// A receiver DECLARED as the sealed base dispatches on the closed set; the
// variable's known construction narrows it to exactly one live target.
fun advanceTotal(): Int {
    val t: Ticket = Ticket.Advance(5)
    return t.price() + 1
}

fun refund(ticket: Ticket): Int = -ticket.price()
