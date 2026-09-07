// Negative half first: the clean sibling field must stay untainted later;
// structurally, the fixture must not invent declarations that do not exist.
// kosi:want-not declaration name=Audit kind=class
// kosi:want-not diagnostic code=parse-error
//
// Positive half.
// kosi:want declaration name=Payment kind=data-class
// kosi:want declaration name=renamed kind=function
// kosi:want usage name=~.copy
package fixtures.records

data class Payment(val id: String, val amountCents: Long, val memo: String)

fun renamed(payment: Payment, memo: String): Payment =
    payment.copy(memo = memo)
