// the PARTIAL half of the pathKind vocabulary. The depth report's
// reachability table had measured `partial` at ZERO on every bundled
// fixture and every pinned repo — an elided slice, the class a consumer
// must be told about (endpoints guaranteed, the middle cut), existed
// nowhere the corpus could see. The chain below runs a taint value through
// one hundred summary boundaries; the composed trace outgrows the default
// trace cap (64 nodes — a first 40-hop draft measured COMPLETE at 42
// nodes, which is why the number is what it is), the walk is cut, and the
// published slice is PARTIAL — the schema's `pathKind=partial`, counted
// non-zero in the depth report from here on. The finding itself still
// ships: an elided trace is a degraded WITNESS, not a refused answer.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want-not diagnostic code=lowering-failed
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~hop100 mode=resolved
package fixtures.elided

/** Hop 1: one boundary, one passthrough. */

fun hop1(s: String): String = hop2(s)

/** Hop 2: one boundary, one passthrough. */

fun hop2(s: String): String = hop3(s)

/** Hop 3: one boundary, one passthrough. */

fun hop3(s: String): String = hop4(s)

/** Hop 4: one boundary, one passthrough. */

fun hop4(s: String): String = hop5(s)

/** Hop 5: one boundary, one passthrough. */

fun hop5(s: String): String = hop6(s)

/** Hop 6: one boundary, one passthrough. */

fun hop6(s: String): String = hop7(s)

/** Hop 7: one boundary, one passthrough. */

fun hop7(s: String): String = hop8(s)

/** Hop 8: one boundary, one passthrough. */

fun hop8(s: String): String = hop9(s)

/** Hop 9: one boundary, one passthrough. */

fun hop9(s: String): String = hop10(s)

/** Hop 10: one boundary, one passthrough. */

fun hop10(s: String): String = hop11(s)

/** Hop 11: one boundary, one passthrough. */

fun hop11(s: String): String = hop12(s)

/** Hop 12: one boundary, one passthrough. */

fun hop12(s: String): String = hop13(s)

/** Hop 13: one boundary, one passthrough. */

fun hop13(s: String): String = hop14(s)

/** Hop 14: one boundary, one passthrough. */

fun hop14(s: String): String = hop15(s)

/** Hop 15: one boundary, one passthrough. */

fun hop15(s: String): String = hop16(s)

/** Hop 16: one boundary, one passthrough. */

fun hop16(s: String): String = hop17(s)

/** Hop 17: one boundary, one passthrough. */

fun hop17(s: String): String = hop18(s)

/** Hop 18: one boundary, one passthrough. */

fun hop18(s: String): String = hop19(s)

/** Hop 19: one boundary, one passthrough. */

fun hop19(s: String): String = hop20(s)

/** Hop 20: one boundary, one passthrough. */

fun hop20(s: String): String = hop21(s)

/** Hop 21: one boundary, one passthrough. */

fun hop21(s: String): String = hop22(s)

/** Hop 22: one boundary, one passthrough. */

fun hop22(s: String): String = hop23(s)

/** Hop 23: one boundary, one passthrough. */

fun hop23(s: String): String = hop24(s)

/** Hop 24: one boundary, one passthrough. */

fun hop24(s: String): String = hop25(s)

/** Hop 25: one boundary, one passthrough. */

fun hop25(s: String): String = hop26(s)

/** Hop 26: one boundary, one passthrough. */

fun hop26(s: String): String = hop27(s)

/** Hop 27: one boundary, one passthrough. */

fun hop27(s: String): String = hop28(s)

/** Hop 28: one boundary, one passthrough. */

fun hop28(s: String): String = hop29(s)

/** Hop 29: one boundary, one passthrough. */

fun hop29(s: String): String = hop30(s)

/** Hop 30: one boundary, one passthrough. */

fun hop30(s: String): String = hop31(s)

/** Hop 31: one boundary, one passthrough. */

fun hop31(s: String): String = hop32(s)

/** Hop 32: one boundary, one passthrough. */

fun hop32(s: String): String = hop33(s)

/** Hop 33: one boundary, one passthrough. */

fun hop33(s: String): String = hop34(s)

/** Hop 34: one boundary, one passthrough. */

fun hop34(s: String): String = hop35(s)

/** Hop 35: one boundary, one passthrough. */

fun hop35(s: String): String = hop36(s)

/** Hop 36: one boundary, one passthrough. */

fun hop36(s: String): String = hop37(s)

/** Hop 37: one boundary, one passthrough. */

fun hop37(s: String): String = hop38(s)

/** Hop 38: one boundary, one passthrough. */

fun hop38(s: String): String = hop39(s)

/** Hop 39: one boundary, one passthrough. */

fun hop39(s: String): String = hop40(s)

/** Hop 40: one boundary, one passthrough. */

fun hop40(s: String): String = hop41(s)

/** Hop 41: one boundary, one passthrough. */

fun hop41(s: String): String = hop42(s)

/** Hop 42: one boundary, one passthrough. */

fun hop42(s: String): String = hop43(s)

/** Hop 43: one boundary, one passthrough. */

fun hop43(s: String): String = hop44(s)

/** Hop 44: one boundary, one passthrough. */

fun hop44(s: String): String = hop45(s)

/** Hop 45: one boundary, one passthrough. */

fun hop45(s: String): String = hop46(s)

/** Hop 46: one boundary, one passthrough. */

fun hop46(s: String): String = hop47(s)

/** Hop 47: one boundary, one passthrough. */

fun hop47(s: String): String = hop48(s)

/** Hop 48: one boundary, one passthrough. */

fun hop48(s: String): String = hop49(s)

/** Hop 49: one boundary, one passthrough. */

fun hop49(s: String): String = hop50(s)

/** Hop 50: one boundary, one passthrough. */

fun hop50(s: String): String = hop51(s)

/** Hop 51: one boundary, one passthrough. */

fun hop51(s: String): String = hop52(s)

/** Hop 52: one boundary, one passthrough. */

fun hop52(s: String): String = hop53(s)

/** Hop 53: one boundary, one passthrough. */

fun hop53(s: String): String = hop54(s)

/** Hop 54: one boundary, one passthrough. */

fun hop54(s: String): String = hop55(s)

/** Hop 55: one boundary, one passthrough. */

fun hop55(s: String): String = hop56(s)

/** Hop 56: one boundary, one passthrough. */

fun hop56(s: String): String = hop57(s)

/** Hop 57: one boundary, one passthrough. */

fun hop57(s: String): String = hop58(s)

/** Hop 58: one boundary, one passthrough. */

fun hop58(s: String): String = hop59(s)

/** Hop 59: one boundary, one passthrough. */

fun hop59(s: String): String = hop60(s)

/** Hop 60: one boundary, one passthrough. */

fun hop60(s: String): String = hop61(s)

/** Hop 61: one boundary, one passthrough. */

fun hop61(s: String): String = hop62(s)

/** Hop 62: one boundary, one passthrough. */

fun hop62(s: String): String = hop63(s)

/** Hop 63: one boundary, one passthrough. */

fun hop63(s: String): String = hop64(s)

/** Hop 64: one boundary, one passthrough. */

fun hop64(s: String): String = hop65(s)

/** Hop 65: one boundary, one passthrough. */

fun hop65(s: String): String = hop66(s)

/** Hop 66: one boundary, one passthrough. */

fun hop66(s: String): String = hop67(s)

/** Hop 67: one boundary, one passthrough. */

fun hop67(s: String): String = hop68(s)

/** Hop 68: one boundary, one passthrough. */

fun hop68(s: String): String = hop69(s)

/** Hop 69: one boundary, one passthrough. */

fun hop69(s: String): String = hop70(s)

/** Hop 70: one boundary, one passthrough. */

fun hop70(s: String): String = hop71(s)

/** Hop 71: one boundary, one passthrough. */

fun hop71(s: String): String = hop72(s)

/** Hop 72: one boundary, one passthrough. */

fun hop72(s: String): String = hop73(s)

/** Hop 73: one boundary, one passthrough. */

fun hop73(s: String): String = hop74(s)

/** Hop 74: one boundary, one passthrough. */

fun hop74(s: String): String = hop75(s)

/** Hop 75: one boundary, one passthrough. */

fun hop75(s: String): String = hop76(s)

/** Hop 76: one boundary, one passthrough. */

fun hop76(s: String): String = hop77(s)

/** Hop 77: one boundary, one passthrough. */

fun hop77(s: String): String = hop78(s)

/** Hop 78: one boundary, one passthrough. */

fun hop78(s: String): String = hop79(s)

/** Hop 79: one boundary, one passthrough. */

fun hop79(s: String): String = hop80(s)

/** Hop 80: one boundary, one passthrough. */

fun hop80(s: String): String = hop81(s)

/** Hop 81: one boundary, one passthrough. */

fun hop81(s: String): String = hop82(s)

/** Hop 82: one boundary, one passthrough. */

fun hop82(s: String): String = hop83(s)

/** Hop 83: one boundary, one passthrough. */

fun hop83(s: String): String = hop84(s)

/** Hop 84: one boundary, one passthrough. */

fun hop84(s: String): String = hop85(s)

/** Hop 85: one boundary, one passthrough. */

fun hop85(s: String): String = hop86(s)

/** Hop 86: one boundary, one passthrough. */

fun hop86(s: String): String = hop87(s)

/** Hop 87: one boundary, one passthrough. */

fun hop87(s: String): String = hop88(s)

/** Hop 88: one boundary, one passthrough. */

fun hop88(s: String): String = hop89(s)

/** Hop 89: one boundary, one passthrough. */

fun hop89(s: String): String = hop90(s)

/** Hop 90: one boundary, one passthrough. */

fun hop90(s: String): String = hop91(s)

/** Hop 91: one boundary, one passthrough. */

fun hop91(s: String): String = hop92(s)

/** Hop 92: one boundary, one passthrough. */

fun hop92(s: String): String = hop93(s)

/** Hop 93: one boundary, one passthrough. */

fun hop93(s: String): String = hop94(s)

/** Hop 94: one boundary, one passthrough. */

fun hop94(s: String): String = hop95(s)

/** Hop 95: one boundary, one passthrough. */

fun hop95(s: String): String = hop96(s)

/** Hop 96: one boundary, one passthrough. */

fun hop96(s: String): String = hop97(s)

/** Hop 97: one boundary, one passthrough. */

fun hop97(s: String): String = hop98(s)

/** Hop 98: one boundary, one passthrough. */

fun hop98(s: String): String = hop99(s)

/** Hop 99: one boundary, one passthrough. */

fun hop99(s: String): String = hop100(s)

/** Hop 100: the sink. */

fun hop100(s: String): String {

    ProcessBuilder(s)

    return s

}

/** The entry: the source, then the first of one hundred boundaries. */
fun entry() {
    val raw = readLine()!!
    hop1(raw)
}
