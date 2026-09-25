// A summary visit whose facts pass 10,000 on one key (a 101-field Leaf in a
// 101-field Mid, read through two pickers) EXPLODES, and a default run then
// widens its summary: deep's field paths become `p0.*`. A widened path must
// match every deeper reader; lookups were exact, so the caller's taint at
// `m.g3.f0` never met `p0.*` and the flow main finds was lost in default
// mode (atom-tools#95 review). The counts are in truncations.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want flow source=untrusted-input sink=process-exec fn=~explode.explodes mode=resolved
// kosi:want diagnostic code=dataflow-truncated mode=resolved
//
// Negative half: the same shape with no source is clean.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~cleanExplodes
package fixtures.widened.explode

class Leaf(val f0: String, val f1: String, val f2: String, val f3: String, val f4: String, val f5: String, val f6: String, val f7: String, val f8: String, val f9: String, val f10: String, val f11: String, val f12: String, val f13: String, val f14: String, val f15: String, val f16: String, val f17: String, val f18: String, val f19: String, val f20: String, val f21: String, val f22: String, val f23: String, val f24: String, val f25: String, val f26: String, val f27: String, val f28: String, val f29: String, val f30: String, val f31: String, val f32: String, val f33: String, val f34: String, val f35: String, val f36: String, val f37: String, val f38: String, val f39: String, val f40: String, val f41: String, val f42: String, val f43: String, val f44: String, val f45: String, val f46: String, val f47: String, val f48: String, val f49: String, val f50: String, val f51: String, val f52: String, val f53: String, val f54: String, val f55: String, val f56: String, val f57: String, val f58: String, val f59: String, val f60: String, val f61: String, val f62: String, val f63: String, val f64: String, val f65: String, val f66: String, val f67: String, val f68: String, val f69: String, val f70: String, val f71: String, val f72: String, val f73: String, val f74: String, val f75: String, val f76: String, val f77: String, val f78: String, val f79: String, val f80: String, val f81: String, val f82: String, val f83: String, val f84: String, val f85: String, val f86: String, val f87: String, val f88: String, val f89: String, val f90: String, val f91: String, val f92: String, val f93: String, val f94: String, val f95: String, val f96: String, val f97: String, val f98: String, val f99: String, val f100: String)

class Mid(val g0: Leaf, val g1: Leaf, val g2: Leaf, val g3: Leaf, val g4: Leaf, val g5: Leaf, val g6: Leaf, val g7: Leaf, val g8: Leaf, val g9: Leaf, val g10: Leaf, val g11: Leaf, val g12: Leaf, val g13: Leaf, val g14: Leaf, val g15: Leaf, val g16: Leaf, val g17: Leaf, val g18: Leaf, val g19: Leaf, val g20: Leaf, val g21: Leaf, val g22: Leaf, val g23: Leaf, val g24: Leaf, val g25: Leaf, val g26: Leaf, val g27: Leaf, val g28: Leaf, val g29: Leaf, val g30: Leaf, val g31: Leaf, val g32: Leaf, val g33: Leaf, val g34: Leaf, val g35: Leaf, val g36: Leaf, val g37: Leaf, val g38: Leaf, val g39: Leaf, val g40: Leaf, val g41: Leaf, val g42: Leaf, val g43: Leaf, val g44: Leaf, val g45: Leaf, val g46: Leaf, val g47: Leaf, val g48: Leaf, val g49: Leaf, val g50: Leaf, val g51: Leaf, val g52: Leaf, val g53: Leaf, val g54: Leaf, val g55: Leaf, val g56: Leaf, val g57: Leaf, val g58: Leaf, val g59: Leaf, val g60: Leaf, val g61: Leaf, val g62: Leaf, val g63: Leaf, val g64: Leaf, val g65: Leaf, val g66: Leaf, val g67: Leaf, val g68: Leaf, val g69: Leaf, val g70: Leaf, val g71: Leaf, val g72: Leaf, val g73: Leaf, val g74: Leaf, val g75: Leaf, val g76: Leaf, val g77: Leaf, val g78: Leaf, val g79: Leaf, val g80: Leaf, val g81: Leaf, val g82: Leaf, val g83: Leaf, val g84: Leaf, val g85: Leaf, val g86: Leaf, val g87: Leaf, val g88: Leaf, val g89: Leaf, val g90: Leaf, val g91: Leaf, val g92: Leaf, val g93: Leaf, val g94: Leaf, val g95: Leaf, val g96: Leaf, val g97: Leaf, val g98: Leaf, val g99: Leaf, val g100: Leaf)

fun pickG(m: Mid, k: Int): Leaf = when (k) {
    0 -> m.g0
    1 -> m.g1
    2 -> m.g2
    3 -> m.g3
    4 -> m.g4
    5 -> m.g5
    6 -> m.g6
    7 -> m.g7
    8 -> m.g8
    9 -> m.g9
    10 -> m.g10
    11 -> m.g11
    12 -> m.g12
    13 -> m.g13
    14 -> m.g14
    15 -> m.g15
    16 -> m.g16
    17 -> m.g17
    18 -> m.g18
    19 -> m.g19
    20 -> m.g20
    21 -> m.g21
    22 -> m.g22
    23 -> m.g23
    24 -> m.g24
    25 -> m.g25
    26 -> m.g26
    27 -> m.g27
    28 -> m.g28
    29 -> m.g29
    30 -> m.g30
    31 -> m.g31
    32 -> m.g32
    33 -> m.g33
    34 -> m.g34
    35 -> m.g35
    36 -> m.g36
    37 -> m.g37
    38 -> m.g38
    39 -> m.g39
    40 -> m.g40
    41 -> m.g41
    42 -> m.g42
    43 -> m.g43
    44 -> m.g44
    45 -> m.g45
    46 -> m.g46
    47 -> m.g47
    48 -> m.g48
    49 -> m.g49
    50 -> m.g50
    51 -> m.g51
    52 -> m.g52
    53 -> m.g53
    54 -> m.g54
    55 -> m.g55
    56 -> m.g56
    57 -> m.g57
    58 -> m.g58
    59 -> m.g59
    60 -> m.g60
    61 -> m.g61
    62 -> m.g62
    63 -> m.g63
    64 -> m.g64
    65 -> m.g65
    66 -> m.g66
    67 -> m.g67
    68 -> m.g68
    69 -> m.g69
    70 -> m.g70
    71 -> m.g71
    72 -> m.g72
    73 -> m.g73
    74 -> m.g74
    75 -> m.g75
    76 -> m.g76
    77 -> m.g77
    78 -> m.g78
    79 -> m.g79
    80 -> m.g80
    81 -> m.g81
    82 -> m.g82
    83 -> m.g83
    84 -> m.g84
    85 -> m.g85
    86 -> m.g86
    87 -> m.g87
    88 -> m.g88
    89 -> m.g89
    90 -> m.g90
    91 -> m.g91
    92 -> m.g92
    93 -> m.g93
    94 -> m.g94
    95 -> m.g95
    96 -> m.g96
    97 -> m.g97
    98 -> m.g98
    99 -> m.g99
    else -> m.g100
}

fun pickF(l: Leaf, k: Int): String = when (k) {
    0 -> l.f0
    1 -> l.f1
    2 -> l.f2
    3 -> l.f3
    4 -> l.f4
    5 -> l.f5
    6 -> l.f6
    7 -> l.f7
    8 -> l.f8
    9 -> l.f9
    10 -> l.f10
    11 -> l.f11
    12 -> l.f12
    13 -> l.f13
    14 -> l.f14
    15 -> l.f15
    16 -> l.f16
    17 -> l.f17
    18 -> l.f18
    19 -> l.f19
    20 -> l.f20
    21 -> l.f21
    22 -> l.f22
    23 -> l.f23
    24 -> l.f24
    25 -> l.f25
    26 -> l.f26
    27 -> l.f27
    28 -> l.f28
    29 -> l.f29
    30 -> l.f30
    31 -> l.f31
    32 -> l.f32
    33 -> l.f33
    34 -> l.f34
    35 -> l.f35
    36 -> l.f36
    37 -> l.f37
    38 -> l.f38
    39 -> l.f39
    40 -> l.f40
    41 -> l.f41
    42 -> l.f42
    43 -> l.f43
    44 -> l.f44
    45 -> l.f45
    46 -> l.f46
    47 -> l.f47
    48 -> l.f48
    49 -> l.f49
    50 -> l.f50
    51 -> l.f51
    52 -> l.f52
    53 -> l.f53
    54 -> l.f54
    55 -> l.f55
    56 -> l.f56
    57 -> l.f57
    58 -> l.f58
    59 -> l.f59
    60 -> l.f60
    61 -> l.f61
    62 -> l.f62
    63 -> l.f63
    64 -> l.f64
    65 -> l.f65
    66 -> l.f66
    67 -> l.f67
    68 -> l.f68
    69 -> l.f69
    70 -> l.f70
    71 -> l.f71
    72 -> l.f72
    73 -> l.f73
    74 -> l.f74
    75 -> l.f75
    76 -> l.f76
    77 -> l.f77
    78 -> l.f78
    79 -> l.f79
    80 -> l.f80
    81 -> l.f81
    82 -> l.f82
    83 -> l.f83
    84 -> l.f84
    85 -> l.f85
    86 -> l.f86
    87 -> l.f87
    88 -> l.f88
    89 -> l.f89
    90 -> l.f90
    91 -> l.f91
    92 -> l.f92
    93 -> l.f93
    94 -> l.f94
    95 -> l.f95
    96 -> l.f96
    97 -> l.f97
    98 -> l.f98
    99 -> l.f99
    else -> l.f100
}

fun deep(m: Mid, k: Int): String = pickF(pickG(m, k), k)

fun shallow(m: Mid, k: Int): Leaf = pickG(m, k)


fun explodes() {
    val src = readLine() ?: ""
    val leaf = Leaf(src, "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
    val m = Mid(leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf)
    Runtime.getRuntime().exec(deep(m, 3))
}

/** The same walk over a Mid no source reached: never a flow. */
fun cleanExplodes() {
    val leaf = Leaf("constant", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
    val m = Mid(leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf)
    Runtime.getRuntime().exec(deep(m, 3))
}
