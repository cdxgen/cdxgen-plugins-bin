// The param-to-param EFFECT case: the callee writes one parameter's taint
// into an OBJECT it received as another parameter, field-sensitively. The
// negative half is the callee that writes a DIFFERENT field of the same
// parameter — a write-effect summary keyed on "the callee took both" without
// the field records reports here and is wrong.
// kosi:want-not flow source=untrusted-input sink=process-exec fn=~execLabelWrite known-fail=syntax:1
// kosi:want-not diagnostic code=parse-error
//
// kosi:want flow source=untrusted-input sink=process-exec fn=~execCommandWrite known-fail=syntax:1
package fixtures.summary.paramtoparam

class Box {
    var command: String = ""
    var label: String = "build"
}

fun writeCommand(box: Box, raw: String) {
    box.command = raw
}

fun writeLabel(box: Box, raw: String) {
    box.label = raw
}

fun execCommandWrite() {
    val box = Box()
    writeCommand(box, readLine() ?: "")
    ProcessBuilder(box.command)
}

fun execLabelWrite() {
    val box = Box()
    writeLabel(box, readLine() ?: "")
    ProcessBuilder(box.command)
}
