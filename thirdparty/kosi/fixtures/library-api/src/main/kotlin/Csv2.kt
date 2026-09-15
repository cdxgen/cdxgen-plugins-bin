// The homonym package: same simple names, different canonical names. The
// graph keys on canonical names, so nothing here may satisfy the other
// file's expectations. Internal and uncalled: if the other file's roots
// leaked across names, this class would light up as reached and its
// want-not would fail.
package fixtures.csv2

internal class CsvWriter {
    fun row(): String = ""
}
