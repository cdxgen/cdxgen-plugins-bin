// Negative half first: reachability must not claim dead code runs — the
// private helper has no callers and no root can reach it, so claiming it
// would be the graph inventing execution. The homonym-named public function
// in the other package must not be confused with this one.
// kosi:want-not reachable symbol=~secretHelper mode=exported
// kosi:want-not reachable symbol=~fixtures.csv2 mode=exported
// kosi:want-not diagnostic code=parse-error
//
// Positive half: a LIBRARY fixture (no main function). `--roots exported`
// must root the public API and reach the public surface; this fixture is
// where the exported-reach gate measures its fraction.
// kosi:want reachable symbol=~CsvWriter.row mode=exported
// kosi:want reachable symbol=~parseRow mode=exported
// kosi:want declaration name=CsvWriter kind=class
// kosi:want-not declaration name=Secret kind=class
package fixtures.csv

public class CsvWriter(private val separator: Char = ',') {
    public fun row(vararg cells: String): String = cells.joinToString(separator.toString())
    public fun quote(cell: String): String = "\"" + cell.replace("\"", "\"\"") + "\""
    public fun render(rows: List<List<String>>): String {
        val out = StringBuilder()
        for (r in rows) {
            out.append(row(*r.toTypedArray()))
        }
        return out.toString()
    }
}

public fun parseRow(line: String, separator: Char = ','): List<String> = line.split(separator)

internal fun normalize(lines: List<String>): List<String> = lines.filter { it.isNotBlank() }

private fun secretHelper(): Int = 42
